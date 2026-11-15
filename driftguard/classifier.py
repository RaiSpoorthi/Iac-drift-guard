"""Assign a security severity to each drifted resource.

Each rule looks at one class of risk and returns zero or more
(severity, reason) pairs. A finding takes the highest severity any rule gave it.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from driftguard.detector import DELETED, DriftItem


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    item: DriftItem
    severity: Severity
    reasons: list[str]


Hit = tuple[Severity, str]
Rule = Callable[[DriftItem], list[Hit]]


def _touches(item: DriftItem, *roots: str) -> bool:
    """True if any changed path starts at one of the given top-level attributes."""
    for path in item.changed:
        top = path.split(".", 1)[0].split("[", 1)[0]
        if top in roots:
            return True
    return False


# ---------------------------------------------------------------------------
# Network exposure
# ---------------------------------------------------------------------------
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


def _world_admin_ports(rules: Iterable[dict[str, Any]]) -> set[tuple[int, str]]:
    exposed: set[tuple[int, str]] = set()
    for rule in rules or []:
        cidrs = set(rule.get("cidr_blocks") or []) | set(rule.get("ipv6_cidr_blocks") or [])
        if not cidrs & WORLD_CIDRS:
            continue
        protocol = str(rule.get("protocol"))
        low, high = int(rule.get("from_port") or 0), int(rule.get("to_port") or 0)
        for port, name in ADMIN_PORTS.items():
            if protocol in {"-1", "all"} or (protocol in {"tcp", "6"} and low <= port <= high):
                exposed.add((port, name))
    return exposed


def rule_security_group(item: DriftItem) -> list[Hit]:
    if item.resource_type != "aws_security_group":
        return []
    if item.kind == DELETED:
        return [(Severity.HIGH, "Security group deleted outside Terraform")]
    newly_open = _world_admin_ports((item.actual or {}).get("ingress")) - _world_admin_ports(
        (item.expected or {}).get("ingress")
    )
    hits: list[Hit] = [
        (Severity.CRITICAL, f"{name} (port {port}) opened to the internet")
        for port, name in sorted(newly_open)
    ]
    if not newly_open and _touches(item, "ingress"):
        hits.append((Severity.HIGH, "Inbound rules changed outside Terraform"))
    if _touches(item, "egress"):
        hits.append((Severity.HIGH, "Outbound rules changed outside Terraform"))
    return hits


# ---------------------------------------------------------------------------
# S3 public access
# ---------------------------------------------------------------------------
PAB_FLAGS = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")


def rule_public_access_block(item: DriftItem) -> list[Hit]:
    if item.resource_type != "aws_s3_bucket_public_access_block":
        return []
    if item.kind == DELETED:
        return [(Severity.CRITICAL, "S3 public access block removed")]
    expected, actual = item.expected or {}, item.actual or {}
    disabled = [f for f in PAB_FLAGS if expected.get(f) is True and actual.get(f) is not True]
    if disabled:
        return [(Severity.CRITICAL, f"S3 public access protections disabled: {', '.join(disabled)}")]
    return []


# ---------------------------------------------------------------------------
# IAM privilege escalation
# ---------------------------------------------------------------------------
def _policy_documents(state: dict[str, Any] | None) -> Iterable[str]:
    state = state or {}
    if isinstance(state.get("policy"), str):
        yield state["policy"]
    for inline in state.get("inline_policy") or []:
        if isinstance(inline, dict) and isinstance(inline.get("policy"), str):
            yield inline["policy"]


def _wildcard_actions(document: str) -> set[str]:
    try:
        parsed = json.loads(document)
    except (TypeError, ValueError):
        return set()
    statements = parsed.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    found: set[str] = set()
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        found.update(a for a in actions if a == "*" or a.endswith(":*"))
    return found


def _all_wildcards(state: dict[str, Any] | None) -> set[str]:
    found: set[str] = set()
    for document in _policy_documents(state):
        found |= _wildcard_actions(document)
    return found


def rule_iam(item: DriftItem) -> list[Hit]:
    if not item.resource_type.startswith("aws_iam_"):
        return []
    if item.kind == DELETED:
        return [(Severity.HIGH, "IAM resource deleted outside Terraform")]
    granted = _all_wildcards(item.actual) - _all_wildcards(item.expected)
    if granted:
        return [(Severity.CRITICAL, f"Wildcard permissions granted: {', '.join(sorted(granted))}")]
    if _touches(item, "policy", "inline_policy", "assume_role_policy", "managed_policy_arns"):
        return [(Severity.HIGH, "IAM permissions or trust policy changed outside Terraform")]
    return []


# ---------------------------------------------------------------------------
# Data protection
# ---------------------------------------------------------------------------
def rule_encryption(item: DriftItem) -> list[Hit]:
    if item.resource_type == "aws_s3_bucket_server_side_encryption_configuration":
        if item.kind == DELETED:
            return [(Severity.HIGH, "Default bucket encryption removed")]
        return [(Severity.HIGH, "Bucket encryption settings changed")]
    if item.resource_type == "aws_s3_bucket" and _touches(item, "server_side_encryption_configuration"):
        return [(Severity.HIGH, "Bucket encryption settings changed")]
    if item.resource_type == "aws_dynamodb_table" and _touches(item, "server_side_encryption"):
        return [(Severity.HIGH, "Table encryption settings changed")]
    if item.resource_type == "aws_kms_key" and _touches(item, "enable_key_rotation", "is_enabled", "policy"):
        return [(Severity.HIGH, "KMS key configuration changed")]
    return []


def rule_recoverability(item: DriftItem) -> list[Hit]:
    if item.resource_type == "aws_s3_bucket_versioning":
        if item.kind == DELETED:
            return [(Severity.MEDIUM, "Bucket versioning configuration removed")]
        status = ((item.actual or {}).get("versioning_configuration") or [{}])[0].get("status")
        return [(Severity.MEDIUM, f"Bucket versioning changed to {status or 'unknown'}")]
    if item.resource_type == "aws_s3_bucket" and _touches(item, "versioning"):
        return [(Severity.MEDIUM, "Bucket versioning changed")]
    if item.resource_type == "aws_dynamodb_table" and _touches(item, "point_in_time_recovery"):
        pitr = ((item.actual or {}).get("point_in_time_recovery") or [{}])[0]
        state = "disabled" if not pitr.get("enabled") else "changed"
        return [(Severity.MEDIUM, f"Point-in-time recovery {state}")]
    return []


def rule_tags_only(item: DriftItem) -> list[Hit]:
    if item.kind != DELETED and item.changed and all(
        p.split(".", 1)[0] in {"tags", "tags_all"} for p in item.changed
    ):
        return [(Severity.LOW, "Only tags changed")]
    return []


RULES: list[Rule] = [
    rule_security_group,
    rule_public_access_block,
    rule_iam,
    rule_encryption,
    rule_recoverability,
    rule_tags_only,
]


def classify(item: DriftItem) -> Finding:
    hits = [hit for rule in RULES for hit in rule(item)]
    if not hits:
        if item.kind == DELETED:
            hits = [(Severity.HIGH, "Resource deleted outside Terraform")]
        else:
            hits = [(Severity.MEDIUM, "Configuration changed outside Terraform")]
    severity = max(sev for sev, _ in hits)
    reasons = list(dict.fromkeys(reason for _, reason in sorted(hits, key=lambda h: -h[0])))
    return Finding(item=item, severity=severity, reasons=reasons)


def classify_all(items: Iterable[DriftItem]) -> list[Finding]:
    findings = [classify(item) for item in items]
    return sorted(findings, key=lambda f: (-f.severity, f.item.address))
