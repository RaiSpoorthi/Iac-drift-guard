"""Builders for Terraform JSON plan fragments used across tests."""

from __future__ import annotations

from typing import Any


def drift(address: str, before: dict[str, Any] | None, after: dict[str, Any] | None,
          actions: list[str] | None = None) -> dict[str, Any]:
    rtype = address.split(".")[0]
    if actions is None:
        actions = ["delete"] if after is None else ["update"]
    return {
        "address": address,
        "mode": "managed",
        "type": rtype,
        "name": address.split(".")[1],
        "change": {"actions": actions, "before": before, "after": after},
    }


def change(address: str, before: dict[str, Any] | None, after: dict[str, Any] | None,
           actions: list[str], after_unknown: dict[str, Any] | None = None) -> dict[str, Any]:
    entry = drift(address, before, after, actions)
    entry["change"]["after_unknown"] = after_unknown or {}
    return entry


def plan(resource_drift: list | None = None, resource_changes: list | None = None) -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "resource_drift": resource_drift or [],
        "resource_changes": resource_changes or [],
    }


HTTPS_RULE = {
    "cidr_blocks": ["10.20.0.0/16"], "description": "HTTPS from within the VPC",
    "from_port": 443, "to_port": 443, "protocol": "tcp",
    "ipv6_cidr_blocks": [], "prefix_list_ids": [], "security_groups": [], "self": False,
}

SSH_WORLD_RULE = {
    "cidr_blocks": ["0.0.0.0/0"], "description": "temporary debug access",
    "from_port": 22, "to_port": 22, "protocol": "tcp",
    "ipv6_cidr_blocks": [], "prefix_list_ids": [], "security_groups": [], "self": False,
}

TAGS = {"Project": "driftguard", "Environment": "lab", "Owner": "security-team", "ManagedBy": "terraform"}

LEAST_PRIVILEGE_POLICY = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::driftguard-data-lab/*"}]}'
)

WILDCARD_POLICY = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
