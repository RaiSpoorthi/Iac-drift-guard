"""Turn a Terraform JSON plan into a list of drifted resources.

Terraform reports out-of-band changes in two places of `terraform show -json`:

* ``resource_drift``   - what changed in the real infrastructure since the last
                         apply (before = last known state, after = real state).
* ``resource_changes`` - what Terraform would do to bring reality back in line
                         with the code (before = real state, after = desired).

``resource_drift`` is the primary source. ``resource_changes`` is used as a
fallback so that a needed correction is never silently missed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Attributes that never carry security meaning.
NOISE_KEYS = {"timeouts"}

MODIFIED = "modified"
DELETED = "deleted"


@dataclass
class DriftItem:
    address: str
    resource_type: str
    kind: str  # MODIFIED or DELETED
    expected: dict[str, Any] | None  # what Terraform believes / wants
    actual: dict[str, Any] | None  # what really exists
    changed: list[str] = field(default_factory=list)  # attribute paths that differ


def _is_empty(value: Any) -> bool:
    return value is None or value == [] or value == {} or value == ""


def diff_paths(expected: Any, actual: Any, prefix: str = "") -> list[str]:
    """Return dotted attribute paths whose values differ.

    None, "", [] and {} are treated as equal: providers often refresh an unset
    value as an empty one, and that is not drift.
    """
    if _is_empty(expected) and _is_empty(actual):
        return []
    if isinstance(expected, dict) and isinstance(actual, dict):
        paths: list[str] = []
        for key in sorted(set(expected) | set(actual)):
            if key in NOISE_KEYS:
                continue
            child = f"{prefix}.{key}" if prefix else key
            paths.extend(diff_paths(expected.get(key), actual.get(key), child))
        return paths
    if isinstance(expected, list) and isinstance(actual, list) and len(expected) == len(actual):
        paths = []
        for index, (left, right) in enumerate(zip(expected, actual, strict=True)):
            paths.extend(diff_paths(left, right, f"{prefix}[{index}]"))
        return paths
    return [] if expected == actual else [prefix or "<root>"]


def _without_unknown(values: dict[str, Any] | None, unknown: dict[str, Any] | None) -> dict[str, Any]:
    """Drop top-level attributes Terraform cannot know until apply."""
    values = dict(values or {})
    for key, is_unknown in (unknown or {}).items():
        if is_unknown is True:
            values.pop(key, None)
    return values


def extract_drift(plan: dict[str, Any]) -> list[DriftItem]:
    items: dict[str, DriftItem] = {}

    for rc in plan.get("resource_drift") or []:
        if rc.get("mode") != "managed":
            continue
        change = rc.get("change", {})
        actions = change.get("actions", [])
        if actions == ["no-op"]:
            continue
        address = rc["address"]
        if "delete" in actions and change.get("after") is None:
            items[address] = DriftItem(
                address, rc["type"], DELETED, change.get("before"), None, ["<resource deleted>"]
            )
            continue
        expected, actual = change.get("before") or {}, change.get("after") or {}
        changed = diff_paths(expected, actual)
        if changed:
            items[address] = DriftItem(address, rc["type"], MODIFIED, expected, actual, changed)

    # Fallback: corrections Terraform plans that resource_drift did not explain.
    for rc in plan.get("resource_changes") or []:
        address = rc.get("address")
        if rc.get("mode") != "managed" or address in items:
            continue
        change = rc.get("change", {})
        actions = change.get("actions", [])
        if "update" not in actions and actions != ["delete", "create"] and actions != ["create", "delete"]:
            continue  # creates are new code, not drift; no-ops are clean
        unknown = change.get("after_unknown")
        expected = _without_unknown(change.get("after"), unknown)
        actual = _without_unknown(change.get("before"), unknown)
        changed = diff_paths(expected, actual)
        if changed:
            items[address] = DriftItem(address, rc["type"], MODIFIED, expected, actual, changed)

    return sorted(items.values(), key=lambda item: item.address)
