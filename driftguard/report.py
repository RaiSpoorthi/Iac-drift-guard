"""JSON and Markdown drift reports."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from driftguard.classifier import Finding, Severity


def build_report(findings: list[Finding], **extra: Any) -> dict[str, Any]:
    counts = Counter(f.severity.name for f in findings)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {
            "drifted_resources": len(findings),
            "by_severity": {s.name: counts.get(s.name, 0) for s in sorted(Severity, reverse=True)},
        },
        "findings": [
            {
                "address": f.item.address,
                "type": f.item.resource_type,
                "kind": f.item.kind,
                "severity": f.severity.name,
                "reasons": f.reasons,
                "changed_attributes": f.item.changed,
            }
            for f in findings
        ],
        **extra,
    }


def to_markdown(report: dict[str, Any]) -> str:
    lines = ["# DriftGuard report", "", f"Generated: `{report['generated_at']}`", ""]
    summary = report["summary"]
    if summary["drifted_resources"] == 0:
        lines.append("**No drift detected.** Live infrastructure matches the Terraform code.")
    else:
        lines.append(f"**{summary['drifted_resources']} drifted resource(s)**")
        lines += ["", "| Severity | Count |", "|---|---|"]
        lines += [f"| {name} | {count} |" for name, count in summary["by_severity"].items()]
        lines += ["", "## Findings", "", "| Severity | Resource | What changed |", "|---|---|---|"]
        for f in report["findings"]:
            lines.append(f"| {f['severity']} | `{f['address']}` | {'; '.join(f['reasons'])} |")

    scenarios = report.get("scenarios")
    if scenarios:
        detected = sum(1 for s in scenarios if s["detected"])
        lines += ["", "## Simulated drift scenarios", "",
                  f"Detected with the expected severity: **{detected}/{len(scenarios)}**", "",
                  "| Scenario | Target | Expected | Got | Result |", "|---|---|---|---|---|"]
        for s in scenarios:
            result = "PASS" if s["detected"] else "FAIL"
            lines.append(f"| {s['name']} | `{s['target']}` | {s['expected']} | {s['actual'] or '-'} | {result} |")

    remediation = report.get("remediation")
    if remediation:
        verdict = "verified clean" if remediation["verified"] else "NOT clean - drift remains"
        lines += ["", "## Remediation", "", f"After `terraform apply`: **{verdict}**"]

    timings = report.get("timings_seconds")
    if timings:
        lines += ["", "## Timings (seconds)", ""] + [f"- {k}: {v}" for k, v in timings.items()]
    return "\n".join(lines) + "\n"


def write_reports(report: dict[str, Any], out_dir: Path | str) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path, md_path = out / "drift-report.json", out / "drift-report.md"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(to_markdown(report), encoding="utf-8")
    return json_path, md_path
