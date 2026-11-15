"""Command-line interface.

    python -m driftguard run                      # full loop: deploy -> drift -> detect -> fix -> verify
    python -m driftguard deploy
    python -m driftguard simulate --scenario open_ssh --scenario public_bucket
    python -m driftguard detect --fail-on HIGH
    python -m driftguard remediate
    python -m driftguard scenarios
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from driftguard.classifier import Finding, Severity, classify_all
from driftguard.config import Settings, UnsafeEndpointError
from driftguard.detector import extract_drift
from driftguard.report import build_report, write_reports
from driftguard.simulator import SCENARIOS, Scenario, run_scenarios
from driftguard.terraform import Terraform, TerraformError

ROOT = Path(__file__).resolve().parent.parent


def _log(message: str) -> None:
    print(f"[driftguard] {message}", flush=True)


def _detect(tf: Terraform) -> list[Finding]:
    result = tf.plan()
    return classify_all(extract_drift(result.plan)) if result.has_changes else []


def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        _log("No drift: live infrastructure matches the code.")
        return
    _log(f"{len(findings)} drifted resource(s):")
    for f in findings:
        print(f"  {f.severity.name:<8} {f.item.address:<60} {'; '.join(f.reasons)}")


def score_scenarios(applied: list[Scenario], findings: list[Finding]) -> list[dict]:
    by_address = {f.item.address: f for f in findings}
    rows = []
    for s in applied:
        found = by_address.get(s.target)
        rows.append({
            "name": s.name,
            "description": s.description,
            "target": s.target,
            "expected": s.expected.name,
            "actual": found.severity.name if found else None,
            "detected": bool(found and found.severity == s.expected),
        })
    return rows


def cmd_scenarios(_: argparse.Namespace) -> int:
    for s in SCENARIOS.values():
        print(f"{s.name:<20} {s.expected.name:<9} {s.description}")
    return 0


def cmd_deploy(args: argparse.Namespace, tf: Terraform, settings: Settings) -> int:
    _log("terraform init + apply")
    tf.init()
    tf.apply()
    return 0


def cmd_simulate(args: argparse.Namespace, tf: Terraform, settings: Settings) -> int:
    names = args.scenario or list(SCENARIOS)
    for s in run_scenarios(names, settings, tf.outputs()):
        _log(f"simulated drift: {s.name} - {s.description}")
    return 0


def cmd_detect(args: argparse.Namespace, tf: Terraform, settings: Settings) -> int:
    findings = _detect(tf)
    _print_findings(findings)
    json_path, md_path = write_reports(build_report(findings), args.report_dir)
    _log(f"reports written: {json_path}, {md_path}")
    threshold = Severity[args.fail_on]
    return 2 if any(f.severity >= threshold for f in findings) else 0


def cmd_remediate(args: argparse.Namespace, tf: Terraform, settings: Settings) -> int:
    _log("re-applying Terraform to restore the declared state")
    tf.apply()
    clean = not tf.plan().has_changes
    _log("verified: no drift remains" if clean else "drift still present after apply")
    return 0 if clean else 1


def cmd_run(args: argparse.Namespace, tf: Terraform, settings: Settings) -> int:
    timings: dict[str, float] = {}

    def timed(label: str, fn):
        start = time.perf_counter()
        value = fn()
        timings[label] = round(time.perf_counter() - start, 2)
        return value

    timed("deploy", lambda: (tf.init(), tf.apply()))
    if tf.plan().has_changes:
        _log("Baseline is not clean right after apply; aborting so results are not polluted.")
        return 1
    _log("baseline clean")

    names = args.scenario or list(SCENARIOS)
    applied = timed("simulate", lambda: run_scenarios(names, settings, tf.outputs()))
    for s in applied:
        _log(f"simulated drift: {s.name} - {s.description}")

    findings = timed("detect", lambda: _detect(tf))
    _print_findings(findings)
    scenarios = score_scenarios(applied, findings)

    timed("remediate", tf.apply)
    verified = timed("verify", lambda: not tf.plan().has_changes)

    report = build_report(
        findings,
        scenarios=scenarios,
        remediation={"verified": verified},
        timings_seconds=timings,
    )
    json_path, md_path = write_reports(report, args.report_dir)

    detected = sum(s["detected"] for s in scenarios)
    _log(f"scenarios detected with expected severity: {detected}/{len(scenarios)}")
    for s in scenarios:
        if not s["detected"]:
            _log(f"  MISSED {s['name']}: expected {s['expected']} on {s['target']}, got {s['actual']}")
    _log("remediation verified clean" if verified else "remediation FAILED: drift remains")
    _log(f"reports written: {json_path}, {md_path}")
    return 0 if detected == len(scenarios) and verified else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="driftguard", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--endpoint", default="http://127.0.0.1:5000", help="local AWS emulator URL")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--tf-dir", default=str(ROOT / "terraform"), help="Terraform working directory")
    parser.add_argument("--report-dir", default=str(ROOT / "reports"))
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("scenarios", help="list drift scenarios")
    sub.add_parser("deploy", help="terraform init + apply")
    simulate = sub.add_parser("simulate", help="introduce drift out-of-band")
    simulate.add_argument("--scenario", action="append", choices=list(SCENARIOS),
                          help="repeatable; default = all")
    detect = sub.add_parser("detect", help="find and classify drift, write reports")
    detect.add_argument("--fail-on", default="HIGH", choices=[s.name for s in Severity],
                        help="exit 2 if any finding is at or above this severity")
    sub.add_parser("remediate", help="re-apply Terraform and verify no drift remains")
    run = sub.add_parser("run", help="full loop with scenario scoring")
    run.add_argument("--scenario", action="append", choices=list(SCENARIOS))
    return parser


COMMANDS = {
    "deploy": cmd_deploy,
    "simulate": cmd_simulate,
    "detect": cmd_detect,
    "remediate": cmd_remediate,
    "run": cmd_run,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scenarios":
        return cmd_scenarios(args)
    settings = Settings(endpoint=args.endpoint, region=args.region)
    try:
        settings.validate()
        tf = Terraform(args.tf_dir, env=settings.env())
        return COMMANDS[args.command](args, tf, settings)
    except (UnsafeEndpointError, TerraformError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
