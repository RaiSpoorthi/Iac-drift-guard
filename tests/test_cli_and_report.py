import json

import pytest

from driftguard.classifier import Severity, classify_all
from driftguard.cli import main, score_scenarios
from driftguard.config import Settings, UnsafeEndpointError
from driftguard.detector import extract_drift
from driftguard.report import build_report, to_markdown, write_reports
from driftguard.simulator import SCENARIOS
from tests.helpers import HTTPS_RULE, SSH_WORLD_RULE, TAGS, drift, plan


@pytest.mark.parametrize("endpoint", ["http://127.0.0.1:5000", "http://localhost:5000", "http://moto:5000"])
def test_local_endpoints_are_allowed(endpoint):
    Settings(endpoint=endpoint).validate()


@pytest.mark.parametrize("endpoint", ["https://s3.amazonaws.com", "https://ec2.ap-south-1.amazonaws.com"])
def test_real_aws_endpoints_are_refused(endpoint):
    with pytest.raises(UnsafeEndpointError):
        Settings(endpoint=endpoint).validate()


def test_cli_refuses_real_aws(capsys):
    assert main(["--endpoint", "https://ec2.amazonaws.com", "detect"]) == 1
    assert "Refusing to run" in capsys.readouterr().err


def test_settings_env_uses_dummy_credentials():
    env = Settings().env()
    assert env["AWS_ACCESS_KEY_ID"] == "test"
    assert env["TF_VAR_aws_endpoint"] == "http://127.0.0.1:5000"


def test_scenarios_command_lists_all(capsys):
    assert main(["scenarios"]) == 0
    out = capsys.readouterr().out
    assert all(name in out for name in SCENARIOS)


def _sample_findings():
    p = plan(resource_drift=[
        drift("aws_security_group.app", {"ingress": [HTTPS_RULE]}, {"ingress": [HTTPS_RULE, SSH_WORLD_RULE]}),
        drift("aws_vpc.main", {"tags": TAGS}, {"tags": {**TAGS, "Owner": "unknown"}}),
    ])
    return classify_all(extract_drift(p))


def test_scoring_marks_expected_severity_as_detected():
    rows = score_scenarios([SCENARIOS["open_ssh"], SCENARIOS["tag_tamper"], SCENARIOS["disable_pitr"]],
                           _sample_findings())
    assert [r["detected"] for r in rows] == [True, True, False]
    assert rows[2]["actual"] is None


def test_report_summary_and_markdown(tmp_path):
    report = build_report(_sample_findings(), remediation={"verified": True})
    assert report["summary"]["drifted_resources"] == 2
    assert report["summary"]["by_severity"][Severity.CRITICAL.name] == 1
    md = to_markdown(report)
    assert "SSH (port 22) opened to the internet" in md
    assert "verified clean" in md

    json_path, md_path = write_reports(report, tmp_path)
    assert json.loads(json_path.read_text())["findings"][0]["severity"] == "CRITICAL"
    assert md_path.exists()


def test_clean_report_markdown():
    assert "No drift detected" in to_markdown(build_report([]))
