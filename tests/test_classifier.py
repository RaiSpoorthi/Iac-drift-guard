import pytest

from driftguard.classifier import Severity, classify, classify_all
from driftguard.detector import DELETED, MODIFIED, DriftItem, diff_paths
from tests.helpers import HTTPS_RULE, LEAST_PRIVILEGE_POLICY, SSH_WORLD_RULE, TAGS, WILDCARD_POLICY


def item(address, expected, actual, kind=MODIFIED):
    changed = ["<resource deleted>"] if kind == DELETED else diff_paths(expected, actual)
    return DriftItem(address, address.split(".")[0], kind, expected, actual, changed)


def test_ssh_opened_to_world_is_critical():
    f = classify(item("aws_security_group.app", {"ingress": [HTTPS_RULE]}, {"ingress": [HTTPS_RULE, SSH_WORLD_RULE]}))
    assert f.severity == Severity.CRITICAL
    assert "SSH (port 22) opened to the internet" in f.reasons


def test_all_traffic_rule_exposes_ssh_and_rdp():
    all_open = {**SSH_WORLD_RULE, "protocol": "-1", "from_port": 0, "to_port": 0}
    f = classify(item("aws_security_group.app", {"ingress": [HTTPS_RULE]}, {"ingress": [all_open]}))
    assert f.severity == Severity.CRITICAL
    assert len(f.reasons) == 2


def test_ipv6_world_cidr_counts_as_internet():
    rule = {**SSH_WORLD_RULE, "cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"]}
    f = classify(item("aws_security_group.app", {"ingress": [HTTPS_RULE]}, {"ingress": [HTTPS_RULE, rule]}))
    assert f.severity == Severity.CRITICAL


def test_internal_ingress_change_is_high():
    internal = {**SSH_WORLD_RULE, "cidr_blocks": ["10.20.5.0/24"]}
    f = classify(item("aws_security_group.app", {"ingress": [HTTPS_RULE]}, {"ingress": [HTTPS_RULE, internal]}))
    assert f.severity == Severity.HIGH
    assert f.reasons == ["Inbound rules changed outside Terraform"]


def test_already_open_port_is_not_reported_as_newly_opened():
    f = classify(item("aws_security_group.app",
                      {"ingress": [SSH_WORLD_RULE], "tags": TAGS},
                      {"ingress": [SSH_WORLD_RULE], "tags": {**TAGS, "Owner": "x"}}))
    assert f.severity == Severity.LOW


def test_public_access_block_disabled_is_critical():
    flags = ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
    on = dict.fromkeys(flags, True)
    off = {**on, "block_public_policy": False, "restrict_public_buckets": False}
    f = classify(item("aws_s3_bucket_public_access_block.data", on, off))
    assert f.severity == Severity.CRITICAL
    assert "block_public_policy, restrict_public_buckets" in f.reasons[0]


def test_public_access_block_deleted_is_critical():
    f = classify(item("aws_s3_bucket_public_access_block.data", {"bucket": "b"}, None, DELETED))
    assert f.severity == Severity.CRITICAL


@pytest.mark.parametrize("wildcard", ['"*"', '"s3:*"', '["iam:*"]'])
def test_wildcard_iam_action_is_critical(wildcard):
    policy = '{"Statement":[{"Effect":"Allow","Action":' + wildcard + ',"Resource":"*"}]}'
    f = classify(item("aws_iam_role_policy.app", {"policy": LEAST_PRIVILEGE_POLICY}, {"policy": policy}))
    assert f.severity == Severity.CRITICAL


def test_wildcard_inside_role_inline_policy_is_critical():
    f = classify(item("aws_iam_role.app",
                      {"inline_policy": [{"name": "p", "policy": LEAST_PRIVILEGE_POLICY}]},
                      {"inline_policy": [{"name": "p", "policy": WILDCARD_POLICY}]}))
    assert f.severity == Severity.CRITICAL


def test_deny_wildcard_is_not_escalation():
    deny = '{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
    f = classify(item("aws_iam_role_policy.app", {"policy": LEAST_PRIVILEGE_POLICY}, {"policy": deny}))
    assert f.severity == Severity.HIGH


def test_unparseable_policy_does_not_crash():
    f = classify(item("aws_iam_role_policy.app", {"policy": LEAST_PRIVILEGE_POLICY}, {"policy": "not json"}))
    assert f.severity == Severity.HIGH


def test_encryption_removed_is_high():
    f = classify(item("aws_s3_bucket_server_side_encryption_configuration.data", {"bucket": "b"}, None, DELETED))
    assert f.severity == Severity.HIGH
    assert f.reasons == ["Default bucket encryption removed"]


def test_versioning_suspended_is_medium():
    f = classify(item("aws_s3_bucket_versioning.data",
                      {"versioning_configuration": [{"status": "Enabled"}]},
                      {"versioning_configuration": [{"status": "Suspended"}]}))
    assert f.severity == Severity.MEDIUM
    assert f.reasons == ["Bucket versioning changed to Suspended"]


def test_pitr_disabled_is_medium():
    f = classify(item("aws_dynamodb_table.audit",
                      {"point_in_time_recovery": [{"enabled": True}]},
                      {"point_in_time_recovery": [{"enabled": False}]}))
    assert f.severity == Severity.MEDIUM
    assert f.reasons == ["Point-in-time recovery disabled"]


def test_tag_only_change_is_low():
    f = classify(item("aws_vpc.main", {"tags": TAGS, "tags_all": TAGS},
                      {"tags": {**TAGS, "Owner": "x"}, "tags_all": {**TAGS, "Owner": "x"}}))
    assert f.severity == Severity.LOW


def test_unknown_change_defaults_to_medium_and_unknown_delete_to_high():
    assert classify(item("aws_vpc.main", {"cidr_block": "a"}, {"cidr_block": "b"})).severity == Severity.MEDIUM
    assert classify(item("aws_vpc.main", {"cidr_block": "a"}, None, DELETED)).severity == Severity.HIGH


def test_highest_severity_wins_and_findings_are_sorted():
    sg = item("aws_security_group.app", {"ingress": [HTTPS_RULE], "tags": TAGS},
              {"ingress": [HTTPS_RULE, SSH_WORLD_RULE], "tags": {**TAGS, "Owner": "x"}})
    vpc = item("aws_vpc.main", {"tags": TAGS}, {"tags": {**TAGS, "Owner": "x"}})
    findings = classify_all([vpc, sg])
    assert [f.item.address for f in findings] == ["aws_security_group.app", "aws_vpc.main"]
    assert findings[0].severity == Severity.CRITICAL
