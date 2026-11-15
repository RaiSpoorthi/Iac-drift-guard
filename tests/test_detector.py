from driftguard.detector import DELETED, MODIFIED, diff_paths, extract_drift
from tests.helpers import HTTPS_RULE, SSH_WORLD_RULE, TAGS, change, drift, plan


def test_diff_paths_reports_nested_changes():
    before = {"tags": {"Owner": "a"}, "versioning_configuration": [{"status": "Enabled"}]}
    after = {"tags": {"Owner": "b"}, "versioning_configuration": [{"status": "Suspended"}]}
    assert diff_paths(before, after) == ["tags.Owner", "versioning_configuration[0].status"]


def test_diff_paths_treats_empty_values_as_equal():
    assert diff_paths({"a": None, "b": [], "c": {}}, {"a": "", "b": None, "c": []}) == []


def test_diff_paths_reports_whole_list_when_length_changes():
    assert diff_paths({"ingress": [HTTPS_RULE]}, {"ingress": [HTTPS_RULE, SSH_WORLD_RULE]}) == ["ingress"]


def test_diff_paths_ignores_noise_keys():
    assert diff_paths({"timeouts": {"create": "5m"}}, {"timeouts": None}) == []


def test_clean_plan_has_no_drift():
    assert extract_drift(plan()) == []


def test_modified_resource_is_extracted():
    p = plan(resource_drift=[drift("aws_vpc.main", {"tags": TAGS}, {"tags": {**TAGS, "Owner": "x"}})])
    [item] = extract_drift(p)
    assert item.address == "aws_vpc.main"
    assert item.kind == MODIFIED
    assert item.changed == ["tags.Owner"]


def test_deleted_resource_is_extracted():
    p = plan(resource_drift=[drift("aws_s3_bucket_server_side_encryption_configuration.data", {"bucket": "b"}, None)])
    [item] = extract_drift(p)
    assert item.kind == DELETED
    assert item.actual is None


def test_no_op_and_data_sources_are_ignored():
    noop = drift("aws_vpc.main", {"a": 1}, {"a": 1}, ["no-op"])
    data_source = {**drift("data.aws_caller_identity.me", {"a": 1}, {"a": 2}), "mode": "data"}
    assert extract_drift(plan(resource_drift=[noop, data_source])) == []


def test_drift_with_no_meaningful_difference_is_ignored():
    p = plan(resource_drift=[drift("aws_vpc.main", {"tags": TAGS, "x": None}, {"tags": TAGS, "x": []})])
    assert extract_drift(p) == []


def test_fallback_uses_resource_changes_and_swaps_direction():
    # resource_changes: before = real state, after = desired state
    p = plan(resource_changes=[change(
        "aws_s3_bucket_versioning.data",
        before={"versioning_configuration": [{"status": "Suspended"}]},
        after={"versioning_configuration": [{"status": "Enabled"}]},
        actions=["update"],
    )])
    [item] = extract_drift(p)
    assert item.expected == {"versioning_configuration": [{"status": "Enabled"}]}
    assert item.actual == {"versioning_configuration": [{"status": "Suspended"}]}


def test_fallback_skips_creates_and_unknown_attributes():
    create = change("aws_vpc.new", None, {"cidr_block": "10.0.0.0/16"}, ["create"])
    update = change("aws_vpc.main", {"arn": "real", "tags": TAGS}, {"tags": TAGS}, ["update"], {"arn": True})
    assert extract_drift(plan(resource_changes=[create, update])) == []


def test_resource_drift_takes_priority_over_fallback():
    d = drift("aws_vpc.main", {"tags": TAGS}, {"tags": {**TAGS, "Owner": "x"}})
    c = change("aws_vpc.main", {"tags": {**TAGS, "Owner": "x"}}, {"tags": TAGS}, ["update"])
    [item] = extract_drift(plan(resource_drift=[d], resource_changes=[c]))
    assert item.expected == {"tags": TAGS}
