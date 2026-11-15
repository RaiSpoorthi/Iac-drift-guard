"""Run every drift scenario against an in-process AWS mock and check its effect."""

import json

import boto3
import pytest
from moto import mock_aws

from driftguard.config import Settings
from driftguard.simulator import SCENARIOS, run_scenarios

REGION = "us-east-1"


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    with mock_aws():
        yield


@pytest.fixture
def deployed(aws):
    """Create the same resources Terraform would, and return its outputs."""
    ec2 = boto3.client("ec2", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)
    iam = boto3.client("iam", region_name=REGION)
    ddb = boto3.client("dynamodb", region_name=REGION)

    vpc_id = ec2.create_vpc(CidrBlock="10.20.0.0/16")["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Owner", "Value": "security-team"}])
    sg_id = ec2.create_security_group(GroupName="app", Description="app", VpcId=vpc_id)["GroupId"]

    s3.create_bucket(Bucket="driftguard-data-lab")
    s3.put_bucket_versioning(Bucket="driftguard-data-lab", VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_encryption(Bucket="driftguard-data-lab", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})

    iam.create_role(RoleName="app-role", AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))
    iam.put_role_policy(RoleName="app-role", PolicyName="app-s3", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}))

    ddb.create_table(TableName="audit", BillingMode="PAY_PER_REQUEST",
                     KeySchema=[{"AttributeName": "event_id", "KeyType": "HASH"}],
                     AttributeDefinitions=[{"AttributeName": "event_id", "AttributeType": "S"}])
    ddb.update_continuous_backups(TableName="audit",
                                  PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True})

    return {
        "vpc_id": vpc_id, "security_group_id": sg_id, "bucket_name": "driftguard-data-lab",
        "iam_role_name": "app-role", "iam_role_policy_name": "app-s3", "dynamodb_table_name": "audit",
    }


@pytest.fixture
def settings(monkeypatch):
    # boto3 clients built by the simulator must hit the mock, not a server.
    monkeypatch.setattr("driftguard.simulator.make_clients", lambda _settings: {
        svc: boto3.client(svc, region_name=REGION) for svc in ("ec2", "s3", "iam", "dynamodb")})
    return Settings()


def test_open_ssh(deployed, settings):
    run_scenarios(["open_ssh"], settings, deployed)
    sg = boto3.client("ec2", region_name=REGION).describe_security_groups(GroupIds=[deployed["security_group_id"]])
    perms = sg["SecurityGroups"][0]["IpPermissions"]
    assert any(p.get("FromPort") == 22 and {"CidrIp": "0.0.0.0/0"}.items() <= p["IpRanges"][0].items() for p in perms)


def test_public_bucket(deployed, settings):
    run_scenarios(["public_bucket"], settings, deployed)
    cfg = boto3.client("s3", region_name=REGION).get_public_access_block(Bucket=deployed["bucket_name"])
    assert not any(cfg["PublicAccessBlockConfiguration"].values())


def test_iam_wildcard(deployed, settings):
    run_scenarios(["iam_wildcard"], settings, deployed)
    doc = boto3.client("iam", region_name=REGION).get_role_policy(RoleName="app-role", PolicyName="app-s3")
    document = doc["PolicyDocument"]
    document = json.loads(document) if isinstance(document, str) else document
    assert document["Statement"][0]["Action"] == "*"


def test_remove_encryption(deployed, settings):
    run_scenarios(["remove_encryption"], settings, deployed)
    s3 = boto3.client("s3", region_name=REGION)
    with pytest.raises(s3.exceptions.ClientError):
        s3.get_bucket_encryption(Bucket=deployed["bucket_name"])


def test_suspend_versioning(deployed, settings):
    run_scenarios(["suspend_versioning"], settings, deployed)
    status = boto3.client("s3", region_name=REGION).get_bucket_versioning(Bucket=deployed["bucket_name"])["Status"]
    assert status == "Suspended"


def test_disable_pitr(deployed, settings):
    run_scenarios(["disable_pitr"], settings, deployed)
    desc = boto3.client("dynamodb", region_name=REGION).describe_continuous_backups(TableName="audit")
    pitr = desc["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]
    assert pitr["PointInTimeRecoveryStatus"] == "DISABLED"


def test_tag_tamper(deployed, settings):
    run_scenarios(["tag_tamper"], settings, deployed)
    vpc = boto3.client("ec2", region_name=REGION).describe_vpcs(VpcIds=[deployed["vpc_id"]])["Vpcs"][0]
    assert {"Key": "Owner", "Value": "unknown"} in vpc["Tags"]


def test_all_scenarios_run_together(deployed, settings):
    applied = run_scenarios(list(SCENARIOS), settings, deployed)
    assert [s.name for s in applied] == list(SCENARIOS)


def test_scenarios_target_distinct_resources():
    targets = [s.target for s in SCENARIOS.values()]
    assert len(targets) == len(set(targets))


def test_unknown_scenario_is_rejected(settings):
    with pytest.raises(KeyError):
        run_scenarios(["delete_everything"], settings, {})
