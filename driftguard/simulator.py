"""Simulate the out-of-band changes that cause drift in real teams.

Each scenario mimics something a person might do by hand in the AWS console
(or an attacker might do with stolen credentials), using boto3 against the
local emulator. Every scenario names the Terraform address it should affect
and the severity DriftGuard is expected to assign, so detection can be scored.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import boto3

from driftguard.classifier import Severity
from driftguard.config import DUMMY_CREDENTIALS, Settings

Clients = dict[str, Any]
Outputs = dict[str, str]


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    target: str  # Terraform address expected to drift
    expected: Severity
    run: Callable[[Clients, Outputs], None]


def make_clients(settings: Settings) -> Clients:
    return {
        service: boto3.client(
            service,
            endpoint_url=settings.endpoint,
            region_name=settings.region,
            aws_access_key_id=DUMMY_CREDENTIALS["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=DUMMY_CREDENTIALS["AWS_SECRET_ACCESS_KEY"],
        )
        for service in ("ec2", "s3", "iam", "dynamodb")
    }


def _open_ssh(c: Clients, o: Outputs) -> None:
    c["ec2"].authorize_security_group_ingress(
        GroupId=o["security_group_id"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "temporary debug access"}],
        }],
    )


def _public_bucket(c: Clients, o: Outputs) -> None:
    c["s3"].put_public_access_block(
        Bucket=o["bucket_name"],
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False, "IgnorePublicAcls": False,
            "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
        },
    )


def _iam_wildcard(c: Clients, o: Outputs) -> None:
    c["iam"].put_role_policy(
        RoleName=o["iam_role_name"],
        PolicyName=o["iam_role_policy_name"],
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )


def _remove_encryption(c: Clients, o: Outputs) -> None:
    c["s3"].delete_bucket_encryption(Bucket=o["bucket_name"])


def _suspend_versioning(c: Clients, o: Outputs) -> None:
    c["s3"].put_bucket_versioning(Bucket=o["bucket_name"], VersioningConfiguration={"Status": "Suspended"})


def _disable_pitr(c: Clients, o: Outputs) -> None:
    c["dynamodb"].update_continuous_backups(
        TableName=o["dynamodb_table_name"],
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": False},
    )


def _tag_tamper(c: Clients, o: Outputs) -> None:
    c["ec2"].create_tags(Resources=[o["vpc_id"]], Tags=[{"Key": "Owner", "Value": "unknown"}])


SCENARIOS: dict[str, Scenario] = {
    s.name: s
    for s in [
        Scenario("open_ssh", "SSH opened to 0.0.0.0/0 on the app security group",
                 "aws_security_group.app", Severity.CRITICAL, _open_ssh),
        Scenario("public_bucket", "S3 public access block switched off",
                 "aws_s3_bucket_public_access_block.data", Severity.CRITICAL, _public_bucket),
        Scenario("iam_wildcard", "App role inline policy replaced with Action '*'",
                 "aws_iam_role_policy.app", Severity.CRITICAL, _iam_wildcard),
        Scenario("remove_encryption", "Default KMS encryption deleted from the bucket",
                 "aws_s3_bucket_server_side_encryption_configuration.data", Severity.HIGH, _remove_encryption),
        Scenario("suspend_versioning", "Bucket versioning suspended",
                 "aws_s3_bucket_versioning.data", Severity.MEDIUM, _suspend_versioning),
        Scenario("disable_pitr", "DynamoDB point-in-time recovery turned off",
                 "aws_dynamodb_table.audit", Severity.MEDIUM, _disable_pitr),
        Scenario("tag_tamper", "Owner tag on the VPC overwritten",
                 "aws_vpc.main", Severity.LOW, _tag_tamper),
    ]
}


def run_scenarios(names: list[str], settings: Settings, outputs: Outputs) -> list[Scenario]:
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        raise KeyError(f"Unknown scenario(s): {', '.join(unknown)}. Known: {', '.join(SCENARIOS)}")
    clients = make_clients(settings)
    applied = []
    for name in names:
        scenario = SCENARIOS[name]
        scenario.run(clients, outputs)
        applied.append(scenario)
    return applied
