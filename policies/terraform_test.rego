# Unit tests for the policy gate. Run with:  conftest verify --policy policies
package main

import rego.v1

good_tags := {"Project": "driftguard", "Environment": "lab", "Owner": "security-team"}

plan(changes) := {"resource_changes": changes}

rc(address, rtype, after) := {
	"address": address,
	"mode": "managed",
	"type": rtype,
	"change": {"actions": ["create"], "after": after},
}

https_rule := {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["10.20.0.0/16"]}

ssh_world_rule := {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}

compliant_plan := plan([
	rc("aws_security_group.app", "aws_security_group", {"ingress": [https_rule], "tags": good_tags}),
	rc("aws_s3_bucket.data", "aws_s3_bucket", {"tags": good_tags}),
	rc("aws_s3_bucket_public_access_block.data", "aws_s3_bucket_public_access_block", {
		"block_public_acls": true, "block_public_policy": true,
		"ignore_public_acls": true, "restrict_public_buckets": true,
	}),
	rc("aws_s3_bucket_server_side_encryption_configuration.data", "aws_s3_bucket_server_side_encryption_configuration", {}),
	rc("aws_iam_role_policy.app", "aws_iam_role_policy", {"policy": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"}],
	})}),
])

test_compliant_plan_passes if {
	results := deny with input as compliant_plan
	count(results) == 0
}

test_ssh_open_to_world_denied if {
	results := deny with input as plan([rc("aws_security_group.app", "aws_security_group", {"ingress": [ssh_world_rule], "tags": good_tags})])
	"aws_security_group.app: SSH (port 22) is open to the internet" in results
}

test_all_protocols_open_to_world_denied if {
	all_rule := {"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}
	results := deny with input as plan([rc("aws_security_group.app", "aws_security_group", {"ingress": [all_rule], "tags": good_tags})])
	"aws_security_group.app: RDP (port 3389) is open to the internet" in results
}

test_public_access_flag_off_denied if {
	results := deny with input as plan([rc("aws_s3_bucket_public_access_block.data", "aws_s3_bucket_public_access_block", {
		"block_public_acls": true, "block_public_policy": false,
		"ignore_public_acls": true, "restrict_public_buckets": true,
	})])
	"aws_s3_bucket_public_access_block.data: block_public_policy must be true" in results
}

test_bucket_without_encryption_denied if {
	results := deny with input as plan([rc("aws_s3_bucket.data", "aws_s3_bucket", {"tags": good_tags})])
	"every aws_s3_bucket needs an aws_s3_bucket_server_side_encryption_configuration" in results
}

test_wildcard_iam_denied if {
	policy := json.marshal({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
	results := deny with input as plan([rc("aws_iam_role_policy.app", "aws_iam_role_policy", {"policy": policy})])
	"aws_iam_role_policy.app: wildcard action \"*\" is not allowed" in results
}

test_service_wildcard_iam_denied if {
	policy := json.marshal({"Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]})
	results := deny with input as plan([rc("aws_iam_role_policy.app", "aws_iam_role_policy", {"policy": policy})])
	"aws_iam_role_policy.app: wildcard action \"s3:*\" is not allowed" in results
}

test_missing_owner_tag_denied if {
	results := deny with input as plan([rc("aws_vpc.main", "aws_vpc", {"tags": {"Project": "driftguard", "Environment": "lab"}})])
	"aws_vpc.main: missing required tag \"Owner\"" in results
}

test_null_tags_denied if {
	results := deny with input as plan([rc("aws_vpc.main", "aws_vpc", {"tags": null})])
	count(results) == 3
}
