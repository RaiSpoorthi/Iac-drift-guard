# Policy-as-code gate evaluated against `terraform show -json <planfile>`.
# Run with:  conftest test plan.json --policy policies
package main

import rego.v1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Every managed resource that will exist after the plan is applied.
resources contains rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.change.actions != ["delete"]
}

addresses_of(rtype) := {rc.address | some rc in resources; rc.type == rtype}

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)

admin_ports := {22: "SSH", 3389: "RDP"}

world_cidrs := {"0.0.0.0/0", "::/0"}

taggable := {
	"aws_vpc",
	"aws_security_group",
	"aws_s3_bucket",
	"aws_dynamodb_table",
	"aws_iam_role",
	"aws_kms_key",
}

required_tags := {"Project", "Environment", "Owner"}

pab_flags := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]

# ---------------------------------------------------------------------------
# Rule 1: no SSH/RDP open to the internet
# ---------------------------------------------------------------------------
deny contains msg if {
	some rc in resources
	rc.type == "aws_security_group"
	some rule in rc.change.after.ingress
	cidrs := {c | some c in array.concat(object.get(rule, "cidr_blocks", []), object.get(rule, "ipv6_cidr_blocks", []))}
	count(cidrs & world_cidrs) > 0
	some port, name in admin_ports
	port_in_rule(port, rule)
	msg := sprintf("%s: %s (port %d) is open to the internet", [rc.address, name, port])
}

port_in_rule(_, rule) if rule.protocol == "-1"

port_in_rule(port, rule) if {
	rule.protocol in {"tcp", "6"}
	rule.from_port <= port
	port <= rule.to_port
}

# ---------------------------------------------------------------------------
# Rule 2: every bucket has a public access block with all four flags on
# ---------------------------------------------------------------------------
deny contains msg if {
	some rc in resources
	rc.type == "aws_s3_bucket_public_access_block"
	some flag in pab_flags
	rc.change.after[flag] != true
	msg := sprintf("%s: %s must be true", [rc.address, flag])
}

deny contains msg if {
	count(addresses_of("aws_s3_bucket")) > count(addresses_of("aws_s3_bucket_public_access_block"))
	msg := "every aws_s3_bucket needs an aws_s3_bucket_public_access_block"
}

# ---------------------------------------------------------------------------
# Rule 3: every bucket has default encryption
# ---------------------------------------------------------------------------
deny contains msg if {
	count(addresses_of("aws_s3_bucket")) > count(addresses_of("aws_s3_bucket_server_side_encryption_configuration"))
	msg := "every aws_s3_bucket needs an aws_s3_bucket_server_side_encryption_configuration"
}

# ---------------------------------------------------------------------------
# Rule 4: no wildcard IAM permissions
# ---------------------------------------------------------------------------
deny contains msg if {
	some rc in resources
	rc.type in {"aws_iam_role_policy", "aws_iam_policy"}
	doc := json.unmarshal(rc.change.after.policy)
	some stmt in as_array(doc.Statement)
	stmt.Effect == "Allow"
	some action in as_array(stmt.Action)
	is_wildcard(action)
	msg := sprintf("%s: wildcard action \"%s\" is not allowed", [rc.address, action])
}

is_wildcard(action) if action == "*"

is_wildcard(action) if endswith(action, ":*")

# ---------------------------------------------------------------------------
# Rule 5: mandatory ownership tags
# ---------------------------------------------------------------------------
deny contains msg if {
	some rc in resources
	rc.type in taggable
	tags := object.get(rc.change.after, "tags", {})
	some tag in required_tags
	not has_tag(tags, tag)
	msg := sprintf("%s: missing required tag \"%s\"", [rc.address, tag])
}

has_tag(tags, tag) if {
	is_object(tags)
	tags[tag] != ""
}
