# These outputs are read by the drift simulator to find the resources it tampers with.
output "vpc_id" {
  value = aws_vpc.main.id
}

output "security_group_id" {
  value = aws_security_group.app.id
}

output "bucket_name" {
  value = aws_s3_bucket.data.bucket
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.audit.name
}

output "iam_role_name" {
  value = aws_iam_role.app.name
}

output "iam_role_policy_name" {
  value = aws_iam_role_policy.app.name
}

output "kms_key_id" {
  value = aws_kms_key.data.key_id
}
