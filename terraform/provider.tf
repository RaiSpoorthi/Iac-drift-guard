# The provider is pointed at a local AWS emulator (Moto) instead of real AWS.
# Nothing here can create billable resources: every service endpoint is
# overridden, and credentials come from the environment (dummy "test" keys
# set by the driftguard CLI / CI), never from this file.
provider "aws" {
  region = var.aws_region

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
  s3_use_path_style           = true

  endpoints {
    dynamodb = var.aws_endpoint
    ec2      = var.aws_endpoint
    iam      = var.aws_endpoint
    kms      = var.aws_endpoint
    s3       = var.aws_endpoint
    sts      = var.aws_endpoint
  }
}
