locals {
  name        = "${var.project}-${var.environment}"
  bucket_name = "${var.project}-data-${var.environment}"
  table_name  = "${var.project}-audit-${var.environment}"

  common_tags = {
    Project     = var.project
    Environment = var.environment
    Owner       = var.owner
    ManagedBy   = "terraform"
  }
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
resource "aws_vpc" "main" {
  #checkov:skip=CKV2_AWS_11:Lab VPC on a local emulator; flow logs need a log destination that adds no value here
  #checkov:skip=CKV2_AWS_12:Default security group is not used by any resource in this lab
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, { Name = "${local.name}-vpc" })
}

resource "aws_security_group" "app" {
  #checkov:skip=CKV2_AWS_5:No compute is launched in this lab; the group exists to demonstrate network drift
  name        = "${local.name}-app"
  description = "App tier - HTTPS from inside the VPC only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from within the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "HTTPS to services within the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(local.common_tags, { Name = "${local.name}-app-sg" })
}

# ---------------------------------------------------------------------------
# Encryption key
# ---------------------------------------------------------------------------
resource "aws_kms_key" "data" {
  #checkov:skip=CKV2_AWS_64:The default key policy is used; the emulator has no real account root to scope to
  description             = "Encrypts the ${local.name} data bucket and audit table"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = local.common_tags
}

# ---------------------------------------------------------------------------
# Data bucket
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "data" {
  #checkov:skip=CKV_AWS_18:Access logging needs a second log bucket; out of scope for the lab
  #checkov:skip=CKV_AWS_144:Cross-region replication is not meaningful on a local emulator
  #checkov:skip=CKV2_AWS_62:No event consumers exist in this lab
  #checkov:skip=CKV2_AWS_61:Lab data is short-lived; no lifecycle rules needed
  bucket        = local.bucket_name
  force_destroy = true

  tags = merge(local.common_tags, { Name = local.bucket_name })
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ---------------------------------------------------------------------------
# Audit table
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "audit" {
  name         = local.table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"

  attribute {
    name = "event_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.data.arn
  }

  tags = merge(local.common_tags, { Name = local.table_name })
}

# ---------------------------------------------------------------------------
# Least-privilege application role
# ---------------------------------------------------------------------------
resource "aws_iam_role" "app" {
  name = "${local.name}-app-role"

  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "app" {
  name = "${local.name}-app-s3"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadWriteObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "arn:aws:s3:::${local.bucket_name}/*"
      },
      {
        Sid      = "ListBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = "arn:aws:s3:::${local.bucket_name}"
      }
    ]
  })
}
