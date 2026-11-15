variable "aws_endpoint" {
  description = "Endpoint of the local AWS emulator (Moto server)."
  type        = string
  default     = "http://127.0.0.1:5000"

  validation {
    condition     = can(regex("^https?://(localhost|127\\.0\\.0\\.1|moto)(:[0-9]+)?/?$", var.aws_endpoint))
    error_message = "aws_endpoint must point at a local emulator (localhost / 127.0.0.1). This project never talks to real AWS."
  }
}

variable "aws_region" {
  description = "Region reported to the emulator."
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Short project name used in resource names and tags."
  type        = string
  default     = "driftguard"
}

variable "environment" {
  description = "Environment name used in resource names and tags."
  type        = string
  default     = "lab"
}

variable "owner" {
  description = "Value of the Owner tag on every resource."
  type        = string
  default     = "security-team"
}

variable "vpc_cidr" {
  description = "CIDR block of the lab VPC."
  type        = string
  default     = "10.20.0.0/16"
}
