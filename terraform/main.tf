terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "AWS-Honeypot-Threat-Intel"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}
