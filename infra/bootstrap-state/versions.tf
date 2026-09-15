terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.31.0, < 6.0.0"
    }
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.aws_account_id]
  default_tags {
    tags = {
      Project          = "node-operator"
      Deployment       = var.name
      DeploymentRegion = var.aws_region
      ManagedBy        = "terraform"
    }
  }
}
