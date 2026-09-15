# Synthetic, non-secret input that exercises the explicitly enabled GitOps OCI
# foundation without contacting AWS. Never use it for a live apply.
aws_account_id                   = "123456789012"
name                             = "node-operator"
availability_zones               = ["ap-northeast-2a", "ap-northeast-2c"]
private_subnet_cidrs             = ["10.80.0.0/20", "10.80.16.0/20"]
offline_validation               = true
enable_private_gitops_foundation = true
