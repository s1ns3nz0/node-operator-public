# Synthetic, non-secret input for validating the enabled release signer plan.
# The subnet IDs are deliberately fake and must never be used for an apply.
aws_account_id                   = "123456789012"
name                             = "node-operator"
availability_zones               = ["ap-northeast-2a", "ap-northeast-2c"]
private_subnet_cidrs             = ["10.80.0.0/20", "10.80.16.0/20"]
offline_validation               = true
enable_private_gitops_foundation = false

enable_release_signer            = true
enable_release_signer_ecr_mirror = true
release_signer_subnet_ids        = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
release_signer_image             = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-vault-release-signer@sha256:3674b70a8c02a7fd0734e8e0d7c7f4f33fe7701f30b4c6f21569877721d55d07"
