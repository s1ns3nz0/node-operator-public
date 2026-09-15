# Synthetic, non-secret selected execution role for KMS policy plan checks.
aws_account_id                   = "123456789012"
name                             = "node-operator"
availability_zones               = ["ap-northeast-2a", "ap-northeast-2c"]
private_subnet_cidrs             = ["10.80.0.0/20", "10.80.16.0/20"]
offline_validation               = true
enable_private_gitops_foundation = false
terraform_apply_role_arn         = "arn:aws:iam::123456789012:role/SelectedTerraformApply"
