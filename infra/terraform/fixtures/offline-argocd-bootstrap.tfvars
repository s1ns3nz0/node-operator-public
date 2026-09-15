# Synthetic, non-secret input that exercises the dedicated Argo CD bootstrap
# executor. These values must never be used for a live apply.
aws_account_id                     = "123456789012"
name                               = "node-operator"
availability_zones                 = ["ap-northeast-2a", "ap-northeast-2c"]
private_subnet_cidrs               = ["10.80.0.0/20", "10.80.16.0/20"]
offline_validation                 = true
offline_hoodi_nat_public_ip        = "198.51.100.42"
enable_private_gitops_foundation   = true
enable_gitops_client_ecr_publisher = true
gitops_client_chart_version        = "0.1.20"
gitops_client_chart_oci_digest     = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
gitops_client_chart_values = {
  deployment = {
    profile         = "deployment"
    storageKmsKeyId = "arn:aws:kms:ap-northeast-2:123456789012:key/11111111-2222-3333-4444-555555555555"
  }
  dast = { enabled = false }
  clients = {
    vaultAgentImage = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-vault@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    deployment = {
      nethermindImage = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-nodes@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      prysmImage      = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-nodes@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      prysmP2PHostIp  = "198.51.100.42"
    }
  }
}

enable_argocd_bootstrap_runner        = true
enable_argocd_bootstrap_cluster_admin = true
argocd_bootstrap_subnet_ids           = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
argocd_bootstrap_image                = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-argocd@sha256:3674b70a8c02a7fd0734e8e0d7c7f4f33fe7701f30b4c6f21569877721d55d07"
