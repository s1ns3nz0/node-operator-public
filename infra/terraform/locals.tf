locals {
  common_tags = merge(var.tags, {
    "ManagedBy"        = "terraform"
    "Project"          = "node-operator"
    "Deployment"       = var.name
    "DeploymentRegion" = var.aws_region
    "Environment"      = "baseline"
    "SecurityTier"     = "private"
  })

  name_prefix = "${var.name}-baseline"
}
