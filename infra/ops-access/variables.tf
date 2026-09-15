variable "aws_region" {
  type    = string
  default = "ap-northeast-2"
}
variable "name" {
  type    = string
  default = "node-operator"
}
variable "vpc_id" { type = string }
variable "subnet_id" { type = string }
variable "cluster_security_group_id" { type = string }

variable "existing_ssm_endpoint_security_group_id" {
  description = "Existing shared SSM interface-endpoint security group. Set only for reviewed state migration; null creates isolated endpoints."
  type        = string
  default     = null
  nullable    = true
}

variable "manage_cluster_ingress_rule" {
  description = "Whether this root owns the host-to-EKS API ingress rule. Set false when importing a host whose rule remains baseline-owned."
  type        = bool
  default     = true
}

variable "manage_existing_endpoint_ingress_rule" {
  description = "Explicit migration opt-in when this ops state already owns its host-to-shared-endpoint ingress rule. False leaves an existing shared endpoint rule with its current external owner."
  type        = bool
  default     = false
}

variable "retained_host_instance_id" {
  description = "Compatibility field for older input files. Must remain null; retired maintainer-host adoption is no longer supported."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.retained_host_instance_id == null
    error_message = "retained_host_instance_id must be null; create or resume this deployment's managed host instead."
  }
}

variable "ebs_optimized" {
  description = "EBS optimization is required for the deployment-managed operations host."
  type        = bool
  default     = true
  nullable    = false
}
