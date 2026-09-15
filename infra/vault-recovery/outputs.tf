output "recovery_instance_id" {
  description = "Non-secret identifier of the isolated, SSM-managed recovery host."
  value       = aws_instance.host.id
}

output "recovery_host_role_arn" {
  description = "Non-secret ARN of the dedicated EC2 recovery role."
  value       = aws_iam_role.host.arn
}

output "recovery_vpc_id" {
  description = "Non-secret identifier of the dedicated recovery VPC."
  value       = aws_vpc.recovery.id
}

output "interface_endpoint_ids" {
  description = "Non-secret IDs of the interface endpoints in the recovery VPC."
  value       = { for service, endpoint in aws_vpc_endpoint.interface : service => endpoint.id }
}

output "recovery_expiry" {
  description = "Explicit expiry tag for cleanup tracking."
  value       = var.recovery_expiry
}
