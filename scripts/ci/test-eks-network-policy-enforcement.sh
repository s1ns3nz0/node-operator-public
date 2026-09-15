#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
eks="$root/infra/terraform/eks.tf"

fail() { printf 'FAIL EKS NetworkPolicy enforcement: %s\n' "$*" >&2; exit 1; }

test -f "$eks" || fail 'missing EKS Terraform configuration'
grep -Fq 'resource "aws_eks_addon" "vpc_cni"' "$eks" || fail 'missing VPC CNI add-on'
grep -Fq 'configuration_values = jsonencode({' "$eks" || fail 'VPC CNI configuration is unmanaged'
grep -Fq 'enableNetworkPolicy = "true"' "$eks" || fail 'VPC CNI does not enforce Kubernetes NetworkPolicy'
grep -Fq 'resolve_conflicts_on_update = "PRESERVE"' "$eks" || fail 'VPC CNI update conflict handling changed'

printf 'PASS EKS VPC CNI is configured to enforce Kubernetes NetworkPolicy.\n'
