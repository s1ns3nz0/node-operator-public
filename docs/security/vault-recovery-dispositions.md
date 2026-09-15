# Recovery-only scanner dispositions

Both entries expire on 2026-10-03 and match check, Terraform resource and the
canonical `infra/vault-recovery/main.tf` path. They neither authorize deployment
nor suppress raw evidence. A different path, resource or check still blocks.
Infrastructure PR149 cannot approve its own exceptions; the trusted policy
change must receive independent approval and land first.

## Basic monitoring: CKV_AWS_126

The user explicitly selected basic EC2 monitoring, not paid detailed monitoring.
The temporary private recovery host retains that preference. This accepts
coarser EC2 performance metrics, not missing security logs. VPC flow logs,
IMDSv2, encryption, no public address and expiry-bounded data access remain
required in PR149. Detailed monitoring does not replace Vault audit logging.
Owner: s1ns3nz0. Reconsider if this host becomes long-lived or operational SLOs
require finer-grained metrics.

## ECR layer endpoint: CKV_AWS_283

AWS documents a minimum S3 gateway endpoint policy allowing `s3:GetObject`
with `Principal: *` solely for the regional `prod-REGION-starport-layer-bucket/*`.
This is an endpoint permission filter for ECR image-layer downloads, not a
public bucket policy or anonymous access grant to Vault snapshots. Endpoint
policies do not replace object/IAM authorization. The corresponding recovery
statement must contain only that regional bucket and read action; the separate
snapshot statement must retain its exact host principal, object and VersionId.
The isolated VPC must have no internet or live-peer path and only endpoint/S3
egress. Raw CKV_AWS_283 remains visible for review. Owner: s1ns3nz0.

Evidence: [AWS minimum S3 bucket permissions for ECR](https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html).
Residual risk is access to other authorized objects within the regional ECR
layer bucket; manifests/repository IAM and pinned image digests remain required.
This disposition does not waive wildcard access to any customer bucket.

No exception is granted for VPC flow logging, permissive default security
groups, unconstrained SSM writes, or restrictable wildcard IAM resources.
