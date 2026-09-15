# Ephemeral OCI release staging

This isolated Terraform root creates only two private S3 buckets and one
GitHub Actions OIDC read role for a temporary OCI release. It does not create
an OIDC provider, KMS key, EKS resource, validator, remote backend, or any
other existing-state integration.

The versioned staging bucket uses SSE-S3 (`AES256`), bucket-owner-enforced
ownership, all S3 public-access blocks, TLS-only bucket access, and S3 server
access logging to the separate access-log bucket. The staging policy denies
`s3:PutObject` to every principal except the explicitly supplied uploader ARN.
The log bucket separately permits S3's log-delivery service at its dedicated
prefix, so that upload restriction cannot interfere with access-log delivery.
Neither bucket uses Object Lock or a compliance retention rule, and both set
`force_destroy = false`.

The OIDC role trusts only `sts.amazonaws.com` audience tokens whose subject is
exactly one of the two configured repository environments:
`gitops-evidence-reader` or `release`. Its sole permission is
`s3:GetObjectVersion` for the configured OCI prefix. It cannot list, upload,
delete, or read an unversioned object.

## Use and cleanup

1. Copy `terraform.tfvars.example` outside source control and replace its
   placeholders. `deployment_name` must be a new, explicit globally unique
   name; do not reuse prior bucket names. The configured account must be the
   intended account: both the provider allow-list and a caller-identity
   precondition reject a mismatch.
2. Initialize and review without configuring a backend. This root defaults to
   local state and must not share an existing Terraform state file.

   ```sh
   terraform -chdir=infra/release-staging init
   terraform -chdir=infra/release-staging plan -var-file=/approved/path/release-staging.tfvars
   ```

3. After the approved temporary release finishes, first disable staging access
   logging. Delete every object version and delete marker from the staging
   bucket, and every object from the access-log bucket, then run the reviewed
   destroy. S3 log delivery can be asynchronous, so retry cleanup if a late
   log arrives. `force_destroy = false` deliberately makes Terraform stop
   until contents have been explicitly cleaned up. Apply and destroy only
   under the separately approved release procedure.

Never place credentials, GitHub tokens, release payloads, or Terraform state
in this repository.
