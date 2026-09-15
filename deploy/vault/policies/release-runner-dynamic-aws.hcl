# The GitHub release job can only mint one short-lived AWS credential.
# `read` is intentional: it issues a lease and does not expose an AWS
# secrets-engine configuration or any other Vault path.
path "aws/creds/release-runner" {
  capabilities = ["read"]
}
