# Release runner dynamic AWS credential contract

This template defines a single Vault AWS secrets-engine role. The Vault
policy, not the AWS policy, is read-only: the sole allowed Vault operation is
reading `aws/creds/release-runner`, which creates a short-lived lease. The
leased AWS identity has only the actions in
[`aws/release-runner-assumed-role-policy.json`](aws/release-runner-assumed-role-policy.json):
upload a signer input, start and inspect the approved CodeBuild signer, and
read its output. It cannot administer IAM, read arbitrary release objects, or
access Vault Transit.

The AWS secrets engine is configured by an approved operator using its own
bootstrapping identity. Do not place an AWS access key, secret key, Vault
token, or role-assumption credential in this repository. The bootstrap
identity and its rotation are an external operational control.

```sh
vault secrets enable aws
vault write aws/roles/release-runner \
  credential_type=assumed_role \
  role_arns="arn:aws:iam::REPLACE_WITH_ACCOUNT_ID:role/REPLACE_WITH_VAULT_DYNAMIC_AWS_ROLE" \
  policy_document=@deploy/vault/aws/release-runner-assumed-role-policy.json \
  default_sts_ttl=15m \
  max_sts_ttl=15m
```

`REPLACE_WITH_VAULT_DYNAMIC_AWS_ROLE` is a dedicated IAM role assumed by Vault,
not the GitHub runner or CodeBuild role. Its trust policy must allow only the
Vault AWS secrets-engine identity. The role is disabled until the private
runner, JWT role, Vault audit device, and failure-path tests are all approved.

Dynamic AWS credentials are not reusable after their lease expires. The
workflow must unset them after the signer artifacts are copied and must not
fall back to direct `sts:AssumeRoleWithWebIdentity`.
