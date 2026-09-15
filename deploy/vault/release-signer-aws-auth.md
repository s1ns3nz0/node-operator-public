# Vault AWS Auth role

Apply from the Vault administration boundary after the Terraform-managed
CodeBuild role exists:

```sh
vault write auth/aws/role/release-signer \
  auth_type=iam \
  bound_iam_principal_arn="arn:aws:iam::<ACCOUNT_ID>:role/node-operator-baseline-release-signer" \
  resolve_aws_unique_ids=false \
  policies=release-signer \
  ttl=5m max_ttl=10m
```

For a private VPC without NAT, route Vault's AWS-auth verification through the
regional STS interface endpoint:

```sh
vault write auth/aws/config/client \
  sts_endpoint=https://sts.ap-northeast-2.amazonaws.com \
  sts_region=ap-northeast-2
```

The role receives only the `release-signer` Transit policy. No static Vault
token is stored in GitHub, CodeBuild, Terraform state, or artifacts.
