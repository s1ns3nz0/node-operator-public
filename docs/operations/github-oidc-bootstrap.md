# GitHub OIDC bootstrap without the GitHub API

`scripts/ops/bootstrap-github-oidc-ecr-publisher.sh` configures the AWS side
using AWS IAM and ECR APIs only. It does not call the GitHub API, modify
`GITHUB_TOKEN`, or store credentials.

## Inputs

Provide these non-secret values in an environment file or exported variables:

```text
AWS_PROFILE=default
AWS_REGION=ap-northeast-2
GITHUB_OWNER=s1ns3nz0
GITHUB_REPOSITORY=node-operator
GITHUB_OWNER_ID=<owner numeric id>
GITHUB_REPOSITORY_ID=<repository numeric id>
```

The owner/repository IDs must be supplied by the operator because this mode
does not query GitHub. The script defaults the ECR repository, role name, and
Environment name to the Fence release values.

## Run

```bash
scripts/ops/bootstrap-github-oidc-ecr-publisher.sh \
  --env-file /absolute/path/bootstrap.env --dry-run
scripts/ops/bootstrap-github-oidc-ecr-publisher.sh \
  --env-file /absolute/path/bootstrap.env
```

The script is idempotent. It ensures the AWS OIDC provider exists, creates an
immutable scan-on-push ECR repository when absent, and creates or updates an
IAM role whose trust subject is restricted to the exact GitHub repository and
`validator-client-ecr-mirror` Environment. The ECR policy is limited to that
repository; only `ecr:GetAuthorizationToken` uses `Resource: "*"` as required
by AWS.

## One-time GitHub UI step

Create the Environment named `validator-client-ecr-mirror` in the repository
settings. Add these non-secret Environment variables using the script output:

```text
AWS_ACCOUNT_ID
VALIDATOR_CLIENT_ECR_MIRROR_ROLE_ARN
```

No AWS access key, OIDC token, or signing secret belongs in GitHub variables.
The workflow requests `id-token: write` and exchanges the short-lived token
for the role at runtime.

## New account checklist

The caller needs AWS IAM permissions to create an OIDC provider, role policy,
and ECR repository, plus repository-admin permission for the one-time GitHub
Environment UI step. The repository Terraform currently assumes the OIDC
provider already exists; run this bootstrap before `terraform apply` in a new
AWS account.
