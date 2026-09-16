# node-operator

Hoodi validator operator for isolated AWS/EKS deployments. It provisions the
non-secret platform first, keeps validator custody and activation as separate
guarded ceremonies, and deploys only digest-pinned artifacts.

## Install a Hoodi validator

> **Status:** the public installer is under active verification. It creates
> AWS resources in the selected account and must be run only with a dedicated
> AWS identity and a clear teardown plan.

From a checkout of this repository, authenticate the AWS CLI to the intended
account, start Docker Desktop, then run the sole installer entrypoint:

```bash
bash scripts/release/node-operator-install.sh
```

The installer accepts no flags. It builds and verifies a local release bundle,
derives the selected account and Region from the AWS CLI profile, prompts only
for non-secret deployment choices, and creates a new isolated deployment name.
On macOS it installs Cosign through Homebrew if needed. On other platforms,
install Docker, AWS CLI, and Cosign before starting the installer.

Do not provide AWS access keys, GitHub tokens, private keys, Vault recovery
material, or validator passwords to the script or its prompts. Keep validator
keystore files in a private local directory; custody, deposit submission, and
validator activation occur only in their later explicit ceremonies.

### What the installer verifies

Before baseline Terraform applies, the installer creates deployment-scoped ECR
and KMS prerequisites, builds the reviewed first-party Vault artifacts from the
verified bundle source, pushes them to the new private ECR repositories, and
creates a signed local artifact-authority record. The installation stops if an
artifact is not digest-pinned, its authority is incomplete, a bundle check
fails, or a destination does not match the selected deployment.

The output work directory is resumable. Do not reuse a work directory from a
different deployment attempt. Resources are tagged with `Project=node-operator`
and a unique `Deployment` name so they can be identified for teardown.

### Prerequisites

- An AWS CLI profile for the target account and Region.
- Permissions to create the deployment-scoped Terraform backend, KMS keys, S3,
  ECR, IAM/OIDC, VPC, EKS, EC2, and CloudWatch resources.
- Docker Desktop (or a compatible Docker daemon) running locally.
- `git`, `jq`, `terraform`, `kubectl`, `python3`, and `gh` available on `PATH`.
- macOS: Homebrew is used automatically only when Cosign is missing. Linux and
  other platforms require a preinstalled `cosign` binary.

For the detailed operational boundaries and teardown procedure, see
[`docs/operations/release-bootstrap.md`](docs/operations/release-bootstrap.md).

## OpenSSF Best Practices

This project follows the OpenSSF Best Practices criteria. Registration and the
project-specific badge are maintained at [bestpractices.dev](https://bestpractices.dev/);
the repository intentionally does not embed a fabricated project ID.

The repository source is licensed under [Apache-2.0](LICENSE).

## Local policy checks

The policy foundation is runnable without AWS credentials. Install OPA, Conftest,
and ShellCheck, then run:

```bash
scripts/ci/test-policy.sh
scripts/ci/test-normalizer.sh
scripts/ci/test-conftest.sh
scripts/ci/test-script-quality.sh
```

`policy/tests/fixtures/` contains only synthetic, non-sensitive evidence. CI keeps
only normalized JSON/SARIF evidence for 90 days; raw logs and secret candidates are
not retained. See [the policy-as-code guide](docs/policy-as-code.md).
