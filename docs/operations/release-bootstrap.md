# Hoodi release bootstrap

The distributable Hoodi release is a deterministic, non-secret artifact. A
consumer verifies the extracted artifact before using its Terraform baseline:

```sh
tar -xf node-operator-release-bundle.tar -C release
release/source/scripts/release/node-operator-release.sh verify --bundle-root release
release/source/scripts/release/node-operator-release.sh bootstrap plan \
  --bundle-root release --config /controlled-input/hoodi.ap-northeast-2.tfvars
```

`bootstrap apply` uses the same verified input after the reviewed plan is
approved. AWS credentials and the configured encrypted Terraform backend must
come from the controlled execution environment. The release archive contains
neither credentials nor backend state.

The infrastructure entrypoint first creates the exact deployment-bound
private ECR/KMS and publisher OIDC prerequisite closure, then mirrors and
re-verifies every release-authorized immutable artifact before baseline
infrastructure is applied. Operators do not separately publish artifacts for a
fresh deployment. The separately approved private Argo CD bootstrap phase
remains a distinct boundary. The release contract accepts only the `0.1.<run>`
version format; promotion must verify and carry the exact immutable OCI digest
before changing the Application. No historical chart revision is assumed to
exist in a new account.

SSM access, Vault initialization/unseal, Vault writes, validator key custody,
remote-signer activation, and validator duties are deliberately not bootstrap
operations. They require their own command and approval boundary.

## Fresh zero-resource infrastructure

For a new account scope, create the three non-secret configuration files from
the AWS account ID and the exact IAM role that will retain Terraform backend
access. If the current AWS identity is that role, omit
`--backend-principal-arn` and it is derived after an account-match check:

```sh
release/source/scripts/release/prepare-zero-resource-inputs.sh \
  --aws-account-id <new-account-id> \
  --backend-principal-arn arn:aws:iam::<new-account-id>:role/<terraform-role> \
  --output-dir /controlled-input/node-operator-zero
```

Then run one verified command:

```sh
release/source/scripts/release/node-operator-release.sh zero apply \
  --bundle-root release \
  --inputs /controlled-input/node-operator-zero/zero-resource-inputs.json \
  --work-dir /controlled-state/node-operator-zero-bootstrap
```

The command creates and migrates the encrypted Terraform backend, then applies
foundation-network and the baseline. It derives VPC, subnet, route-table, and
NAT inputs from the foundation output; a second VPC is not allowed. The work
directory is a new mode-0700 directory and contains plan/state material, so
retain it under controlled operator storage.

The command bootstraps and verifies the release-authorized immutable artifact
set as part of infrastructure. Private Argo bootstrap, optional SSM access,
Vault initialize/restore, custody, and validator activation stay separate
approved operations.

If the final validator identity and approved immutable client images are known
at the beginning, generate both the zero-resource configuration and the
initially fenced validator manifests in one non-secret command. This prevents
the AWS account ID and validator identity from being copied between commands:

```sh
release/source/scripts/release/prepare-hoodi-zero-release-inputs.sh \
  --aws-account-id <new-account-id> \
  --backend-principal-arn arn:aws:iam::<new-account-id>:role/<terraform-role> \
  --validator-set hoodi-example \
  --validator-public-key <0x-validator-public-key> \
  --withdrawal-address <0x-withdrawal-address> \
  --web3signer-image <private-ecr@sha256:...> \
  --postgres-image <private-ecr@sha256:...> \
  --prysm-validator-image <private-ecr@sha256:...> \
  --signing-fence-image <private-ecr@sha256:...> \
  --kubernetes-api-cidr <operator-ip>/32 \
  --output-dir /controlled-input/hoodi-zero-release
```

For an operator terminal, the same values can be collected once interactively.
The current AWS short-lived identity supplies the account and role binding; it
never prompts for or stores credentials, Vault material, custody keys, or a
wallet secret:

```sh
release/source/scripts/release/hoodi-validator-release.sh interactive prepare \
  --bundle-root release \
  --output-dir /controlled-input/hoodi-zero-release
```

When the current identity is an IAM user rather than the Terraform role, the
prompt additionally requests the exact same-account backend role ARN once.

Use `zero-resource/zero-resource-inputs.json` with `zero apply`. The generated
`validator-deployment/validator-deployment-handoff.json` remains at zero
replicas and is staged only after the separately created SSM session handoff.
`hoodi-validator-release.sh` is the corresponding execution entrypoint: its
`infrastructure apply` and `stage plan|apply` commands consume the one prepared
handoff and reject cross-account or unfenced substitutions before delegating to
the existing guarded commands.

After `infrastructure apply`, derive the isolated SSM input set without copying
the zero-work directory's handoff path:

```sh
release/source/scripts/release/hoodi-validator-release.sh ops-inputs prepare \
  --bundle-root release \
  --inputs /controlled-input/hoodi-zero-release/hoodi-zero-release-inputs.json \
  --zero-work-dir /controlled-state/node-operator-zero-bootstrap \
  --output-dir /controlled-input/node-operator-ops-access
```

When applying that reviewed ops-access plan through the release entrypoint,
provide a new mode-0600 `--private-eks-session-handoff` path. It is required
there so the following validator staging command receives the exact SSM host
and EKS cluster from Terraform output rather than manually copied values.

For the separately managed private EKS operations host, derive its isolated
Terraform inputs from the zero-release work directory rather than copying VPC,
subnet, or backend values by hand. The command verifies the current AWS account
and reads the cluster security group from the EKS control plane:

```sh
release/source/scripts/release/prepare-ops-access-inputs.sh \
  --handoff /controlled-state/node-operator-zero-bootstrap/ops-access-handoff.json \
  --output-dir /controlled-input/node-operator-ops-access
```

Pass `ops-access-inputs.json` to `node-operator-ops-access.sh` with a private
saved-plan location; do not retype its config or backend paths. Its reviewed
`apply` can write a new mode-0600 `--session-handoff` file. Pass that handoff
to the validator staging command so the private EKS cluster name and SSM
instance ID are never copied into shell environment variables by hand.

After publishing a chart and preparing the digest-bound Argo input, create a
reviewed private plan against the same `--work-dir` used by `zero apply`; only
then apply that exact saved plan:

```sh
scripts/release/apply-argocd-bootstrap.sh plan \
  --baseline-work-dir /controlled-state/node-operator-zero-bootstrap \
  --baseline-config /controlled-input/baseline.tfvars \
  --bootstrap-input /controlled-state/argocd.tfvars.json \
  --plan-file /controlled-state/argocd-bootstrap.tfplan
```

After Argo health and private-CD verification are accepted, revoke the
temporary runner and its cluster-admin association using the original disabled
baseline input and a separately reviewed deletion-only plan.

After `zero apply`, configure the GitOps publisher using the generated
non-secret handoff (it writes only an AWS account ID and restricted OIDC role
ARN to the protected GitHub environment):

```sh
release/source/scripts/release/configure-gitops-publisher.sh \
  --handoff /controlled-state/node-operator-zero-bootstrap/gitops-publisher-handoff.json
```

The protected environment still requires its configured approval before the
publisher can create an immutable chart. Never put GitHub tokens, Vault
material, custody keys, or validator secrets in the handoff.
