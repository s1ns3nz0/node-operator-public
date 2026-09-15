# Terraform credential boundary

The isolated `ops-access` wrapper supports two authentication modes:

- Existing ambient mode preserves compatibility for an already approved,
  single-role ceremony.
- Separated mode requires a backend profile, provider profile, and the exact
  IAM role or user ARN expected from each profile. All four arguments are
  mandatory.
  The two profile names and resolved principals must both be distinct.

In separated mode, the S3 backend receives its profile through Terraform's
backend configuration while the provider receives `AWS_PROFILE`. Conflicting
exported credential, web-identity, container-credential, and default-profile
environment variables are rejected or removed from the child process. Before
Terraform starts, the wrapper calls STS for each named profile, normalizes an
assumed-role session ARN to its IAM role ARN, preserves an IAM user ARN, and compares it with the exact
allowlist. Exported access keys and session tokens are rejected. A named
profile's underlying credential storage is an operator-owned AWS CLI concern;
the wrapper does not prove that it is short-lived. Profile names and principal
ARNs are identifiers, not credentials; neither state nor token values are
printed. For assumed roles with IAM paths, STS does not expose enough data to
reconstruct every path; an expected path mismatch therefore fails closed.

Example shape (identifiers only):

```sh
scripts/release/node-operator-ops-access.sh plan \
  --root "$BUNDLE_ROOT" \
  --config "$PRIVATE_TFVARS" \
  --backend-config "$PRIVATE_BACKEND_HCL" \
  --plan-file "$PRIVATE_PLAN" \
  --backend-profile backend-readwrite \
  --expected-backend-principal-arn arn:aws:iam::123456789012:role/BackendRole \
  --provider-profile provider-read \
  --expected-provider-principal-arn arn:aws:iam::123456789012:user/ProviderRead
```

This separation does not authorize apply and does not make the provider role
sufficient. A refresh-backed plan must still pass the retained-host guard. Any
future provider permission change, including `iam:GetRole`, needs an exact
least-privilege policy review and separate authorization.

Use `verify` for a lock-free, refresh-backed read. It succeeds only when every
managed resource is a no-op retained-host action, prints only a count and plan
digest, and uses an isolated temporary Terraform data directory so backend
initialization cannot reuse or rewrite the module's active metadata. It removes
that directory, the temporary saved plan, and JSON on exit. Backend init also
uses Terraform's read-only dependency lock-file mode. It cannot be
combined with `--allow-create` and produces no apply artifact. Verification
with a management identity is read-only evidence only; it does not approve
using that identity for `apply`.

## Remaining identity decision

The separated verification path is operational, but it does not create or
prove a dedicated least-privilege provider role. The successful check used the
existing management user for provider reads and did not reduce that user's
permissions. Unattended apply is not verified or approved. If automation later
needs provider access, define the exact refresh/apply API allowlist from a
reviewed plan, create a dedicated role only with separate authorization, and
repeat exact-principal verification. Do not add broad `iam:Get*` access to the
backend role merely to make provider refresh convenient.
