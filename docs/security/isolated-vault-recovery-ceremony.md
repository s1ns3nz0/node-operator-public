# Isolated real-snapshot recovery: execution boundaries

This is preparation for the approved Hoodi recovery rehearsal, not evidence
that a restore or upgrade has succeeded. The temporary recovery host exists;
the original EKS Vault cluster remains unchanged.

## Temporary auto-unseal access

The isolated role needs Encrypt, Decrypt and DescribeKey on the original seal
key to open the restored barrier. Its IAM policy alone is insufficient because
the existing seal key policy does not delegate this use through account IAM.
Do not replace that policy, reuse the live Vault role, or grant CreateGrant to
the recovery host.

`scripts/ops/manage-isolated-vault-recovery-grant.py` confines grant management
to the reviewed account, key, recovery role, grant name and expiry. Run its
help before use. The default is a read-only plan; create and revoke must be
explicit. A separately provisioned, temporary AWS profile assuming the existing
KMS administrator role is required. Do not put credentials in source control
or shell arguments. Acquiring that session is not implemented by this helper.

The administrator session should itself be restricted to DescribeKey,
ListGrants and RevokeGrant on the exact seal key and CreateGrant constrained to
the exact recovery principal and the three required operations. No key-policy
mutation or cryptographic operation is needed by the grant manager.
The session-policy template is
`deploy/vault/bootstrap/isolated-recovery-grant-session-policy.json`. It must
be passed when acquiring the administrator session; the grant manager cannot prove
that an existing profile was issued with this session policy. The wrapper
`scripts/ops/with-isolated-vault-grant-admin.py` acquires a 900-second session
with that exact policy and invokes only the fixed grant manager. AWS authorizes
RevokeGrant at key scope, so the helper's exact grant identity validation is
also required to avoid revoking an unrelated grant on that key.
The IAM set condition permits nonempty subsets of the three operations; it
does not require all three. The helper must request and validate exactly all
three and reject an existing named grant with a subset or additional operation.
The session policy also prevents CreateGrant after the approved expiry using
AWS time, while keeping inspect/revoke available for cleanup after expiry.

Grants do not provide a wall-clock expiry. The recovery host's explicit IAM
deny after `2026-09-10T12:00:00Z` is a separate safeguard; grant revocation and
resource cleanup remain mandatory. Creation and revocation are eventually
consistent. A successful revoke request is not proof that every endpoint has
already denied use. The helper does not print or persist GrantToken.

Sources: [AWS KMS grants](https://docs.aws.amazon.com/kms/latest/developerguide/grants.html),
[CreateGrant API](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateGrant.html).

## Required before snapshot restore

- Reconfirm the isolated VPC, no live peer routes, private endpoints, scoped
  host role, IAM expiry deny, and current SSM health. The grant helper is not a
  replacement for these checks.
- Keep exact S3 version and checksum verification on the isolated encrypted
  host. Never download the real snapshot to the workstation or CI.
- Pin the old and candidate Vault image digests to reviewed evidence. Do not
  use a mutable tag or treat a synthetic Shamir test as an AWS KMS restore.
- Design the local-only listener and credentials path explicitly: IMDSv2 hop
  limit one prevents ordinary Docker bridge access to instance credentials.
  Do not increase it or enable broad host networking without a reviewed design.
- Recreate isolated file/socket audit destinations before restored requests.
  Do not reconnect restored audit sinks or retry_join configuration to live
  services. No recovered validator keys may reach a signer.
- Recovery shares, generated tokens and any restored credentials stay solely
  within the user-operated terminal ceremony. Revoke newly generated tokens;
  remember that the snapshot can contain credentials revoked after it was taken.
- Prove restore health and metadata-only checks, then the candidate upgrade.
  Do not read/export custody secrets merely to prove that restore succeeded.
- Stop the isolated Vault, revoke the exact temporary grant, verify cleanup
  and retain only non-sensitive evidence. Full infrastructure teardown requires
  its own reviewed destroy plan; expiry tags do not perform teardown.

Until these execution requirements are implemented and reviewed, do not start
the real clone, upgrade the original cluster, or activate the validator client.

## Host-only restore implementation

`scripts/ops/rehearse-isolated-vault-restore.py` is an isolated rehearsal, not
a live EKS upgrade executor. Its default plan does not restore anything.
Execution is intentionally restricted to the approved Linux EC2 recovery host
and requires an interactive controlling terminal. Do not run `--execute` from
CI, an agent tool, or SSM Run Command: the original recovery quorum must only
enter the user-operated interactive process. Do not enable shell tracing or
terminal session recording for the ceremony.
The account's existing `SSM-SessionManagerRunShell` records sessions to S3 and
must not be overwritten or used for this ceremony. The separate template
`deploy/vault/bootstrap/isolated-recovery-session-document.json` disables
terminal transcripts only for the dedicated, fixed recovery command. It does
not offer a general shell, accepts no command parameters, and retains SSM
session lifecycle/CloudTrail metadata and the clone's local Vault audit devices.
Creation/readback of the separate named session document and digest-bound,
root-owned staging under `/opt/node-operator-isolated-recovery/` must precede
user execution. These have not yet occurred. The host script must reject any
other EC2 instance, so this template cannot authorize a restore on another host.

The reviewed networking exception is Docker host networking **only on this
dedicated isolated host**. It allows the Vault KMS seal to use the host's
IMDSv2 role without increasing hop limit one or copying AWS credentials into
container arguments, files or environment. Both Vault API and cluster
listeners bind loopback; no ports are published and no live retry-join target
is configured. The container must remain non-root with dropped capabilities
and a read-only root filesystem. This is not permission to use host networking
in EKS or a shared machine. Root/SSM administrators on this temporary host can
access local process memory and loopback traffic and are part of the trusted
ceremony boundary.

Before execution, revalidate security groups, endpoints and routes. Restored
tokens, leases and auth configuration can revive historical access paths;
the isolated host role and endpoint policy must still forbid unrelated AWS
actions and live peer access. No signer process is present or permitted.
Local audit sinks must not forward restored events outside the host.

After S3 download and image pulls, but before starting either Vault version,
the runtime installs UUID-owned IPv4/IPv6 output chains for dedicated UID
65000. They allow IPv4 loopback, IMDS TCP/80, private KMS endpoint TCP/443,
and DNS to the VPC resolver only; all other output is rejected. IPv6 output is
rejected. These rules must take precedence over existing OUTPUT accepts and
remain installed until the owned Vault container is stopped. They do not
alter the host's SSM/root traffic or flush built-in firewall chains. A missing
firewall command or non-private KMS DNS answer blocks execution.

Residual trust: the VPC resolver can receive arbitrary DNS questions and the
isolated host's loopback services remain reachable. This is containment of
restored credentials, not proof that every historical token has been revoked.
No live signer or other application service may run on the recovery host.
Root volume encryption and AWS route/SG/endpoint state require the separate
operator preflight; IMDS instance identity does not prove those settings.

Snapshot API acceptance is not proof of completed restoration. The script
must observe a changed cluster identity, healthy unsealed restored state,
expected local audit configuration and single-node Raft membership before
testing the candidate image. Candidate verification uses the same restored
cluster and metadata, without exporting custody secrets. There is no automatic
binary downgrade. Failure cleanup must stop the owned container before deleting
its sensitive local data, and must not print PASS if token cleanup fails.
The metadata comparison covers mount names and policy names, not full mount
configuration or policy body equivalence. Audit destinations/options and
singleton Raft member fields are validated separately. Delivery counters show
local audit traffic, not a full request-ID-correlated activity log review.

Temporary grant use remains separate:

```sh
python3 scripts/ops/with-isolated-vault-grant-admin.py --mode plan
# Only after restore code review, host isolation preflight, and user readiness:
python3 scripts/ops/with-isolated-vault-grant-admin.py --mode create
# After stopping the isolated rehearsal; also required after a failed attempt:
python3 scripts/ops/with-isolated-vault-grant-admin.py --mode revoke
```

Source staging and the user interactive SSM command must bind the reviewed
script digest to the exact recovery instance before execution. This PR does
not claim that source staging, real restore, candidate upgrade, token cleanup,
or grant revocation has occurred. Mock checks are implementation evidence only.

API references: [Raft snapshot restore](https://developer.hashicorp.com/vault/api-docs/system/storage/raft),
[root generation and OTP encoding](https://developer.hashicorp.com/vault/api-docs/system/generate-root).
Session reference: [AWS session document schema](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-schema.html).
