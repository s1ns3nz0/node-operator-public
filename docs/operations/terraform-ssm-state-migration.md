# Legacy SSM state migration plan

The current baseline Terraform state contains two generations of operations
access addresses: legacy `temporary_ssm_ops_host` resources and transitional
`ssm_ops_host` data addresses. Operations access must move to an isolated
`ops-access` root and state before either generation is removed from the
baseline configuration. The state listing alone is not evidence that every
address still has a corresponding live AWS resource; refresh-backed planning
in the maintenance window is required.

## Current ownership discovery (2026-09-08)

The running host `i-0123456789abcdef0` is already owned by a separate **local**
ops state, not by the baseline's stale host address. The observed local state
has lineage `4194a7ca-cf28-4cce-2f92-84cb76ddbe60`, serial 10, and nine managed
resources. The stale baseline instance `i-0123456789abcdef0` is no longer returned
by EC2. Do not recreate it or import the running host from that stale address.

For this existing ops state, preserve all resource/content identities while
migrating to the isolated encrypted remote key. Compare and record the original
and resulting lineage/serial: Terraform 1.5.7 can reset these metadata fields
when initializing an empty remote destination, as documented in
[bootstrap-state reconciliation](bootstrap-state-reconciliation.md). Never
force-rewrite metadata to hide a mismatch. Set
`existing_ssm_endpoint_security_group_id = "sg-0123456789abcdef0"`,
`manage_existing_endpoint_ingress_rule = true`, and
`manage_cluster_ingress_rule = true`: this state already owns both ingress
rules. The module's moved blocks retain their old uncounted addresses as `[0]`.
These settings are not universal defaults for a host whose rules have another
owner. A migration plan must show no rule deletion/replacement and no host
replacement before the new state is made authoritative.

Back up the original state privately, verify that the destination key is empty,
and use the reviewed backend migration procedure; never force-copy or discard
the original state. Do not simultaneously leave two writable authoritative
copies. Monitoring and EBS-optimization changes are separate from ownership
migration. The initial private preview with AWS provider 5.100 proposed host
replacement solely for `ebs_optimized: false -> true`; this blocks resource
apply. EC2 reports that this `t3.micro` type is EBS-optimized by default, so
the representation mismatch is not evidence that the actual capability is
missing. The reviewed explicit retained-host inputs below subsequently produced
a read-only preview with the host unchanged and four rule-description updates.
That preview used a private state copy, was not applied, and is not an
authoritative state owner. Re-plan from the canonical owner before execution.
Do not replace or stop the host, disable hardening for new instances,
or add an exception without a reviewed decision. Any future host-changing plan
also requires checking active SSM/DAST sessions and explicit impact approval.

## Reviewed retained-host representation opt-in

Fresh `ops-access` hosts always retain `ebs_optimized = true`. The nullable
`retained_host_instance_id` variable is null by default and may name only
`i-0123456789abcdef0`. When set, Terraform reads the exact host, its subnet,
and its EC2 instance-type capability before accepting the legacy false value.
The resource lifecycle preconditions require the configured VPC/subnet, type
`t3.micro`, observed `ebs_optimized = false`, and type capability
`ebs_optimized_support = default`. Any other host, type, network identity, or
capability fails planning; this is not a generic drift suppression.

The dedicated SSM-only operations host uses basic EC2 monitoring
(`monitoring = false`) for both fresh and retained representations. This
matches the observed host and avoids enabling detailed-monitoring charges; it
does not change encrypted gp3 root storage, IMDSv2, IAM, or network controls.

The guarded `ebs_optimized` input defaults to true. It is not a general tuning
option: a blocking lifecycle precondition requires true for a fresh host and
false only alongside the exact retained-host ID. A retained-host configuration
must explicitly set both `retained_host_instance_id` and `ebs_optimized = false`.
All existing identity, network and default-capability checks still apply.

Before any separately authorized state or infrastructure action, render a
saved plan and run `scripts/ci/check-ops-access-ssm-retention-plan.sh` on its
private JSON form. The guard requires the exact host in prior state, requires
the host to remain a no-op with the reviewed false representation, and rejects
create, delete, replacement, unknown guarded values, or a false EBS
optimization value on any other managed instance. It requires precisely the
nine reviewed managed addresses (including the moved ingress addresses), exact
IDs and complete before/planned/change value consistency. Apart from optional
description and tag metadata on non-host resources, it rejects every retained
network or IAM change. Keep saved plans and raw state outside Git. This guard
does not authorize apply, import, remote-state migration, or a host restart.

## General migration sequence

This sequence describes other legacy ownership layouts, not the current
nine-resource local-state migration above. Do not import the current host again
or apply these generic ingress ownership flags to its already-owned rules.
For the current host, migrate the existing canonical local state rather than
initializing an empty remote state and planning a second host. A fresh-user
deployment is a separate path and must not import this environment's resources.

1. Create the new root with a distinct encrypted state key and no dependency on
   workload, Vault, or GitOps resources except read-only EKS/VPC outputs. Copy
   `infra/ops-access/backend.hcl.example` outside the bundle and use the
   `node-operator/ops-access/terraform.tfstate` key; do not use local state.
2. Run the isolated `ops-access plan` command with a new private `--plan-file`.
   It prints the saved-plan SHA-256 only after the wrapper renders and checks
   the plan JSON. Apply requires that same path and `--expected-sha`; it
   re-renders, rechecks, and rehashes immediately before applying the exact
   saved plan. It may propose a new host only for a genuinely zero-resource
   environment with `--allow-create` and an explicit null retention opt-in.
   Fresh mode positively requires a single created `aws_instance.host` with
   EBS optimization, encrypted gp3 root storage, IMDSv2, private addressing,
   IAM profile/security group, and basic monitoring. A failed retained-host
   plan cannot fall through to fresh mode. Plan paths must be absolute,
   private, and non-symlinked; the wrapper creates JSON with a restrictive
   umask. Against an existing environment, it is evidence to review: do not
   apply a plan that replaces an active host,
   endpoint, IAM role, or security-group rule.
3. In a reviewed maintenance window, create the isolated host resources in the
   new state using Terraform import or a state move procedure that preserves
   each exact AWS identifier. Never recreate an active tunnel host implicitly.
   If the live host uses shared baseline SSM interface endpoints, set
   `existing_ssm_endpoint_security_group_id` and
   `manage_cluster_ingress_rule = false` in the non-secret migration tfvars.
   This root then owns the host and its egress only; it neither recreates nor
   takes ownership of the shared endpoints or the baseline-owned EKS ingress.
4. Verify new-state ownership with `terraform state list`; retain only resource
   addresses and no raw state output in evidence.
5. Remove both legacy and transitional addresses from the baseline state only
   after the isolated state plans no replacement or destroy. Then remove their
   baseline configuration.
6. Test the saved-plan apply path, private EKS tunnel, and a separately
   reviewed explicit destroy-plan interface independently in a disposable
   environment. Direct destroy remains disabled. There is deliberately no
   Scheduler implementation or permission in this root.

Do not combine this migration with a client, Vault, validator, or generic
baseline Terraform apply.
