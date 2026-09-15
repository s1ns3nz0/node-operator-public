# Validator key operations

This runbook implements the non-secret operational boundary for the Hoodi
validator use cases. It does not authorize access to Vault tokens, recovery
material, validator key material, or withdrawal credentials. Those actions are
performed only under the separately controlled custody procedure.

## Invariants

- The release Transit key, CI identity, validator signing key, withdrawal
  credential, and slashing-protection history are separate assets.
- Git, CI logs, Terraform state, container images, Kubernetes `Secret`
  manifests, and ConfigMaps contain none of those assets or their passwords.
- A validator client calls only the namespaced remote signer service. It has no
  direct Vault egress, no signer key mount, and no permission to mutate the
  fencing lease.
- A remote signer receives an audience-bound, short-lived workload identity
  only for its own validator set. Its policy must deny list, delete, export,
  release Transit paths, CI paths, and every other validator set.
- No handover activates a replacement until the old signer is fenced and its
  slashing history is verified.

## UC-2: onboarding and deposit preparation

1. Conduct key generation outside Kubernetes in an operator-controlled,
   isolated ceremony. Generate the EIP-2335 encrypted keystore, its password,
   and withdrawal credential as separately controlled records.
2. Independently verify the deposit data and record only the public key,
   deposit-data SHA-256, custody-record SHA-256, and approval identifiers in
   the approved evidence system. The `validator-onboarding-contract` ConfigMap
   lists the required metadata but is never populated with key material.
3. Use a one-time Vault ceremony role to write the encrypted keystore and its
   password to distinct versioned, environment- and validator-set-scoped
   locations. The runtime signer role must not read either onboarding record.
4. Before activation, prove the signer identity cannot use CI/release paths,
   cannot access a second validator set, and the validator client cannot read
   Vault directly.

## UC-3: remote signer activation

1. Deploy a reviewed, digest-pinned remote-signer implementation using only
   the `validator-remote-signer` service account and labels required by
   `deploy/validator/network-policies.yaml`.
2. Configure its private service endpoint as
   `validator-<validator-set>-remote-signer.validator-operations.svc:9000`.
   The service selector must include the same `node-operator.io/validator-set`
   label as the signer Pod; a namespace-wide signer Service is prohibited. The
   service is `ClusterIP`; any TLS private key or workload credential is
   provisioned outside Git.
3. Configure the consensus validator client with no keystore file, no
   withdrawal credential, and no direct Vault connection. Permit only the
   remote signer endpoint and require mutually authenticated, audience-bound
   requests before enabling duties.
4. Confirm one permitted signing request succeeds and prove that a direct Vault
   read from the client, a CI identity signer call, and a cross-set signer call
   are denied. Retain only non-secret request correlation identifiers.

The reviewed templates in `deploy/validator/vault/` deliberately use
`REPLACE_WITH_VALIDATOR_SET`. Instantiate one narrowly scoped policy per set;
never replace it with a wildcard. The Kubernetes auth-role template binds only
`validator-remote-signer` in `validator-operations`, sets audience `vault`,
and issues a five-minute token with no default policy. Applying these templates
requires the separately authorized Vault operator procedure and is outside
this non-secret GitOps contract.

## UC-4: slashing protection and failover

The Kubernetes Lease `validator-<validator-set>-primary` is a fence signal,
not a substitute for a signer-supported slashing database. The active signer
is enabled only when the designated fence controller owns that set-specific
lease. Signers and the client receive no Kubernetes RBAC to mutate it.

1. Stop and fence the current signer. Record its holder identity, lease state,
   revocation/fencing evidence ID, and incident or change approval ID.
2. Export slashing-protection interchange data from the old active system to
   encrypted, integrity-protected backup. Record its SHA-256 only.
3. Import into the candidate replacement, independently verify the import hash
   and validator-set match, then acquire the lease through the controller.
4. Test an old-signer request after fencing; it must fail before the replacement
   signs. Do not bypass this sequence merely because a pod has restarted.

## UC-5: compromise, rotation, and voluntary exit

1. Immediately revoke the affected signer workload identity and policy, then
   fence the signer before attempting any key rotation, recovery, or exit.
2. Preserve audit correlation IDs, current fencing state, and slashing-history
   hashes in immutable incident evidence. Do not delete evidence or overwrite
   the only historical copy.
3. Use the approved network-specific recovery or voluntary-exit ceremony.
   Withdrawal credentials require separate recovery approval and are never
   mounted in the signer or validator client.
4. Re-enable signing only after independent approval proves a scoped identity,
   validated slashing import, successful post-fence denial test, and audit
   evidence continuity.

## Required evidence for promotion

For each active validator set, retain the non-secret fields specified by
`validator-operations-evidence-contract`. A missing fence record, failed
slashing import verification, lost audit correlation, or unavailable signer
identity revocation is fail-closed: do not enable validator duties.
