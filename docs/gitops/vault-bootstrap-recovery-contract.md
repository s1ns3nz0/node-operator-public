# Vault bootstrap and recovery contract

This is a non-secret, declarative release-path readiness contract. It describes
the evidence an approved operator must collect before release credentials can be
enabled. It neither creates cloud resources nor changes a live Vault instance.
The ordered machine-checkable form is
`deploy/vault/bootstrap/release-path-contract.json`.

## Operator-only bootstrap boundary

Live initialization and unsealing happen only during a separately authorized
rollout and only at the operator administration boundary. No `vault operator init`,
`vault operator unseal`, or apply command is included or executable in this
repository contract. Root material, recovery material, and unseal
material are external to CI, GitOps, Terraform state, logs, and evidence. The
contract never generates, accepts, records, or automates that material.

The operator must record an approval identifier, environment identifier, Vault
cluster identifier, status, and a denied-path result without recording a
credential, key, token, or recovery value. Until that boundary is proven,
release credentials remain denied.

## Ordered readiness gate

The phases are intentionally ordered; a later phase cannot become release-ready
when an earlier phase lacks a passed result or a failed deny-path probe.

1. Prove private DNS, TLS, routing, and audit correlation against the private
   connectivity and runner contracts.
2. Prove the operator-only initialize/unseal boundary while keeping all root,
   recovery, and unseal material external.
3. Prove that the approved audit device delivers a correlated record.
4. Prove encrypted Raft snapshots, their approved retention, and a restore
   drill in an isolated environment.
5. Configure and test the GitHub JWT release role and its dynamic AWS policy
   against the checked-in, restricted artifacts.
6. Configure and test the AWS secrets-engine dynamic release role; static
   credentials and unauthorized lease paths are denied.
7. Configure and test the AWS-authenticated private CodeBuild signer role with
   its restricted workload identity and route.
8. Configure and test the Transit release key policy. The signer may only sign
   and verify; read, export, rotate, delete, and administration are denied.

Each phase must retain a status and a denied-path result. The minimum
non-secret correlation fields are defined in the JSON contract: operator and
environment approval references; GitHub repository, run, and workflow
references; Vault audit request ID; AWS request ID; CodeBuild build ID; private
DNS/TLS probe IDs; snapshot and isolated restore-drill references; and the
boolean Transit verification status. Do not retain an OIDC JWT, Vault token,
AWS credential, private key, recovery value, unseal value, root token, or
Transit signature.

## Audit and recovery failure boundary

The audit destination, encrypted snapshot destination, retention values, and
isolated restore environment are environment-owned configuration, not values
for this repository. A missing audit-delivery probe, missing encryption or
retention proof, an unsuccessful restore drill, uncorrelated evidence, or a
successful unauthorized-path probe is fail-closed: no release credential is
issued and no signer build is accepted.

This contract is an implementation prerequisite, not deployment authorization.
Applying the JWT, AWS secrets engine, AWS auth, audit, Raft recovery, or
Transit configuration happens only after a separately authorized live rollout
has established the private connectivity, TLS, and operator boundaries.
