# Validator signing fence security model

The signing fence is a TLS passthrough proxy between one fixed-name validator
client Pod and Web3Signer. It never terminates, inspects, or logs signing
traffic. NetworkPolicy exposes Web3Signer only to the fence and exposes the
fence only to the set-scoped client. Prysm continues to verify the Web3Signer
certificate end to end.

The proxy has a dedicated per-set service account. Its bound projected token
is mounted only in the proxy and permits `get`/`patch` of one Lease plus `get`
of the one fixed client Pod. It pins that Pod's UID and IP after validating its
name, labels, phase, and deletion state, then revalidates the same identity on
every renewal. A second source IP is rejected for the proxy lifetime.

Lease ownership uses resource-version and holder-identity JSON Patch tests. An
empty Lease or a different demonstrably expired holder can be acquired; a live
other holder or an expired lease owned by this process fails closed. Each
Kubernetes request has a hard timeout. The proxy maintains an independent
monotonic authority deadline, closes its listener and all active connections
on loss, and caps each connection by the remaining authority window.

This bounds but cannot retract a signing request already accepted upstream.
The retained Web3Signer slashing database remains the final double-signing
control. Source-IP and Pod-UID binding depends on enforced NetworkPolicy and
the reviewed fixed-name StatefulSet; it is not mutual TLS client identity.

Deleting a Vault Kubernetes role does not revoke an already issued token or a
key loaded by Web3Signer. Therefore role deletion alone is not UC-5 fail-closed evidence.
UC-5 must fence the client first, observe zero client Pods and closed proxy
authority, then perform the bounded role probe. Recovery still requires the
same slashing PVC/database identity and a later successfully included duty.

## Expired Lease handover

Proxy shutdown intentionally leaves holder history in the Lease. Clearing an
expired holder is a separate reviewed maintenance operation, never an automatic
takeover. `release-expired-hoodi-validator-fence-lease.sh` requires the exact
Lease UID, resourceVersion and old holder plus the retained slashing PVC UID.
It accepts only the expected zero-replica client StatefulSet, signer Deployment
and fence Deployment, no legacy client Deployment, and no matching Pods. The
Lease must have a valid non-future `renewTime`, a bounded duration, and be
expired beyond its duration and safety margin.

Immediately before mutation the helper re-reads all controller, Pod and PVC
preconditions, then JSON-patches only `holderIdentity` using tests for Lease
UID, resourceVersion, holder, renewTime and duration. It never retries a CAS
failure, force-reclaims a live holder, scales a workload, or changes the PVC.
Fresh readback must show the same Lease UID, a new resourceVersion and an empty
holder. Dry-run performs no mutation.

Lease CAS cannot atomically protect separate controller and Pod objects. The
operation therefore also requires an exclusive, reviewed maintenance and
GitOps reconciliation pause. This is a bounded recovery transition, not a
general distributed-transaction guarantee and not proof that UC-5 passed.
