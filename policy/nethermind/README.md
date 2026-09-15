# Nethermind workload policy

`hardening.rego` is the static policy contract for the Hoodi Nethermind
StatefulSet, its dedicated EBS StorageClass, and its selected NetworkPolicies.
It enforces the approved digest, 2 TiB encrypted gp3 storage (10,000 IOPS,
250 MiB/s, nonempty KMS key), non-root/read-only/seccomp/capability-drop
posture, P2P probes, required hostname anti-affinity with Prysm, and the
absence of world egress. It also requires the dedicated `nethermind-execution`
ServiceAccount and disables automatic API-token mounting.

Run locally when OPA/Conftest is available:

```sh
conftest test --all-namespaces --policy policy/nethermind policy/nethermind/fixtures/secure.yaml
! conftest test --all-namespaces --policy policy/nethermind policy/nethermind/fixtures/insecure.yaml
```
