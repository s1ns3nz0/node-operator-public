# Nethermind Hoodi workload overlay

This local-only overlay renders a single hardened Nethermind execution-client
StatefulSet for Hoodi. It includes no validator, key, secret, mainnet setting,
snapshot schedule, deployment instruction, or external endpoint.

The image is pinned to the approved `1.39.3-chiseled` linux/amd64 digest:

```
nethermind/nethermind@sha256:ec5f6c8158dbf82d4ddbd5500f895c930f52aa3b4c998148d9e1b452793d828e
```

The Pod uses a separate service account and storage class from Prysm. Its
`nethermind-data` PVC requests 2 TiB gp3 with 10,000 IOPS, 250 MiB/s
throughput, EBS encryption, and the KMS alias created by the T-2 baseline.
The local manifests do not contact AWS; a future approved build integration
must resolve that alias before an apply.

`--config=hoodi` selects the Hoodi chain configuration. JSON-RPC is explicitly
disabled because an authenticated Engine API requires a separately managed JWT
secret, which is outside this task's no-secret boundary. Connecting the
consensus client is a later, separately authorized integration.

This overlay requires the T-3 restricted namespace and default-deny policy. It
also requires nodes labelled `node-operator.io/network=hoodi` and
`node-operator.io/role=execution` in the approved Seoul zones. Required pod
anti-affinity prevents colocation with Prysm on a hostname.

The only added egress is DNS, Hoodi P2P TCP/UDP 30303, and HTTPS TCP 443, all
via explicitly labelled controlled gateway pods. This overlay supplies no
gateway, public service, ingress policy, or external exposure; without a
matching gateway the client safely has no external path.
