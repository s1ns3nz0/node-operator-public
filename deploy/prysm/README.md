# Prysm Hoodi workload overlay

This local-only overlay defines one hardened Prysm beacon-node StatefulSet for
the Hoodi test network. It deliberately includes no validator client, validator
keys, secret, mainnet option, snapshot schedule, deployment instruction, or
external network endpoint.

The image is pinned to the approved v7.1.8 linux/amd64 digest:

```
offchainlabs/prysm-beacon-chain@sha256:49f8454eb2a756402eb781025e370eef7d613668c2914bad4cca9c1aa11fafa4
```

## Prerequisites outside this overlay

The T-3 base manifests establish the `node-operator` namespace, restricted Pod
Security labels, and default-deny policy. They must be present alongside this
overlay. This directory intentionally does not include them because the base
has no Kustomize entrypoint and this task's ownership is limited to
`deploy/prysm/**`.

The workload requires nodes labelled `node-operator.io/network=hoodi` and
`node-operator.io/role=consensus` in either approved Seoul availability zone.
Its anti-affinity rule prevents colocation with a pod labelled
`app.kubernetes.io/name=nethermind` on a hostname.

`prysm-hoodi-gp3-kms` requests 500 GiB gp3 at 6,000 IOPS and 250 MiB/s, with
EBS encryption and the alias made by the T-2 baseline. The real build step must
confirm that alias in its approved account before any apply; this task performs
no AWS access.

The default-deny boundary permits DNS and only P2P (TCP/UDP 13000) or HTTPS
(TCP 443) connections to labelled, controlled egress-gateway pods. The gateway,
its destination allowlist, and any external exposure are intentionally outside
this workload. Without that gateway, the client remains safely unable to reach
Hoodi peers or HTTPS resources.
