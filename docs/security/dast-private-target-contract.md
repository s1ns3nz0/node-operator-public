# Private DAST target contract

[`policy/dast/private-target-contract.json`](../../policy/dast/private-target-contract.json)
is a source-only contract, not a DAST result. It does not start a scanner,
contact a cluster, registry, or endpoint.

It permits only a digest-pinned private ECR scanner, a loopback/RFC1918/Kubernetes
service target, and bounded `GET` requests to `/healthz`, `/health`, or
`/metrics`. JSON-RPC, Engine API, validator, Vault, and every mutating HTTP
method are rejected.

Live DAST requires a separate approved task: disposable namespace and service,
proven scanner image, private runner identity, Argo `Synced`/`Healthy` evidence,
redacted summary-only collection, and cleanup. This document grants none of
those runtime permissions.

Run the offline contract check with:

```sh
bash scripts/ci/test-dast-target-contract.sh
```
