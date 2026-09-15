# Prysm static workload policy

`hardening.rego` validates the rendered, local-only Prysm contract: the
approved v7.1.8 digest, 500 GiB encrypted gp3 storage (6,000 IOPS / 250
MiB/s), execution hardening, probes, Nethermind hostname anti-affinity, and
the absence of world egress.

The fixtures contain no credentials, endpoints, or cluster identifiers. With
OPA and Conftest installed, exercise them locally with:

```sh
opa test --fail-on-empty --ignore fixtures policy
conftest test --all-namespaces --policy policy/prysm policy/tests/fixtures/prysm-secure.yaml
! conftest test --all-namespaces --policy policy/prysm policy/tests/fixtures/prysm-insecure.yaml
```
