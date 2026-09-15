# Local Cilium policy lab

This is an AWS-free, disposable Kind lab for validating the base
`default-deny-ingress-egress` and `allow-dns` policies with a real Cilium
dataplane. It is separate from `node-operator-local`, which retains Kind's
default CNI for general manifest study.

Create the Cilium Kind cluster with the default CNI disabled:

```sh
kind create cluster --name node-operator-cilium --config deploy/local-cilium/kind-config.yaml
```

Install the pinned official Cilium chart into that context. The validation run
used chart version `1.20.1` with digest
`sha256:906ce40d35daad838d12add8a5ba7033e767767f51799a93c7eace2cec9cdc05`.

```sh
helm upgrade --install cilium oci://quay.io/cilium/charts/cilium \
  --version 1.20.1 --namespace kube-system \
  --kube-context kind-node-operator-cilium \
  --set image.pullPolicy=IfNotPresent --set ipam.mode=kubernetes
```

Run the bounded probe:

```sh
scripts/ci/test-local-cilium-policy.sh
```

The probe is digest-pinned, non-privileged, and automatically deleted. It
checks that cluster DNS succeeds while TCP egress to `1.1.1.1:443` fails under
the base policies. It does not start a node client or sync Hoodi.

This lab proves local Cilium enforcement only. It does not validate EKS, the
AWS VPC CNI, EBS/gp3/KMS, Pod Identity, managed-node behavior, or the Prysm and
Nethermind workload-specific controlled-egress policies.
