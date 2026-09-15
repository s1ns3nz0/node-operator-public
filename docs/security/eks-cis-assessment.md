# EKS CIS assessment

This assessment distinguishes a worker-node prerequisite from full EKS CIS
compliance. Never report skipped, manual, inaccessible or unsupported controls
as passed. A successful kube-bench process exit alone is not a passing assessment.

## Pinned supported profile

The current implementation inventories all 13 node controls from kube-bench
v0.16.0 commit `5c6c22d51b926020e7414e1f1e051851d1a2feff`,
`cfg/eks-1.5.0/node.yaml`. The canonical list is
`policy/data/cis_eks.json`. This is the supported **EKS 1.5.0** profile, not a
claim of coverage for the newer CIS EKS 2.0.0 benchmark.

Upstream candidate Linux/amd64 image:
`docker.io/aquasec/kube-bench@sha256:d2e6f685f16cf71228630305d7d69b1fe0c6cbf42a3275cdfc8a55f5f925bbee`.
This is inspected upstream metadata, not a reviewed private-ECR approval.
Do not run a latest tag or bypass the approved-image path.

## Collection and decision

The eventual approved private node runner must use
`kube-bench run --targets node --benchmark eks-1.5.0 --json` and collect one
report per independently enumerated node. Its node identity, image digest and
cluster context must be bound by the execution evidence. Host PID visibility
and read-only host configuration mounts require a separately reviewed short-lived
runner; no broad cluster-admin or writable host mounts are justified by this check.

For an already collected report, evaluate locally:

```sh
bash scripts/ops/evaluate-eks-cis.sh /absolute/node-report.json actual-node-name /absolute/new-evidence-directory
```

The normalizer checks exact control coverage and statuses, recomputes counts,
and omits audit commands, actual values and raw diagnostic text. OPA blocks
FAIL, WARN, INFO, malformed or incomplete evidence. A pass is explicitly
`eks-worker-node`, never full-cluster compliance. Raw report custody and signed
execution evidence remain separate from the redacted decision.

For complete local inventory coverage, use
`python3 scripts/ops/evaluate-eks-cis-inventory.py --nodes /absolute/nodes.json --region ap-northeast-2 --reports /absolute/reports.json --output /absolute/new-output`.
The report manifest has shape `{"reports":{"node-name":"/absolute/raw.json"}}`.
Missing, extra or duplicate nodes cannot pass, and each normalized assessment
is retained even when another node fails. This mapping is supplied by the caller:
it does not prove where or when a report was produced. Live execution must bind
cluster/node identity, image digest, collection time and report hash before an
aggregate is accepted as deployment evidence. Only trusted collected reports
should enter this local evaluator; its `accepted` field is a policy result,
not proof of fresh benchmark execution.

## Remaining full assessment requirements

- Resolve compatibility of the chosen profile with the deployed EKS version
  and AL2023 node configuration; do not silently fall back to generic Kubernetes.
- Enumerate all node groups/nodes; reject missing-node reports.
- Assess customer-managed IAM, policies, managed services and EKS configuration
  with appropriate AWS/API and manual evidence.
- Record AWS-managed control-plane responsibilities rather than claiming host
  checks on inaccessible AWS control-plane nodes succeeded.
- Archive signed raw/normalized/OPA evidence under the approved access policy;
  rerun after material configuration changes.

No live scan has been performed by adding these files.

References: [AWS host security guidance](https://docs.aws.amazon.com/eks/latest/best-practices/protecting-the-infrastructure.html),
[pinned kube-bench node profile](https://github.com/aquasecurity/kube-bench/blob/5c6c22d51b926020e7414e1f1e051851d1a2feff/cfg/eks-1.5.0/node.yaml),
[CIS benchmark catalog](https://www.cisecurity.org/benchmark/kubernetes).
