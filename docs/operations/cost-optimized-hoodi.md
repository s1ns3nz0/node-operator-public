# Cost-optimized Hoodi operation

The private EKS API remains private. Compute is split into three managed node
groups. The system pool stays at one node so Argo CD and platform add-ons remain
available; the two Hoodi pools stay at zero while idle:

| Pool | Instance type | Maximum | Purpose |
| --- | --- | --- | --- |
| `node-operator-managed` | `m7i.2xlarge` | 1–3 | Kubernetes system add-ons, Argo CD, Vault, and control-plane-adjacent workloads |
| `node-operator-consensus` | `m7i.2xlarge` | 1 | Prysm Hoodi consensus client |
| `node-operator-execution` | `m7i.4xlarge` | 1 | Nethermind Hoodi execution client |

The system pool must be ready before either client pool and is deliberately not
an idle-shutdown target. Scaling the two Hoodi pools to zero stops their EC2
compute charges, but the system node and retained EBS PVC capacity continue to
incur charges.

## Apply prerequisite

The Terraform apply input must set `hoodi_nat_gateway_id` to the already
approved NAT gateway that is the default route for both private worker
subnets. Terraform only reads that gateway; it does not create or alter public
networking. The dedicated Hoodi security group permits only TCP/443,
TCP/UDP 30303, TCP/UDP 9000 (Hoodi consensus bootnodes), TCP/UDP 13000
(Prysm TCP and QUIC), and UDP 12000 (Prysm discovery) beyond the VPC. Flow
Logs remain enabled.

## Start a Hoodi session

Use the checked-in operator script from a private EKS access path. It requires
an explicit `--yes`, checks only the presence of the externally delivered
Engine-JWT Secret object (never its data), scales the two worker pools, and
waits for both reviewed StatefulSets to become Ready.

```bash
scripts/ops/hoodi-session.sh start --yes
```

Confirm node labels before applying the two StatefulSets:

```bash
kubectl get nodes -L node-operator.io/network,node-operator.io/role
kubectl get pods -n kube-system
```

## Stop a Hoodi session

Scale clients down before worker pools. This does not delete retained EBS
volumes. It leaves the system pool and Argo CD running for a fast resume.

```bash
scripts/ops/hoodi-session.sh stop --yes
```

Terraform ignores operational client-pool `desiredSize` drift so an intervening
plan does not unexpectedly stop an active Hoodi session. The always-on system
pool remains `min=1`, `desired=1`, `max=3` by policy.

## Use the private SSM tunnel only on demand

The private SSM operations host is intentionally disabled by default. Create
it only for the operation window, optionally setting an explicit future
automatic-termination timestamp. It does not start any EKS node group. Stop
or destroy it again after the session ends.

```bash
terraform -chdir=infra/terraform apply \
  -var='enable_temporary_ssm_ops_host=true' \
  -var='temporary_ssm_ops_host_termination_at=2026-09-06T22:00:00'
# Start the SSM port-forward session and finish the required cluster operation.
terraform -chdir=infra/terraform apply \
  -var='enable_temporary_ssm_ops_host=false'
```

Use the normal apply path with the same approved preservation variables used
for creation so Terraform removes the instance and its count-controlled SSM
support resources together. A targeted destroy of only
`aws_instance.temporary_ssm_ops_host` is emergency cleanup only: it leaves the
associated IAM, security-group, endpoint, and optional scheduler resources in
state while `enable_temporary_ssm_ops_host=true`.

Do not terminate Vault PVCs, release-artifact buckets, or the NAT gateway as
part of an idle shutdown. Those are persistent dependencies rather than idle
worker compute.
