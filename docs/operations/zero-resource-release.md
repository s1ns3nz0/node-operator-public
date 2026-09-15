# Zero-resource release sequence

The release starts without any node-operator cloud resource. Its first phase
uses local Terraform state only to create the encrypted S3 backend and DynamoDB
lock table in `infra/bootstrap-state`. Every later phase must initialize using
the non-secret `backend` output from that root.

The next implementation phase is `foundation-network`: it will own the VPC,
public NAT egress edge, private worker subnets, and the NAT EIP required by
Hoodi peers. The baseline must consume those outputs and must not create a
second VPC or accept an externally supplied NAT ID.

Foundation uses its own encrypted remote key. Copy
`infra/foundation-network/backend.hcl.example` outside the bundle, replace its
placeholders from reviewed bootstrap outputs for bucket, region, lock table,
encryption and CMK, and keep the exact key
`node-operator/foundation-network/terraform.tfstate`. Before a
migration, verify the destination is empty, retain a private backup, compare
canonical content and managed resource IDs, separately review metadata, and
require final no-drift. Never use force-copy. This source support authorizes
no remote initialization, migration, or apply.

## Baseline migration map

The current baseline cannot be switched by replacing only a NAT variable:
`aws_vpc.private`, `aws_subnet.private`, and the private route table are also
used by EKS, VPC endpoints, private runners, and legacy operations access.
The replacement baseline root therefore consumes these non-secret foundation
outputs:

| Consumer | Foundation input | Required boundary |
| --- | --- | --- |
| EKS control plane and system node group | `system_subnet_ids` | no default internet route |
| Hoodi execution/consensus node groups | `hoodi_subnet_ids` | NAT egress only for documented Hoodi ports |
| Interface and S3 endpoints | `vpc_id`, `system_subnet_ids`, `system_route_table_id` | reachable by private platform nodes |
| Private Argo/Vault runners | `vpc_id`, `system_subnet_ids` | no general internet egress |
| Operations access | `vpc_id`, `system_subnet_ids` | separate state; never a baseline dependency |

The old baseline VPC/subnet/route resources and the legacy SSM resources must
remain untouched until the replacement baseline has a reviewed zero-resource
plan. State moves/imports are an explicit maintenance action, not an outcome
of ordinary `apply`.

Destroy testing is intentionally deferred. The state backend itself must be
destroyed last from local state only after every dependent root is empty and
its S3 state object is no longer needed.
