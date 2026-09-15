# Private Vault release endpoint

Apply `deploy/vault/release-endpoint.yaml` only after the Vault certificate has
been reissued with `vault.node-operator.internal` in its SAN. The Kubernetes
service controller creates an internal NLB in the tagged private subnets; it
passes TCP 8200 through to the active Vault pod and never exposes TCP 8201.

Create a Route 53 **private** hosted zone for `node-operator.internal`,
associate it only with the node-operator VPC, and create an alias record for
`vault.node-operator.internal` that targets the generated internal NLB. Do
not create a public hosted zone or public record.

Before enabling a signer build, verify DNS resolves only in the VPC, the NLB
is internal, Vault's certificate validates the release hostname, and the
NetworkPolicy has no public CIDR. Do not print certificate, Vault-token, or
private-key material.

The release signer CodeBuild security group permits TCP 8200 only to the
private VPC CIDR for this endpoint. It does not permit internet egress or a
public Vault listener.
