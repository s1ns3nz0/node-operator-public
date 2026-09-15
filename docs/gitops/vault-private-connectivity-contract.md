# Vault private connectivity contract

This is a non-secret operating contract for the connection between private
release infrastructure and the existing Vault service. It is not authorization
to create DNS, routes, load balancers, security groups, NetworkPolicies, or a
cloud endpoint; those actions and their live validation are separately
authorized rollout work.

## Fixed service identity and exposure boundary

The only release-facing Vault name is `vault.node-operator.internal`. Clients
connect to that name over **HTTPS/TCP 8200** only. HTTP, certificate-bypass
(`-k`), raw-IP access, alternate hostnames, public Internet DNS, and a public
endpoint are prohibited. No endpoint address, load-balancer address, hosted
zone identifier, or route target belongs in this repository.

The approved exposure pattern is an **internal gateway or private endpoint**
that fronts the existing Kubernetes `ClusterIP` service. It provides a private
release-facing route without changing that service into a `LoadBalancer`,
`NodePort`, public ingress, or public listener. The endpoint is reachable only
from the approved private runner and private CodeBuild network paths, and is
not a general in-cluster or Internet gateway.

The private hosted zone is split-horizon: its release-network view resolves
`vault.node-operator.internal` to the approved private endpoint, while public
DNS has no record for that name. A resolver must not fall back to public DNS.
The public DNS has no record outside the private hosted-zone view.

## TLS identity and certificate lifecycle

The endpoint presents a certificate from the approved private CA. The
non-secret Kubernetes TLS secret remains `vault-tls`; it is externally
provisioned and contains the server certificate, private key, and CA chain,
but is never stored in Git, Terraform state, CI logs, or release evidence.

The certificate subject/SAN includes exactly
`vault.node-operator.internal` for this release path. Clients set SNI to that
name and validate the complete chain, hostname, key usage, current validity,
and revocation status where the private PKI supports it. The certificate
rotation procedure must preserve a valid overlap between old and new chains,
and an authenticated expiration probe must alert before the agreed renewal
window. An expired certificate, an untrusted CA, a hostname mismatch, or a
failed rotation/expiration probe blocks release signing.

## Separate private routes and least privilege

The self-hosted release runner and CodeBuild are separate sources. Each has a
distinct route, security-group rule, and Kubernetes/mesh policy that permits
only its required egress to `vault.node-operator.internal` on TCP 8200. Neither
path permits `0.0.0.0/0`, general Internet egress, NAT/public fallback, HTTP,
or a route to another Vault port. The runner route is used for GitHub JWT login
and its narrowly scoped dynamic AWS lease. The CodeBuild route is used only by
the signer identity for Vault Transit operations.

Vault admission is defense in depth: network policy and gateway source rules
admit only the Vault pods, approved in-cluster workloads, the runner path, and
the CodeBuild path. Vault then authenticates and authorizes each request using
its distinct JWT, AWS, and Transit policies; source-network access alone never
grants a token or signing permission. Every deny, TLS failure, or policy
mismatch is fail-closed.

Raft is separate from the release API route. TCP 8201 is permitted only between
the Vault server pods required for Raft cluster traffic. It is not exposed by
the private endpoint, runner, CodeBuild, gateway, or any public-facing route.

## Release prerequisites and correlation probes

Before a release credential is requested or a signer build is started, all of
these probes must pass and be retained as non-secret evidence:

1. **DNS probe:** the runner and CodeBuild resolvers each return the approved
   private route for `vault.node-operator.internal`; public DNS returns no
   record and neither resolver uses a public fallback.
2. **TLS probe:** each source completes HTTPS/TCP 8200 with the private CA,
   expected SNI/SAN, and a currently valid certificate; the rotation and
   expiration probes are healthy.
3. **Route probe:** each source can reach only TCP 8200 at the approved
   endpoint, while HTTP, all-address egress, NAT/public fallback, and TCP 8201
   are denied.
4. **Authorization probe:** the runner can exercise only its JWT/login and
   dynamic-lease path, and CodeBuild can exercise only Transit sign/verify;
   an unauthorized source or operation is denied and captured in Vault audit
   records.
5. **Audit correlation probe:** the DNS/TLS/route probe results and Vault audit
   request IDs are linked to the GitHub run, AWS request, and CodeBuild build
   identifiers defined in the private runner contract.

Missing evidence, an unresolved private name, unexpected DNS answer, TLS
failure, route broadening, missing audit correlation, or any failed deny-path
probe prevents the release from continuing. These checks do not authorize a
live rollout; DNS, route, endpoint, load-balancer, security-group, and
NetworkPolicy creation and validation in cloud remain separate authorized
rollout work.
