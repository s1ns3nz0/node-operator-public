# node-operator

[![CI](https://github.com/s1ns3nz0/node-operator-public/actions/workflows/continuous-integration.yml/badge.svg?branch=main)](https://github.com/s1ns3nz0/node-operator-public/actions/workflows/continuous-integration.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/s1ns3nz0/node-operator-public)](https://github.com/s1ns3nz0/node-operator-public/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/s1ns3nz0/node-operator-public)](https://github.com/s1ns3nz0/node-operator-public/issues)

A security-first hands-on exercise: running a **Prysm (consensus) + Nethermind (execution)** **Hoodi testnet Ethereum validator** on **AWS EKS**.

![Validator attesting on Hoodi](docs/assets/validator-attestation.png)

## Purpose

- Practice deploying and operating a Hoodi validator on AWS EKS the safe way.
- Treat key custody (Vault), signing protection (Fence), and artifact integrity (Cosign/SBOM) as first-class design constraints, not an afterthought.
- Ship a verifiable CI/CD pipeline so the deployment process itself can be trusted, not just the running system.

## Install

```bash
bash scripts/release/node-operator-install.sh
```

A single, no-argument entrypoint. It detects your AWS CLI profile/Region, verifies a local release bundle, and only then asks for the minimal interactive input needed for deployment.

Prerequisites: an AWS CLI profile, Docker, and `git`/`jq`/`terraform`/`kubectl`/`python3`/`gh`. On macOS, Cosign is installed automatically via Homebrew if missing.

See [`docs/operations/release-bootstrap.md`](docs/operations/release-bootstrap.md) for the full operational boundaries and teardown procedure.

## Key management with Vault

Validator signing keys, TLS material, and JWTs never live in plain Kubernetes Secrets or on the validator client's filesystem. HashiCorp Vault is the single source of truth for all of it:

- **Validator keystores** are onboarded once through a guarded custody ceremony and stored under a validator-set-scoped KV path. Read/write policies are split by role: an onboarding role can only `create`/`update` the keystore, password, and TLS material — it can never read them back; a runtime signer role can only `read` its own set's data, with no `list` permission, so it cannot enumerate other validator sets.
- **mTLS certificates** for the fence↔signer transport are minted and rotated by Vault. The signer's TLS bundle (`signer-tls`) and the fence's client certificate (`client-tls`) are separate Vault paths, injected into their respective Pods at runtime. A `known-clients` allowlist pins which client certificate fingerprints the signer will accept, so possession of *a* valid client cert alone is not enough.
- **The Engine API JWT** shared between Nethermind and Prysm is generated and stored in Vault, not baked into a manifest or environment variable, and is retrieved just-in-time by the client Pods.
- **The slashing-protection database password** follows the same pattern: written once during onboarding, read-only at runtime, and never exposed to the validator client itself (the client has no Vault access at all — only the signer and fence do).
- Every Vault policy explicitly denies `transit/*`, `auth/*`, and `sys/*` for these narrow roles, so a compromised workload identity cannot escalate into Vault administration or use Transit to sign or decrypt unrelated data.
- Vault itself is bootstrapped from a pinned, digest-verified Helm release; unseal/recovery material and generated root tokens are handled through short, explicit ceremonies rather than left resident in the cluster.

In short: **no validator private key, TLS private key, or JWT is ever stored outside Vault**, and each component (onboarding tool, signer, fence, slashing DB) gets the narrowest possible Vault capability for the one secret it actually needs.

## Security

- CI/CD controls: [`docs/security/ci-cd-security-controls.md`](docs/security/ci-cd-security-controls.md)
- Per-control implementation detail: [`docs/security/ci-cd-security-control-implementation.md`](docs/security/ci-cd-security-control-implementation.md)
- Threat model: [`THREAT-MODEL.md`](THREAT-MODEL.md)

## Related write-ups

Design rationale and lessons learned from building this project are written up separately:

- [CI/CD Security Controls and Implementation in the Pipeline Design](https://miata.cloud/posts/ci-cd-security-controls-implemented-in-the-pipeline-design/)
- [AWS Infrastructure Overview](https://miata.cloud/posts/hoodi-node-validator-aws-architecture-overview/)
- [Kubernetes Namespace Design for a Hoodi Validator](https://miata.cloud/posts/kubernetes-namespace-design-for-a-hoodi-validator/)
- [Private EKS Security Design Review](https://miata.cloud/posts/securing-a-hoodi-ethereum-testnet-validator-on-aws-eks/)
- [Vault Secret Management for Hoodi Validator](https://miata.cloud/posts/vault-secret-management-for-hoodi-validator/)
- [Cert-manager and Vault: Roles, Scope, and Collaboration](https://miata.cloud/posts/cert-manager-and-vault-roles-scope-and-collaboration/)
- [Prioritizing Security Controls: Hoodi Validator Lessons](https://miata.cloud/posts/prioritizing-security-controls-hoodi-validator-lessons/)

License: [Apache-2.0](LICENSE).
