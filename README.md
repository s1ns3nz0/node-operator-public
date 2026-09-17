# node-operator

[![CI](https://github.com/s1ns3nz0/node-operator-public/actions/workflows/continuous-integration.yml/badge.svg?branch=main)](https://github.com/s1ns3nz0/node-operator-public/actions/workflows/continuous-integration.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/s1ns3nz0/node-operator-public)](https://github.com/s1ns3nz0/node-operator-public/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/s1ns3nz0/node-operator-public)](https://github.com/s1ns3nz0/node-operator-public/issues)

I run a **Prysm + Nethermind** Hoodi testnet validator on **AWS EKS**. This repo is that setup, treated less like "get a validator running" and more like a security engineering exercise: what talks to what, who holds which key, and what happens if one Pod gets compromised.

![Validator attesting on Hoodi](docs/assets/validator-attestation.png)

## What this is for

Most validator guides get you to a green checkmark and stop there. I wanted to know:

- Where does the signing key actually live, and who can touch it?
- What's the blast radius if the validator client gets popped?
- Can I prove the CI/CD pipeline itself isn't the weak point?

So the install path, the Kubernetes layout, and the CI pipeline are all designed with those questions in mind, not just "does it sync."

## Install

```bash
bash scripts/release/node-operator-install.sh
```

One command, no flags. It reads your AWS CLI profile and Region, verifies the release bundle locally, and only then asks you the handful of things it actually needs.

You'll need: an AWS CLI profile, Docker, and `git`/`jq`/`terraform`/`kubectl`/`python3`/`gh` on your PATH. On macOS it grabs Cosign via Homebrew if you don't have it.

Full teardown and operational notes live in [`docs/operations/release-bootstrap.md`](docs/operations/release-bootstrap.md).

## How keys and certs are handled

The short version: nothing sensitive sits in a plain Kubernetes Secret or on the validator client's disk. Vault owns it all, and every component gets the narrowest slice of Vault it needs to do its one job.

- **Validator keystores** go through a one-time custody ceremony, then live under a KV path scoped to that validator set. The onboarding role can write the keystore, password, and TLS material but can never read them back. The runtime signer role can read, but only its own set's data, and it has no `list` permission, so it can't go fishing for other validator sets.
- **mTLS between the fence and the signer** is two separate Vault-managed certificate paths: `signer-tls` for the signer, `client-tls` for the fence. A `known-clients` allowlist pins exactly which client cert fingerprints the signer trusts, so having *a* valid cert isn't enough on its own.
- **The Engine API JWT** shared by Nethermind and Prysm comes from Vault and gets pulled just-in-time, not baked into a manifest.
- **The slashing-protection DB password** follows the same write-once, read-only pattern, and the validator client itself has zero Vault access. Only the signer and the fence do.
- Every one of these roles explicitly denies `transit/*`, `auth/*`, and `sys/*`. If a workload identity gets compromised, it can't pivot into Vault administration or start signing/decrypting things it has no business touching.
- Vault ships from a pinned, digest-verified Helm release. Unseal and recovery material go through short, explicit ceremonies instead of sitting around in the cluster.

## Security

- [CI/CD controls](docs/security/ci-cd-security-controls.md)
- [Per-control implementation, with code](docs/security/ci-cd-security-control-implementation.md)
- [Threat model](THREAT-MODEL.md)

## More on the design decisions

I wrote up the reasoning behind the harder calls separately, including where I got the priorities wrong the first time:

- [CI/CD Security Controls and Implementation in the Pipeline Design](https://miata.cloud/posts/ci-cd-security-controls-implemented-in-the-pipeline-design/)
- [AWS Infrastructure Overview](https://miata.cloud/posts/hoodi-node-validator-aws-architecture-overview/)
- [Kubernetes Namespace Design for a Hoodi Validator](https://miata.cloud/posts/kubernetes-namespace-design-for-a-hoodi-validator/)
- [Private EKS Security Design Review](https://miata.cloud/posts/securing-a-hoodi-ethereum-testnet-validator-on-aws-eks/)
- [Vault Secret Management for Hoodi Validator](https://miata.cloud/posts/vault-secret-management-for-hoodi-validator/)
- [Cert-manager and Vault: Roles, Scope, and Collaboration](https://miata.cloud/posts/cert-manager-and-vault-roles-scope-and-collaboration/)
- [Prioritizing Security Controls: Hoodi Validator Lessons](https://miata.cloud/posts/prioritizing-security-controls-hoodi-validator-lessons/)

License: [Apache-2.0](LICENSE).
