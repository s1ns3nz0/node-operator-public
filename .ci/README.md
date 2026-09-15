# Build and security inputs

This directory contains release inputs, not disposable CI output. Dockerfiles,
patches, source locks, scanner settings and approved digest lists must remain
versioned to reproduce and verify the published images.

| Group | Purpose |
| --- | --- |
| `scanners`, `toolchains` | Pinned CI scanners and reusable build/tool containers |
| `fence-security` | Fence-only SAST and isolated real-process DAST assets |
| `validator-signing-fence`, `vault-audit-relay` | First-party runtime image builds |
| `prysm-*`, `nethermind-runtime`, `web3signer-hardened`, `postgres-runtime` | Client, signer and database builds, including dependency patches |
| `vault-*-hardened`, `vault-runtime-*` | Vault build inputs and vulnerability applicability evidence |
| `validator-*-probe`, `upcheck-python-runtime` | Runtime diagnostic images |
| `validator`, `gitops`, `dast` | Approved image/artifact digests consumed by release and verification scripts |

`Dockerfile.dockerignore` files are per-Dockerfile build-context allowlists;
they are intentionally separate. Do not merge them into a permissive global
ignore file. Some retained recipes document an existing image without an
automatic publisher; lack of a workflow reference alone does not imply disuse.

## Required workflow ownership

- `CI / Policy Rules`: Rego, Terraform policy and rendered manifest tests.
- `CI / Evidence Contracts`: evidence normalization, PR gate and
  baseline filtering contracts, private target contract and suite ownership.
- `CI / Code Quality`: script quality and remaining implementation tests.
- `CI / quality`: compatibility gate requiring Code Quality and Fence Security.

The general CI workflows are consolidated into `ci.yml`. Release
eligibility validates unchanged job names against that exact path. Policy jobs still run
on PRs and main pushes. No signing, scan, approval or release gate is removed.

## English presentation conventions

Workflow display titles use `CI`, `CI <Subject>`, `Release <Artifact>` or
`Mirror <Artifact>`. Job and step names describe the target, such as `Policy
Rules`, `Shell Quality`, or `Release Bundle`, without redundant action prefixes.
These labels do not imply that a step has passed.

Publisher filenames are identity-bound; retain them unless the corresponding
OIDC and signature-verification policies are migrated together. Required check
contexts `quality`, `scanners`, and `CI Evidence Decision` remain unchanged.
`CI` and `CI Evidence Review Signal` are also event-routing identities,
so their exact titles must remain aligned with workflow-run consumers.

Workflow-referenced test, verification and scan entrypoints describe their
scope in an English `Check objective:` header. These comments distinguish
offline contract tests from runtime scans; they are not execution evidence.

See [the CI execution guide](../scripts/ci/README.md) for local suite commands,
orchestration boundaries and workflow filename exceptions.
