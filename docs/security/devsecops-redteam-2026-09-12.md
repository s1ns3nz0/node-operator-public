# DevSecOps pipeline red-team report

**Date:** 2026-09-12
**Framework:** DoD DevSecOps Activities & Tools Guidebook v2.5, NIST SP 800-218 SSDF v1.1, and NIST SP 800-204D

## HIGH severity (0)

The required workflows have explicit permissions, all third-party Actions are
commit-SHA pinned, security scans are not globally allowed to pass on failure,
and release publication is gated by eligibility plus reproducibility. No static
High/Critical pattern was found by the repository red-team contract.

## MEDIUM severity (0 after remediation)

The OPA evaluation step intentionally retains a rejected policy decision so that
redacted evidence can be published. The same job always runs the exact-SHA
`publish-pr-evidence-check.sh` status, which fails the required check on any
rejected or missing decision. The new red-team contract keeps these two halves
coupled.

## LOW / accepted boundaries

- Private runtime post-deployment observations are an explicitly authorized
  `CI Operations` task because GitHub-hosted runners cannot reach the private
  EKS API. The scripts are read-only and record validator duty evidence.
- Existing immutable GitOps ECR mirrors retain AWS-managed AES256 until a
  separately approved repository migration; no secret material is published.

## Passing controls

- DEVELOP: full-history Gitleaks and review/branch-protection evidence.
- BUILD: pinned toolchains, Semgrep/gosec SAST, OSV/Grype dependency checks,
  CycloneDX SBOM generation, and image input digests.
- TEST: unit/contract/regression tests and isolated Fence DAST.
- RELEASE: go/no-go eligibility, reproducible bundle, SBOM SCA with Critical /
  High / Unknown rejection, Cosign signature and SLSA provenance.
- DELIVER: immutable private ECR mirrors, OIDC-scoped publishers, digest
  equality checks, and retained non-sensitive evidence.
- DEPLOY: guarded private-EKS staging, Vault/Kyverno/Terraform contracts, and
  read-only post-deployment validator/Beacon/signing observations.

## NIST mapping

| Control | Evidence | Status |
|---|---|---|
| SP 800-204D §5.1.1 secure build | SHA-pinned actions/tools, SBOM and reproducibility gates | PASS |
| SP 800-204D §5.1.2 repository operations | explicit permissions, OIDC, immutable digest mirrors | PASS |
| SP 800-204D §5.1.3 evidence integrity | Cosign/SLSA attestations, exact-SHA OPA evidence, retention | PASS |
| SP 800-204D §5.1.4 secure commits | full-history secret scan, review signal, protected checks | PASS |
| SSDF PO/PS/PW/RV | CI red-team contract plus existing scanner and release gates | PASS |

The authoritative NIST publication is [SP 800-204D](https://csrc.nist.gov/pubs/sp/800/204/d/final).
