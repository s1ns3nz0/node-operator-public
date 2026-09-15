# DevSecOps Pipeline Red Team Report

**Date:** 2026-09-10
**Framework:** DoD Guidebook v2.5 + SSDF SP 800-218 + SP 800-204D

Scope: the self-built `cmd/validator-signing-fence` PR and image-release path.
This is a scoped engineering review, not a compliance certification. The retired
`node-operator-dast` namespace is not recreated. No live Vault, Beacon, wallet,
signer credential, or validator key is used by the new dynamic tests.

## 🔴 HIGH Severity (0 unresolved design findings in this scope)

The previously absent static/dynamic gate is addressed by `fence-security.yml`.
Both the existing required `CI Quality / quality` job and the signing-fence
publisher depend on that reusable workflow. Scanner errors must fail closed.
The required quality job uses `always()` and explicitly rejects any dependency
result other than `success`; a failed security job cannot turn the required
check into a silently accepted skipped job.
Execution acceptance remains pending until the exact PR revision passes CI;
source wiring alone is not evidence of a successful scan.

References: DoD Tables 1 and 14; SSDF PO.4.1, PW.7.2, PW.8.2;
SP 800-204D §5.1.1 and §5.1.3.

## 🟡 MEDIUM Severity (2 reviewed source findings)

### M1: G304, configurable service-account token file

- **Document:** SSDF PW.7.2, RV.2.1; SP 800-204D §5.1.1.
- **Current:** `main.go:523` reads the CLI-selected token path. Actual gosec
  v2.22.10 reports MEDIUM G304. An attacker controlling process arguments could
  choose another file readable by the process.
- **Fix/compensation:** keep the reviewed manifest's fixed
  `/var/run/secrets/fence/token` path, read-only projected short-lived token,
  non-root scratch image, read-only root filesystem, and scoped Lease RBAC.
  Network requests cannot select this path. Do not add arbitrary user-provided
  paths to deployment templates. Reassess if CLI configuration becomes remote
  input. The finding remains visible, not suppressed.

### M2: G304, configurable Kubernetes CA file

- **Document:** SSDF PW.7.2, RV.2.1; SP 800-204D §5.1.1.
- **Current:** `main.go:534` reads the CLI-selected CA path. Actual gosec
  v2.22.10 reports MEDIUM G304.
- **Fix/compensation:** reviewed manifests fix the read-only public-CA mount at
  `/var/run/secrets/fence-ca/ca.crt`; malformed PEM is rejected and TLS certificate
  verification stays enabled. A principal able to replace the Pod command or CA
  mount already controls the workload deployment. Retain least-privilege
  deployment RBAC and reviewed manifests. Reassess on any trust-boundary change.

The explicit gate rejects HIGH static findings and HIGH/unknown dynamic risks;
MEDIUM/LOW findings stay in the retained reports for review. This is not a
general exemption for future findings or scanner execution errors.

## 🟢 LOW Severity (0 additional findings)

No additional low-severity source findings were identified in this scoped pass.
ZAP alert counts are determined from each actual run, not assumed here.

## ✅ Passing Controls (design and observed checks)

- Checksum-pinned gosec archive; digest-pinned ZAP and Go builder; SHA-pinned
  checkout, setup-go, and artifact actions (SSDF PO.3.2).
- Ephemeral GitHub runner, checkout credentials disabled, no cloud credentials
  in security jobs. OIDC write permission is limited to the downstream publisher
  (SSDF PW.4.1; SP 800-204D §5.1.2).
- Go unit tests and real-process black-box checks: synthetic mTLS passthrough,
  source-IP mismatch, competing Lease, malformed Lease, and renewal/API outage
  terminating existing connections. Process exit/health unavailability is an
  acceptable fail-closed outcome; a stable HTTP 503 is not required.
- ZAP examines the actual HTTP health listener only. It does not inspect BLS
  correctness or decrypt the TLS passthrough. The black-box cases exercise the
  fence authorization and connection-lifecycle behavior separately.
- Existing image release generates and rescans CycloneDX SBOM, blocks
  critical/high/unknown SCA results, signs the exact digest, attaches provenance
  and scan statements, then authenticates the evidence collector's inputs
  (SSDF PS.2.1, PS.3.2; SP 800-204D §5.1.3).
- Existing repository CI checks secrets with full-history checkout and reviews
  workflow/IaC changes. The fence gate does not replace these controls
  (SSDF PS.1.1; SP 800-204D §5.1.4).
- New security reports, including failure reports when produced, are archived
  for 30 days with source revision and report hashes (SSDF RV.1.1–RV.1.3).
- The DAST fixture has no external network, credentials or Docker socket. ZAP
  shares only that fixture's loopback namespace, not the host network. Its
  writable artifact directory contains synthetic/public test data only.
- No expression-derived shell commands, floating actions, security
  `continue-on-error`, or unrelated production DAST targets are introduced.

## NIST Control Mapping

| Control | SSDF | SP 800-204D | Status |
|---|---|---|---|
| Ownership, IaC and security requirements | PO.1.1, PO.2.1, PO.4.1, PO.5.1 | §5.1.1 | Harness, reviewed manifests, required gates |
| Pinned isolated build tooling | PO.3.1–PO.3.2, PW.4.1 | §5.1.1–§5.1.2 | Pinned; runtime scan acceptance requires CI |
| Static and dynamic tests | PW.7.2, PW.8.1–PW.8.2 | §5.1.1 | Fence-only; actual local black-box/SAST observed |
| Source and dependency protection | PS.1.1, PW.4.4, PW.7.1 | §5.1.4 | Existing secret/SCA/review gates retained |
| Signed release and SBOM | PS.2.1, PS.3.1–PS.3.2, PW.9.1 | §5.1.3 | Existing authenticated release path retained |
| Findings and evidence retention | RV.1.1–RV.1.3, RV.2.1 | §5.1.3 | Reports retained; G304 assessment above |
| Disclosure process | RV.3.1 | — | Repository security process, not changed here |

## Summary

Total scoped source findings: HIGH=0, MEDIUM=2, LOW=0. These counts do not
replace the per-run scanner reports. Final acceptance requires a successful
exact-revision CI run and an independently reviewed change.

Phase coverage (qualitative; percentages would imply an unsupported compliance
score): DEVELOP=review/secret checks; BUILD=pinned builder/SAST;
TEST=unit/black-box/ZAP; RELEASE=SCA/signatures/provenance/required gate;
DELIVER=immutable ECR and retained evidence; DEPLOY=separate existing deployment
workflow. This change does not claim a full DoD lifecycle audit or a newly
implemented continuous post-deployment scanning system.
