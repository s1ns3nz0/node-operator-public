## Change and verification

Describe the change, executed checks, and remaining deployment gates. Distinguish
local builds/manual publication from CI-attested releases and live validation.

## Prysm residual-risk decision

Select one: not applicable / no exceptions / passed-with-exceptions.

For any unavoidable Prysm library finding, follow
[`docs/operations/prysm-risk-acceptance.md`](../docs/operations/prysm-risk-acceptance.md)
and link a per-finding assessment containing:

- Immutable image digest, source and patch revisions, SBOM, unfiltered scan,
  scanner version and database timestamp. Include ignored/suppressed findings.
- Advisory/package/version/severity, applicability and impact, remediation
  attempts and reproducible test evidence.
- Implemented compensating controls, validation evidence and residual risk.
- Decision, accountable reviewer, delegated authorization, expiry within
  30 days, and concrete remediation follow-up.

Assessment and CI artifact links:

Do not paste credentials, recovery shares, keystores or raw Vault audit data.
Local temporary paths alone are not reviewer-accessible evidence: attach
sanitized artifacts with hashes or link retained CI artifacts before promotion.

Acceptance applies only to the assessed Prysm library finding and exact image.
It does not waive other images, OS findings, failed scanners, missing evidence,
mTLS identity, fencing, slashing protection or live readiness. Retain original
severity counts and label an exception as accepted, never fixed.
