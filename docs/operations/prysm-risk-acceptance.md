# Prysm residual vulnerability acceptance

User authorization: first remediate all feasible findings. If Prysm-required
libraries cannot safely be fixed, a documented residual-risk exception may
permit the build. This is not a blanket waiver for other images, toolchains,
operating-system packages, scanner failures, or missing evidence.

The default remains zero Critical/High findings. Preserve the original scan
and severity counts; never relabel an accepted finding as fixed or a clean
scan. Every unmatched, expired, or unassessed finding continues to block.

Before proposing an exception, attempt a supported upgrade, minimal dependency
patch and an alternative runtime where applicable. Record actual build/test
failures or upstream compatibility evidence, not merely scanner `wont-fix`
labels. A passing build alone does not demonstrate that an upgrade is safe.

Each PR requesting an exception must attach:

- Exact image digest, source/patch revisions, SBOM and unfiltered scan with
  scanner version and vulnerability database timestamp.
- Vulnerability identifiers and aliases, affected package/version, severity,
  upstream advisory links and the available fix or reason none is usable.
- Runtime applicability, entry point, attack prerequisites and impact on
  signing, custody, consensus duties and availability. Unknown reachability
  must be stated as unknown, not claimed to be unreachable.
- Remediation attempts and reproducible test results.
- Implemented compensating controls with validation evidence, their limits,
  and remaining risk. Private networking or non-root execution alone is not
  proof of mitigation.
- A per-finding accept/reject decision, accountable integration reviewer,
  the user's delegated authorization, expiry date (at most 30 days), and a
  concrete upgrade/removal action. Reassess on image, dependency, exploit or
  advisory change, and when a compatible fix becomes available.

Report the outcome as `passed-with-exceptions`, separately from clean `passed`.
Build acceptance does not bypass mTLS identity, single-validator fencing,
slashing protection, custody or live readiness gates. A credible unmitigated
key-disclosure or duplicate-signing path remains a stop condition requiring
an explicit decision about that concrete risk.

Current status: no finding has been accepted yet. Existing generic release
gates remain unchanged; any automated exception path must be scoped to Prysm,
match exact findings and image digest, check expiry and fail closed on missing
evidence before it is used.
