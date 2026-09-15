# External supply-chain workflows

The repository uses two narrowly scoped external controls:

* `repository-posture.yml` runs the official OpenSSF Scorecard action on the
  trusted `main` source, on a weekly schedule, and by manual dispatch. It
  publishes SARIF to code scanning and archives a bounded JSON envelope. The
  job has no repository write permission; its OIDC permission is only for the
  Scorecard result publication.
* `release-bundle.yml` invokes GitHub's `actions/attest-build-provenance`
  action for the exact release tarball. The resulting SLSA provenance is
  tied to the workflow run and artifact digest and is generated only during
  release verification/publication paths.

All third-party actions are pinned to immutable commit SHAs. Scorecard posture
is evidence for merge/release policy; it is not a replacement for SBOM,
Cosign signature, vulnerability, or artifact-digest checks. SLSA provenance is
similarly consumed with the existing exact-source and exact-digest gates.
