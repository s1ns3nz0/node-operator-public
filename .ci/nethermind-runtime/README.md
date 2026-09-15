# Nethermind 1.39.3 runtime security update

The existing approved application is copied byte-for-byte from its immutable
upstream image into official ASP.NET 10.0.11 resolute-chiseled. No application
source, consensus rule, database format, network configuration or dependency
manifest is rewritten. The final image must be scanned; a base-image scan is
not sufficient.

Upstream [Dockerfile.chiseled](https://github.com/NethermindEth/nethermind/blob/28cbe2a0ae28373f66abdc584f3eaf21516e84b3/Dockerfile.chiseled)
uses `--no-self-contained`. Its old ASP.NET 10.0.10 runtime contains
[GHSA-m93f-wj8c-rp8p](https://github.com/dotnet/runtime/security/advisories/GHSA-m93f-wj8c-rp8p),
fixed by Microsoft in 10.0.11. This is runtime remediation, not a vulnerability
exception or an upgrade to the unrelated Nethermind 2.0 release candidate.

Build with Docker for Linux/amd64. Before publication, compare every regular
file and symlink under `/nethermind` against the original image, verify the
reported application version and both installed .NET runtimes, and scan the
exact final artifact with a valid vulnerability database. Keep the upstream
application's original license files. A passing smoke test does not replace
the retained-volume and private-network restart review before deployment.

Run `scripts/ci/test-nethermind-runtime.sh` for the Docker build, complete
application-directory comparison, runtime/version smoke and final-image scan.
The source and candidate containers are never started during directory
comparison; all execution tests have networking disabled. The test removes
only its owned disposable containers, anonymous volumes and temporary copies.
Set `NETHERMIND_SCAN_OUTPUT` to retain the raw scan at an explicit path.
