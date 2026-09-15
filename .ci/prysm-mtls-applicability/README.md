# Prysm OpenPGP applicability review

GO-2026-5932 affects the unmaintained `golang.org/x/crypto/openpgp`
packages. Module-level scanning flags `golang.org/x/crypto v0.56.0`
even when those packages are absent from the validator build.

This is not a clean scan or a vulnerability waiver. Admission requires the
exact reviewed advisory, an unexpired seven-day review window, no Critical or
High findings, and no other Unknown finding. The immutable linux/amd64 image,
validator binary hash, complete build dependency list, raw scan, and SBOM are
bound in signed evidence. Any affected OpenPGP import fails admission.

The residual assumption is the integrity of the reviewed build and its generated
dependency inventory. Cosign workflow/source binding, digest checks, protected
publication, and separate retained raw evidence support independent review.
Renewal requires a new reviewed manifest and fresh evidence; it is not automatic.
The repository maintainers own that review. Nothing here authorizes activation.

Source: https://pkg.go.dev/vuln/GO-2026-5932
