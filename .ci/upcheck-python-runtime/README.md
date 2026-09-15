# Python health-proxy runtime candidate

This replaces the full ZAP distribution only as the runtime for existing Python
stdlib proxy code. It does not replace the separately scoped DAST scanner.
The official linux/amd64 Python3.14.7 Alpine image is pinned by manifest digest;
OpenSSL and libuuid are upgraded, followed by exact-image scanning. Runtime is
UID1000 and supports read-only execution; server certificates remain verified.

Validated local candidate:
`sha256:fb305627ba331d70f8cc82509a4fae4be858422fd257e170543fbbefcefb9588`.
Grype: C0/H0/M8/L1, ignored0. The source base initially retained libuuid2.42.1
with four High findings; the final package update resolves those findings.
This is not a vulnerability-free claim or an end-to-end proxy check.

The current signer proxy must not be declared healthy after an image-only
change: Web3Signer26.4.2 requires TLS client authentication, and its public
Service now routes through the fence. Preserve that protection and never mount
the validator signing credential into the DAST scanner. Resolve and test the
health contract and NetworkPolicies before a signer-proxy rollout. No image
publication or live changes are performed by this Dockerfile.
