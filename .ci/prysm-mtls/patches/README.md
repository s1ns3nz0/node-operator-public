# Prysm Web3Signer HTTP mTLS patch

`0001-web3signer-http-mtls.patch` applies to Prysm v7.1.8 commit
`51b5a75ebbadf05af22bd2601b5baf7a9e99b66d`.

It adds dedicated Web3Signer HTTP client certificate, key, and CA flags. The
three values are all-or-none, require an HTTPS endpoint, use TLS 1.2 or newer,
and retain Go's normal DNS/IP hostname verification. These flags are separate
from Prysm's gRPC TLS configuration.

The mTLS HTTP client rejects every redirect. This prevents a signing request
or client certificate from being forwarded to a different endpoint, including
one whose certificate chains to the same configured CA.

Certificates are loaded when the validator process starts. Rotating any of the
three files therefore requires a controlled validator restart with the same
slashing-protection database.

Verification performed against the pinned upstream source:

```text
go test ./validator/keymanager/remote-web3signer/internal
go test ./validator/keymanager/remote-web3signer
go test ./validator/node -run 'TestWeb3SignerConfig' -count=1
git diff --check
```

The transport tests perform synthetic mutual-TLS handshakes and verify that a
hostname mismatch, wrong server CA, untrusted client certificate, and redirect
are rejected. The redirect destination must receive zero requests. No
production certificate, key, endpoint, or request body is included in this
patch.
