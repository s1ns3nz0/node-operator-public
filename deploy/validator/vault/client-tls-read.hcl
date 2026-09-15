# The validator client receives only its own mTLS identity.  It cannot read
# BLS custody, signer server TLS, slashing credentials, or Vault metadata.
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/client-tls" {
  capabilities = ["read"]
}
path "node-operator-runtime/metadata/validators/*" { capabilities = ["deny"] }
path "transit/*" { capabilities = ["deny"] }
path "auth/*" { capabilities = ["deny"] }
path "sys/*" { capabilities = ["deny"] }
