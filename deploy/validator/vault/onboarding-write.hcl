# One-time custody role only. It can create the exact runtime records but never
# read them back, list metadata, use Transit, or administer Vault.
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/keystore" {
  capabilities = ["create", "update"]
}
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/password" {
  capabilities = ["create", "update"]
}
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/slashing-db-password" {
  capabilities = ["create", "update"]
}
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/signer-tls" {
  capabilities = ["create", "update"]
}
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/client-tls" {
  capabilities = ["create", "update"]
}
path "node-operator-runtime/metadata/validators/*" { capabilities = ["deny"] }
path "transit/*" { capabilities = ["deny"] }
path "auth/*" { capabilities = ["deny"] }
path "sys/*" { capabilities = ["deny"] }
