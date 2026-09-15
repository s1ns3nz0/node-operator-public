# A signer can read only its own rendered inputs. No list permission prevents
# discovery of other validator sets; no delete prevents custody destruction.
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/keystore" {
  capabilities = ["read"]
}
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/password" {
  capabilities = ["read"]
}
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/slashing-db-password" {
  capabilities = ["read"]
}
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/signer-tls" {
  capabilities = ["read"]
}
path "node-operator-runtime/metadata/validators/*" { capabilities = ["deny"] }
path "transit/*" { capabilities = ["deny"] }
path "auth/*" { capabilities = ["deny"] }
path "sys/*" { capabilities = ["deny"] }
