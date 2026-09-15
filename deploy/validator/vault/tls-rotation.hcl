# Ephemeral recovery policy. It can update only the existing signer TLS record
# using KV-v2 CAS and read only that record's version metadata. It cannot read
# TLS payloads or touch BLS, password, or slashing-protection records.
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/signer-tls" {
  capabilities = ["update"]
}
path "node-operator-runtime/metadata/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/signer-tls" {
  capabilities = ["read"]
}
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/client-tls" {
  capabilities = ["update"]
}
path "node-operator-runtime/metadata/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/client-tls" {
  capabilities = ["read"]
}
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/keystore" { capabilities = ["deny"] }
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/password" { capabilities = ["deny"] }
path "node-operator-runtime/data/validators/hoodi/REPLACE_WITH_VALIDATOR_SET/runtime/slashing-db-password" { capabilities = ["deny"] }
path "transit/*" { capabilities = ["deny"] }
path "auth/*" { capabilities = ["deny"] }
path "sys/*" { capabilities = ["deny"] }
