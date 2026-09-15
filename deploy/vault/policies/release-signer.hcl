# Applied to the short-lived CodeBuild signer identity.
# The transit key never leaves Vault. The signer can create a signature and
# immediately ask Transit to verify that exact signature; it cannot read,
# export, rotate, or administer the key.
path "transit/sign/node-operator-release" {
  capabilities = ["update"]
}

path "transit/verify/node-operator-release" {
  capabilities = ["update"]
}

# Explicitly do not grant key read/export, delete, rotate, or config access.
