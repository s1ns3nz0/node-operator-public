path "sys/generate-root/attempt" {
  capabilities = ["read", "update", "delete"]
}

path "sys/generate-root/update" {
  capabilities = ["update"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}
