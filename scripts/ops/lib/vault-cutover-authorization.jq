# Legacy migration evidence remains distinct from the new activation ceremony.
.secret_values_emitted == false and .source_secrets_retained == true and
((.operation == "live-runtime-secret-migration") or
 (.schema_version == 1 and .operation == "activate-existing-hoodi-vault-v2" and
  .runtime_mount == "node-operator-runtime" and .custody_preserved == true and
  .transport_verified == true and .engine_jwt_verified == true and
  .generated_root_revoked == true and .live_roles_installed == true and .public_trust_config_updated == true and
  .client_and_fence_quiesced == true and .live_workloads_changed == false))
