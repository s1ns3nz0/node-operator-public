# Copied into a disposable offline test workspace only; never part of the root module.
output "offline_test_kms_key_administrator_policy" {
  value = data.aws_iam_policy_document.kms_key_administrator.json
}

output "offline_test_audit_replica_key_policy" {
  value = data.aws_iam_policy_document.audit_replica_key.json
}
