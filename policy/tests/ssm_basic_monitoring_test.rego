package nodeoperator.decision_test

import rego.v1
import data.nodeoperator.decision

ssm_exception := {"rule":"iac.checkov","check_id":"CKV_AWS_126","subject":"aws_instance.host","file_path":"infra/ops-access/main.tf","owner":"s1ns3nz0","rationale":"user-selected basic monitoring","issue":"docs/security/ssm-basic-monitoring-disposition.md","expires_at":"2026-10-03T00:00:00Z"}
ssm_finding := {"resource":"aws_instance.host","check_id":"CKV_AWS_126","check_name":"Detailed monitoring","file_path":"infra/ops-access/main.tf"}

test_ssm_exact_path_check_and_resource_match if {
  fixture := {"policy":{"exceptions":[ssm_exception]}}
  decision.checkov_exception_applies(ssm_finding) with input as fixture
  not decision.exception_applies("iac.checkov", "aws_instance.host", "CKV_AWS_126") with input as fixture
}

test_ssm_other_or_missing_identity_never_matches if {
  fixture := {"policy":{"exceptions":[ssm_exception]}}
  every change in [
    {"file_path":"infra/terraform/main.tf"},
    {"file_path":"/infra/ops-access/main.tf"},
    {"file_path":"infra/ops-access/../ops-access/main.tf"},
    {"file_path":""}, {"file_path":null},
    {"resource":"aws_instance.other"}, {"check_id":"CKV_AWS_135"}
  ] {
    not decision.checkov_exception_applies(object.union(ssm_finding, change)) with input as fixture
  }
  not decision.checkov_exception_applies(object.remove(ssm_finding, ["file_path"])) with input as fixture
}

test_ssm_invalid_paths_in_register_fail_closed if {
  every path in ["", null, true, "/infra/ops-access/main.tf", "infra//ops-access/main.tf", "infra/./ops-access/main.tf", "infra/../ops-access/main.tf", "infra\\ops-access\\main.tf"] {
    exception := object.union(ssm_exception, {"file_path":path})
    decision.invalid_exception(exception)
    not decision.checkov_exception_applies(object.union(ssm_finding, {"file_path":path})) with input as {"policy":{"exceptions":[exception]}}
  }
}

test_ssm_wrong_rule_and_expired_exception_block if {
  every change in [{"rule":"workflow.unsafe"}, {"expires_at":"2020-01-01T00:00:00Z"}] {
    not decision.checkov_exception_applies(ssm_finding) with input as {"policy":{"exceptions":[object.union(ssm_exception,change)]}}
  }
}
