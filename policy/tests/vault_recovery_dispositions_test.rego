package nodeoperator.decision_test

import rego.v1
import data.nodeoperator.decision

recovery_exceptions := [e | some e in data.data.exceptions; object.get(e, "file_path", "") == "infra/vault-recovery/main.tf"]

test_recovery_dispositions_exactly_two if {
  count(recovery_exceptions) == 2
  {e.check_id | some e in recovery_exceptions} == {"CKV_AWS_126", "CKV_AWS_283"}
  every e in recovery_exceptions {
    finding := {"resource":e.subject, "check_id":e.check_id, "file_path":e.file_path}
    fixture := {"policy":{"exceptions":[e]}}
    decision.checkov_exception_applies(finding) with input as fixture
    every mutation in [{"file_path":"infra/ops-access/main.tf"}, {"file_path":"infra/terraform/main.tf"}, {"resource":"other"}, {"check_id":"CKV_AWS_111"}, {"file_path":"infra/vault-recovery/../vault-recovery/main.tf"}] {
      not decision.checkov_exception_applies(object.union(finding, mutation)) with input as fixture
    }
    not decision.checkov_exception_applies(object.remove(finding, ["file_path"])) with input as fixture
    not decision.checkov_exception_applies(finding) with input as {"policy":{"exceptions":[object.union(e,{"expires_at":"2020-01-01T00:00:00Z"})]}}
  }
}
