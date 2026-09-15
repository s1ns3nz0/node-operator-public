package nodeoperator.decision_test

import rego.v1
import data.nodeoperator.decision

gate_trigger_exception := {"rule":"workflow.unsafe","check_id":"dangerous-triggers","subject":".github/workflows/evidence-gate.yml","owner":"fjybjinsu","rationale":"reviewed trust boundary","issue":"docs/security/workflow-trigger-exception.md#ci-evidence-gate","expires_at":"2026-10-03T00:00:00Z"}

test_gate_trigger_disposition_is_exact if {
  fixture := {"policy":{"exceptions":[gate_trigger_exception]}}
  decision.exception_applies("workflow.unsafe", ".github/workflows/evidence-gate.yml", "dangerous-triggers") with input as fixture
  not decision.exception_applies("workflow.unsafe", ".github/workflows/other.yml", "dangerous-triggers") with input as fixture
  not decision.exception_applies("workflow.unsafe", ".github/workflows/evidence-gate.yml", "untrusted-zizmor-suppression") with input as fixture
  not decision.exception_applies("iac.checkov", ".github/workflows/evidence-gate.yml", "dangerous-triggers") with input as fixture
}

test_gate_trigger_expired_or_malformed_disposition_blocks if {
  every expiry in ["2020-01-01T00:00:00Z", "invalid", null] {
    fixture := {"policy":{"exceptions":[object.union(gate_trigger_exception,{"expires_at":expiry})]}}
    not decision.exception_applies("workflow.unsafe", ".github/workflows/evidence-gate.yml", "dangerous-triggers") with input as fixture
  }
}

test_gate_inline_suppression_is_still_blocked if {
  fixture := object.union(base_input, {"policy":{"exceptions":[gate_trigger_exception]},"evidence":object.union(base_input.evidence,{"zizmor":{"findings":[{"path":"workflow-yaml","rule_id":"untrusted-zizmor-suppression","message":"inline suppression rejected"}]}})})
  result := decision.decision with input as fixture
  result.violations[_].id == "workflow.unsafe"
}
