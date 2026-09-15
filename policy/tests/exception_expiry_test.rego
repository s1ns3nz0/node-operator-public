package nodeoperator.decision_test

import rego.v1
import data.nodeoperator.decision

test_registered_checkov_exceptions_are_exact_and_current if {
  count(data.data.exceptions) > 0
  every exception in data.data.exceptions {
    not decision.invalid_exception(exception)
    fixture := {"policy":{"exceptions":[exception]}}
    registered_exception_matches(exception) with input as fixture
    not decision.exception_applies(exception.rule, sprintf("%s-other", [exception.subject]), exception.check_id) with input as fixture
    not decision.exception_applies(exception.rule, exception.subject, "CKV_UNREGISTERED") with input as fixture
  }
}

registered_exception_matches(exception) if {
  not "file_path" in object.keys(exception)
  decision.exception_applies(exception.rule, exception.subject, exception.check_id)
}

registered_exception_matches(exception) if {
  "file_path" in object.keys(exception)
  decision.checkov_exception_applies({"resource":exception.subject,"check_id":exception.check_id,"file_path":exception.file_path})
}

test_malformed_expiry_cannot_exempt_checkov if {
  every expiry in ["not-a-date", "2026-99-99T00:00:00Z", 12345, true] {
    exception := {"rule":"iac.checkov", "check_id":"CKV_AWS_136", "subject":"aws_ecr_repository.test", "owner":"reviewer", "rationale":"bounded", "issue":"docs/security/checkov-2026-09-08-disposition.md", "expires_at":expiry}
    finding := {"resource":"aws_ecr_repository.test", "check_id":"CKV_AWS_136", "check_name":"encryption"}
    fixture := object.union(base_input, {"evidence":object.union(base_input.evidence, {"checkov":{"failed_checks":[finding]}}), "policy":{"exceptions":[exception]}})
    result := decision.decision with input as fixture
    result.violations[_].id == "exception.invalid"
    result.violations[_].id == "iac.checkov"
  }
}
