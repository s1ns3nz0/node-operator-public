package nodeoperator.decision_test

import rego.v1
import data.nodeoperator.decision

base_input := {"subject": {"commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "evidence": {"gitleaks": {"findings": []}, "osv": {"vulnerabilities": []}, "semgrep": {"findings": []}, "zizmor": {"findings": []}, "checkov": {"failed_checks": []}, "format": {"status": "passed", "check": "git-diff-check"}, "terraform": {"status": "not_applicable", "modules": []}}, "policy": {"exceptions": []}, "scm": {"changed_files": ["README.md"], "pull_request": {"author": "s1ns3nz0", "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "approvers": []}}

test_clean_evidence_passes if { decision.decision with input as base_input; decision.decision.summary.block == 0 }
test_missing_evidence_blocks if { result := decision.decision with input as object.remove(base_input, ["evidence"]); result.summary.block == 9 }
test_missing_scm_posture_blocks if { fixture := object.remove(base_input, ["scm"]); result := decision.decision with input as fixture; result.summary.block == 1; result.violations[_].id == "scm.incomplete" }
test_failed_formatting_blocks if { fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"format": {"status": "failed", "check": "git-diff-check"}})}); result := decision.decision with input as fixture; result.summary.block == 1; result.violations[_].id == "format.failed" }
test_failed_terraform_validation_blocks if { fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"terraform": {"status": "failed", "modules": [{"module": "infra", "status": "failed"}]}})}); result := decision.decision with input as fixture; result.summary.block == 1; result.violations[_].id == "terraform.validation" }
test_incomplete_sca_evidence_blocks if { fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"osv": {"vulnerabilities": "malformed"}})}); result := decision.decision with input as fixture; result.summary.block == 1; result.violations[_].id == "evidence.incomplete" }
test_secret_blocks if { fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"gitleaks": {"findings": [{"path": "config.env"}]}})}); result := decision.decision with input as fixture; result.summary.block == 1 }
test_semgrep_finding_blocks if { fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"semgrep": {"findings": [{"path": "app.js", "rule_id": "nodeoperator.no-eval", "severity": "ERROR"}]}})}); result := decision.decision with input as fixture; result.summary.block == 1; result.violations[_].id == "sast.semgrep" }
test_checkov_iac_failure_blocks if { fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"checkov": {"failed_checks": [{"resource": "aws_s3_bucket.insecure", "check_id": "CKV_AWS_18", "check_name": "S3 bucket access logging must be enabled"}]}})}); result := decision.decision with input as fixture; result.summary.block == 1; result.violations[_].id == "iac.checkov" }
test_unpinned_workflow_blocks if { fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"zizmor": {"findings": [{"path": ".github/workflows/pull-request.yml", "rule_id": "unpinned-uses", "message": "action reference is not pinned to a commit SHA"}]}})}); result := decision.decision with input as fixture; result.summary.block == 1; result.violations[_].id == "workflow.unsafe" }
test_workflow_exception_requires_exact_path_and_rule if {
  exception := {"rule": "workflow.unsafe", "check_id": "dangerous-triggers", "subject": ".github/workflows/ci-review-refresh-handler.yml", "owner": "fjybjinsu", "rationale": "trusted review refresh", "issue": "docs/security/workflow-trigger-exception.md#ci-review-refresh", "expires_at": "2026-10-03T00:00:00Z"}
  finding := {"path": ".github/workflows/ci-review-refresh-handler.yml", "rule_id": "dangerous-triggers", "message": "workflow_run trigger"}
  fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"zizmor": {"findings": [finding]}}), "policy": {"exceptions": [exception]}})
  result := decision.decision with input as fixture
  result.summary.block == 0
}
test_workflow_exception_does_not_cover_another_path if {
  exception := {"rule": "workflow.unsafe", "check_id": "dangerous-triggers", "subject": ".github/workflows/ci-review-refresh-handler.yml", "owner": "fjybjinsu", "rationale": "trusted review refresh", "issue": "docs/security/workflow-trigger-exception.md#ci-review-refresh", "expires_at": "2026-10-03T00:00:00Z"}
  finding := {"path": ".github/workflows/attacker.yml", "rule_id": "dangerous-triggers", "message": "workflow_run trigger"}
  fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"zizmor": {"findings": [finding]}}), "policy": {"exceptions": [exception]}})
  result := decision.decision with input as fixture
  result.summary.block == 1
}
test_workflow_exception_does_not_cover_another_rule if {
  exception := {"rule": "workflow.unsafe", "check_id": "dangerous-triggers", "subject": ".github/workflows/ci-review-refresh-handler.yml", "owner": "fjybjinsu", "rationale": "trusted review refresh", "issue": "docs/security/workflow-trigger-exception.md#ci-review-refresh", "expires_at": "2026-10-03T00:00:00Z"}
  finding := {"path": ".github/workflows/ci-review-refresh-handler.yml", "rule_id": "unpinned-uses", "message": "unpinned action"}
  fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"zizmor": {"findings": [finding]}}), "policy": {"exceptions": [exception]}})
  result := decision.decision with input as fixture
  result.summary.block == 1
}
test_critical_vulnerability_blocks if { fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"osv": {"vulnerabilities": [{"package": "example", "severity": "CRITICAL", "fix_available": false}]}})}); result := decision.decision with input as fixture; result.summary.block == 1 }
test_high_without_fix_warns if { fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"osv": {"vulnerabilities": [{"package": "example", "severity": "HIGH", "fix_available": false}]}})}); result := decision.decision with input as fixture; result.summary.warn == 1 }
test_expired_exception_blocks if { fixture := object.union(base_input, {"policy": {"exceptions": [{"rule": "iac.checkov", "check_id": "CKV_AWS_58", "subject": "aws_eks_cluster.private", "owner": "fjy", "rationale": "temporary", "issue": "https://github.com/s1ns3nz0/node-operator/issues/1", "expires_at": "2020-01-01T00:00:00Z"}]}}); result := decision.decision with input as fixture; result.summary.block == 1 }
test_checkov_exception_requires_matching_id_and_resource if {
  exception := {"rule": "iac.checkov", "check_id": "CKV_AWS_58", "subject": "aws_eks_cluster.private", "owner": "fjy", "rationale": "bounded", "issue": "docs/security/checkov-kms-eks-exception-register.md#eks-001", "expires_at": "2026-09-30T00:00:00Z"}
  finding := {"resource": "aws_eks_cluster.private", "check_id": "CKV_AWS_58", "check_name": "EKS encryption"}
  fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"checkov": {"failed_checks": [finding]}}), "policy": {"exceptions": [exception]}})
  result := decision.decision with input as fixture
  result.summary.block == 0
}
test_checkov_exception_does_not_match_another_check_id if {
  exception := {"rule": "iac.checkov", "check_id": "CKV_AWS_58", "subject": "aws_eks_cluster.private", "owner": "fjy", "rationale": "bounded", "issue": "docs/security/checkov-kms-eks-exception-register.md#eks-001", "expires_at": "2026-09-30T00:00:00Z"}
  finding := {"resource": "aws_eks_cluster.private", "check_id": "CKV_AWS_356", "check_name": "different finding"}
  fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"checkov": {"failed_checks": [finding]}}), "policy": {"exceptions": [exception]}})
  result := decision.decision with input as fixture
  result.summary.block == 1
  result.violations[_].id == "iac.checkov"
}
test_checkov_exception_does_not_match_another_resource if {
  exception := {"rule": "iac.checkov", "check_id": "CKV_AWS_58", "subject": "aws_eks_cluster.private", "owner": "fjy", "rationale": "bounded", "issue": "docs/security/checkov-kms-eks-exception-register.md#eks-001", "expires_at": "2026-09-30T00:00:00Z"}
  finding := {"resource": "aws_eks_cluster.other", "check_id": "CKV_AWS_58", "check_name": "different resource"}
  fixture := object.union(base_input, {"evidence": object.union(base_input.evidence, {"checkov": {"failed_checks": [finding]}}), "policy": {"exceptions": [exception]}})
  result := decision.decision with input as fixture
  result.summary.block == 1
  result.violations[_].id == "iac.checkov"
}
test_sensitive_change_requires_secondary_approval if { fixture := object.union(base_input, {"scm": {"changed_files": ["policy/decision.rego"], "pull_request": {"author": "s1ns3nz0"}, "approvers": []}}); result := decision.decision with input as fixture; result.summary.require_approval == 1 }
test_sensitive_change_rejects_self_approval if { fixture := object.union(base_input, {"scm": {"changed_files": ["policy/decision.rego"], "pull_request": {"author": "s1ns3nz0"}, "approvers": ["s1ns3nz0"]}}); result := decision.decision with input as fixture; result.summary.block == 1 }
