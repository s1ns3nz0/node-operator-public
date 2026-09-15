package nodeoperator.decision

import rego.v1

decision := {"violations": violations, "summary": {"block": count([v | some v in violations; v.class == "block"]), "warn": count([v | some v in violations; v.class == "warn"]), "require_approval": count([v | some v in violations; v.class == "require-approval"])}}

violations contains violation if {
  tool := data.nodeoperator.config.required_evidence[_]
  object.get(object.get(input, "evidence", {}), tool, null) == null
  violation := finding("evidence.missing", "block", sprintf("required %s evidence is missing", [tool]), tool, sprintf("evidence.%s", [tool]))
}

violations contains violation if {
  format := object.get(object.get(input, "evidence", {}), "format", {})
  object.get(format, "status", "") != "passed"
  violation := finding("format.failed", "block", "formatting evidence did not pass", object.get(format, "check", "format"), "evidence.format")
}

violations contains violation if {
  terraform := object.get(object.get(input, "evidence", {}), "terraform", {})
  status := object.get(terraform, "status", "")
  not status in {"passed", "not_applicable"}
  violation := finding("terraform.validation", "block", "offline Terraform validation did not pass", "terraform", "evidence.terraform")
}

violations contains violation if {
  scm_incomplete
  violation := finding("scm.incomplete", "block", "pull-request posture evidence is missing or malformed", "scm", "scm")
}

violations contains violation if {
  tool := data.nodeoperator.config.required_evidence[_]
  result := object.get(object.get(input, "evidence", {}), tool, null)
  result != null
  evidence_incomplete(tool, result)
  violation := finding("evidence.incomplete", "block", sprintf("required %s evidence is incomplete or malformed", [tool]), tool, sprintf("evidence.%s", [tool]))
}

violations contains violation if {
  item := object.get(object.get(object.get(input, "evidence", {}), "gitleaks", {}), "findings", [])[_]
  violation := finding("secret.detected", "block", "secret detection finding reported", object.get(item, "path", "unknown"), "evidence.gitleaks")
}

violations contains violation if {
  item := object.get(object.get(object.get(input, "evidence", {}), "semgrep", {}), "findings", [])[_]
  violation := finding("sast.semgrep", "block", "Semgrep finding reported", object.get(item, "rule_id", "unknown"), "evidence.semgrep")
}

violations contains violation if {
  item := object.get(object.get(object.get(input, "evidence", {}), "checkov", {}), "failed_checks", [])[_]
  not checkov_exception_applies(item)
  violation := finding("iac.checkov", "block", object.get(item, "check_name", "IaC policy failure"), object.get(item, "resource", "unknown"), "evidence.checkov")
}

violations contains violation if {
  vulnerability := object.get(object.get(object.get(input, "evidence", {}), "osv", {}), "vulnerabilities", [])[_]
  upper(object.get(vulnerability, "severity", "")) == "CRITICAL"
  violation := finding("vulnerability.critical", "block", "Critical vulnerability reported", object.get(vulnerability, "package", "unknown"), "evidence.osv")
}

violations contains violation if {
  vulnerability := object.get(object.get(object.get(input, "evidence", {}), "osv", {}), "vulnerabilities", [])[_]
  upper(object.get(vulnerability, "severity", "")) == "HIGH"
  object.get(vulnerability, "fix_available", false)
  violation := finding("vulnerability.high-fix", "block", "High vulnerability has an available fix", object.get(vulnerability, "package", "unknown"), "evidence.osv")
}

violations contains violation if {
  vulnerability := object.get(object.get(object.get(input, "evidence", {}), "osv", {}), "vulnerabilities", [])[_]
  severity := upper(object.get(vulnerability, "severity", ""))
  severity in {"MEDIUM", "LOW"}
  violation := finding("vulnerability.review", "warn", sprintf("%s vulnerability reported", [severity]), object.get(vulnerability, "package", "unknown"), "evidence.osv")
}

violations contains violation if {
  vulnerability := object.get(object.get(object.get(input, "evidence", {}), "osv", {}), "vulnerabilities", [])[_]
  upper(object.get(vulnerability, "severity", "")) == "HIGH"
  not object.get(vulnerability, "fix_available", false)
  violation := finding("vulnerability.review", "warn", "HIGH vulnerability reported without an available fix", object.get(vulnerability, "package", "unknown"), "evidence.osv")
}

violations contains violation if {
  item := object.get(object.get(object.get(input, "evidence", {}), "zizmor", {}), "findings", [])[_]
  not exception_applies("workflow.unsafe", object.get(item, "path", "unknown"), object.get(item, "rule_id", "unknown"))
  violation := finding("workflow.unsafe", "block", object.get(item, "message", "unsafe workflow finding"), object.get(item, "path", "unknown"), "evidence.zizmor")
}

violations contains violation if {
  exception := object.get(object.get(input, "policy", {}), "exceptions", [])[_]
  invalid_exception(exception)
  violation := finding("exception.invalid", "block", "exception must include rule, subject, owner, rationale, issue, and an unexpired RFC3339 expiry within 30 days", object.get(exception, "subject", "unknown"), "policy.exceptions")
}

violations contains violation if {
  sensitive_change
  author := object.get(object.get(object.get(input, "scm", {}), "pull_request", {}), "author", "")
  author != ""
  approver := object.get(object.get(input, "scm", {}), "approvers", [])[_]
  approver == author
  violation := finding("review.self-approval", "block", "pull request author cannot approve a sensitive-path change", author, "scm.approvers")
}

violations contains violation if {
  sensitive_change
  not "fjybjinsu" in object.get(object.get(input, "scm", {}), "approvers", [])
  violation := finding("review.sensitive-path", "require-approval", "sensitive-path change requires @fjybjinsu approval", "sensitive-path", "scm.approvers")
}

# Release evidence is deliberately opt-in at the input boundary: PR evidence
# has no artifact object, while every build/release evaluation must provide one.
# Once that object is present, every release claim below is fail-closed.
violations contains violation if {
  release_context
  release_evidence_missing
  violation := finding("release.posture.missing", "block", "required repository posture evidence is missing", "posture", "evidence.posture")
}

violations contains violation if {
  release_context
  not valid_artifact_digest(release_digest)
  violation := finding("release.subject.invalid", "block", "release subject must identify one immutable sha256 artifact digest", "artifact", "subject.artifact_digest")
}

violations contains violation if {
  release_context
  posture_incomplete
  violation := finding("release.posture.incomplete", "block", "repository posture evidence is incomplete or malformed", "posture", "evidence.posture")
}

violations contains violation if {
  release_context
  posture_complete
  posture_drifted
  violation := finding("release.posture.drift", "block", "repository posture has drifted from the required baseline", "posture", "evidence.posture")
}

violations contains violation if {
  release_context
  artifact_evidence_missing("sbom")
  violation := finding("release.sbom.missing", "block", "SBOM evidence is missing", "sbom", "artifact.sbom")
}

violations contains violation if {
  release_context
  sbom_incomplete
  violation := finding("release.sbom.incomplete", "block", "SBOM evidence is incomplete or malformed", "sbom", "artifact.sbom")
}

violations contains violation if {
  release_context
  sbom_complete
  not sbom_matches_subject
  violation := finding("release.sbom.digest-mismatch", "block", "SBOM digest does not match the release subject", "sbom", "artifact.sbom")
}

violations contains violation if {
  release_context
  artifact_evidence_missing("signature")
  violation := finding("release.signature.missing", "block", "signature evidence is missing", "signature", "artifact.signature")
}

violations contains violation if {
  release_context
  signature_incomplete
  violation := finding("release.signature.incomplete", "block", "signature evidence is incomplete or malformed", "signature", "artifact.signature")
}

violations contains violation if {
  release_context
  signature_complete
  object.get(release_signature, "status", "") != "verified"
  violation := finding("release.signature.unverified", "block", "artifact signature is not verified", "signature", "artifact.signature")
}

violations contains violation if {
  release_context
  signature_complete
  not signature_matches_subject
  violation := finding("release.signature.digest-mismatch", "block", "signature digest does not match the release subject", "signature", "artifact.signature")
}

violations contains violation if {
  release_context
  artifact_evidence_missing("provenance")
  violation := finding("release.provenance.missing", "block", "provenance evidence is missing", "provenance", "artifact.provenance")
}

violations contains violation if {
  release_context
  provenance_incomplete
  violation := finding("release.provenance.incomplete", "block", "provenance evidence is incomplete or malformed", "provenance", "artifact.provenance")
}

violations contains violation if {
  release_context
  provenance_complete
  object.get(release_provenance, "status", "") != "verified"
  violation := finding("release.provenance.unverified", "block", "artifact provenance is not verified", "provenance", "artifact.provenance")
}

violations contains violation if {
  release_context
  provenance_complete
  not subject_digest_in_provenance
  violation := finding("release.provenance.digest-mismatch", "block", "provenance subject digest does not match the release subject", "provenance", "artifact.provenance")
}

violations contains violation if {
  release_context
  provenance_complete
  object.get(release_provenance, "source_commit", "") != release_commit_sha
  violation := finding("release.provenance.source-mismatch", "block", "provenance source commit does not match the release subject", "provenance", "artifact.provenance")
}

violations contains violation if {
  release_context
  provenance_complete
  not object.get(release_provenance, "builder_id", "") in data.nodeoperator.config.trusted_builder_ids
  violation := finding("release.provenance.untrusted-builder", "block", "provenance builder is not trusted for release eligibility", object.get(release_provenance, "builder_id", "unknown"), "artifact.provenance")
}

violations contains violation if {
  release_context
  artifact_evidence_missing("scan")
  violation := finding("release.scan.missing", "block", "artifact scan evidence is missing", "scan", "artifact.scan")
}

violations contains violation if {
  release_context
  scan_incomplete
  violation := finding("release.scan.incomplete", "block", "artifact scan evidence is incomplete or malformed", "scan", "artifact.scan")
}

violations contains violation if {
  release_context
  scan_complete
  scan_stale
  violation := finding("release.scan.stale", "block", "artifact vulnerability scan is older than the allowed maximum age", "scan", "artifact.scan")
}

violations contains violation if {
  release_context
  scan_complete
  scan_has_critical_findings
  violation := finding("release.scan.critical", "block", "artifact scan reported critical vulnerabilities", "scan", "artifact.scan")
}

sensitive_change if {
  path := object.get(object.get(input, "scm", {}), "changed_files", [])[_]
  prefix := data.nodeoperator.config.sensitive_path_prefixes[_]
  startswith(path, prefix)
}

release_context if {
  is_object(object.get(input, "artifact", null))
}

release_evidence_missing if {
  required := data.nodeoperator.config.release_required_evidence[_]
  object.get(object.get(input, "evidence", {}), required, null) == null
}

release_posture := object.get(object.get(input, "evidence", {}), "posture", null)

posture_incomplete if {
  not release_evidence_missing
  not is_object(release_posture)
}

posture_incomplete if {
  is_object(release_posture)
  not is_number(object.get(release_posture, "scorecard_score", null))
}

posture_incomplete if {
  is_object(release_posture)
  score := object.get(release_posture, "scorecard_score", -1)
  score < 0
}

posture_incomplete if {
  is_object(release_posture)
  score := object.get(release_posture, "scorecard_score", 11)
  score > 10
}

posture_incomplete if {
  is_object(release_posture)
  not is_string(object.get(release_posture, "status", null))
}

posture_incomplete if {
  is_object(release_posture)
  field := ["branch_protection", "commit_signing", "workflow_pinning"][_]
  not is_boolean(object.get(release_posture, field, null))
}

posture_complete if {
  not posture_incomplete
}

posture_drifted if {
  object.get(release_posture, "status", "") != "passed"
}

posture_drifted if {
  field := ["branch_protection", "commit_signing", "workflow_pinning"][_]
  object.get(release_posture, field, false) != true
}

posture_drifted if {
  object.get(release_posture, "scorecard_score", 0) < data.nodeoperator.config.minimum_scorecard_score
}

release_artifact := object.get(input, "artifact", {})
release_sbom := object.get(release_artifact, "sbom", null)
release_signature := object.get(release_artifact, "signature", null)
release_provenance := object.get(release_artifact, "provenance", null)
release_scan := object.get(release_artifact, "scan", null)
release_digest := object.get(object.get(input, "subject", {}), "artifact_digest", "")
release_commit_sha := object.get(object.get(input, "subject", {}), "commit_sha", "")

artifact_evidence_missing(name) if {
  object.get(release_artifact, name, null) == null
}

valid_artifact_digest(value) if {
  is_string(value)
  regex.match("^sha256:[0-9a-f]{64}$", value)
}

valid_commit_sha(value) if {
  is_string(value)
  regex.match("^[0-9a-f]{40}$", value)
}

sbom_incomplete if {
  not artifact_evidence_missing("sbom")
  not is_object(release_sbom)
}

sbom_incomplete if {
  is_object(release_sbom)
  object.get(release_sbom, "status", "") != "complete"
}

sbom_incomplete if {
  is_object(release_sbom)
  not object.get(release_sbom, "format", "") in {"cyclonedx-json", "spdx-json"}
}

sbom_incomplete if {
  is_object(release_sbom)
  not is_number(object.get(release_sbom, "component_count", null))
}

sbom_incomplete if {
  is_object(release_sbom)
  object.get(release_sbom, "component_count", -1) < 0
}

sbom_incomplete if {
  is_object(release_sbom)
  not valid_artifact_digest(object.get(release_sbom, "artifact_digest", ""))
}

sbom_complete if {
  not sbom_incomplete
}

sbom_matches_subject if {
  valid_artifact_digest(release_digest)
  object.get(release_sbom, "artifact_digest", "") == release_digest
}

signature_incomplete if {
  not artifact_evidence_missing("signature")
  not is_object(release_signature)
}

signature_incomplete if {
  is_object(release_signature)
  not valid_artifact_digest(object.get(release_signature, "artifact_digest", ""))
}

signature_incomplete if {
  is_object(release_signature)
  not is_array(object.get(release_signature, "identities", null))
}

signature_incomplete if {
  is_object(release_signature)
  is_array(object.get(release_signature, "identities", null))
  count(object.get(release_signature, "identities", [])) == 0
}

signature_incomplete if {
  is_object(release_signature)
  some identity in object.get(release_signature, "identities", [])
  not valid_signature_identity(identity)
}

valid_signature_identity(identity) if {
  is_object(identity)
  is_string(object.get(identity, "subject", null))
  object.get(identity, "subject", "") != ""
  is_string(object.get(identity, "issuer", null))
  object.get(identity, "issuer", "") != ""
}

signature_complete if {
  not signature_incomplete
}

signature_matches_subject if {
  valid_artifact_digest(release_digest)
  object.get(release_signature, "artifact_digest", "") == release_digest
}

provenance_incomplete if {
  not artifact_evidence_missing("provenance")
  not is_object(release_provenance)
}

provenance_incomplete if {
  is_object(release_provenance)
  not is_array(object.get(release_provenance, "subject_digests", null))
}

provenance_incomplete if {
  is_object(release_provenance)
  is_array(object.get(release_provenance, "subject_digests", null))
  count(object.get(release_provenance, "subject_digests", [])) == 0
}

provenance_incomplete if {
  is_object(release_provenance)
  some digest in object.get(release_provenance, "subject_digests", [])
  not valid_artifact_digest(digest)
}

provenance_incomplete if {
  is_object(release_provenance)
  field := ["status", "builder_id", "build_type", "source_commit"][_]
  not is_string(object.get(release_provenance, field, null))
}

provenance_incomplete if {
  is_object(release_provenance)
  field := ["builder_id", "build_type"][_]
  object.get(release_provenance, field, "") == ""
}

provenance_incomplete if {
  is_object(release_provenance)
  not valid_commit_sha(object.get(release_provenance, "source_commit", ""))
}

provenance_complete if {
  not provenance_incomplete
}

subject_digest_in_provenance if {
  valid_artifact_digest(release_digest)
  release_digest in object.get(release_provenance, "subject_digests", [])
}

scan_incomplete if {
  not artifact_evidence_missing("scan")
  not is_object(release_scan)
}

scan_incomplete if {
  is_object(release_scan)
  object.get(release_scan, "status", "") != "completed"
}

scan_incomplete if {
  is_object(release_scan)
  object.get(release_scan, "complete", false) != true
}

scan_incomplete if {
  is_object(release_scan)
  not is_string(object.get(release_scan, "scanned_at", null))
}

scan_incomplete if {
  is_object(release_scan)
  not valid_rfc3339(object.get(release_scan, "scanned_at", ""))
}

scan_incomplete if {
  is_object(release_scan)
  not is_number(object.get(release_scan, "age_seconds", null))
}

scan_incomplete if {
  is_object(release_scan)
  age := object.get(release_scan, "age_seconds", -1)
  age < 0
}

scan_incomplete if {
  is_object(release_scan)
  not is_object(object.get(release_scan, "findings", null))
}

scan_incomplete if {
  is_object(release_scan)
  severity := ["critical", "high", "medium", "low", "unknown"][_]
  not is_number(object.get(object.get(release_scan, "findings", {}), severity, null))
}

scan_complete if {
  not scan_incomplete
}

scan_stale if {
  object.get(release_scan, "age_seconds", 0) > data.nodeoperator.config.maximum_scan_age_seconds
}

scan_has_critical_findings if {
  object.get(object.get(release_scan, "findings", {}), "critical", 0) > 0
}

valid_rfc3339(value) if {
  is_string(value)
  time.parse_rfc3339_ns(value)
}

scm_incomplete if {
  scm := object.get(input, "scm", null)
  not is_object(scm)
}

scm_incomplete if {
  scm := object.get(input, "scm", {})
  is_object(scm)
  not is_array(object.get(scm, "changed_files", null))
}

scm_incomplete if {
  scm := object.get(input, "scm", {})
  is_object(scm)
  not is_array(object.get(scm, "approvers", null))
}

scm_incomplete if {
  scm := object.get(input, "scm", {})
  is_object(scm)
  object.get(object.get(scm, "pull_request", {}), "head_sha", "") != object.get(object.get(input, "subject", {}), "commit_sha", "")
}

evidence_array_fields := {
  "gitleaks": "findings",
  "osv": "vulnerabilities",
  "semgrep": "findings",
  "zizmor": "findings",
  "checkov": "failed_checks",
}

evidence_incomplete(tool, result) if {
  evidence_array_fields[tool]
  not is_object(result)
}

evidence_incomplete(tool, result) if {
  is_object(result)
  field := evidence_array_fields[tool]
  not is_array(object.get(result, field, null))
}

invalid_exception(exception) if {
  required := ["rule", "check_id", "subject", "owner", "rationale", "issue", "expires_at"][_]
  not object.get(exception, required, "")
}

invalid_exception(exception) if {
  not valid_exception_expiry(exception)
}

valid_exception_expiry(exception) if {
  expiry := object.get(exception, "expires_at", null)
  is_string(expiry)
  parsed := time.parse_rfc3339_ns(expiry)
  is_number(parsed)
}

invalid_exception(exception) if {
  expires_at := time.parse_rfc3339_ns(object.get(exception, "expires_at", ""))
  expires_at <= time.now_ns()
}

invalid_exception(exception) if {
  expires_at := time.parse_rfc3339_ns(object.get(exception, "expires_at", ""))
  expires_at > time.now_ns() + data.nodeoperator.config.exception_maximum_ttl_hours * 3600000000000
}

exception_applies(rule, subject, check_id) if {
  exception := object.get(object.get(input, "policy", {}), "exceptions", [])[_]
  not "file_path" in object.keys(exception)
  exception.rule == rule
  exception.subject == subject
  exception.check_id == check_id
  not invalid_exception(exception)
}

checkov_exception_applies(item) if {
  exception_applies("iac.checkov", object.get(item, "resource", "unknown"), object.get(item, "check_id", "unknown"))
}

checkov_exception_applies(item) if {
  exception := object.get(object.get(input, "policy", {}), "exceptions", [])[_]
  exception.rule == "iac.checkov"
  exception.subject == item.resource
  exception.check_id == item.check_id
  canonical_exception_path(exception.file_path)
  exception.file_path == item.file_path
  not invalid_exception(exception)
}

canonical_exception_path(path) if {
  is_string(path)
  path != ""
  not startswith(path, "/")
  not contains(path, "\\")
  every component in split(path, "/") {
    component != ""
    component != "."
    component != ".."
  }
}

invalid_exception(exception) if {
  "file_path" in object.keys(exception)
  not canonical_exception_path(exception.file_path)
}

finding(id, class, reason, subject, evidence_ref) := {"id": id, "class": class, "reason": reason, "subject": subject, "evidence_ref": evidence_ref}
