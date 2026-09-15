package nodeoperator.decision_test

import rego.v1
import data.nodeoperator.decision

release_digest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
release_builder := "https://github.com/Attestations/GitHubHostedActions@v1"

release_base_input := object.union(base_input, {
  "subject": object.union(base_input.subject, {"artifact_digest": release_digest}),
  "evidence": object.union(base_input.evidence, {
    "posture": {
      "status": "passed",
      "scorecard_score": 10,
      "branch_protection": true,
      "commit_signing": true,
      "workflow_pinning": true,
    },
  }),
  "artifact": {
    "sbom": {
      "status": "complete",
      "format": "cyclonedx-json",
      "component_count": 1,
      "artifact_digest": release_digest,
    },
    "signature": {
      "status": "verified",
      "artifact_digest": release_digest,
      "identities": [{"subject": "https://github.com/s1ns3nz0/node-operator", "issuer": "https://token.actions.githubusercontent.com"}],
    },
    "provenance": {
      "status": "verified",
      "subject_digests": [release_digest],
      "builder_id": release_builder,
      "build_type": "https://slsa.dev/provenance/v1",
      "source_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
    "scan": {
      "status": "completed",
      "complete": true,
      "scanned_at": "2026-09-01T00:00:00Z",
      "age_seconds": 60,
      "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
    },
  },
})

release_result(fixture) := result if {
  result := decision.decision with input as fixture
}

release_with_evidence(evidence) := {
  "subject": release_base_input.subject,
  "evidence": evidence,
  "policy": release_base_input.policy,
  "scm": release_base_input.scm,
  "artifact": release_base_input.artifact,
}

release_with_artifact(artifact) := {
  "subject": release_base_input.subject,
  "evidence": release_base_input.evidence,
  "policy": release_base_input.policy,
  "scm": release_base_input.scm,
  "artifact": artifact,
}

test_release_clean_evidence_passes if {
  result := release_result(release_base_input)
  result.summary.block == 0
}

test_release_invalid_subject_digest_blocks if {
  fixture := object.union(release_base_input, {"subject": object.union(release_base_input.subject, {"artifact_digest": "sha256:not-a-digest"})})
  result := release_result(fixture)
  result.violations[_].id == "release.subject.invalid"
}

test_release_missing_posture_blocks if {
  fixture := release_with_evidence(object.remove(release_base_input.evidence, ["posture"]))
  result := release_result(fixture)
  result.violations[_].id == "release.posture.missing"
}

test_release_posture_drift_blocks if {
  drifted := object.union(release_base_input.evidence.posture, {"workflow_pinning": false})
  fixture := object.union(release_base_input, {"evidence": object.union(release_base_input.evidence, {"posture": drifted})})
  result := release_result(fixture)
  result.violations[_].id == "release.posture.drift"
}

test_release_missing_sbom_blocks if {
  fixture := release_with_artifact(object.remove(release_base_input.artifact, ["sbom"]))
  result := release_result(fixture)
  result.violations[_].id == "release.sbom.missing"
}

test_release_incomplete_sbom_blocks if {
  incomplete := object.union(release_base_input.artifact.sbom, {"component_count": -1})
  fixture := object.union(release_base_input, {"artifact": object.union(release_base_input.artifact, {"sbom": incomplete})})
  result := release_result(fixture)
  result.violations[_].id == "release.sbom.incomplete"
}

test_release_sbom_digest_mismatch_blocks if {
  mismatched := object.union(release_base_input.artifact.sbom, {"artifact_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"})
  fixture := object.union(release_base_input, {"artifact": object.union(release_base_input.artifact, {"sbom": mismatched})})
  result := release_result(fixture)
  result.violations[_].id == "release.sbom.digest-mismatch"
}

test_release_missing_signature_blocks if {
  fixture := release_with_artifact(object.remove(release_base_input.artifact, ["signature"]))
  result := release_result(fixture)
  result.violations[_].id == "release.signature.missing"
}

test_release_unverified_signature_blocks if {
  unverified := object.union(release_base_input.artifact.signature, {"status": "failed"})
  fixture := object.union(release_base_input, {"artifact": object.union(release_base_input.artifact, {"signature": unverified})})
  result := release_result(fixture)
  result.violations[_].id == "release.signature.unverified"
}

test_release_signature_digest_mismatch_blocks if {
  mismatched := object.union(release_base_input.artifact.signature, {"artifact_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"})
  fixture := object.union(release_base_input, {"artifact": object.union(release_base_input.artifact, {"signature": mismatched})})
  result := release_result(fixture)
  result.violations[_].id == "release.signature.digest-mismatch"
}

test_release_missing_provenance_blocks if {
  fixture := release_with_artifact(object.remove(release_base_input.artifact, ["provenance"]))
  result := release_result(fixture)
  result.violations[_].id == "release.provenance.missing"
}

test_release_provenance_digest_mismatch_blocks if {
  mismatched := object.union(release_base_input.artifact.provenance, {"subject_digests": ["sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]})
  fixture := object.union(release_base_input, {"artifact": object.union(release_base_input.artifact, {"provenance": mismatched})})
  result := release_result(fixture)
  result.violations[_].id == "release.provenance.digest-mismatch"
}

test_release_provenance_source_mismatch_blocks if {
  mismatched := object.union(release_base_input.artifact.provenance, {"source_commit": "cccccccccccccccccccccccccccccccccccccccc"})
  fixture := object.union(release_base_input, {"artifact": object.union(release_base_input.artifact, {"provenance": mismatched})})
  result := release_result(fixture)
  result.violations[_].id == "release.provenance.source-mismatch"
}

test_release_untrusted_builder_blocks if {
  untrusted := object.union(release_base_input.artifact.provenance, {"builder_id": "https://example.invalid/untrusted-builder"})
  fixture := object.union(release_base_input, {"artifact": object.union(release_base_input.artifact, {"provenance": untrusted})})
  result := release_result(fixture)
  result.violations[_].id == "release.provenance.untrusted-builder"
}

test_release_missing_scan_blocks if {
  fixture := release_with_artifact(object.remove(release_base_input.artifact, ["scan"]))
  result := release_result(fixture)
  result.violations[_].id == "release.scan.missing"
}

test_release_incomplete_scan_blocks if {
  incomplete := object.union(release_base_input.artifact.scan, {"status": "not_run", "complete": false})
  fixture := object.union(release_base_input, {"artifact": object.union(release_base_input.artifact, {"scan": incomplete})})
  result := release_result(fixture)
  result.violations[_].id == "release.scan.incomplete"
}

test_release_stale_scan_blocks if {
  stale := object.union(release_base_input.artifact.scan, {"age_seconds": 86401})
  fixture := object.union(release_base_input, {"artifact": object.union(release_base_input.artifact, {"scan": stale})})
  result := release_result(fixture)
  result.violations[_].id == "release.scan.stale"
}

test_release_critical_scan_finding_blocks if {
  critical := object.union(release_base_input.artifact.scan, {"findings": {"critical": 1, "high": 0, "medium": 0, "low": 0, "unknown": 0}})
  fixture := object.union(release_base_input, {"artifact": object.union(release_base_input.artifact, {"scan": critical})})
  result := release_result(fixture)
  result.violations[_].id == "release.scan.critical"
}
