package nodeoperator.image_sbom_test

import rego.v1
import data.nodeoperator.image_sbom

valid := {
    "schema_version": 1, "stage": "build", "subject": "release-build",
    "source_revision": "1111111111111111111111111111111111111111",
    "docker_archive_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "sbom_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "image_config_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "claims": {"signature": false, "registry_manifest_digest": false, "sca": false},
}

test_valid_build_receipt if { image_sbom.allow with input as valid }
test_missing_evidence_denied if { not image_sbom.allow with input as {} }
test_mutable_revision_denied if {
    not image_sbom.allow with input as object.union(valid, {"source_revision": "main"})
}
test_unverified_security_claim_denied if {
    not image_sbom.allow with input as object.union(valid, {"claims": {"signature": true, "registry_manifest_digest": false, "sca": false}})
}
test_other_stage_denied if {
    not image_sbom.allow with input as object.union(valid, {"stage": "deploy"})
}
