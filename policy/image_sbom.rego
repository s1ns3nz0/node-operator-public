package nodeoperator.image_sbom

import rego.v1

# Evaluated only AFTER image_sbom_evidence.py verifies the actual archive/SBOM
# bytes and expected source/image identity. This gate does not verify signatures,
# run SCA, or authorize deployment; those remain separate required controls.
default allow := false

allow if {
    input.schema_version == 1
    input.stage == "build"
    regex.match(`^[a-z0-9][a-z0-9-]{0,62}$`, input.subject)
    regex.match(`^[0-9a-f]{40}$`, input.source_revision)
    regex.match(`^[0-9a-f]{64}$`, input.docker_archive_sha256)
    regex.match(`^[0-9a-f]{64}$`, input.sbom_sha256)
    regex.match(`^sha256:[0-9a-f]{64}$`, input.image_config_digest)
    input.claims == {"signature": false, "registry_manifest_digest": false, "sca": false}
}
