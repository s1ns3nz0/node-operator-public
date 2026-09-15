# CodeBuild signer input and output contract

This is the implemented code contract for the private CodeBuild signer. The
Terraform project remains disabled by default: `enable_release_signer=false`,
`enable_release_signer_ecr_mirror=false`, and `release_signer_image=""`
create no signer resources. It does not claim
that a signer image has been published, that Terraform has been applied, or
that a private runner, Vault route, and dynamic identity are live.

## Immutable signer input

The release runner creates exactly one immutable source archive for a source
revision. Its S3 object key is SHA-named:

```
s3://<input-bucket>/release-input/sha256/<source-revision>.zip
```

`<source-revision>` is the full immutable Git commit SHA recorded in
`provenance-input.json`. The archive is written once under the release-input
prefix and must not use a mutable location such as `bootstrap.zip`, a branch,
or a tag. The archive root contains exactly these reviewed files:

```
node-operator-release-bundle.tar
node-operator-release-bundle.sha256
provenance-input.json
buildspec-release-sign.yml
```

The checksum file must bind the bundle bytes, and the provenance subject and
source revision must bind the same bundle and Git SHA. The reviewed
`buildspec-release-sign.yml` is carried in that archive. CodeBuild must select
that archive-local buildspec explicitly; no hidden project-level, external
S3, branch, or tag buildspec is permitted.

The CodeBuild invocation uses that same `<input-bucket>` and exact
`release-input/sha256/<source-revision>.zip` value for its S3 source-location
override. The source-version is the S3 VersionId read from that exact object,
not the Git SHA. This binds CodeBuild to the immutable stored object version
while the archive key and provenance continue to bind the Git revision. A
mismatch among the archive key, source-location override, object version,
bundle checksum, or provenance source revision fails the release.

The private signer role has `GetObjectVersion` only under `release-input/*`,
plus bucket-scoped `ListBucketVersions` required by CodeBuild source selection.
It receives no object-version write or delete permission.

The upload uses S3's `If-None-Match: *` precondition, so a SHA-named archive
cannot silently overwrite an existing input object. The project source has a
deliberately unusable placeholder location and can run only with the exact
source-location override above; its archive-local buildspec is
`buildspec-release-sign.yml`. If the object already exists, the runner reads
and compares the reviewed archive members before reusing its immutable S3
version; it cannot replace the input.

## Verification output and consumer gate

CodeBuild reads only the declared source archive and produces a single ZIP
output package named `release-signer-output.zip`, under a build-ID namespace.
It contains the four non-secret files needed by the existing release
verification gate:

```
node-operator-release-bundle.tar
node-operator-release-bundle.sha256
provenance-input.json
release-verification.json
```

`release-verification.json` must bind the bundle digest, provenance-file
digest and subject digest, source revision, and builder identity. Its evidence
also includes the CodeBuild build ID. The release consumer extracts this
package and calls `scripts/ci/verify-release-signature.sh` on the complete
directory. It gates
on `release-verification.json`, not raw `signature.json` or `verify.json`.
Raw signature/verification response files, Vault tokens, static credentials,
and key material are never output artifacts. The verifier accepts the
format-bound Transit signature inside `release-verification.json` only as the
non-secret evidence required to prove that Vault verified the payload.

The selected CodeBuild container image must be a digest, never a tag-only
reference. It must be the same-account private ECR repository created by the
separate ECR mirror contract in `ap-northeast-2`; GHCR is never a private
CodeBuild runtime dependency.

## Activation preconditions

The repository code already implements the archive, project, and consumer
portions of this contract.
Runtime activation is an approved atomic change after plan review. It must set
`enable_release_signer=true` together with
`enable_release_signer_ecr_mirror=true`, a same-account ECR `...@sha256:<digest>`
`release_signer_image`, and one or more
explicit private `release_signer_subnet_ids`; Terraform rejects an enabled
project without those inputs. Terraform `aws_codebuild_project` and
`release-bundle.yml` input archive packaging already implement the reviewed source,
output, and consumer fields. Runtime activation must also satisfy all of the
following:

1. The reviewed digest-pinned signer image is published and available to the
   private CodeBuild runtime.
2. The private runner, Vault route, and dynamic identity preconditions are
   live and independently verified.
3. Terraform is separately reviewed and applied with the required enablement
   inputs; the workflow's existing OIDC-to-AWS role is reviewed against that
   deployed project.

No static credentials, raw Transit response artifacts, or public Vault
endpoint are introduced by this code contract.
