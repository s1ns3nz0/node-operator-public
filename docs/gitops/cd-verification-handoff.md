# GitOps CD verification hand-off

The GitOps repository owns promotion. The current application revision is a
chart version tag, so it is not yet a digest-bound CD subject despite the
repository README saying otherwise. No CD workflow currently proves Argo
`Synced` and `Healthy` after a promotion, and no DAST run has occurred.

The GitOps-repository change must add one private-runner workflow with this
ordered, fail-closed contract:

1. accept exactly one `sha256:<64-hex>` OCI chart digest and approved Argo
   Application name/namespace;
2. obtain short-lived AWS credentials only through GitHub OIDC and an
   environment-protected role limited to `eks:DescribeCluster` plus the
   Kubernetes read access needed for that one Application;
3. wait for that Application's observed revision to equal the supplied digest,
   and require both `Synced` and `Healthy` before any probe;
4. validate and execute the private DAST contract only against a disposable
   read-only health service; persist a digest-bound summary, never captures;
5. upload Argo and DAST summaries together and fail the workflow on any
   timeout, revision mismatch, unhealthy state, or DAST rejection.

The runner role, its CodeBuild project, private subnet/security-group path,
and GitHub environment protection are deployment resources. Creating or
running them needs a distinct authorization; this hand-off is not an apply or
deployment instruction.
