# kube-bench EKS node candidate

This directory is a local-only kube-bench `v0.16.0` candidate at source commit
`5c6c22d51b926020e7414e1f1e051851d1a2feff`. It is not an approved image, a
live EKS scan, or a publication claim.

The recipe compiles only the upstream binary using the pinned Go 1.27.1 image
and the upstream locked module graph. It copies the exact upstream EKS 1.5.0
node profile and keeps all 13 node controls. Its entrypoint accepts only:

```text
kube-bench run --targets node --benchmark eks-1.5.0 --json
```

That restriction leaves out generic profile execution. The profile's executable
audits require `/bin/sh`, `/bin/cat`, `stat`, and procps `ps -fC`; it does not
use the upstream generic image's Bash helper, findutils, gcompat, jq, kubectl,
OpenShift compatibility, or OpenSSL path.

The package-pinned local build produced index
`sha256:b8cedabbce26a2f439201ca5cd6a28222dad4b609192c0c8e2d59d7d3488d85f`
and Linux/amd64 manifest
`sha256:5c93168d0f8bdcb45ab2ed0c638c569f791f4d9f5afb0426e17d80d0cc114691`.
Its SBOM/Grype evidence recorded 0 critical, 0 high, and 3 medium findings
with none ignored. This is observation, not image approval.

The Dockerfile now freezes the exact 23-package closure observed through the
local image's APK database. Rebuild and rescan passed with the counts above;
image admission and host-mounted runtime validation remain required before
approval. Local smoke executed all 13 checks but cannot prove EKS compliance:
all 13 failed without required host mounts, and the real OPA evaluator rejected
the report. On the same-wrapper pre-pin candidate an unsupported
master invocation correctly exited 64. Pinning source, base images, and package
versions does not by itself make the build reproducible.
