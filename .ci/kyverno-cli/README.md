# Kyverno CLI 1.19.1 candidate

This is an unbuilt, offline-review candidate for the Linux/amd64 `kubectl-kyverno` binary only. It pins upstream tag `v1.19.1` to commit `40ec788d48bb28d83dbf85538e962a59db9d45c6`, uses Go 1.27.1, and updates the exact upstream etcd client package precondition from v3.6.8 to v3.6.14 through `go get`. It preserves the immutable official v1.19.1 CLI runtime image and replaces only `/ko-app/kubectl-kyverno`. It is not an approved image, SBOM, scan result, publication, or proof that the reported finding is fixed.
