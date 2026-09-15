#!/usr/bin/env python3
# Check objective: Reject invalid mirror targets and input combinations before obtaining AWS credentials.
# Purpose: Validate manual private-ECR mirror target, source digest, destination, and main-branch constraints.
# Inputs: MIRROR_TARGET, SOURCE, DESTINATION, and GITHUB_REF environment variables.
# Outputs: A concise PASS line or a nonzero rejection.
# Side effects: Pure local input validation; no GitHub, AWS, registry, or filesystem mutation.
import os
import re

TARGETS = {"signer", "gitops", "private-dast", "validator-client", "validator-log-collector",
           "validator-runtime", "vault-chart", "cert-manager-chart"}
SOURCED = {"signer", "gitops", "validator-client", "validator-log-collector"}


def validate(target, source, destination, ref):
    if ref != "refs/heads/main":
        raise ValueError("mirror dispatch requires main")
    if target not in TARGETS:
        raise ValueError("unknown mirror target")
    if target in SOURCED:
        if not re.fullmatch(r"[^\s@]+@sha256:[a-f0-9]{64}", source):
            raise ValueError("selected target requires an immutable source digest")
    elif source:
        raise ValueError("selected target uses reviewed repository inputs; omit source")
    if target == "gitops":
        if destination not in {"argocd", "charts", "nodes", "vault", "cert-manager"}:
            raise ValueError("gitops requires an approved destination")
    elif destination not in {"", "none"}:
        raise ValueError("destination is only supported for gitops")


if __name__ == "__main__":
    try:
        validate(os.environ.get("MIRROR_TARGET", ""), os.environ.get("SOURCE", ""),
                 os.environ.get("DESTINATION", ""), os.environ.get("GITHUB_REF", ""))
    except ValueError as error:
        raise SystemExit(str(error)) from None
    print("PASS: mirror input contract; target-specific allowlist checks remain required.")
