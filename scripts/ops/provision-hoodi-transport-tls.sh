#!/usr/bin/env bash
set -euo pipefail

# Retained only to fail closed for older automation. Creating TLS Kubernetes
# Secrets would bypass the Vault custody boundary. Fresh onboarding uses
# recover-and-onboard-hoodi-validator-keystore.sh; live migration uses
# recover-and-migrate-hoodi-runtime-secrets-to-vault.sh.
printf '%s\n' 'REFUSED: transport TLS Kubernetes Secret provisioning is retired. Use Vault-backed onboarding or live migration.' >&2
exit 65
