# Private GitOps evidence reader

The Release Bundle workflow reads reviewed chart evidence from the private
`s1ns3nz0/node-operator-gitops` repository. Its built-in token cannot cross that
repository boundary. Do not copy a developer's GitHub login token into CI.

## One-time owner setup

1. At <https://github.com/settings/apps/new>, register a private GitHub App.
   Use a unique name such as `s1ns3nz0-gitops-evidence-reader`, homepage
   `https://github.com/s1ns3nz0/node-operator`, disable webhooks, and allow
   installation only on your account. No callback URL is needed.
2. Set repository **Actions: Read-only**. Metadata read access is implicit.
   Do not grant Contents write, Administration, Workflows or organization access.
3. Install the App only on `node-operator-gitops` using selected repositories.
4. Generate its private key and retain the PEM locally with mode `0600`.
   Do not paste it into chat, Git, logs or shell command arguments.
5. In Node Operator's `gitops-evidence-reader` Actions environment, store the
   Client ID as `GITOPS_EVIDENCE_APP_CLIENT_ID` and the PEM as the secret
   `GITOPS_EVIDENCE_APP_PRIVATE_KEY`. With the actual values/absolute path:

   ```bash
   gh variable set GITOPS_EVIDENCE_APP_CLIENT_ID --repo s1ns3nz0/node-operator \
     --env gitops-evidence-reader --body '<Client ID>'
   gh secret set GITOPS_EVIDENCE_APP_PRIVATE_KEY --repo s1ns3nz0/node-operator \
     --env gitops-evidence-reader < /absolute/path/to/private-key.pem
   ```

Environment deployment rules must allow only the `main` branch and version
tags matching `v*.*.*`. Tag publication also requires the existing reviewed-main
ancestry and exact-revision release eligibility gate. Do not allow arbitrary
feature branches to obtain the App credential.

## Runtime boundary and rotation

The SHA-pinned token action restricts each token to `node-operator-gitops` and
`actions: read`, and revokes it at job cleanup. The custom token is passed only
to the chart evidence retrieval command, not to other repository operations.
Exact source/run/artifact/hash checks are unchanged. Local CLI retrieval may
use the operator's existing login; Actions fails closed without the App token.

For key rotation, generate a replacement App key, replace the environment
secret from the new PEM, verify one successful bundle run, then revoke the old
key in GitHub App settings. Revoke a compromised key immediately. To disable
access, uninstall the App or revoke its keys; do not weaken evidence validation.

References: [GitHub token scope](https://docs.github.com/en/actions/concepts/security/github_token),
[installation token action](https://github.com/actions/create-github-app-token).
