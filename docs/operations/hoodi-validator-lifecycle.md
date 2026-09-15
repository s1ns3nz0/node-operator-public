# Hoodi validator lifecycle and evidence

This procedure is for one fresh `hoodi-<identifier>` validator key. It must
not be used with any pre-existing `test-*` custody data.

## UC-1 — fresh key and deposit decision

Create the key in an empty directory outside the repository with a verified
deposit CLI. Keep its mnemonic and keystore password offline. Run
`validate-hoodi-deposit-data.sh` before opening the Hoodi Launchpad; it accepts
only one `hoodi` entry, exactly `32000000000` Gwei, and a type-1 withdrawal
credential derived from the operator-supplied withdrawal address.

The generated attestation contains public information only. The operator must
compare its public key, withdrawal address, credential, and 32 HoodiETH amount
against the Launchpad UI, then sign the transaction with their own wallet. No
repository script connects to a wallet or submits the transaction.

## UC-2 — signer readiness

Use a separate, short-lived Vault onboarding identity for the new set. The
runtime identity must be limited to that set's encrypted keystore, its password,
and the slashing-database credential. It has no list, delete, Transit, CI, or
cross-set capability. Do not promote the test signer: it has a non-persistent
database and explicitly uses PostgreSQL `trust` authentication.

The operational signer requires a retained PostgreSQL volume, database
authentication, a current Web3Signer image review, and a dedicated transport
authentication design compatible with the exact Prysm release. The required
transport gate is intentionally not bypassed by this document.

`deploy/validator/` contains the non-signing namespace, fencing, network, and
storage boundaries. Render `runtime-template.yaml` with
`render-hoodi-validator-runtime.sh` only after supplying reviewed private ECR
digests. The generated signer uses Vault Agent files, `POSTGRES_PASSWORD_FILE`,
a retained PVC, and Web3Signer TLS PKCS#12 files. It never takes a password or
keystore through a manifest, command line, environment value, or Git.

For a fresh set, `prepare-hoodi-validator-deployment.sh` performs both safe
renders in one command and writes a mode-0700 controlled directory containing
the two zero-replica manifests and a non-secret handoff. It does not apply a
manifest, contact Vault, accept custody input, or scale the validator:

```sh
scripts/release/prepare-hoodi-validator-deployment.sh \
  --validator-set hoodi-example \
  --validator-public-key 0x... \
  --withdrawal-address 0x... \
  --aws-account-id <new-aws-account-id> \
  --web3signer-image <new-aws-account-id>.dkr.ecr.ap-northeast-2.amazonaws.com/...@sha256:... \
  --postgres-image <new-aws-account-id>.dkr.ecr.ap-northeast-2.amazonaws.com/...@sha256:... \
  --prysm-validator-image <new-aws-account-id>.dkr.ecr.ap-northeast-2.amazonaws.com/...@sha256:... \
  --signing-fence-image <new-aws-account-id>.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fence@sha256:... \
  --kubernetes-api-cidr <operator-ip>/32 \
  --output-dir /controlled-state/hoodi-example-prepared
```

Before any resource is created, submit the generated manifests for a private
API server-side admission check:

```sh
scripts/release/stage-hoodi-validator-deployment.sh plan \
  --handoff /controlled-state/hoodi-example-prepared/validator-deployment-handoff.json \
  --private-eks-session-handoff /controlled-state/private-eks-session.json
```

After the private-cluster health and the operator's review are accepted, use
the same handoff with `apply`. This creates only the non-secret database
runtime and zero-replica signer, client, and fence controllers. It cannot
initialize Vault, take custody material, or enable signing.

## UC-3 — deposit and activation observation

Record UC-3 evidence after the transaction is visible through the locally
synced beacon node. Continue recording until the validator has an index and an
active status. Network activation timing is determined by Hoodi's queue; do not
infer activation solely from a transaction receipt.

## UC-4 — duties and fencing

Deploy the Prysm validator client only after UC-2 and UC-3. It receives neither
the keystore nor Vault access; it reaches only the in-cluster beacon API and
the reviewed signer endpoint. Its first attestation/proposal evidence and the
active signer lease are recorded with the collector.

After UC-3 returns a validator index, run
`observe-private-hoodi-validator-duties.sh`. It records current-epoch
attester, proposer, and sync-committee assignments from the private Beacon
API. An assignment alone is not proof of a signature: UC-4 closes only when
the assignment, Prysm validator log, Web3Signer audit request ID, and public
history agree. A missing external record is an alert, never a reason to repeat
a signing request.

## UC-5 — interruption and recovery

Revoke signer workload access and fence it first. A signing attempt must fail
closed. Recovery requires a reviewed slashing-history continuity check before
the replacement gets the lease. Never use collected evidence as a substitute
for slashing protection data.

## Evidence collection

For every state change run:

```sh
scripts/ops/collect-hoodi-validator-evidence.sh \
  --phase uc-3 --validator-set hoodi-example \
  --validator-public-key 0x... \
  --output-dir /absolute/audit/hoodi-example
```

The collector stores pod readiness, fence metadata, and bounded Kubernetes
event metadata. It purposefully excludes raw logs because raw application logs
cannot be treated as a safe secret boundary. Logs needed for debugging must be
exported through the approved redacting audit pipeline.
