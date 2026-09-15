# Validator observability contract

Every stored lifecycle record uses `evidence-envelope.schema.json`. A record
must have a correlation ID and can contain only public identifiers: validator
public key, validator-set ID, deposit-data hash, deposit transaction hash,
Vault audit request ID, Kubernetes UID, release SHA, explorer URL, timestamp,
and a response hash.

The following values are prohibited in every evidence object, raw-log export,
search index, error report, and CI output: mnemonic, encrypted keystore,
password, token, recovery material, kubeconfig, cloud credential, or any
unredacted Vault request/response value.

The internal Prysm beacon source is authoritative for operational readiness.
Etherscan and Beaconcha.in are asynchronous, public corroboration only. Their
availability must never decide whether validator duties start or stop.
Etherscan V2 (Hoodi chain ID `560048`) confirms only the deposit receipt and
DepositContract event. Beaconcha.in V2 requires a Bearer API token and an
explicit `chain: "hoodi"`; it corroborates public status and duty history only
after an index exists.

`reconcile-hoodi-validator-evidence.sh` turns an identity mismatch, missing
credential, explorer error, or indexing delay into a durable observability
record. It is deliberately not coupled to deployment, fencing, or signing;
only a mismatched identity requires the operator to stop and investigate the
evidence chain.

All timestamps are UTC. `correlation_id` is generated once per lifecycle
change and propagated as a Vault correlation header where supported, Kubernetes
annotation, observer field, and archive object metadata.
