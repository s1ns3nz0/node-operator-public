#!/usr/bin/env python3
"""Fixed Hoodi UC-5 preflight and user-recovery ceremony entrypoint.

This never activates the client/Fence or declares UC-5 complete. Only the
companion interactive recovery wrapper may provide the administrator token.
"""
import argparse
import importlib.util
import json
import os
import pathlib
import stat
import sys
import uuid

LIB = pathlib.Path(__file__).resolve().parent / "lib"
# Public on-chain BLS identity, not an API credential or signing secret.
VALIDATOR_PUBLIC_IDENTITY = "0xa3866b82651039224bfd725fc81e7ff17c1765021dff37f3fd4bc01405e2ed14c97c7c5c82cd95104d8f82c4229ab0d0"
STAGE = "arguments"

def load(name):
    spec = importlib.util.spec_from_file_location(name, LIB / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def read_evidence(directory, name):
    """Read fixed operator-owned evidence, never follow file/dir symlinks."""
    if name not in {"ceremony-outcome.json", "kubernetes-baseline.json", "continuity-gates.json", "history-before.json"}:
        raise RuntimeError("unrecognized evidence file")
    directory = pathlib.Path(directory)
    if not directory.is_absolute(): raise RuntimeError("absolute evidence directory required")
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise RuntimeError("unsafe evidence directory")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                    stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 262144):
                raise RuntimeError("unsafe evidence file")
            raw = handle.read(262145)
            if len(raw) > 262144: raise RuntimeError("evidence exceeds limit")
            return json.loads(raw)
    finally:
        os.close(parent)

def main():
    global STAGE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("preflight", "execute", "cleanup-root", "prepare-activation"))
    parser.add_argument("--validator-set", choices=("hoodi-example",), default="hoodi-example")
    parser.add_argument("--evidence-dir", type=pathlib.Path)
    parser.add_argument("--ceremony-dir", type=pathlib.Path)
    args = parser.parse_args()
    if os.environ.get("PRIVATE_VAULT_SESSION") != "1":
        parser.error("the reviewed private Vault session is required")
    if args.mode != "cleanup-root" and args.evidence_dir is None:
        parser.error("--evidence-dir is required")
    control_module = load("uc5-kube-control")
    probes_module = load("uc5-probes")
    reader = load("uc5-audit-reader")
    beacon = load("uc5-beacon-reader")
    adapter = load("uc5-vault-adapter")
    transport, api = None, None
    ceremony_entered = False
    try:
        if args.mode in ("execute", "cleanup-root"):
            if os.environ.get("UC5_USER_RECOVERY") != "1":
                raise RuntimeError("interactive recovery wrapper required")
            transport = adapter.TunnelTransport(os.environ.get("VAULT_ADDR", ""), os.environ.get("VAULT_CACERT", ""),
                                                os.environ.get("VAULT_TLS_SERVER_NAME", "vault.vault.svc"),
                                                os.environ.get("VAULT_TOKEN", ""))
            api = adapter.VaultAdapter(transport)
            if args.mode == "cleanup-root":
                status, _ = transport("GET", adapter.LOOKUP_SELF)
                # The supplied credential came from this wrapper's ceremony.
                # A failed lookup must not prevent attempting its own cleanup;
                # revoke_administrator requires a subsequent confirmed 403.
                if status != 403: api.revoke_administrator()
                return 0
        control = control_module.Control(str(uuid.uuid4()))
        probes = probes_module.ProbeService(control, VALIDATOR_PUBLIC_IDENTITY, args.evidence_dir,
                    audit_reader=reader.read_records, beacon_reader=beacon.read_ready,
                    audit_hmac_reader=api.runtime_role_audit_hash if api else lambda: None)
        if args.mode == "prepare-activation":
            if args.ceremony_dir is None: raise RuntimeError("completed ceremony directory required")
            if args.evidence_dir.resolve() == args.ceremony_dir.resolve():
                raise RuntimeError("use a distinct activation evidence directory")
            for name in ("history-after.json", "continuity-gates.json", "private-activation-evidence.json", "signer-activation-evidence.json"):
                target = args.evidence_dir / name
                if target.exists() or target.is_symlink(): raise RuntimeError("activation output already exists")
            STAGE = "completed_ceremony_evidence"
            gate = load("uc5-activation-evidence")
            outcome = read_evidence(args.ceremony_dir, "ceremony-outcome.json")
            gate.require_completed_ceremony(outcome)
            baseline = read_evidence(args.ceremony_dir, "kubernetes-baseline.json")
            continuity = read_evidence(args.ceremony_dir, "continuity-gates.json")
            before_history = read_evidence(args.ceremony_dir, "history-before.json")
            gate.require_continuity(continuity, baseline, VALIDATOR_PUBLIC_IDENTITY)
            probes.baseline, probes.absent_at = baseline, continuity["signer_absent_observed_at"]
            STAGE = "post_recovery_continuity"
            collection_complete = False
            try:
                control.acquire_maintenance_lock()
                probes._verify_restored_pod(baseline)
                if list(probes._restored_instance) != continuity["signer_instance"]:
                    raise RuntimeError("recovered signer instance changed")
                probes.verify_continuity(baseline, before_history)
                inputs = probes.activation_inputs
                records = gate.adapt(inputs["beacon"], inputs["tls"], inputs["observed_at"], VALIDATOR_PUBLIC_IDENTITY)
                probes._save("private-activation-evidence.json", records["private_evidence"])
                probes._save("signer-activation-evidence.json", records["signer_evidence"])
                collection_complete = True
            finally:
                ownership = control.reconcile_maintenance_lock()
                if ownership == "owned" and collection_complete:
                    control.release_owned_maintenance_lock()
                elif ownership == "owned":
                    print("INCOMPLETE: uc5-hoodi-example-maintenance marker retained; ceremony_id=" + control.ceremony_id + "; inspect owned diagnostic Pods and continuity failure before recovery. No activation performed.", file=sys.stderr)
            print("PASS: fresh post-recovery activation evidence collected; client/Fence remain stopped. Run the existing activation gate next.")
            return 0
        if args.mode == "preflight":
            state = load("uc5-kube-state")
            STAGE = "baseline_collection"
            baseline = state.collect_baseline(control_module.kubectl, VALIDATOR_PUBLIC_IDENTITY)
            STAGE = "probe_admission"
            probes.preflight(baseline)
            STAGE = "private_beacon_readiness"
            result = beacon.read_ready(VALIDATOR_PUBLIC_IDENTITY)
            STAGE = "preflight_evidence"
            probes._save("preflight.json", {"result": "PASS_NONDESTRUCTIVE_PREFLIGHT", "validator_public_key": VALIDATOR_PUBLIC_IDENTITY,
                          "collected_at_utc": probes_module.utc(), "beacon": result,
                          "runtime_role_checked": False, "uc5_complete": False})
            print("PASS: non-destructive UC-5 admission and private Beacon preflight; no maintenance started.")
            return 0
        STAGE = "action_initialization"
        actions = load("uc5-live-actions").LiveActions(args.evidence_dir, VALIDATOR_PUBLIC_IDENTITY, api, control,
                                                     control_module.kubectl, probes)
        ceremony = load("uc5-ceremony")
        ceremony_entered = True
        STAGE = "ceremony"
        result = ceremony.run(actions)
        if actions.baseline is not None:
            probes._save("kubernetes-baseline.json", actions.baseline)
        probes._save("ceremony-outcome.json", result)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["result"] == "PROBE_COMPLETE" else 1
    finally:
        if api is not None and not ceremony_entered and args.mode == "execute":
            api.revoke_administrator()
        if transport is not None: transport.close()

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit("FAILED: UC-5 stage=" + STAGE + "; raw details withheld.") from None
