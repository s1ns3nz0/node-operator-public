#!/usr/bin/env python3
"""Render GET-only TLS negative probes; requires stopped client/fence externally."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location(
    "network_probe", Path(__file__).with_name("render-signer-network-probe.py")
)
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)
parser = argparse.ArgumentParser()
parser.add_argument("--validator-set", required=True)
parser.add_argument("--expected-public-key", required=True)
parser.add_argument("--fixture-name", required=True)
args = parser.parse_args()
if not network.SET_RE.fullmatch(args.validator_set) or not network.KEY_RE.fullmatch(args.expected_public_key):
    parser.error("invalid validator identity")
if not re.fullmatch(r"signer-tls-fixture-[a-z0-9]{6,12}", args.fixture_name):
    parser.error("fixture must use the dedicated synthetic-resource prefix")

items = []
for role in ("pre", "badca", "badclient", "post"):
    pod = network.pod(
        f"signer-tls-{role}-{args.validator_set}", args.validator_set,
        args.expected_public_key, "validator-signing-fence", role,
        "success" if role in ("pre", "post") else "TLS rejection",
        "May match fence Service selectors: both real client/fence must be stopped.",
    )
    pod["metadata"]["labels"]["node-operator.io/purpose"] = "signer-tls-probe"
    pod["metadata"]["annotations"]["node-operator.io/control-semantics"] = (
        "Same fixed GET, network labels and image; only CA or client identity differs. "
        "Require successful pre/post controls and unchanged NetworkPolicies."
    )
    if role in ("badca", "badclient"):
        real = f"validator-{args.validator_set}-client-tls"
        client_source = args.fixture_name if role == "badclient" else real
        ca_source = args.fixture_name if role == "badca" else real
        pod["spec"]["volumes"] = [{"name": "client-tls", "projected": {
            "defaultMode": 288,
            "sources": [
                {"secret": {"name": client_source, "items": [
                    {"key": "tls.crt", "path": "tls.crt"},
                    {"key": "tls.key", "path": "tls.key"},
                ]}},
                {"secret": {"name": ca_source, "items": [
                    {"key": "ca.crt", "path": "ca.crt"},
                ]}},
            ],
        }}]
    items.append(pod)
print(json.dumps({"apiVersion": "v1", "kind": "List", "items": items}))
