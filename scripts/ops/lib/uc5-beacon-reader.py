#!/usr/bin/env python3
"""Bounded private Hoodi Beacon readiness read; never queries duties or signs."""
import json, re, select, socket, subprocess, time, urllib.request

NS, POD, GENESIS_ROOT, GENESIS_TIME, VALIDATOR_INDEX = "node-operator", "prysm-beacon-0", "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f", 1742213400, "1559065"

class BeaconReaderError(RuntimeError): pass
KEY = re.compile(r"^0x[0-9a-f]{96}$")
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise BeaconReaderError("private Beacon redirect refused")

class KubectlTransport:
    def pod(self):
        out = subprocess.check_output(["kubectl", "-n", NS, "get", "pod", POD, "-o", "json"], text=True, timeout=25)
        return json.loads(out)
    def start(self, port):
        return subprocess.Popen(["kubectl", "-n", NS, "port-forward", "--address=127.0.0.1", "pod/" + POD, f"{port}:3500"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    def ready(self, process, port):
        deadline = time.monotonic() + 10
        expected = f"Forwarding from 127.0.0.1:{port} -> 3500"
        while time.monotonic() < deadline:
            if process.poll() is not None: raise BeaconReaderError("private Beacon port-forward exited")
            if not select.select([process.stdout], [], [], .2)[0]: continue
            line = process.stdout.readline().strip()
            if line == expected: return True
        raise BeaconReaderError("private Beacon port-forward readiness timed out")
    def get(self, port, path):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"Accept": "application/json"})
        with opener.open(request, timeout=10) as response:
            if response.status != 200 or response.geturl() != request.full_url: raise BeaconReaderError("private Beacon response is invalid")
            raw = response.read(65537)
            if len(raw) > 65536: raise BeaconReaderError("private Beacon response is invalid")
            return json.loads(raw)
    def stop(self, process):
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)

def _uid(pod):
    meta = pod.get("metadata", {}) if isinstance(pod, dict) else {}
    uid = meta.get("uid")
    if meta.get("name") != POD or meta.get("namespace") != NS or not isinstance(uid, str) or not uid: raise BeaconReaderError("private Beacon Pod identity is malformed")
    return uid

def _port():
    sock = socket.socket(); sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]; sock.close(); return port

def read_ready(expected_public_key, transport=None, now_epoch=None, sleep=time.sleep):
    if not isinstance(expected_public_key, str) or KEY.fullmatch(expected_public_key) is None: raise BeaconReaderError("expected validator public key is malformed")
    transport, now_epoch = transport or KubectlTransport(), now_epoch or time.time
    before = _uid(transport.pod()); process = None
    try:
        port = _port(); process = transport.start(port)
        if transport.ready(process, port) is not True: raise BeaconReaderError("private Beacon port-forward readiness is unconfirmed")
        if getattr(process, "poll", lambda: None)() is not None: raise BeaconReaderError("private Beacon port-forward exited")
        # A small distance can briefly appear around slot boundaries even with
        # all three health flags false. Re-observe, never accept that lag as PASS.
        # Keep one owned transport and the original Pod identity across attempts.
        for attempt in range(9):
            genesis = transport.get(port, "/eth/v1/beacon/genesis").get("data", {})
            sync = transport.get(port, "/eth/v1/node/syncing").get("data", {})
            validator = transport.get(port, "/eth/v1/beacon/states/head/validators/" + expected_public_key).get("data", {})
            head_response = transport.get(port, "/eth/v1/beacon/headers/head")
            head = head_response.get("data", {})
            if genesis.get("genesis_validators_root") != GENESIS_ROOT or genesis.get("genesis_time") != str(GENESIS_TIME): raise BeaconReaderError("private Beacon Hoodi genesis mismatch")
            if any(sync.get(key) is not False for key in ("is_syncing", "is_optimistic", "el_offline")): raise BeaconReaderError("private Beacon is not fully synced")
            value = validator.get("validator", {})
            if str(validator.get("index")) != VALIDATOR_INDEX or value.get("pubkey") != expected_public_key or validator.get("status") != "active_ongoing": raise BeaconReaderError("private Beacon validator identity mismatch")
            try: slot, age = int(head.get("header", {}).get("message", {}).get("slot")), int(now_epoch()) - GENESIS_TIME
            except (TypeError, ValueError): raise BeaconReaderError("private Beacon head is malformed") from None
            if head.get("canonical") is not True or head_response.get("execution_optimistic", False) is not False or age < 0 or not max(0, age // 12 - 2) <= slot <= age // 12 + 2: raise BeaconReaderError("private Beacon head is unreasonable")
            if _uid(transport.pod()) != before: raise BeaconReaderError("private Beacon Pod changed during read")
            if getattr(process, "poll", lambda: None)() is not None: raise BeaconReaderError("private Beacon port-forward exited")
            distance = str(sync.get("sync_distance"))
            if distance == "0":
                return {"result": "PASS_PRIVATE_BEACON_READY", "scope": "private Beacon readiness only; not duty evidence", "pod_uid": before, "validator_public_key": expected_public_key, "validator_index": VALIDATOR_INDEX, "head_slot": slot}
            if distance not in ("1", "2") or attempt == 8: raise BeaconReaderError("private Beacon is not fully synced")
            sleep(3)
    except BeaconReaderError: raise
    except Exception as error: raise BeaconReaderError("private Beacon read failed") from error
    finally:
        if process is not None: transport.stop(process)
