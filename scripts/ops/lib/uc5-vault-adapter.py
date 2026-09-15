#!/usr/bin/env python3
"""Narrow Vault transport for UC-5 configuration capture and exact role restore.

No KV endpoints, policy writes, bootstrap, retries, redirects or credential
issuance. The caller owns the maintenance guards and root-token lifecycle.
This module does not start a ceremony or modify anything when imported.
"""
import http.client
import importlib.util
import json
import pathlib
import re
import socket
import ssl

SPEC = importlib.util.spec_from_file_location(
    "uc5_role_state", pathlib.Path(__file__).with_name("uc5-runtime-role-state.py"))
STATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATE)
ROLES = frozenset((STATE.RUNTIME_ROLE, STATE.DB_ROLE, STATE.CLIENT_ROLE))
POLICIES = frozenset((STATE.RUNTIME_POLICY, STATE.DB_POLICY, STATE.CLIENT_POLICY))
MAX_RESPONSE = 65536
LOOKUP_SELF = "auth/token/lookup-self"
REVOKE_SELF = "auth/token/revoke-self"
AUDIT_HASH = "sys/audit-hash/validator-socket"
AUDIT_CONFIG = "sys/audit"


class AdapterError(RuntimeError):
    """Only fixed messages leave the credential-bearing transport."""


class TunnelTransport:
    def __init__(self, address, ca_file, server_name, token):
        match = re.fullmatch(r"https://127\.0\.0\.1:(18200|18201)", address)
        if not match or server_name != "vault.vault.svc":
            raise AdapterError("reviewed private Vault tunnel required")
        if not isinstance(token, str) or not 1 <= len(token) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise AdapterError("administrator credential shape invalid")
        if not isinstance(ca_file, (str, pathlib.Path)):
            raise AdapterError("explicit private Vault CA file required")
        ca_path = pathlib.Path(ca_file)
        if not ca_path.is_absolute() or ca_path.is_symlink() or not ca_path.is_file():
            raise AdapterError("private Vault CA must be an absolute regular non-symlink file")
        try:
            self.context = ssl.create_default_context(cafile=str(ca_path))
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            raise AdapterError("Vault CA initialization failed") from None
        self.port = int(match[1])
        self._token = token

    def close(self):
        # Drops this reference only; not secure memory erasure or token revocation.
        self._token = None

    def __call__(self, method, path, payload=None):
        if not ((method == "GET" and path in ROLES | POLICIES | {LOOKUP_SELF, AUDIT_CONFIG} and payload is None) or
                (method == "POST" and path == STATE.RUNTIME_ROLE) or
                (method == "DELETE" and path == STATE.RUNTIME_ROLE and payload is None) or
                (method == "POST" and path == REVOKE_SELF and payload is None) or
                (method == "POST" and path == AUDIT_HASH and payload == {"input": "hoodi-hoodi-example-runtime"})):
            raise AdapterError("Vault operation outside UC-5 configuration boundary")
        if method == "POST" and path == STATE.RUNTIME_ROLE:
            STATE._role(payload)
        if self._token is None:
            raise AdapterError("Vault transport is closed")
        connection = http.client.HTTPSConnection("vault.vault.svc", context=self.context, timeout=15)
        raw_socket = None
        try:
            raw_socket = socket.create_connection(("127.0.0.1", self.port), timeout=15)
            connection.sock = self.context.wrap_socket(raw_socket, server_hostname="vault.vault.svc")
            connection.request(method, "/v1/" + path,
                               body=None if payload is None else json.dumps(payload),
                               headers={"Content-Type": "application/json", "X-Vault-Token": self._token})
            response = connection.getresponse()
            status = response.status
            # Error bodies may contain sensitive details. Do not read or follow.
            if status != 200:
                return status, None
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise AdapterError("Vault response exceeds size limit")
            return status, json.loads(raw)
        except AdapterError:
            raise
        except Exception:
            # Never chain exception objects containing headers or raw responses.
            raise AdapterError("Vault configuration request failed") from None
        finally:
            connection.close()
            if raw_socket is not None:
                raw_socket.close()


class VaultAdapter:
    def __init__(self, transport):
        self.transport = transport

    def _read(self, path, allowed, optional=False):
        if path not in allowed:
            raise AdapterError("Vault read path is not allowlisted")
        status, response = self.transport("GET", path)
        # Only runtime role absence is expected after the later deletion step.
        if status == 404 and optional:
            return None
        if status != 200 or not isinstance(response, dict) or not isinstance(response.get("data"), dict):
            raise AdapterError("Vault configuration read did not succeed")
        return response["data"]

    def read_role(self, path):
        return self._read(path, ROLES, optional=path == STATE.RUNTIME_ROLE)

    def read_policy(self, path):
        value = self._read(path, POLICIES)
        if not isinstance(value.get("policy"), str) or not value["policy"]:
            raise AdapterError("Vault policy response malformed")
        return value["policy"]

    def write_role(self, path, value):
        if path != STATE.RUNTIME_ROLE:
            raise AdapterError("only the fixed runtime role may be restored")
        validated = STATE._role(value)
        status, _ = self.transport("POST", path, validated)
        if status != 204:
            raise AdapterError("runtime role write not acknowledged; readback required")
        # STATE.restore performs exact readback and non-target drift checks.

    def administrator_ready(self):
        status, response = self.transport("GET", LOOKUP_SELF)
        if status != 200 or not isinstance(response, dict) or not isinstance(response.get("data"), dict):
            raise AdapterError("administrator metadata lookup failed")
        if response["data"].get("policies") != ["root"]:
            raise AdapterError("recovery-generated root credential required")
        # Do not retain token id/accessor or copy lookup body into evidence.
        return True

    def delete_runtime_role(self, snapshot):
        """Caller must hold maintenance coordination and pass fresh live guards.

        This pre-read/write/readback sequence is NOT atomic against other admins.
        The caller must mark deletion attempted before invoking this method so
        even a lost HTTP response triggers exact restoration.
        """
        target = STATE._validate_snapshot(snapshot)
        STATE.verify(self, snapshot)
        current = self.read_role(STATE.RUNTIME_ROLE)
        if current is None or STATE._hash(current) != STATE._hash(target):
            raise AdapterError("runtime role drift before deletion")
        status, _ = self.transport("DELETE", STATE.RUNTIME_ROLE)
        if status != 204:
            raise AdapterError("runtime role deletion outcome unconfirmed")
        if self.read_role(STATE.RUNTIME_ROLE) is not None:
            raise AdapterError("runtime role absence not confirmed")
        return True

    def runtime_role_audit_hash(self):
        # Device-specific HMAC permits matching only the known role in audit logs.
        status, response = self.transport("POST", AUDIT_HASH, {"input": "hoodi-hoodi-example-runtime"})
        if status != 200 or not isinstance(response, dict):
            raise AdapterError("runtime role audit hash unavailable")
        value = response.get("data", response)
        value = value.get("hash") if isinstance(value, dict) else None
        if not isinstance(value, str) or re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", value) is None:
            raise AdapterError("runtime role audit hash malformed")
        return value

    def audit_ready(self):
        status, response = self.transport("GET", AUDIT_CONFIG)
        if status != 200 or not isinstance(response, dict):
            raise AdapterError("Vault audit configuration unavailable")
        devices = response.get("data")
        if not isinstance(devices, dict):
            raise AdapterError("Vault audit configuration malformed")
        device = devices.get("validator-socket/")
        if not isinstance(device, dict) or device.get("type") != "socket":
            raise AdapterError("reviewed Vault audit device absent")
        options = device.get("options")
        if (not isinstance(options, dict) or options.get("log_raw") != "false" or
                options.get("socket_type") != "unix" or
                options.get("address") != "/vault/audit/validator-audit.sock"):
            raise AdapterError("Vault audit device differs from reviewed configuration")
        return True

    def revoke_administrator(self):
        status, _ = self.transport("POST", REVOKE_SELF)
        if status != 204:
            raise AdapterError("administrator revocation unconfirmed")
        status, _ = self.transport("GET", LOOKUP_SELF)
        if status != 403:
            raise AdapterError("revoked administrator rejection unconfirmed")
        return "revoked"
