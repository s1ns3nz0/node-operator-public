#!/usr/bin/env python3
"""A narrow, per-UID egress fence for the isolated recovery host.

DNS is necessarily permitted only to the VPC resolver.  That is not an
application-layer DNS allow-list: software running as the fenced UID can still
ask that resolver arbitrary questions, but it cannot connect to answers other
than the validated KMS addresses, IMDS, or loopback.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import socket
import subprocess
import uuid


class EgressError(RuntimeError):
    """Safe failure: never includes subprocess stdout, stderr, or arguments."""


class EgressGuard:
    """Install and remove only UUID-owned iptables chains for one dedicated UID."""

    UID = 65000
    KMS_HOST = "kms.ap-northeast-2.amazonaws.com"
    KMS_PORT = 443
    KMS_NETWORK = ipaddress.ip_network("10.91.0.0/25")
    VPC_RESOLVER = "10.91.0.2"
    IMDS = "169.254.169.254"
    WAIT_SECONDS = "5"
    COMMAND_TIMEOUT_SECONDS = 15

    def __init__(self, *, require_root: bool = False) -> None:
        self.require_root = require_root
        unique = uuid.uuid4().hex[:20]
        # Linux xtables chain names are short; the random part remains ample
        # while leaving the chain recognizably owned by this guard.
        self.ipv4_chain = f"NOIRG4_{unique}"
        self.ipv6_chain = f"NOIRG6_{unique}"
        self._ipv4_chain_created = False
        self._ipv4_jump_added = False
        self._ipv6_chain_created = False
        self._ipv6_jump_added = False
        self._installed = False

    @staticmethod
    def _failure(message: str, exc: BaseException) -> EgressError:
        return EgressError(message)

    def _iptables(self, binary: str, *arguments: str) -> None:
        if binary not in {"iptables", "ip6tables"}:
            raise EgressError("unsupported firewall command")
        try:
            subprocess.run(
                [binary, "-w", self.WAIT_SECONDS, *arguments], check=True,
                text=True, capture_output=True, timeout=self.COMMAND_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise self._failure("firewall command failed", exc) from exc

    def _ensure_root_and_no_uid_processes(self) -> None:
        if self.require_root and os.geteuid() != 0:
            raise EgressError("egress guard requires a root caller")
        try:
            completed = subprocess.run(
                ["ps", "-eo", "uid="], check=True, text=True,
                capture_output=True, timeout=self.COMMAND_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise self._failure("could not verify dedicated UID is unused", exc) from exc
        try:
            uids = {int(value.strip()) for value in completed.stdout.splitlines() if value.strip()}
        except ValueError as exc:
            raise EgressError("could not verify dedicated UID is unused") from exc
        if self.UID in uids:
            raise EgressError("dedicated recovery UID already has host processes")

    def _validated_kms_addresses(self) -> list[str]:
        try:
            results = socket.getaddrinfo(self.KMS_HOST, self.KMS_PORT, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise EgressError("could not resolve the approved KMS endpoint") from exc
        if not results:
            raise EgressError("approved KMS endpoint resolved to no addresses")
        addresses: list[str] = []
        for _family, _type, _protocol, _canonical_name, sockaddr in results:
            try:
                address = ipaddress.ip_address(sockaddr[0])
            except (IndexError, ValueError) as exc:
                raise EgressError("approved KMS endpoint returned an invalid address") from exc
            if not isinstance(address, ipaddress.IPv4Address) or address not in self.KMS_NETWORK:
                raise EgressError("approved KMS endpoint returned an address outside the private allow-list")
            addresses.append(str(address))
        return sorted(set(addresses))

    def _install_ipv4(self, kms_addresses: list[str]) -> None:
        self._iptables("iptables", "-N", self.ipv4_chain)
        self._ipv4_chain_created = True
        self._iptables("iptables", "-A", self.ipv4_chain, "-d", "127.0.0.1/32", "-j", "ACCEPT")
        self._iptables("iptables", "-A", self.ipv4_chain, "-p", "tcp", "-d", self.IMDS, "--dport", "80", "-j", "ACCEPT")
        for address in kms_addresses:
            self._iptables("iptables", "-A", self.ipv4_chain, "-p", "tcp", "-d", address, "--dport", str(self.KMS_PORT), "-j", "ACCEPT")
        for protocol in ("tcp", "udp"):
            self._iptables("iptables", "-A", self.ipv4_chain, "-p", protocol, "-d", self.VPC_RESOLVER, "--dport", "53", "-j", "ACCEPT")
        self._iptables("iptables", "-A", self.ipv4_chain, "-j", "REJECT")
        # Attach only a complete terminal chain. Position one prevents a
        # pre-existing OUTPUT ACCEPT rule from bypassing this UID fence.
        self._iptables("iptables", "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", str(self.UID), "-j", self.ipv4_chain)
        self._ipv4_jump_added = True

    def _install_ipv6(self) -> None:
        # Do not silently omit the IPv6 fence: an unavailable ip6tables must
        # fail closed and trigger rollback of the already-installed IPv4 rule.
        self._iptables("ip6tables", "-N", self.ipv6_chain)
        self._ipv6_chain_created = True
        self._iptables("ip6tables", "-A", self.ipv6_chain, "-j", "REJECT")
        self._iptables("ip6tables", "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", str(self.UID), "-j", self.ipv6_chain)
        self._ipv6_jump_added = True

    def install(self) -> None:
        if self._installed or any((self._ipv4_chain_created, self._ipv4_jump_added, self._ipv6_chain_created, self._ipv6_jump_added)):
            raise EgressError("egress guard is already installed or incomplete")
        # Both checks happen before any firewall mutation.  In particular, a
        # public/empty/mixed KMS answer leaves OUTPUT untouched.
        kms_addresses = self._validated_kms_addresses()
        self._ensure_root_and_no_uid_processes()
        try:
            self._install_ipv4(kms_addresses)
            self._install_ipv6()
            self._installed = True
        except EgressError as exc:
            try:
                self.close()
            except EgressError as rollback_error:
                raise EgressError("egress guard installation failed and rollback failed") from rollback_error
            raise EgressError("egress guard installation failed") from exc

    def _close_family(self, binary: str, chain: str, jump_added: bool, chain_created: bool) -> list[EgressError]:
        failures: list[EgressError] = []
        if jump_added:
            try:
                self._iptables(binary, "-D", "OUTPUT", "-m", "owner", "--uid-owner", str(self.UID), "-j", chain)
            except EgressError as exc:
                failures.append(exc)
        if chain_created:
            try:
                # This flush targets only the exact UUID-owned child chain,
                # never a built-in chain such as OUTPUT.
                self._iptables(binary, "-F", chain)
                self._iptables(binary, "-X", chain)
            except EgressError as exc:
                failures.append(exc)
        return failures

    def close(self) -> None:
        failures = self._close_family("ip6tables", self.ipv6_chain, self._ipv6_jump_added, self._ipv6_chain_created)
        failures.extend(self._close_family("iptables", self.ipv4_chain, self._ipv4_jump_added, self._ipv4_chain_created))
        if failures:
            raise EgressError("egress guard cleanup failed")
        self._ipv4_chain_created = self._ipv4_jump_added = False
        self._ipv6_chain_created = self._ipv6_jump_added = False
        self._installed = False
