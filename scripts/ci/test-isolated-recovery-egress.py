#!/usr/bin/env python3
# Check objective: Verify isolated recovery egress guards without invoking host firewall commands.
"""Mocked tests for the isolated recovery egress guard; never call iptables."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).parents[1] / "ops" / "lib" / "isolated-recovery-egress.py"
SPEC = importlib.util.spec_from_file_location("isolated_recovery_egress", SCRIPT)
assert SPEC and SPEC.loader
egress = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(egress)


def private_kms(address: str = "10.91.0.10") -> list[tuple]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]


class EgressGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.commands: list[list[str]] = []

    def runner(self, command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if command[0] == "ps":
            return subprocess.CompletedProcess(command, 0, "0\n1000\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    def install(self, guard: object) -> None:
        with patch.object(egress.socket, "getaddrinfo", return_value=private_kms()), patch.object(egress.subprocess, "run", self.runner):
            guard.install()

    def test_install_sequence_is_uid_scoped_wait_locked_and_exact(self) -> None:
        guard = egress.EgressGuard()
        self.install(guard)
        expected_v4 = guard.ipv4_chain
        expected_v6 = guard.ipv6_chain
        self.assertEqual(self.commands[0], ["ps", "-eo", "uid="])
        self.assertEqual(self.commands[1], ["iptables", "-w", "5", "-N", expected_v4])
        self.assertIn(["iptables", "-w", "5", "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", "65000", "-j", expected_v4], self.commands)
        self.assertIn(["iptables", "-w", "5", "-A", expected_v4, "-d", "127.0.0.1/32", "-j", "ACCEPT"], self.commands)
        self.assertIn(["iptables", "-w", "5", "-A", expected_v4, "-p", "tcp", "-d", "169.254.169.254", "--dport", "80", "-j", "ACCEPT"], self.commands)
        self.assertIn(["iptables", "-w", "5", "-A", expected_v4, "-p", "tcp", "-d", "10.91.0.10", "--dport", "443", "-j", "ACCEPT"], self.commands)
        self.assertIn(["iptables", "-w", "5", "-A", expected_v4, "-p", "udp", "-d", "10.91.0.2", "--dport", "53", "-j", "ACCEPT"], self.commands)
        self.assertIn(["ip6tables", "-w", "5", "-A", expected_v6, "-j", "REJECT"], self.commands)
        self.assertIn(["ip6tables", "-w", "5", "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", "65000", "-j", expected_v6], self.commands)
        self.assertTrue(all(command[0] == "ps" or command[1:3] == ["-w", "5"] for command in self.commands))
        self.assertFalse(any(command[3:5] == ["-A", "OUTPUT"] for command in self.commands))
        self.assertFalse(any("-P" in command or ("-F" in command and "OUTPUT" in command) for command in self.commands))

    def test_public_empty_ipv4_or_ipv6_dns_results_never_mutate(self) -> None:
        cases = [[], private_kms("54.1.2.3"), [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00::1", 443, 0, 0))], private_kms() + [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00::1", 443, 0, 0))]]
        for result in cases:
            guard = egress.EgressGuard()
            with patch.object(egress.socket, "getaddrinfo", return_value=result), patch.object(egress.subprocess, "run", self.runner):
                with self.assertRaises(egress.EgressError): guard.install()
            self.assertEqual(self.commands, [])

    def test_uid_process_or_optional_nonroot_refuses_before_mutation(self) -> None:
        guard = egress.EgressGuard()
        def occupied(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            self.commands.append(command)
            return subprocess.CompletedProcess(command, 0, "65000\n", "")
        with patch.object(egress.socket, "getaddrinfo", return_value=private_kms()), patch.object(egress.subprocess, "run", occupied):
            with self.assertRaises(egress.EgressError): guard.install()
        self.assertEqual(self.commands, [["ps", "-eo", "uid="]])
        root_guard = egress.EgressGuard(require_root=True)
        with patch.object(egress.os, "geteuid", return_value=1000), patch.object(egress.socket, "getaddrinfo", return_value=private_kms()), patch.object(egress.subprocess, "run", self.runner):
            with self.assertRaises(egress.EgressError): root_guard.install()
        self.assertEqual(self.commands, [["ps", "-eo", "uid="]])

    def test_partial_install_rolls_back_only_owned_handles(self) -> None:
        guard = egress.EgressGuard()
        def partial(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            self.commands.append(command)
            if command[0] == "ps": return subprocess.CompletedProcess(command, 0, "", "")
            if command[0] == "ip6tables" and command[3:5] == ["-N", guard.ipv6_chain]:
                raise subprocess.CalledProcessError(1, command, stderr="private failure")
            return subprocess.CompletedProcess(command, 0, "", "")
        with patch.object(egress.socket, "getaddrinfo", return_value=private_kms()), patch.object(egress.subprocess, "run", partial):
            with self.assertRaises(egress.EgressError) as raised: guard.install()
        self.assertNotIn("private failure", str(raised.exception))
        self.assertIn(["iptables", "-w", "5", "-D", "OUTPUT", "-m", "owner", "--uid-owner", "65000", "-j", guard.ipv4_chain], self.commands)
        self.assertIn(["iptables", "-w", "5", "-F", guard.ipv4_chain], self.commands)
        self.assertIn(["iptables", "-w", "5", "-X", guard.ipv4_chain], self.commands)
        self.assertFalse(any("OUTPUT" in command and "-F" in command for command in self.commands))

    def test_cleanup_failure_raises_and_never_broadens_target(self) -> None:
        guard = egress.EgressGuard()
        self.install(guard)
        self.commands.clear()
        def broken_cleanup(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            self.commands.append(command)
            if command[:4] == ["ip6tables", "-w", "5", "-D"]:
                raise subprocess.CalledProcessError(1, command, stderr="secret")
            return subprocess.CompletedProcess(command, 0, "", "")
        with patch.object(egress.subprocess, "run", broken_cleanup):
            with self.assertRaises(egress.EgressError) as raised: guard.close()
        self.assertEqual(str(raised.exception), "egress guard cleanup failed")
        self.assertFalse(any("-P" in command or ("-F" in command and "OUTPUT" in command) for command in self.commands))
        self.assertTrue(all(guard.ipv4_chain in command or guard.ipv6_chain in command for command in self.commands))

    def test_unavailable_ip6tables_fails_closed_and_rolls_back(self) -> None:
        guard = egress.EgressGuard()
        def no_ip6(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            self.commands.append(command)
            if command[0] == "ps": return subprocess.CompletedProcess(command, 0, "", "")
            if command[0] == "ip6tables": raise FileNotFoundError()
            return subprocess.CompletedProcess(command, 0, "", "")
        with patch.object(egress.socket, "getaddrinfo", return_value=private_kms()), patch.object(egress.subprocess, "run", no_ip6):
            with self.assertRaises(egress.EgressError): guard.install()
        self.assertIn(["iptables", "-w", "5", "-X", guard.ipv4_chain], self.commands)


if __name__ == "__main__":
    unittest.main()
