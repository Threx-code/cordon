"""Public network only (`core/netguard`): a name may resolve only to globally routable addresses.

The guard replaces `socket.getaddrinfo` for its whole process, so it is exercised in a child
interpreter, never installed in the test process. Every address below is numeric: resolving it
needs no network, and no connection is made."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from cordon_scanner.core.netguard import ALLOWED, ENABLE, NetworkGuard
from cordon_scanner.mcp.runner import Runner


class Child:
    PROBE = (
        "import json, socket, sys\n"
        "from cordon_scanner.core.netguard import NetworkGuard\n"
        "NetworkGuard.install_if_enabled()\n"
        "out = {}\n"
        "for host in sys.argv[1:]:\n"
        "    try:\n"
        "        socket.getaddrinfo(host, 443)\n"
        "        out[host] = 'allowed'\n"
        "    except socket.gaierror:\n"
        "        out[host] = 'refused'\n"
        "print(json.dumps(out))\n"
    )

    @staticmethod
    def resolve(hosts: list[str], env: dict[str, str]) -> dict[str, str]:
        run = subprocess.run(
            [sys.executable, "-c", Child.PROBE, *hosts],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
            env={**os.environ, **env},
        )
        return json.loads(run.stdout)


class TestPublic:
    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "169.254.169.254", "100.64.0.1",
            "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1",  # noqa: S104 - addresses the guard must refuse
            "2002:0a00:0001::1", "not-an-address",
        ],
    )  # fmt: skip
    def test_inside_the_network(self, address: str) -> None:
        assert NetworkGuard.public(address) is False

    @pytest.mark.parametrize(
        "address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"]
    )
    def test_public_addresses(self, address: str) -> None:
        assert NetworkGuard.public(address) is True


class TestTheGuard:
    HOSTS = ("127.0.0.1", "169.254.169.254", "10.1.2.3", "::1", "8.8.8.8")

    def test_off_by_default_nothing_changes(self) -> None:
        assert set(Child.resolve(list(self.HOSTS), {ENABLE: ""}).values()) == {"allowed"}

    def test_on_private_names_are_refused_and_public_ones_resolve(self) -> None:
        found = Child.resolve(list(self.HOSTS), {ENABLE: "1"})
        assert found == {
            "127.0.0.1": "refused",
            "169.254.169.254": "refused",
            "10.1.2.3": "refused",
            "::1": "refused",
            "8.8.8.8": "allowed",
        }

    def test_operator_named_hosts_are_exempt(self) -> None:
        found = Child.resolve(["10.1.2.3", "10.9.9.9"], {ENABLE: "1", ALLOWED: "10.1.2.3"})
        assert found == {"10.1.2.3": "allowed", "10.9.9.9": "refused"}


class TestMcpScansAreGuarded:
    def test_scans_the_mcp_server_runs_reach_the_public_network_only(self) -> None:
        assert Runner(offline=False).environment[ENABLE] == "1"

    def test_the_operator_can_allow_the_private_network(self) -> None:
        environment = Runner(
            offline=False, private_network=True, environment={ENABLE: "1"}
        ).environment
        assert ENABLE not in environment
