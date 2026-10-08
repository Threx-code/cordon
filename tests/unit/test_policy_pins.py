"""Organisation policy distribution (advanced gap E1).

The policy is copied into every repository, the copies drift, and `--policy <url>` needed
`--allow-network`, which the same policy forbids. The probes: a vendored copy pinned by digest is
read only while it still matches; `config policy-drift` compares a copy with the published one
without fetching anything; `config fetch-policy` is the one explicit fetch, after which a scan
reads the policy offline.
"""

from __future__ import annotations

import hashlib

import pytest

from cordon_scanner.cli.main import CommandLine
from cordon_scanner.core.config import ConfigResolver
from cordon_scanner.core.distribution import PolicyDistribution
from cordon_scanner.core.errors import ConfigError, ExitCode

POLICY = """version: 1
name: org

enforce:
  allow_network: false

suppressions:
  max_duration_days: 90
"""


class PinHelpers:
    @staticmethod
    def write(tmp_path, text: str = POLICY):
        path = tmp_path / "cordon-policy.yaml"
        path.write_bytes(text.encode())  # as published: no newline translation on Windows
        return path, hashlib.sha256(text.encode()).hexdigest()


class TestAVendoredCopyPinnedByDigest:
    def test_it_is_read_while_it_matches(self, tmp_path) -> None:
        path, digest = PinHelpers.write(tmp_path)
        _, constraints = ConfigResolver.load_org_policy(f"{path}#sha256={digest}")
        assert constraints.allow_network is False

    def test_an_edited_copy_is_refused(self, tmp_path) -> None:
        path, digest = PinHelpers.write(tmp_path)
        path.write_text(POLICY.replace("allow_network: false", "allow_network: true"))
        with pytest.raises(ConfigError, match="does not match its pinned digest"):
            ConfigResolver.load_org_policy(f"{path}#sha256={digest}")


class TestDrift:
    def test_a_matching_copy(self, tmp_path, capsys) -> None:
        path, digest = PinHelpers.write(tmp_path)
        code = CommandLine.run(
            [
                "config",
                "policy-drift",
                str(path),
                "--published",
                f"https://policy.example.test/p.yaml#sha256={digest}",
            ]
        )
        assert code == int(ExitCode.CLEAN) and "matches" in capsys.readouterr().out

    def test_a_drifted_copy(self, tmp_path, capsys) -> None:
        path, _ = PinHelpers.write(tmp_path)
        published = tmp_path / "published.yaml"
        published.write_text(POLICY.replace("90", "30"))
        code = CommandLine.run(["config", "policy-drift", str(path), "--published", str(published)])
        assert code == int(ExitCode.FINDINGS) and "drifted" in capsys.readouterr().out

    def test_a_url_without_a_digest_cannot_be_compared(self, tmp_path) -> None:
        with pytest.raises(ConfigError):
            PolicyDistribution.published_digest("https://policy.example.test/p.yaml")


class TestFetchOnceThenOffline:
    def test_fetched_once_and_read_from_the_cache_with_the_network_off(
        self, tmp_path, monkeypatch, capsys
    ) -> None:
        body = POLICY.encode()
        digest = hashlib.sha256(body).hexdigest()
        url = f"https://policy.example.test/p.yaml#sha256={digest}"
        fetched: list[str] = []

        def fetch(address: str) -> bytes:
            fetched.append(address)
            return body

        monkeypatch.setattr(PolicyDistribution, "_fetch", staticmethod(fetch))
        monkeypatch.setattr(
            "cordon_scanner.core.cache.ScanCache.default_cache_dir",
            staticmethod(lambda: tmp_path / "cache"),
        )
        assert CommandLine.run(["config", "fetch-policy", url]) == int(ExitCode.CLEAN)
        assert fetched == ["https://policy.example.test/p.yaml"]
        # The scan's own resolution, with network access not asked for: the cache answers.
        _, constraints = ConfigResolver.load_org_policy(
            url, allow_network=False, cache_dir=tmp_path / "cache"
        )
        assert constraints.allow_network is False and len(fetched) == 1
