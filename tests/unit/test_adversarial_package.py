"""The package fixes from the adversarial review, each tested as the attack it closes.

Every test here is written from the attacker's side: the input a hostile repository, cache or
control plane would supply, and the outcome that must no longer follow from it.
"""

from __future__ import annotations

import gzip
import io
import json
import subprocess
import sys
import tarfile
import time
import types
import zipfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.archive.safe import ArchiveReader, Rejection
from cordon_scanner.core.config import Config, ConfigResolver
from cordon_scanner.core.errors import ArchiveError
from cordon_scanner.core.limits import DEFAULT_LIMITS
from cordon_scanner.core.local_seal import LocalSeal
from cordon_scanner.core.models import Evidence, RedactionMode


class AdversarialKit:
    @staticmethod
    def scan(root: Path, **overrides):
        return Scanner(Config.default().with_overrides(use_cache=False, **overrides)).scan(root)

    @staticmethod
    def tgz(files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def zip_bytes(files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        return buffer.getvalue()


class TestThePerFileBudgetCannotSkipMalwareDetection:
    """P-1: padding a file so an earlier detector spends the budget no longer hides a payload."""

    def test_the_malware_detectors_run_even_when_the_budget_is_spent(self, tmp_path) -> None:
        (tmp_path / "install.js").write_text("const p = atob(process.argv[2]);\neval(p);\n")
        limits = DEFAULT_LIMITS.merged(per_file_timeout=1e-9, max_workers=1)
        result = AdversarialKit.scan(tmp_path, limits=limits)
        rules = {f.rule_id for f in result.findings}
        assert "SUSPECT.DECODE_EXEC.001" in rules
        timeout = [f for f in result.findings if f.rule_id == "OPERATIONAL.FILE.TIMEOUT"]
        if timeout:
            for always in ("capability", "obfuscation", "secrets", "binary"):
                assert (
                    always
                    not in timeout[0].message.split("did not run on it:", 1)[1].split(".", 1)[0]
                )


class TestARepositoryCannotConfigureItsOwnBlindness:
    """P-2, P-11: a scan target's own config cannot load plugins or switch detection off."""

    CONFIG = (
        "version: 1\n"
        "scan:\n"
        "  allow_plugins: true\n"
        "  expand_archives: false\n"
        "  intel_feed: false\n"
        "  max_intel_age: 0\n"
        '  minified: ["**", "*.js", "vendor/app.min.js"]\n'
    )

    def test_every_blinding_setting_is_withheld(self, tmp_path) -> None:
        (tmp_path / "cordon.yaml").write_text(self.CONFIG)
        config = ConfigResolver.resolve(root=tmp_path)
        assert config.allow_plugins is False
        assert config.expand_archives is True
        assert config.intel_feed is True
        assert config.max_intel_age is None
        assert config.minified == ("vendor/app.min.js",)
        assert set(config.clamped_settings) >= {
            "scan.allow_plugins",
            "scan.expand_archives",
            "scan.intel_feed",
            "scan.max_intel_age",
            "scan.minified",
        }

    def test_each_attempt_fails_the_default_gate(self, tmp_path) -> None:
        (tmp_path / "cordon.yaml").write_text(self.CONFIG)
        (tmp_path / "a.txt").write_text("hello\n")
        config = ConfigResolver.resolve(root=tmp_path, use_cache=False)
        result = Scanner(config).scan(tmp_path)
        weakened = [f for f in result.findings if f.rule_id == "POLICY.CONFIG.GATE_WEAKENED"]
        assert len(weakened) >= 5 and all(f.severity.name == "HIGH" for f in weakened)

    def test_a_narrow_minified_path_is_kept_and_reported_like_an_exclusion(self, tmp_path) -> None:
        (tmp_path / "cordon.yaml").write_text(
            'version: 1\nscan:\n  minified: ["dist/bundle.min.js"]\n'
        )
        config = ConfigResolver.resolve(root=tmp_path)
        assert (
            config.minified == ("dist/bundle.min.js",)
            and "scan.minified" not in config.clamped_settings
        )
        assert "dist/bundle.min.js" in config.untrusted_exclusions

    def test_the_operator_may_still_enable_plugins(self, tmp_path) -> None:
        assert Config.default().with_overrides(allow_plugins=True).allow_plugins is True


class TestPluginTrustRunsNoForeignCode:
    """P-3: deciding whether an entry point is ours never imports the package it names."""

    def test_a_foreign_package_claiming_our_name_is_not_imported(
        self, tmp_path, monkeypatch
    ) -> None:
        from cordon_scanner.core import registry

        marker = tmp_path / "ran"
        package = tmp_path / "evilpkg"
        package.mkdir()
        (package / "__init__.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
        (package / "mod.py").write_text("X = 1\n")
        monkeypatch.syspath_prepend(str(tmp_path))
        entry = types.SimpleNamespace(
            module="evilpkg.mod", value="evilpkg.mod:X", name="capability"
        )
        assert registry.Registry._is_ours(entry, registry.DISTRIBUTION) is False
        assert not marker.exists()
        assert "evilpkg" not in sys.modules

    def test_a_genuine_built_in_is_still_ours(self) -> None:
        from cordon_scanner.core import registry

        entry = types.SimpleNamespace(
            module="cordon_scanner.detect.capability", value="", name="capability"
        )
        assert registry.Registry._is_ours(entry, registry.DISTRIBUTION) is True


class TestTheCacheDirectoryIsNotTrusted:
    """P-4: what the cache holds is read only if this install wrote it."""

    @pytest.fixture
    def sync(self, tmp_path, monkeypatch):
        from cordon_scanner.intel import advisories

        directory = tmp_path / "sync"
        directory.mkdir()
        monkeypatch.setattr(
            advisories.AdvisoryFiles, "user_sync_dir", staticmethod(lambda: directory)
        )
        advisories.ShippedAdvisories.reset_caches()
        yield directory
        advisories.ShippedAdvisories.reset_caches()

    def test_a_planted_empty_database_is_refused_and_the_shipped_one_used(self, sync) -> None:
        from cordon_scanner.intel import advisories

        planted = sync / "advisories-npm.json.gz"
        planted.write_bytes(gzip.compress(b"[]"))
        digest = advisories.AdvisoryFiles.digest_of(planted)
        (sync / advisories.DIGESTS_NAME).write_text(json.dumps({"advisories-npm.json.gz": digest}))
        records = advisories.ShippedAdvisories._read_shipped("npm")
        assert len(records) > 1000, "the shipped npm database is still the one in use"
        assert "advisories-npm.json.gz" in advisories.AdvisoryFiles.refused_synced_files()

    def test_a_sealed_sync_is_used(self, sync) -> None:
        from cordon_scanner.intel import advisories
        from support import SealedSync

        record = {
            "ecosystem": "npm",
            "id": "GHSA-test",
            "name": "only-in-sync",
            "versions": ["1.0.0"],
            "summary": "s",
        }
        (sync / "advisories-npm.json.gz").write_bytes(gzip.compress(json.dumps([record]).encode()))
        SealedSync.seal(sync)
        assert [r["name"] for r in advisories.ShippedAdvisories._read_shipped("npm")] == [
            "only-in-sync"
        ]

    def test_a_sealed_manifest_does_not_cover_a_file_changed_after_it(self, sync) -> None:
        from cordon_scanner.intel import advisories
        from support import SealedSync

        (sync / "advisories-npm.json.gz").write_bytes(gzip.compress(b'[{"name": "a", "id": "x"}]'))
        SealedSync.seal(sync)
        (sync / "advisories-npm.json.gz").write_bytes(gzip.compress(b"[]"))
        assert len(advisories.ShippedAdvisories._read_shipped("npm")) > 1000

    def test_an_unsealed_overlay_withdraws_nothing(self, sync) -> None:
        from cordon_scanner.intel.feed import FeedStore

        FeedStore.state_dir().mkdir(parents=True)
        FeedStore.overlay_path("npm").write_text(
            json.dumps({"upsert": {}, "withdraw": ["GHSA-anything"]})
        )
        assert FeedStore.read_overlay("npm") == ([], frozenset())

    def test_a_sealed_overlay_is_read(self, sync) -> None:
        from cordon_scanner.intel.feed import FeedStore

        FeedStore._save_overlays({"npm": {"upsert": {}, "withdraw": ["GHSA-x"]}})
        assert FeedStore.read_overlay("npm") == ([], frozenset({"GHSA-x"}))

    def test_a_planted_self_signed_root_and_reset_state_are_ignored(self, sync) -> None:
        from cordon_scanner.intel.feed import FeedState, FeedStore

        directory = FeedStore.state_dir()
        directory.mkdir(parents=True)
        (directory / "root.json").write_text(
            json.dumps({"signed": {"version": 999}, "signatures": []})
        )
        (directory / "state.json").write_text(json.dumps({"serial": 0, "timestamp_version": 0}))
        state = FeedState.load(directory)
        assert state.root is None and state.serial == 0

    def test_state_this_install_wrote_round_trips(self, sync) -> None:
        from cordon_scanner.intel.feed import FeedState, FeedStore

        directory = FeedStore.state_dir()
        FeedState(root={"signed": {"version": 3}}, serial=7, timestamp_version=5).save(directory)
        loaded = FeedState.load(directory)
        assert loaded.serial == 7 and loaded.root == {"signed": {"version": 3}}

    def test_seals_are_bound_to_their_label(self) -> None:
        sealed = LocalSeal.sealed("feed-overlay", {"withdraw": []})
        assert LocalSeal.valid("feed-overlay", sealed)
        assert not LocalSeal.valid("feed-state", sealed)
        assert not LocalSeal.valid("feed-overlay", {**sealed, "withdraw": ["x"]})


class TestPolyglotArchives:
    """P-5: a tarball with a zip appended is read as both, and reported."""

    def test_both_halves_are_read(self) -> None:
        tar_part = AdversarialKit.tgz({"package/install.js": b"eval(atob(x));\n"})
        zip_part = AdversarialKit.zip_bytes({"README.md": b"benign\n"})
        result = ArchiveReader.extract(tar_part + zip_part, path="pkg.tgz")
        names = {m.name for m in result.members}
        assert "package/install.js" in names
        assert "zip-appended/README.md" in names
        assert any(r.reason == Rejection.POLYGLOT for r in result.rejected)

    def test_the_scan_reports_the_polyglot_at_high(self, tmp_path) -> None:
        tar_part = AdversarialKit.tgz({"package/index.js": b"module.exports = 1;\n"})
        (tmp_path / "vendor.tgz").write_bytes(tar_part + AdversarialKit.zip_bytes({"a.txt": b"a"}))
        result = AdversarialKit.scan(tmp_path)
        polyglot = [f for f in result.findings if f.rule_id == "SUSPECT.ARCHIVE.POLYGLOT.001"]
        assert polyglot and polyglot[0].severity.name == "HIGH"

    def test_an_ordinary_zip_and_tarball_are_not_polyglots(self) -> None:
        plain_zip = ArchiveReader.extract(AdversarialKit.zip_bytes({"a": b"1"}), path="a.zip")
        plain_tgz = ArchiveReader.extract(AdversarialKit.tgz({"a": b"1"}), path="a.tgz")
        assert not plain_zip.rejected and not plain_tgz.rejected

    def test_a_zip_with_a_stub_in_front_is_read_as_the_zip(self) -> None:
        stubbed = b"MZ" + b"\x00" * 200 + AdversarialKit.zip_bytes({"inner.txt": b"x"})
        result = ArchiveReader.extract(stubbed, path="setup.exe.zip")
        assert [m.name for m in result.members] == ["inner.txt"]

    def test_the_zip_path_honours_the_deadline(self) -> None:
        with pytest.raises(ArchiveError, match="time budget"):
            ArchiveReader.extract(
                AdversarialKit.zip_bytes({"a": b"1"}), path="a.zip", deadline=time.monotonic() - 1
            )


class TestGitRunsNoDriverTheRepositoryDefines:
    """P-6: a clean filter in the scanned repository's own config never runs."""

    def test_diff_against_the_tree_does_not_run_a_clean_filter(self, tmp_path) -> None:
        from cordon_scanner.sources.git import GitRepository

        marker = tmp_path / "pwned"
        repo = tmp_path / "repo"
        repo.mkdir()

        def git(*args: str) -> None:
            subprocess.run(
                ["git", "-c", "user.email=t@example.test", "-c", "user.name=t", *args],
                cwd=repo,
                check=True,
                capture_output=True,
            )

        git("init", "-q")
        (repo / "a.txt").write_text("one\n")
        git("add", "-A")
        git("commit", "-q", "-m", "one")
        (repo / ".gitattributes").write_text("*.txt filter=evil\n")
        git("config", "filter.evil.clean", f"sh -c 'touch {marker}; cat'")
        (repo / "a.txt").write_text("two\n")
        GitRepository(repo).changed_files("HEAD")
        assert not marker.exists(), "the repository's clean filter ran during the scan"

    def test_the_overrides_name_every_driver_found(self, tmp_path) -> None:
        from cordon_scanner.sources.git import GitRepository

        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "filter.evil.smudge", "x"], cwd=repo, check=True)
        subprocess.run(["git", "config", "diff.word.textconv", "y"], cwd=repo, check=True)
        overrides = GitRepository(repo).driver_overrides()
        joined = " ".join(overrides)
        for key in (
            "filter.evil.clean=",
            "filter.evil.smudge=",
            "filter.evil.process=",
            "diff.word.textconv=",
        ):
            assert key in joined


class TestSecretEvidenceRevealsNothing:
    """P-9: a published secret hash cannot be checked against guesses; fingerprints carry no value."""

    def test_the_hash_is_keyed(self) -> None:
        assert Evidence.secret_hash(b"hunter2").startswith("hmac-sha256:")
        assert Evidence.secret_hash(b"hunter2") != Evidence.hash_bytes(b"hunter2")
        assert Evidence.secret_hash(b"hunter2") == Evidence.secret_hash(b"hunter2")

    def test_two_values_in_one_place_share_a_fingerprint(self) -> None:
        from cordon_scanner.core.models import (
            Category,
            Confidence,
            EvidenceKind,
            Explanation,
            Finding,
            Location,
            RedactionMode,
            RiskScore,
            Severity,
        )

        def finding(value: bytes) -> Finding:
            return Finding(
                rule_id="SECRET.GITHUB.TOKEN.001",
                category=Category.SUSPICIOUS,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                message="m",
                location=Location(path="deploy.py", line=1),
                evidence=Evidence(
                    kind=EvidenceKind.HASH,
                    match_hash=Evidence.secret_hash(value),
                    redaction=RedactionMode.HASH_ONLY,
                ),
                remediation="r",
                explanation=Explanation(summary="s", matched_rule="SECRET.GITHUB.TOKEN.001"),
                risk=RiskScore(value=0, base=0, confidence_multiplier=1.0),
                detector="secrets",
            )

        assert finding(b"one").fingerprint == finding(b"two").fingerprint


class TestUploadsCarryNoCode:
    """P-10: an upload strips every code excerpt the local report keeps."""

    def test_snippets_are_removed(self, tmp_path) -> None:
        from cordon_scanner.cloud.results import SignedResults

        (tmp_path / "install.js").write_text("const p = atob(process.argv[2]);\neval(p);\n")
        result = AdversarialKit.scan(tmp_path, evidence=RedactionMode.MASKED)
        assert any(f.evidence.snippet for f in result.findings), "the local report keeps excerpts"
        document = json.loads(SignedResults.results_bytes(result))
        assert all(f["evidence"].get("snippet") is None for f in document["findings"])
        assert "atob" not in SignedResults.results_bytes(result).decode()


class TestTheRunnerTrustsNoRedirectAndNoControlPlaneSwitch:
    """P-7, P-15."""

    @staticmethod
    def config(**kwargs):
        from cordon_scanner.cloud.runner import RunnerConfig

        return RunnerConfig(
            url="https://cloud.example.test",
            token="t",
            runner_id="r",
            allowed_hosts=frozenset({"files.example.test"}),
            **kwargs,
        )

    def test_a_redirect_off_the_allowlist_is_refused(self) -> None:
        import urllib.request

        from cordon_scanner.cloud.runner import CheckedRedirects, JobRefused

        handler = CheckedRedirects(self.config())
        request = urllib.request.Request("https://files.example.test/a.tgz")
        with pytest.raises(JobRefused):
            handler.redirect_request(
                request, None, 302, "Found", {}, "http://169.254.169.254/latest/meta-data"
            )
        with pytest.raises(JobRefused):
            handler.redirect_request(
                request, None, 302, "Found", {}, "https://internal.example.test/x"
            )
        allowed = handler.redirect_request(
            request, None, 302, "Found", {}, "https://files.example.test/b.tgz"
        )
        assert allowed is not None and allowed.full_url == "https://files.example.test/b.tgz"

    def test_an_artefact_named_dot_dot_lands_inside_the_workspace(self, tmp_path) -> None:
        import hashlib

        from cordon_scanner.cloud.runner import CloudRunner

        body = b"payload"

        class Answer:
            def __init__(self):
                self.stream = io.BytesIO(body)

            def read(self, n):
                return self.stream.read(n)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        target = {
            "url": "https://files.example.test/x/..",
            "sha256": hashlib.sha256(body).hexdigest(),
        }
        path = CloudRunner.fetch_artifact(
            target, self.config(), tmp_path, opener=lambda *a, **k: Answer()
        )
        assert path.parent == tmp_path and path.name == "artifact"

    def test_the_control_plane_cannot_turn_on_network_lookups(self) -> None:
        assert self.config().allow_online is False

    def test_a_runner_scan_clamps_the_repositorys_own_config(self, tmp_path, monkeypatch) -> None:
        from cordon_scanner.cloud import runner

        (tmp_path / "cordon.yaml").write_text(
            "version: 1\nscan:\n  allow_plugins: true\n  offline: false\n"
        )
        seen = {}

        class Recorder:
            def __init__(self, config):
                seen["config"] = config

            def scan(self, target):
                raise RuntimeError("stop after the configuration was built")

        monkeypatch.setattr("cordon_scanner.Scanner", Recorder)
        monkeypatch.setattr(runner.CloudRunner, "heartbeat", staticmethod(lambda *a, **k: True))
        job = runner.Job(
            id="j",
            lease_id="l",
            lease_seconds=60,
            target={"type": "local"},
            options={"online": True},
        )
        outcome = runner.CloudRunner.execute(
            job, self.config(), fetchers={"local": lambda t, c, w: tmp_path}
        )
        assert outcome == {"status": "failed", "error": "the job failed on the runner; see its log"}
        assert seen["config"].allow_plugins is False
        assert seen["config"].offline is True, (
            "the job asked for the network and the operator did not allow it"
        )
