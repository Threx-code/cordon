"""Incremental cache.

The cache is an optimisation that can silently produce wrong answers, which
makes it one of the more dangerous components here. Two properties are
non-negotiable and both are asserted directly:

**A cache hit is identical to a cold run.** If it is not, the cache is a source
of false negatives that nothing else in the system can detect.

**Anything that changes a finding changes the key.** Including context. A file's
findings depend on where it sits, not only on what it contains.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.engine.cache import CacheKey, CacheSignature, ScanCache
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    RiskFactor,
    RiskScore,
    Severity,
)
from support import ROOT as REPO
from support import requires_malicious_corpus


class CacheHelpers:
    """Helpers for test_cache.py."""

    @staticmethod
    def make_finding(rule_id: str = "TEST.RULE.001") -> Finding:
        return Finding(
            rule_id=rule_id,
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            message="something",
            location=Location(path="src/app.py", line=4, column=2, byte_start=10, byte_end=20),
            evidence=Evidence(
                kind=EvidenceKind.SNIPPET,
                match_hash=Evidence.hash_bytes(b"x"),
                redaction=RedactionMode.MASKED,
                snippet="payload",
                span=(10, 20),
                metadata=(("k", "v"),),
            ),
            remediation="fix it",
            explanation=Explanation(
                summary="because",
                matched_rule=rule_id,
                contributing=("A@1",),
                escalations=("runs at install time",),
            ),
            risk=RiskScore(
                value=72,
                base=70,
                confidence_multiplier=0.75,
                factors=(RiskFactor("install_time", 15, "runs during install"),),
            ),
            detector="test",
            references=("https://example.invalid/r",),
        )


BASE_KEY = {
    "content_hash": "aaa",
    "rulepack_hash": "bbb",
    "config_hash": "ccc",
    "detector_signature": "ddd",
    "path": "src/app.py",
    "in_install_hook": False,
    "language": "python",
}


class TestCacheKey:
    def test_same_inputs_give_the_same_digest(self) -> None:
        assert CacheKey(**BASE_KEY).digest() == CacheKey(**BASE_KEY).digest()

    @pytest.mark.parametrize("field", sorted(BASE_KEY))
    def test_every_field_participates_in_the_digest(self, field: str) -> None:
        """A field that does not change the key is a field that can return a
        result computed under different conditions."""
        changed = dict(BASE_KEY)
        current = changed[field]
        changed[field] = (not current) if isinstance(current, bool) else f"{current}-x"
        assert CacheKey(**BASE_KEY).digest() != CacheKey(**changed).digest()

    def test_install_context_changes_the_key(self) -> None:
        """The specific bug this guards. Identical code is suspicious in an
        application module and malicious in an install hook, so a content-only
        key returns findings computed for a different file."""
        plain = CacheKey(**{**BASE_KEY, "in_install_hook": False})
        hook = CacheKey(**{**BASE_KEY, "in_install_hook": True})
        assert plain.digest() != hook.digest()

    def test_path_changes_the_key(self) -> None:
        a = CacheKey(**{**BASE_KEY, "path": "a.py"})
        b = CacheKey(**{**BASE_KEY, "path": "b.py"})
        assert a.digest() != b.digest()


class TestDetectorSignature:
    def test_version_change_invalidates(self) -> None:
        class D:
            def __init__(self, i, v):
                self.id, self.version = i, v

        assert CacheSignature.detector_signature(
            [D("a", "1.0")]
        ) != CacheSignature.detector_signature([D("a", "1.1")])

    def test_order_does_not_matter(self) -> None:
        class D:
            def __init__(self, i, v):
                self.id, self.version = i, v

        a, b = D("a", "1"), D("b", "1")
        assert CacheSignature.detector_signature([a, b]) == CacheSignature.detector_signature(
            [b, a]
        )

    def test_changing_the_code_invalidates_without_touching_the_version(self) -> None:
        """The declared version used to be the whole identity, which made cache
        correctness depend on somebody remembering to edit a string.

        0.1.1 came one line from proving how that fails. Its entire content was a
        false-positive fix in `detect/secrets.py`: the file content being scanned,
        the rule pack and the configuration were all unchanged, so every affected
        entry would have been served from the cache and the release would have
        done nothing for anyone who had ever run a scan.
        """
        import sys
        import types

        first = types.ModuleType("cordon_fake_detector")
        first.__file__ = "cordon_fake_detector.py"

        class D:
            id = "fake"
            version = "1.0"

        D.__module__ = "cordon_fake_detector"
        sys.modules["cordon_fake_detector"] = first

        # `inspect.getsource` reads the file named by `__file__`, not the module
        # object, so the two bodies are written to disk under one name in turn.
        import unittest.mock

        try:
            with unittest.mock.patch(
                "cordon_scanner.engine.cache.inspect.getsource", return_value="PATTERN = 'a'"
            ):
                CacheSignature._module_hash.cache_clear()
                before = CacheSignature.detector_signature([D()])
            with unittest.mock.patch(
                "cordon_scanner.engine.cache.inspect.getsource", return_value="PATTERN = 'b'"
            ):
                CacheSignature._module_hash.cache_clear()
                after = CacheSignature.detector_signature([D()])
        finally:
            CacheSignature._module_hash.cache_clear()
            del sys.modules["cordon_fake_detector"]

        assert before != after, "a changed detector must not serve cached findings"

    def test_changing_analysis_code_a_detector_calls_invalidates(
        self, tmp_path, monkeypatch
    ) -> None:
        """A detector's own module is not all that decides its findings: the analysis it calls lives
        elsewhere. Keyed on its module alone, a release that fixed detection in that analysis kept
        serving every warm cache (on by default) the findings of the code it replaced."""
        from cordon_scanner.foundation.paths import PackagePaths

        (tmp_path / "detect").mkdir()
        (tmp_path / "analysis").mkdir()
        (tmp_path / "detect" / "d.py").write_text("ID = 'd'\n", encoding="utf-8")
        flow = tmp_path / "analysis" / "flow.py"
        monkeypatch.setattr(PackagePaths, "root", staticmethod(lambda: tmp_path))

        class D:
            id = "d"
            version = "1.0"

        def signature(source: str) -> str:
            flow.write_text(source, encoding="utf-8")
            CacheSignature._package_hash.cache_clear()
            return CacheSignature.detector_signature([D()])

        monkeypatch.setattr(CacheSignature, "_wheel_record", staticmethod(lambda root: None))
        try:
            before = signature("SINKS = ('eval',)\n")
            after = signature("SINKS = ('eval', 'exec')\n")
        finally:
            CacheSignature._package_hash.cache_clear()
        assert before != after, "changed analysis must not serve cached findings"

    def test_an_installed_wheel_is_known_by_its_record_on_every_machine(
        self, tmp_path, monkeypatch
    ) -> None:
        """The same release installed on two machines has different modification times; its
        RECORD, which holds every file's SHA-256, is the same, so a restored CI cache still hits."""
        from cordon_scanner.foundation.paths import PackagePaths

        (tmp_path / "engine").mkdir()
        (tmp_path / "engine" / "cache.py").write_text("x = 1\n", encoding="utf-8")
        monkeypatch.setattr(PackagePaths, "root", staticmethod(lambda: tmp_path))
        record = b"cordon_scanner/engine/cache.py,sha256=abc,6\n"
        monkeypatch.setattr(CacheSignature, "_wheel_record", staticmethod(lambda root: record))
        try:
            CacheSignature._package_hash.cache_clear()
            first = CacheSignature._package_hash()
            import os

            os.utime(tmp_path / "engine" / "cache.py", ns=(5, 5))
            CacheSignature._package_hash.cache_clear()
            assert CacheSignature._package_hash() == first
        finally:
            CacheSignature._package_hash.cache_clear()
        assert first.startswith("wheel-")

    def test_a_real_detector_contributes_a_code_hash(self) -> None:
        from cordon_scanner.detect.secrets.detector import SecretDetector

        identity = CacheSignature._detector_identity(SecretDetector())
        name, version, code = identity.split("@")
        assert (name, version) == ("secrets", SecretDetector.version)
        assert len(code) == 16 and code != "nosource"

    def test_line_endings_do_not_change_the_hash(self) -> None:
        """Otherwise one release has two signatures depending on whether the
        checkout used LF or CRLF, and a CI cache restored onto a runner whose
        checkout differs from the one that saved it never hits. Not wrong, but a
        cache that never hits is one nobody keeps paying to store."""
        import unittest.mock

        def hash_of(source: str) -> str:
            CacheSignature._module_hash.cache_clear()
            with unittest.mock.patch(
                "cordon_scanner.engine.cache.inspect.getsource", return_value=source
            ):
                return CacheSignature._module_hash("cordon_scanner.detect.secrets.secrets")

        try:
            assert hash_of("a = 1\nb = 2\n") == hash_of("a = 1\r\nb = 2\r\n")
        finally:
            CacheSignature._module_hash.cache_clear()

    def test_a_module_with_no_source_falls_back_rather_than_failing(self) -> None:
        """A frozen or zipped build has no source to read. Refusing to scan would
        be a worse answer than reverting to the declared version, which is what
        shipped before this; `nosource` is named in the signature rather than
        substituted silently, so two builds of one release do not collide."""
        CacheSignature._module_hash.cache_clear()
        try:
            assert CacheSignature._module_hash("cordon_scanner.no.such.module") == "nosource"
        finally:
            CacheSignature._module_hash.cache_clear()


class TestRoundTrip:
    def test_findings_survive_a_round_trip_exactly(self, tmp_path) -> None:
        """A cached finding must be indistinguishable from a fresh one
        everywhere downstream, or the equivalence claim is empty."""
        cache = ScanCache(tmp_path)
        key = CacheKey(**BASE_KEY)
        original = CacheHelpers.make_finding()

        cache.put(key, [original])
        restored = cache.get(key)

        assert restored is not None
        assert len(restored) == 1
        assert restored[0].to_dict() == original.to_dict()
        assert restored[0].fingerprint == original.fingerprint

    def test_miss_returns_none(self, tmp_path) -> None:
        assert ScanCache(tmp_path).get(CacheKey(**BASE_KEY)) is None

    def test_disabled_cache_never_hits(self, tmp_path) -> None:
        cache = ScanCache(tmp_path, enabled=False)
        cache.put(CacheKey(**BASE_KEY), [CacheHelpers.make_finding()])
        assert cache.get(CacheKey(**BASE_KEY)) is None


class TestResilience:
    def test_corrupt_entry_is_a_miss_not_an_error(self, tmp_path) -> None:
        """A corrupt cache must degrade to a slower scan, never to a failed one.
        The cache is an optimisation and must not be able to break the thing it
        accelerates."""
        cache = ScanCache(tmp_path)
        key = CacheKey(**BASE_KEY)
        cache.put(key, [CacheHelpers.make_finding()])

        entry = next(tmp_path.rglob("*.json"))
        entry.write_text("{ this is not json", encoding="utf-8")

        assert cache.get(key) is None
        assert not entry.exists(), "a corrupt entry should be removed, not retried"

    def test_truncated_entry_is_a_miss(self, tmp_path) -> None:
        cache = ScanCache(tmp_path)
        key = CacheKey(**BASE_KEY)
        cache.put(key, [CacheHelpers.make_finding()])
        entry = next(tmp_path.rglob("*.json"))
        whole = entry.read_text(encoding="utf-8")
        entry.write_text(whole[: len(whole) // 2], encoding="utf-8")
        assert cache.get(key) is None

    def test_entry_missing_a_field_is_a_miss(self, tmp_path) -> None:
        cache = ScanCache(tmp_path)
        key = CacheKey(**BASE_KEY)
        cache.put(key, [CacheHelpers.make_finding()])
        entry = next(tmp_path.rglob("*.json"))
        payload = json.loads(entry.read_text(encoding="utf-8"))
        del payload["findings"][0]["risk"]
        entry.write_text(json.dumps(payload), encoding="utf-8")
        assert cache.get(key) is None

    def test_unwritable_directory_does_not_raise(self, tmp_path) -> None:
        blocked = tmp_path / "ro"
        blocked.mkdir()
        blocked.chmod(0o500)
        try:
            cache = ScanCache(blocked / "sub")
            cache.put(CacheKey(**BASE_KEY), [CacheHelpers.make_finding()])
        finally:
            blocked.chmod(0o700)

    def test_oversized_entry_is_not_cached(self, tmp_path) -> None:
        """One hostile file must not become a permanent disk-space problem."""
        cache = ScanCache(tmp_path)
        key = CacheKey(**BASE_KEY)
        cache.put(key, [CacheHelpers.make_finding(f"RULE.{i:05d}") for i in range(20000)])
        assert cache.get(key) is None


class TestCacheCorrectnessEndToEnd:
    def test_warm_scan_matches_a_cold_scan(self, tmp_path) -> None:
        """The property everything else rests on."""
        project = tmp_path / "repo"
        project.mkdir()
        (project / "loader.js").write_text("const p = atob(BLOB);\neval(p);\n", encoding="utf-8")
        (project / "clean.js").write_text("export const x = 1;\n", encoding="utf-8")

        cache_dir = tmp_path / "cache"
        cold = Scanner(
            Config.default().with_overrides(cache_dir=str(cache_dir), use_cache=False)
        ).scan(project)
        warm_scanner = Scanner(
            Config.default().with_overrides(cache_dir=str(cache_dir), use_cache=True)
        )
        warm_scanner.scan(project)  # populate
        warm = warm_scanner.scan(project)  # serve from cache

        assert [f.to_dict() for f in cold.findings] == [f.to_dict() for f in warm.findings]

    @requires_malicious_corpus
    def test_identical_content_at_different_paths_is_not_confused(self, tmp_path) -> None:
        """The regression that motivated putting context in the key.

        Byte-identical content in an install hook and in an ordinary module must
        not share a cache entry: the first is malicious, the second is not, and
        a content-only key promoted the ordinary module to a malware finding.
        """
        # Read from the corpus rather than inlined here. A payload-shaped
        # literal in a test file is a true positive when Cordon scans its own
        # repository, and the corpus is the one place such samples belong --
        # which also gives the payload a single definition rather than two.
        corpus = REPO / "corpus" / "malicious" / "exfil-python-install-hook" / "setup.py"
        body = corpus.read_text(encoding="utf-8")

        hook_project = tmp_path / "hook"
        hook_project.mkdir()
        (hook_project / "setup.py").write_text(body, encoding="utf-8")

        plain_project = tmp_path / "plain"
        plain_project.mkdir()
        (plain_project / "reporting.py").write_text(body, encoding="utf-8")

        cache_dir = tmp_path / "cache"
        config = Config.default().with_overrides(cache_dir=str(cache_dir), use_cache=True)

        hook_result = Scanner(config).scan(hook_project)
        plain_result = Scanner(config).scan(plain_project)

        assert any(f.category is Category.MALICIOUS for f in hook_result.findings), (
            "the install hook must be reported as malicious"
        )
        assert not any(f.category is Category.MALICIOUS for f in plain_result.findings), (
            "identical content outside a hook must not inherit the hook's verdict"
        )

    def test_cache_statistics_are_reported(self, tmp_path) -> None:
        project = tmp_path / "repo"
        project.mkdir()
        (project / "a.js").write_text("const x = 1;\n", encoding="utf-8")

        scanner = Scanner(
            Config.default().with_overrides(cache_dir=str(tmp_path / "cache"), use_cache=True)
        )
        scanner.scan(project)
        second = scanner.scan(project)
        assert second.stats.cache_hits > 0


class TestEverythingAFileDependsOnIsInTheKey:
    """The key held the file's bytes, path and language, the rule pack, the configuration and the
    detectors' code; a file's findings depend on more than that, and each gap served a stale
    result to a warm cache, which is on by default."""

    SETUP = (
        "import os, subprocess\n"
        "from setuptools import setup\n"
        "from setuptools.command.install import install\n\n\n"
        "class Post(install):\n"
        "    def run(self):\n"
        "        install.run(self)\n"
        "        subprocess.Popen([os.path.join(os.path.dirname(__file__), 'dist', 'pip_security')])\n\n\n"
        "setup(name='probe', version='1.0', cmdclass={'install': Post})\n"
    )

    @staticmethod
    def setup_rules(tree, cache_dir) -> list[str]:
        config = Config.default().with_overrides(cache_dir=str(cache_dir), use_cache=True)
        return sorted(
            f.rule_id
            for f in Scanner(config).scan(tree).findings
            if f.location.path.endswith("setup.py")
        )

    def test_a_file_whose_role_changed_is_not_served_its_old_findings(self, tmp_path) -> None:
        """`setup.py` unchanged; what it spawns becomes a native binary the package ships. A cold
        scan blocks it; the warm one served what the file was found to be when the spawned file
        was a script."""
        tree, cache_dir = tmp_path / "tree", tmp_path / "cache"
        (tree / "dist").mkdir(parents=True)
        (tree / "setup.py").write_text(self.SETUP, encoding="utf-8")
        (tree / "dist" / "pip_security").write_text("print('hello')\n", encoding="utf-8")
        before = self.setup_rules(tree, cache_dir)
        (tree / "dist" / "pip_security").write_bytes(b"\x7fELF\x02\x01\x01" + bytes(64))
        warm = self.setup_rules(tree, cache_dir)
        cold = self.setup_rules(tree, tmp_path / "cold")
        assert "MALWARE.INSTALL.CONSUMER_CODE.001" not in before
        assert "MALWARE.INSTALL.CONSUMER_CODE.001" in cold
        assert warm == cold

    @staticmethod
    def context(**facts):
        from cordon_scanner.detect.base import ScanContext

        return ScanContext(config=Config.default(), rules=Scanner(Config.default()).rules, **facts)

    def test_the_context_is_in_the_signature_and_where_the_tree_was_unpacked_is_not(self) -> None:
        from cordon_scanner.foundation.results import Repository

        config = Config.default()

        def signature(**facts) -> str:
            return CacheSignature.scan_signature([], self.context(**facts), config)

        plain = signature(repository=Repository(root="/tmp/unpacked-1"))
        assert signature(repository=Repository(root="/tmp/unpacked-2")) == plain
        assert (
            signature(
                repository=Repository(root="/tmp/unpacked-1"),
                import_entry_paths=frozenset({"index.js"}),
            )
            != plain
        )
        assert signature(repository=Repository(root="/tmp/unpacked-1"), distribution="npm") != plain

    def test_a_refresh_of_the_synced_intelligence_changes_the_signature(
        self, tmp_path, monkeypatch
    ) -> None:
        """A feed refresh that condemns a release must reach a warm cache: the condemned-feed
        detectors read the synced files, which no other part of the key names."""
        import os

        from cordon_scanner.foundation.paths import StatePaths

        monkeypatch.setattr(StatePaths, "synced_intel_dir", staticmethod(lambda: tmp_path))
        (tmp_path / "feed").mkdir()
        overlay = tmp_path / "feed" / "npm.json"
        overlay.write_text("{}", encoding="utf-8")
        os.utime(overlay, ns=(1, 1))
        ctx, config = self.context(), Config.default()
        before = CacheSignature.scan_signature([], ctx, config)
        overlay.write_text('{"condemned": ["x"]}', encoding="utf-8")
        os.utime(overlay, ns=(2, 2))
        assert CacheSignature.scan_signature([], ctx, config) != before

    def test_the_rule_files_contents_are_in_the_signature(self, tmp_path) -> None:
        """The configuration says only whether a rule file is set."""
        rules = tmp_path / "local.yar"
        rules.write_text("rule a { condition: true }\n", encoding="utf-8")
        config = Config.default().with_overrides(rule_file=str(rules))
        ctx = self.context()
        before = CacheSignature.scan_signature([], ctx, config)
        rules.write_text("rule b { condition: false }\n", encoding="utf-8")
        assert CacheSignature.scan_signature([], ctx, config) != before

    def test_an_included_members_contents_are_in_the_signature(self, tmp_path) -> None:
        rules = tmp_path / "index.yar"
        rules.write_text('include "member.yar"\n', encoding="utf-8")
        member = tmp_path / "member.yar"
        member.write_text("rule a { condition: true }\n", encoding="utf-8")
        config = Config.default().with_overrides(rule_file=str(rules))
        ctx = self.context()
        before = CacheSignature.scan_signature([], ctx, config)
        member.write_text("rule a { condition: false }\n", encoding="utf-8")
        assert CacheSignature.scan_signature([], ctx, config) != before

    def test_a_result_that_says_it_is_incomplete_is_not_cached(self, tmp_path) -> None:
        """A detector failure from one bad moment (memory, load) was served for that content
        until the code changed."""
        cache = ScanCache(tmp_path)
        cache.put(CacheKey(**BASE_KEY), [CacheHelpers.make_finding("OPERATIONAL.DETECTOR.FAILED")])
        assert cache.get(CacheKey(**BASE_KEY)) is None


class TestWatch:
    """A file's inspection that reaches past its own bytes is not cached (`Watch`)."""

    @staticmethod
    def reached(tmp_path, action) -> str:
        from cordon_scanner.engine.cache import ScanCache

        (tmp_path / "own.md").write_text("x", encoding="utf-8")
        (tmp_path / "other.md").write_text("y", encoding="utf-8")
        with ScanCache.watch(str(tmp_path), "own.md") as watch:
            action()
        return watch.reached

    def test_its_own_file_and_the_standard_library_are_not_reached(self, tmp_path) -> None:
        import json as stdlib_json

        assert not self.reached(tmp_path, lambda: (tmp_path / "own.md").read_text(encoding="utf-8"))
        assert not self.reached(tmp_path, lambda: Path(stdlib_json.__file__).open("rb").close())

    def test_another_file_of_the_tree_is_reached(self, tmp_path) -> None:
        assert (
            self.reached(tmp_path, lambda: (tmp_path / "other.md").read_text(encoding="utf-8"))
            == "open in the tree"
        )
        assert self.reached(tmp_path, lambda: list(tmp_path.iterdir()))

    def test_its_own_file_through_dot_dot_is_still_its_own_and_a_way_out_is_not(
        self, tmp_path
    ) -> None:
        sub = tmp_path / "sub"
        sub.mkdir()
        assert not self.reached(
            tmp_path, lambda: (sub / ".." / "own.md").read_text(encoding="utf-8")
        )
        assert self.reached(tmp_path, lambda: (sub / ".." / "other.md").read_text(encoding="utf-8"))

    def test_a_socket_a_process_and_a_file_elsewhere_are_reached(self, tmp_path) -> None:
        import socket
        import subprocess
        import sys
        import tempfile

        def connect() -> None:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.01)
                with contextlib.suppress(OSError):
                    s.connect(("127.0.0.1", 9))

        assert self.reached(tmp_path, connect) == "socket.connect"
        assert self.reached(
            tmp_path, lambda: subprocess.run([sys.executable, "-c", "0"], check=False)
        )
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("z")
        assert (
            self.reached(tmp_path, lambda: Path(handle.name).open(encoding="utf-8").close())
            == "open outside the package"
        )

    def test_nothing_is_reached_when_no_file_is_being_inspected(self, tmp_path) -> None:
        from cordon_scanner.engine.cache import Watch

        with ScanCache.watch(str(tmp_path), "own.md"):
            pass
        (tmp_path / "other.md").write_text("y", encoding="utf-8")
        assert getattr(Watch.current, "watch", None) is None


class TestTheWatchNeverBreaksWhatItWatches:
    def test_a_path_it_cannot_resolve_is_counted_as_reached_not_raised(
        self, tmp_path, monkeypatch
    ) -> None:
        """`Path.absolute` reads the working directory, which a test or a hook may have deleted. An
        audit hook that raised there would fail the detector's own open with the hook's error."""
        from cordon_scanner.engine.cache import Watch

        gone = tmp_path / "gone"
        gone.mkdir()
        monkeypatch.chdir(gone)
        gone.rmdir()
        with ScanCache.watch(str(tmp_path), "own.md") as watch:
            Watch._audit("open", ("relative.md", "r", 0))
        assert watch.reached == "open"
