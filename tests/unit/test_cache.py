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

import json
import pathlib

import pytest

from cordon import Scanner
from cordon.core.cache import CacheKey, ScanCache
from cordon.core.config import Config
from cordon.core.models import (
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
from support import requires_corpus


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

        assert ScanCache.detector_signature([D("a", "1.0")]) != ScanCache.detector_signature(
            [D("a", "1.1")]
        )

    def test_order_does_not_matter(self) -> None:
        class D:
            def __init__(self, i, v):
                self.id, self.version = i, v

        a, b = D("a", "1"), D("b", "1")
        assert ScanCache.detector_signature([a, b]) == ScanCache.detector_signature([b, a])


class TestRoundTrip:
    def test_findings_survive_a_round_trip_exactly(self, tmp_path) -> None:
        """A cached finding must be indistinguishable from a fresh one
        everywhere downstream, or the equivalence claim is empty."""
        cache = ScanCache(tmp_path)
        key = CacheKey(**BASE_KEY)
        original = make_finding()

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
        cache.put(CacheKey(**BASE_KEY), [make_finding()])
        assert cache.get(CacheKey(**BASE_KEY)) is None


class TestResilience:
    def test_corrupt_entry_is_a_miss_not_an_error(self, tmp_path) -> None:
        """A corrupt cache must degrade to a slower scan, never to a failed one.
        The cache is an optimisation and must not be able to break the thing it
        accelerates."""
        cache = ScanCache(tmp_path)
        key = CacheKey(**BASE_KEY)
        cache.put(key, [make_finding()])

        entry = next(tmp_path.rglob("*.json"))
        entry.write_text("{ this is not json")

        assert cache.get(key) is None
        assert not entry.exists(), "a corrupt entry should be removed, not retried"

    def test_truncated_entry_is_a_miss(self, tmp_path) -> None:
        cache = ScanCache(tmp_path)
        key = CacheKey(**BASE_KEY)
        cache.put(key, [make_finding()])
        entry = next(tmp_path.rglob("*.json"))
        entry.write_text(
            entry.read_text(encoding="utf-8")[: len(entry.read_text(encoding="utf-8")) // 2]
        )
        assert cache.get(key) is None

    def test_entry_missing_a_field_is_a_miss(self, tmp_path) -> None:
        cache = ScanCache(tmp_path)
        key = CacheKey(**BASE_KEY)
        cache.put(key, [make_finding()])
        entry = next(tmp_path.rglob("*.json"))
        payload = json.loads(entry.read_text(encoding="utf-8"))
        del payload["findings"][0]["risk"]
        entry.write_text(json.dumps(payload))
        assert cache.get(key) is None

    def test_unwritable_directory_does_not_raise(self, tmp_path) -> None:
        blocked = tmp_path / "ro"
        blocked.mkdir()
        blocked.chmod(0o500)
        try:
            cache = ScanCache(blocked / "sub")
            cache.put(CacheKey(**BASE_KEY), [make_finding()])
        finally:
            blocked.chmod(0o700)

    def test_oversized_entry_is_not_cached(self, tmp_path) -> None:
        """One hostile file must not become a permanent disk-space problem."""
        cache = ScanCache(tmp_path)
        key = CacheKey(**BASE_KEY)
        cache.put(key, [make_finding(f"RULE.{i:05d}") for i in range(20000)])
        assert cache.get(key) is None


class TestCacheCorrectnessEndToEnd:
    def test_warm_scan_matches_a_cold_scan(self, tmp_path) -> None:
        """The property everything else rests on."""
        project = tmp_path / "repo"
        project.mkdir()
        (project / "loader.js").write_text("const p = atob(BLOB);\neval(p);\n")
        (project / "clean.js").write_text("export const x = 1;\n")

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

    @requires_corpus
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
        corpus = (
            pathlib.Path(__file__).resolve().parents[2]
            / "corpus"
            / "malicious"
            / "exfil-python-install-hook"
            / "setup.py"
        )
        body = corpus.read_text(encoding="utf-8")

        hook_project = tmp_path / "hook"
        hook_project.mkdir()
        (hook_project / "setup.py").write_text(body)

        plain_project = tmp_path / "plain"
        plain_project.mkdir()
        (plain_project / "reporting.py").write_text(body)

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
        (project / "a.js").write_text("const x = 1;\n")

        scanner = Scanner(
            Config.default().with_overrides(cache_dir=str(tmp_path / "cache"), use_cache=True)
        )
        scanner.scan(project)
        second = scanner.scan(project)
        assert second.stats.cache_hits > 0
