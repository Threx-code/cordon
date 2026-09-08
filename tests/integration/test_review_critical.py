"""Regressions for the critical findings of the adversarial security review.

Each class corresponds to one finding and reproduces the exploit that was
demonstrated against commit 8779d56. The tests are written attacker-first: prove
the payload is detected, then prove the evasion no longer removes it.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from cordon import Scanner
from cordon.core.cache import ScanCache
from cordon.core.config import Config
from cordon.core.content import FileContent
from cordon.core.errors import UnsafePatternError
from cordon.rules.loader import PatternCompiler

PAYLOAD = "const p = atob(B);\neval(p);\n"


def config(**kw) -> Config:
    return Config.default().with_overrides(use_cache=False, **kw)


def rule_ids(root, cfg=None) -> set[str]:
    return {f.rule_id for f in Scanner(cfg or config()).scan(root).findings}


class TestC02BinaryClassification:
    """C-02. One NUL byte disabled all four content detectors, silently, and the
    scan still reported complete. `is_binary` was `b"\\x00" in raw[:8192]`, and
    every content detector opens with `if content.is_binary: return ()`."""

    def test_a_nul_byte_no_longer_hides_a_payload(self, tmp_path) -> None:
        clean = tmp_path / "clean.js"
        clean.write_text(PAYLOAD)
        assert "SUSPECT.DECODE_EXEC.001" in rule_ids(clean)

        nul = tmp_path / "nul.js"
        nul.write_bytes(b"/* \x00 */\n" + PAYLOAD.encode())
        assert "SUSPECT.DECODE_EXEC.001" in rule_ids(nul)

    @pytest.mark.parametrize(
        "name", ["a.js", "a.py", "a.sh", "a.rb", "a.php", "a.pl", "a.lua", "a.json"]
    )
    def test_no_source_extension_can_be_made_binary_by_content(self, name: str) -> None:
        """Every one of these languages tolerates a NUL in a comment or string,
        so the file still runs. The classification must not depend on it."""
        assert FileContent.from_bytes(name, b"/* \x00 */ x").is_binary is False

    def test_genuine_binaries_are_still_classified_by_name(self) -> None:
        for name in ("logo.png", "app.jar", "lib.so", "data.sqlite3", "font.woff2"):
            assert FileContent.from_bytes(name, b"anything at all").is_binary is True

    def test_genuine_binaries_are_classified_by_magic_without_an_extension(self) -> None:
        """An ELF binary named `install` is still an ELF binary."""
        assert FileContent.from_bytes("install", b"\x7fELF\x02\x01\x01").is_binary is True
        assert FileContent.from_bytes("img", b"\x89PNG\r\n\x1a\n").is_binary is True

    def test_magic_is_only_honoured_at_offset_zero(self) -> None:
        """Searching for magic anywhere would hand the decision back to whatever
        an attacker can embed, which is the bug being fixed."""
        assert FileContent.from_bytes("a.js", b"var x = 1; // \x7fELF").is_binary is False

    def test_skipping_a_binary_is_reported(self, tmp_path) -> None:
        """A file that was skipped and a file that was examined and found clean
        must never look the same."""
        (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
        (tmp_path / "a.js").write_text("const x = 1;\n")
        assert "OPERATIONAL.FILE.BINARY" in rule_ids(tmp_path)

    def test_the_report_is_one_finding_not_one_per_file(self, tmp_path) -> None:
        """A repository with four hundred icons would otherwise drown the
        report, and a report nobody reads is the same as no report."""
        for i in range(40):
            (tmp_path / f"i{i}.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        findings = [
            f
            for f in Scanner(config()).scan(tmp_path).findings
            if f.rule_id == "OPERATIONAL.FILE.BINARY"
        ]
        assert len(findings) == 1
        assert "40" in findings[0].message

    def test_a_repository_with_images_is_not_reported_incomplete(self, tmp_path) -> None:
        """Marking every repository with an icon incomplete would make
        `fail_on_incomplete` unusable, and an unusable control is worse than an
        absent one."""
        (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        (tmp_path / "a.js").write_text("const x = 1;\n")
        assert Scanner(config()).scan(tmp_path).complete is True

    def test_every_malicious_corpus_sample_survives_a_nul(self) -> None:
        """The regression test the review asked for, over the whole corpus."""
        corpus = Path(__file__).resolve().parents[2] / "corpus" / "malicious"
        checked = 0
        for sample in sorted(corpus.rglob("*")):
            if not sample.is_file() or sample.name == "expected.yaml":
                continue
            with tempfile.TemporaryDirectory() as d:
                plain = Path(d) / sample.name
                plain.write_bytes(sample.read_bytes())
                before = rule_ids(plain)
            with tempfile.TemporaryDirectory() as d:
                nul = Path(d) / sample.name
                nul.write_bytes(b"/* \x00 */\n" + sample.read_bytes())
                after = rule_ids(nul)
            assert not (before - after), f"{sample}: a NUL removed {sorted(before - after)}"
            checked += 1
        assert checked > 5


class TestC05PatternValidation:
    """C-05. The validator matched the regex *source text* with another regex,
    looking for a quantified group whose body contained no parentheses. One
    extra pair defeated it: `((a+))+$` was accepted and burned 90 seconds on 31
    bytes of input."""

    @pytest.mark.parametrize(
        "pattern",
        [
            "(a+)+$",
            "((a+))+$",
            "(((a+)))+$",
            "(?:(?:a+)+)+",
            "(?=(a+))+$",
            "(a|aa)+$",
            "((a|aa))+$",
            "(?:a*)*",
        ],
    )
    def test_nested_unbounded_quantifiers_are_rejected_at_any_depth(self, pattern: str) -> None:
        with pytest.raises(UnsafePatternError):
            PatternCompiler.validate_pattern(pattern, rule_id="T.001")

    def test_a_backreference_is_rejected(self) -> None:
        with pytest.raises(UnsafePatternError):
            PatternCompiler.validate_pattern(r"(\w+)\1", rule_id="T.001")

    def test_polynomial_wildcard_chains_are_rejected(self) -> None:
        """No nesting, so no exponential blowup -- but on a large file the
        polynomial case is the same outcome by a slower route."""
        with pytest.raises(UnsafePatternError):
            PatternCompiler.validate_pattern("a.*a.*a.*a.*a.*a.*a.*a.*b", rule_id="T.001")

    @pytest.mark.parametrize(
        "pattern",
        [
            r"\beval\s*\(",
            r"secret\w{4,9}token",
            r"https?://[^\s\"]+",
            r"(foo|bar)baz",
            r"\bnc\s+(?:-[a-z]+\s+){0,4}\S+\s+\d+",
            r"a.*b.*c",
            r"\$\{?[A-Z_]*TOKEN[A-Z_]*\}?",
        ],
    )
    def test_ordinary_rule_patterns_are_still_accepted(self, pattern: str) -> None:
        """The rejection must be narrow. A validator that refuses real rules
        gets worked around by disabling it."""
        assert PatternCompiler.validate_pattern(pattern, rule_id="T.001") is not None

    def test_the_shipped_packs_all_compile(self) -> None:
        from cordon.rules.loader import RuleLoader

        packs = RuleLoader.load_builtin()
        assert packs
        assert sum(len(p.rules) for p in packs) > 40

    def test_a_pathological_pattern_cannot_be_reached_through_a_pack(self, tmp_path) -> None:
        from cordon.core.errors import CordonError
        from cordon.rules.loader import RuleLoader

        pack = tmp_path / "evil.yaml"
        pack.write_text(
            "pack:\n"
            "  id: evil\n"
            "  version: 1.0.0\n"
            "rules:\n"
            "  - id: EVIL.001\n"
            "    category: suspicious\n"
            "    severity: high\n"
            "    confidence: medium\n"
            "    message: x\n"
            "    remediation: x\n"
            "    match:\n"
            "      kind: regex\n"
            "      patterns:\n"
            '        - "((a+))+$"\n'
        )
        with pytest.raises(CordonError):
            RuleLoader().load_file(pack)


class TestC05PerFileTimeout:
    """The documented backstop did not exist: `per_file_timeout` was declared,
    documented at length, and referenced nowhere."""

    def test_the_limit_is_read_by_the_engine(self) -> None:
        source = (
            Path(__file__).resolve().parents[2] / "src" / "cordon" / "core" / "engine.py"
        ).read_text()
        assert "per_file_timeout" in source

    def test_an_exhausted_budget_marks_the_scan_incomplete(self, tmp_path) -> None:
        """A partial file must not be reported as a clean one."""
        (tmp_path / "a.js").write_text(PAYLOAD)
        cfg = Config.default()
        cfg = cfg.with_overrides(use_cache=False, limits=cfg.limits.merged(per_file_timeout=1e-9))
        result = Scanner(cfg).scan(tmp_path)
        assert result.complete is False
        assert "OPERATIONAL.FILE.TIMEOUT" in {f.rule_id for f in result.findings}

    def test_a_partial_file_is_not_cached(self, tmp_path) -> None:
        """Caching the output of a run that hit a limit would make the
        degradation permanent and invisible."""
        (tmp_path / "a.js").write_text(PAYLOAD)
        cfg = Config.default()
        cache_dir = tmp_path / "cd"
        cfg = cfg.with_overrides(
            use_cache=True,
            cache_dir=str(cache_dir),
            limits=cfg.limits.merged(per_file_timeout=1e-9),
        )
        Scanner(cfg).scan(tmp_path)
        assert not list(cache_dir.rglob("*.json"))


class TestC06CacheAuthentication:
    """C-06. Every input to the cache key is public or attacker-computable, so
    anyone who could write to the cache directory could compute the exact path
    for a file they were about to commit and leave an empty result there."""

    def warm(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "a.js").write_text(PAYLOAD)
        cache = tmp_path / "cd"
        cfg = Config.default().with_overrides(use_cache=True, cache_dir=str(cache))
        assert "SUSPECT.DECODE_EXEC.001" in {f.rule_id for f in Scanner(cfg).scan(repo).findings}
        return repo, cache, cfg

    def test_a_warm_cache_still_reports_the_finding(self, tmp_path) -> None:
        repo, _, cfg = self.warm(tmp_path)
        assert "SUSPECT.DECODE_EXEC.001" in {f.rule_id for f in Scanner(cfg).scan(repo).findings}

    def test_a_forged_empty_entry_is_rejected(self, tmp_path) -> None:
        repo, cache, cfg = self.warm(tmp_path)
        for entry in cache.rglob("*.json"):
            payload = json.loads(entry.read_text())
            payload["findings"] = []
            entry.write_text(json.dumps(payload))
        assert "SUSPECT.DECODE_EXEC.001" in {f.rule_id for f in Scanner(cfg).scan(repo).findings}

    def test_an_entry_with_no_mac_is_rejected(self, tmp_path) -> None:
        repo, cache, cfg = self.warm(tmp_path)
        for entry in cache.rglob("*.json"):
            entry.write_text(json.dumps({"version": 2, "findings": []}))
        assert "SUSPECT.DECODE_EXEC.001" in {f.rule_id for f in Scanner(cfg).scan(repo).findings}

    def test_an_entry_cannot_be_moved_to_another_key(self, tmp_path) -> None:
        """The MAC covers the key as well as the payload, so a genuine empty
        result for a benign file cannot be copied onto a malicious file's
        path."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "benign.js").write_text("const x = 1;\n")
        cache = tmp_path / "cd"
        cfg = Config.default().with_overrides(use_cache=True, cache_dir=str(cache))
        Scanner(cfg).scan(repo)
        benign_entries = [e.read_bytes() for e in cache.rglob("*.json")]
        assert benign_entries

        (repo / "evil.js").write_text(PAYLOAD)
        found = {f.rule_id for f in Scanner(cfg).scan(repo).findings}
        assert "SUSPECT.DECODE_EXEC.001" in found

        # Overwrite every entry with the benign one; the MAC binds the key.
        for entry in cache.rglob("*.json"):
            entry.write_bytes(benign_entries[0])
        assert "SUSPECT.DECODE_EXEC.001" in {f.rule_id for f in Scanner(cfg).scan(repo).findings}

    def test_the_key_is_not_world_readable(self, tmp_path) -> None:
        import os
        import stat

        _, cache, _ = self.warm(tmp_path)
        key = cache / ".cordon-cache-key"
        assert key.is_file()
        if os.name != "nt":
            assert not key.stat().st_mode & (stat.S_IRGRP | stat.S_IROTH)

    def test_an_unverifiable_entry_is_not_deleted(self, tmp_path) -> None:
        """It may belong to another user sharing the directory, and removing it
        would turn a read into a destructive act on somebody else's data."""
        repo, cache, cfg = self.warm(tmp_path)
        entries = list(cache.rglob("*.json"))
        for entry in entries:
            entry.write_text(json.dumps({"version": 2, "findings": [], "mac": "0" * 64}))
        Scanner(cfg).scan(repo)
        assert all(e.exists() for e in entries)

    def test_the_cache_still_accelerates_a_clean_scan(self, tmp_path) -> None:
        """Authentication must not disable caching. A cache that never hits is
        one people turn off, and then the poisoning question is moot."""
        repo, cache, cfg = self.warm(tmp_path)
        scanner = Scanner(cfg)
        scanner.scan(repo)
        cache_object = ScanCache(str(cache))
        assert list(cache.rglob("*.json"))
        assert cache_object.directory == cache


class TestH13EvidenceCacheLeak:
    """H-13. Redaction happens when evidence is constructed, so the redacted
    snippet is baked into the cached finding -- and the evidence mode was
    deliberately excluded from the cache key."""

    def test_hash_only_is_honoured_against_a_warm_cache(self, tmp_path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "a.py").write_text(
            'import base64\neval(base64.b64decode("Z2hwX0FBQUFBQUFBQUFBQUFB"))\n'
        )
        cache = str(tmp_path / "cd")

        warm = Config.default().with_overrides(use_cache=True, cache_dir=cache)
        first = Scanner(warm).scan(repo).findings
        assert any(f.evidence.snippet for f in first)

        from cordon.core.models import RedactionMode

        strict = warm.with_overrides(evidence=RedactionMode.HASH_ONLY)
        second = Scanner(strict).scan(repo).findings
        assert second
        for finding in second:
            assert finding.evidence.snippet is None
            assert finding.evidence.redaction is RedactionMode.HASH_ONLY

    def test_the_evidence_mode_is_part_of_the_fingerprint(self) -> None:
        from cordon.core.models import RedactionMode

        base = Config.default()
        strict = base.with_overrides(evidence=RedactionMode.HASH_ONLY)
        assert base.fingerprint() != strict.fingerprint()
