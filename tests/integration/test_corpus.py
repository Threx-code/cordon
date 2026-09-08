"""Corpus tests: detection and false-positive control.

These are the tests that decide whether the product works. Everything else
verifies that a component behaves as designed; these two verify that the design
catches what it claims to catch and stays quiet on code that is fine.

The false-positive suite is treated as exactly as important as the detection
suite, and that is a deliberate stance. A scanner that misses a payload has
failed once. A scanner that cries wolf gets a blanket exception appended to it
and then misses everything, forever, while still appearing to run.

Both suites are discovered from the corpus directory rather than enumerated
here, so adding a sample is adding a directory. The intent is that every new
detection and every reported false positive becomes a permanent sample before
the change that addresses it merges.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon import Scanner
from cordon.core.config import Config, RestrictedYamlParser
from cordon.core.models import Category, Severity

CORPUS = Path(__file__).resolve().parents[2] / "corpus"
BENIGN = CORPUS / "benign"
MALICIOUS = CORPUS / "malicious"


def malicious_samples() -> list[Path]:
    if not MALICIOUS.is_dir():
        return []
    return sorted(p for p in MALICIOUS.iterdir() if (p / "expected.yaml").is_file())


def benign_files() -> list[Path]:
    if not BENIGN.is_dir():
        return []
    return sorted(p for p in BENIGN.rglob("*") if p.is_file())


def load_expectation(sample: Path) -> dict:
    return RestrictedYamlParser._load_yaml_subset(
        (sample / "expected.yaml").read_text(encoding="utf-8"),
        source=str(sample / "expected.yaml"),
    )


@pytest.fixture(scope="module")
def scanner() -> Scanner:
    """One scanner for the whole module.

    Also exercises the reuse guarantee: rules are compiled once at construction,
    and repeated scans must not depend on it having been freshly built.

    Caching is off. These tests assert what the detectors currently do, and a
    warm cache answers with what they did when the entry was written -- so a
    change to a detector's behaviour showed up here as a pass until the
    developer happened to clear their cache. That is the wrong way round for the
    suite that guards false-positive rate.
    """
    return Scanner(Config.default().with_overrides(use_cache=False))


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.mark.corpus
class TestMaliciousCorpus:
    """Every malicious sample must produce the finding it declares."""

    @pytest.mark.parametrize("sample", malicious_samples(), ids=lambda p: p.name)
    def test_sample_is_detected(self, scanner: Scanner, sample: Path) -> None:
        expectation = load_expectation(sample)
        result = scanner.scan(sample)
        found = {f.rule_id for f in result.findings}

        for requirement in expectation.get("must_find", []):
            rule_id = requirement["rule"]
            assert rule_id in found, (
                f"{sample.name}: expected {rule_id} but got {sorted(found) or 'nothing'}.\n"
                f"{expectation.get('description', '').strip()}"
            )

            matches = [f for f in result.findings if f.rule_id == rule_id]

            if "path" in requirement:
                paths = {f.location.path for f in matches}
                assert requirement["path"] in paths, (
                    f"{sample.name}: {rule_id} fired but at {paths}, not {requirement['path']}"
                )

            if "min_severity" in requirement:
                floor = Severity.parse(requirement["min_severity"])
                best = max(f.severity for f in matches)
                assert best >= floor, (
                    f"{sample.name}: {rule_id} reported {best}, below the required {floor}"
                )

            if "category" in requirement:
                categories = {str(f.category) for f in matches}
                assert requirement["category"] in categories, (
                    f"{sample.name}: {rule_id} was categorised {categories}, "
                    f"not {requirement['category']}"
                )

        for forbidden in expectation.get("must_not_find", []):
            assert forbidden["rule"] not in found, (
                f"{sample.name}: {forbidden['rule']} fired but must not"
            )

    @pytest.mark.parametrize("sample", malicious_samples(), ids=lambda p: p.name)
    def test_evidence_does_not_leak_credentials(self, scanner: Scanner, sample: Path) -> None:
        """A finding must never carry the value that caused it.

        Reports travel further than the repository does: into CI logs, pull
        request comments, and SARIF uploaded to third parties. The tool that
        finds a leaked secret must not be the mechanism that spreads it.
        """
        expectation = load_expectation(sample)
        if not expectation.get("must_not_leak_evidence"):
            return

        for finding in scanner.scan(sample).findings:
            if finding.evidence.snippet:
                lowered = finding.evidence.snippet.lower()
                for marker in ("_authtoken", "npm_token", "secret_key", "private_key"):
                    assert marker not in lowered, (
                        f"{sample.name}: {finding.rule_id} leaked {marker!r} "
                        f"into evidence: {finding.evidence.snippet!r}"
                    )
            assert finding.evidence.match_hash, "every finding must carry a match hash"


# ---------------------------------------------------------------------------
# False positives
# ---------------------------------------------------------------------------


@pytest.mark.corpus
class TestBenignCorpus:
    """Realistic code must stay quiet.

    A regression here blocks a release exactly as hard as a missed detection.
    """

    def test_benign_corpus_produces_nothing_significant(self, scanner: Scanner) -> None:
        result = scanner.scan(BENIGN)
        noisy = [
            f
            for f in result.findings
            if f.category is not Category.OPERATIONAL and f.severity > Severity.LOW
        ]
        assert not noisy, "false positives on benign code:\n" + "\n".join(
            f"  {f.severity} {f.rule_id} at {f.location} :: {f.evidence.snippet}" for f in noisy
        )

    @pytest.mark.parametrize("path", benign_files(), ids=lambda p: p.name)
    def test_each_benign_file_individually(self, scanner: Scanner, path: Path) -> None:
        """Also scanned one at a time.

        A file that is quiet inside a directory but noisy alone would indicate
        that a finding depends on unrelated neighbours, which would make results
        depend on how the scan was invoked.
        """
        result = scanner.scan(path)
        noisy = [
            f
            for f in result.findings
            if f.category is not Category.OPERATIONAL and f.severity > Severity.LOW
        ]
        assert not noisy, f"{path.name} produced {[f.rule_id for f in noisy]}"

    def test_decode_without_execution_is_not_flagged(self, scanner: Scanner) -> None:
        """The distinction the whole capability model rests on.

        Decoding a data URL is ordinary. Decoding and then executing is a
        loader. If this test fails, the composite model has collapsed into
        single-signal matching and the tool has become unusable.
        """
        result = scanner.scan(BENIGN / "javascript" / "image-utils.js")
        assert not [f for f in result.findings if f.rule_id == "SUSPECT.DECODE_EXEC.001"]

    def test_spawn_without_egress_is_not_flagged(self, scanner: Scanner) -> None:
        """A build helper legitimately shells out to git and make."""
        result = scanner.scan(BENIGN / "python" / "build_helper.py")
        assert not [
            f for f in result.findings if f.rule_id in {"SUSPECT.DROPPER.001", "SUSPECT.EXFIL.001"}
        ]

    def test_named_env_reads_are_not_credential_harvesting(self, scanner: Scanner) -> None:
        """Reading a named setting is not the same as serialising the whole
        environment, and a rule that cannot tell them apart fires on every
        configuration module in existence."""
        result = scanner.scan(BENIGN / "python" / "settings.py")
        assert not [f for f in result.findings if f.severity > Severity.LOW]


# ---------------------------------------------------------------------------
# Cross-cutting guarantees
# ---------------------------------------------------------------------------


@pytest.mark.corpus
class TestScanGuarantees:
    def test_scans_are_deterministic(self, scanner: Scanner) -> None:
        """Constraint C5. Baselines, caching and reproducible gates all depend
        on identical inputs producing identical output."""
        first = scanner.scan(MALICIOUS)
        second = scanner.scan(MALICIOUS)

        assert [f.fingerprint for f in first.findings] == [f.fingerprint for f in second.findings]
        assert [f.risk.value for f in first.findings] == [f.risk.value for f in second.findings]

    def test_scanner_is_reusable(self, scanner: Scanner) -> None:
        """Rules are compiled once at construction. A second scan through the
        same instance must produce the same findings as the first.

        Findings, not the whole document: duration and cache statistics are
        observations of one particular run and legitimately differ. Determinism
        is a claim about what was found, not about how long it took.
        """
        first = scanner.scan(MALICIOUS / "decode-exec-js")
        second = scanner.scan(MALICIOUS / "decode-exec-js")
        assert [f.to_dict() for f in first.findings] == [f.to_dict() for f in second.findings]

    def test_results_are_sorted_by_severity(self, scanner: Scanner) -> None:
        result = scanner.scan(MALICIOUS)
        severities = [
            int(f.severity) for f in result.findings if f.category is not Category.OPERATIONAL
        ]
        assert severities == sorted(severities, reverse=True)

    def test_findings_are_immutable(self, scanner: Scanner) -> None:
        """A caller must not be able to mutate a result and re-serialise it as
        though a scan produced it."""
        result = scanner.scan(MALICIOUS / "decode-exec-js")
        finding = result.findings[0]
        with pytest.raises((AttributeError, TypeError)):
            finding.severity = Severity.INFO  # type: ignore[misc]

    def test_scan_reports_completeness(self, scanner: Scanner) -> None:
        result = scanner.scan(BENIGN)
        assert result.complete is True

    def test_result_records_what_produced_it(self, scanner: Scanner) -> None:
        """A result must be self-describing: months later it should still be
        possible to say which rules and which settings produced it."""
        result = scanner.scan(BENIGN)
        assert result.rulepack_hash
        assert result.config_hash
        assert result.engine_version
        assert result.schema_version >= 1

    def test_install_hook_context_escalates(self, scanner: Scanner) -> None:
        """The core product thesis, asserted directly.

        The same capability combination is suspicious in application code and
        malicious in an install hook, because install-time code runs unprompted,
        as the developer, before any other control applies.
        """
        hook = scanner.scan(MALICIOUS / "exfil-python-install-hook")
        exfil = [f for f in hook.findings if f.rule_id == "MALWARE.EXFIL.001"]
        assert exfil, "expected an exfiltration finding in the install hook"
        assert exfil[0].category is Category.MALICIOUS
        assert exfil[0].severity is Severity.CRITICAL

    def test_same_capabilities_are_quiet_outside_a_hook(self, scanner: Scanner, tmp_path) -> None:
        """The other half of the thesis, and the one that controls noise.

        Credential access plus network egress is what an application does all
        day. Without the install-hook context the pair must not produce a
        malicious finding, or every configuration module in existence becomes a
        critical alert.
        """
        source = (MALICIOUS / "exfil-python-install-hook" / "setup.py").read_text()
        # Identical code, in a module that does not execute at install time.
        (tmp_path / "reporting.py").write_text(source)

        result = scanner.scan(tmp_path)
        assert not [f for f in result.findings if f.category is Category.MALICIOUS], (
            "install-time rules fired outside an install hook"
        )


# ---------------------------------------------------------------------------
# Dogfooding
# ---------------------------------------------------------------------------


@pytest.mark.corpus
class TestSelfScan:
    """Cordon scans Cordon.

    A security tool that cannot pass its own checks has no standing to enforce
    them, and the failures this catches are real rather than ceremonial: a
    private-key header, a complete credential literal and a packer signature all
    reached the repository as test fixtures and were all true positives.

    Fixtures with payload or credential shapes therefore live in the corpus, or
    are assembled at runtime. The corpus is excluded because it exists to hold
    such samples; the rest of the tree is not, because a directory-shaped
    exclusion is exactly what this tool argues against.

    The subject is what git tracks, which is what "the repository" means and
    what CI actually receives. A developer's working tree also holds a
    virtualenv, build output and local scratch directories -- none of which the
    project ships, and any of which can contain a genuine payload that the
    scanner is right to flag and this test has no business failing on. The
    narrowing is expressed with the tool's own `--tracked` source rather than
    with an exclusion list, which would need extending every time somebody
    created a directory.
    """

    def test_the_repository_scans_clean(self, scanner: Scanner) -> None:
        repository = Path(__file__).resolve().parents[2]
        result = self._scan_tracked(repository, scanner)

        offending = [
            f
            for f in result.active
            if f.category is not Category.OPERATIONAL
            and f.severity >= Severity.MEDIUM
            and not f.location.path.startswith("corpus/")
        ]
        assert not offending, "Cordon does not pass its own scan:\n" + "\n".join(
            f"  {f.severity} {f.rule_id} at {f.location}" for f in offending
        )

    @staticmethod
    def _scan_tracked(repository: Path, scanner: Scanner):
        """Scan the tracked files, falling back to the whole tree without git.

        The fallback keeps the test meaningful in a source tarball, where there
        is no repository to ask. It is noisier there, and that is the right way
        round: a false failure is visible, a skipped self-scan is not.
        """
        import shutil

        from cordon import Scanner as _Scanner
        from cordon.sources.git import GitRepository

        if shutil.which("git") is None or GitRepository.discover(repository) is None:
            return scanner.scan(repository)

        from cordon.sources.git import GitPathSource

        tracked = GitRepository(repository).tracked_files()
        return _Scanner(scanner.config, source=GitPathSource(tracked, mode="tracked")).scan(
            repository
        )
