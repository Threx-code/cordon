"""`config validate | fetch-policy | policy-drift | explain`: what each prints and refuses (`cli/commands/config.py`)."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cli.commands.config import ConfigCommand
from cordon_scanner.foundation.errors import ConfigError, ExitCode, PolicyViolationError

POLICY = """
version: 1
name: test-baseline
enforce:
  min_severity_threshold: medium
  allow_network: false
suppressions:
  max_duration_days: 90
  require_justification: true
  require_approver: true
  forbid_categories: [malicious]
  forbid_path_only: true
"""


class _Base:
    @staticmethod
    def run(action: str | None, **over: Any) -> int:
        base: dict[str, Any] = {"path": None, "policy": None}
        return ConfigCommand.run(argparse.Namespace(config_command=action, **{**base, **over}))

    @staticmethod
    def file(tmp_path: Path, name: str, text: str) -> Path:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return path


class TestValidate(_Base):
    def test_a_configuration_checked_against_an_organisation_policy_is_valid_when_it_fits(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config = self.file(
            tmp_path, "cordon.yaml", "version: 1\nscan:\n  severity_threshold: low\n"
        )
        policy = self.file(tmp_path, "policy.yaml", POLICY)
        assert self.run("validate", path=str(config), policy=str(policy)) == int(ExitCode.CLEAN)
        assert "configuration is valid" in capsys.readouterr().out

    def test_a_configuration_weaker_than_the_policy_is_refused(self, tmp_path: Path) -> None:
        config = self.file(
            tmp_path, "cordon.yaml", "version: 1\nscan:\n  severity_threshold: high\n"
        )
        policy = self.file(tmp_path, "policy.yaml", POLICY)
        with pytest.raises(PolicyViolationError, match="less strict than the organisation minimum"):
            self.run("validate", path=str(config), policy=str(policy))


class TestFetchPolicy(_Base):
    def test_a_local_path_is_refused_because_the_command_is_for_the_https_address(self) -> None:
        with pytest.raises(ConfigError, match="https URL with its #sha256= digest"):
            self.run("fetch-policy", url="policy.yaml")


class TestPolicyDrift(_Base):
    def test_a_vendored_policy_that_does_not_exist_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="no policy at"):
            self.run("policy-drift", vendored=str(tmp_path / "gone.yaml"), published="x")


class TestExplain(_Base):
    def test_the_origin_of_each_setting_the_file_made_is_listed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config = self.file(
            tmp_path, "cordon.yaml", "version: 1\nscan:\n  severity_threshold: low\n"
        )
        assert self.run("explain", path=str(config)) == int(ExitCode.CLEAN)
        out = capsys.readouterr().out
        assert "effective configuration" in out
        assert "\norigins\n" in out
        assert "scan.severity_threshold" in out

    def test_an_unknown_action_is_a_config_error(self) -> None:
        with pytest.raises(ConfigError, match="unknown config action: nope"):
            self.run("nope")
