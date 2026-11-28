"""What the `scan` flags turn into: the overrides, the configuration and the refusals (`cli/commands/scan/command.py`)."""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner.cli.commands.scan.command import ScanCommand
from cordon_scanner.cli.parser import CommandParser
from cordon_scanner.foundation.errors import ConfigError, CordonError
from cordon_scanner.foundation.models import Confidence, RedactionMode


class _Base:
    @staticmethod
    def parse(tmp_path: Path, *flags: str) -> object:
        return CommandParser.build().parse_args(["scan", *flags, str(tmp_path)])

    @pytest.fixture(autouse=True)
    def _clean_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in ("CORDON_OFFLINE", "CORDON_CLAMAV", "CORDON_REGISTRY_TOKENS"):
            monkeypatch.delenv(name, raising=False)


class TestTarget(_Base):
    def test_verify_secrets_without_online_is_refused_before_anything_is_read(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(ConfigError, match="--verify-secrets sends each found credential"):
            ScanCommand._target(self.parse(tmp_path, "--verify-secrets"))

    def test_a_target_that_does_not_exist_is_refused_with_a_hint(self, tmp_path: Path) -> None:
        args = CommandParser.build().parse_args(["scan", str(tmp_path / "nope")])
        with pytest.raises(CordonError, match="target does not exist"):
            ScanCommand._target(args)

    def test_host_reads_a_filesystem_root_so_a_file_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "f.txt"
        target.write_text("x", encoding="utf-8")
        args = CommandParser.build().parse_args(["scan", "--host", str(target)])
        with pytest.raises(ConfigError, match="is not a directory"):
            ScanCommand._target(args)


class TestOverrides(_Base):
    def test_each_flag_becomes_the_setting_it_names(self, tmp_path: Path) -> None:
        args = self.parse(
            tmp_path,
            "--confidence",
            "high",
            "--evidence",
            "hash_only",
            "--rules",
            "pack.yaml",
            "--reachability",
            "--no-expand",
            "--clamav",
            "/run/clamd.sock",
            "--keyring",
            "keys.gpg",
            "--rule-module-data",
            "mod=data.json",
            "--judge",
            "local",
            "--judge-blocks",
            "--judge-max-calls",
            "0",
        )
        overrides = ScanCommand._overrides(args)
        assert overrides["confidence_threshold"] is Confidence.parse("high")
        assert overrides["evidence"] is RedactionMode("hash_only")
        assert overrides["extra_rule_paths"] == ("pack.yaml",)
        assert overrides["reachability"] is True
        assert overrides["expand_archives"] is False
        assert overrides["clamav"] == "/run/clamd.sock"
        assert overrides["keyrings"] == ("keys.gpg",)
        assert overrides["rule_module_data"] == (("mod", "data.json"),)
        assert overrides["judge"] == "local"
        assert overrides["judge_blocks"] is True
        assert overrides["judge_max_calls"] == 1

    def test_a_rule_module_data_without_a_file_is_refused_by_name(self, tmp_path: Path) -> None:
        args = self.parse(tmp_path, "--rule-module-data", "mod")
        with pytest.raises(ConfigError, match="MODULE=FILE, not 'mod'"):
            ScanCommand._overrides(args)

    def test_a_confidence_level_that_does_not_exist_is_a_config_error_not_a_crash(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(ConfigError):
            ScanCommand._overrides(self.parse(tmp_path, "--confidence", "certain-ish"))

    def test_a_registry_token_that_is_not_a_variable_name_is_refused(self, tmp_path: Path) -> None:
        args = self.parse(
            tmp_path, "--registry-token", "https://registry.example.invalid=not a name"
        )
        with pytest.raises(ConfigError):
            ScanCommand._overrides(args)


class TestConfigure(_Base):
    def test_a_cache_directory_and_the_hardening_switch_reach_the_configuration(
        self, tmp_path: Path
    ) -> None:
        args = self.parse(tmp_path, "--cache-dir", str(tmp_path / "cache"), "--hardening")
        config, _ = ScanCommand._configure(args, tmp_path, ScanCommand._overrides(args))
        assert str(config.cache_dir) == str(tmp_path / "cache")
        assert config.policy.hardening is True

    def test_a_fail_on_level_that_does_not_exist_is_named_as_the_flag(self, tmp_path: Path) -> None:
        args = self.parse(tmp_path, "--fail-on", "extreme")
        with pytest.raises(ConfigError, match="--fail-on:"):
            ScanCommand._configure(args, tmp_path, ScanCommand._overrides(args))

    def test_the_cloud_policy_flag_and_a_policy_file_cannot_both_name_the_policy(
        self, tmp_path: Path
    ) -> None:
        policy = tmp_path / "policy.yaml"
        policy.write_text("version: 1\n", encoding="utf-8")
        args = self.parse(tmp_path, "--cloud-policy", "--policy", str(policy))
        with pytest.raises(ConfigError, match="both name the organisation policy"):
            ScanCommand._configure(args, tmp_path, {})
