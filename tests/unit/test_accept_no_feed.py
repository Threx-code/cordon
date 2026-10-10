"""`policy.accept_no_feed`: an ecosystem no advisory source covers, accepted by name.

Measured on 84 real repositories: 15 were incomplete only because an ecosystem they use has no
advisory source at all (Homebrew, Nix, CocoaPods, Bazel, conda, Helm, Terraform, vcpkg) -- a
GitHub Action gate they could never pass. Strict by default; a project names the ecosystems whose
gap it accepts, where reviewers see it, and an organisation policy can narrow that.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config, ConfigParser, Policy, RestrictedYamlParser
from cordon_scanner.core.errors import ConfigError

NO_FEED = "OPERATIONAL.ADVISORY.NO_FEED.001"


class TestTheSetting:
    @staticmethod
    def parse(text: str) -> Config:
        return Config.from_dict(
            RestrictedYamlParser._load_yaml_subset(text, source="test.yaml"), source="test.yaml"
        )

    def test_it_is_read(self) -> None:
        config = self.parse("policy:\n  accept_no_feed: [homebrew, nix]\n")
        assert config.policy.accept_no_feed == frozenset({"homebrew", "nix"})

    def test_unset_is_none_not_empty(self) -> None:
        assert self.parse("policy:\n  fail_on_incomplete: true\n").policy.accept_no_feed is None

    def test_a_name_that_is_no_ecosystem_is_refused(self) -> None:
        with pytest.raises(ConfigError, match="names no ecosystem"):
            self.parse("policy:\n  accept_no_feed: [homebrw]\n")

    @pytest.mark.parametrize(
        ("org", "repo", "merged"),
        [
            (None, frozenset({"homebrew"}), frozenset({"homebrew"})),
            (frozenset({"nix"}), None, frozenset({"nix"})),
            (frozenset({"nix"}), frozenset({"nix", "homebrew"}), frozenset({"nix"})),
            (frozenset(), frozenset({"homebrew"}), frozenset()),
            (None, None, None),
        ],
    )
    def test_merged_with_an_organisation_policy(self, org, repo, merged) -> None:
        result = ConfigParser._stricter_policy(
            Policy(accept_no_feed=org), Policy(accept_no_feed=repo)
        )
        assert result.accept_no_feed == merged


class TestTheScan:
    @staticmethod
    def scan(tmp_path, config: str | None) -> tuple[bool, list[str]]:
        (tmp_path / "Brewfile").write_text('brew "jq"\n', encoding="utf-8")
        base = Config.default()
        if config is not None:
            (tmp_path / ".cordon.yaml").write_text(config, encoding="utf-8")
            base = Config.from_file(tmp_path / ".cordon.yaml")
        result = Scanner(base.with_overrides(use_cache=False)).scan(tmp_path)
        return result.complete, [f.message for f in result.findings if f.rule_id == NO_FEED]

    def test_strict_by_default(self, tmp_path) -> None:
        complete, notes = self.scan(tmp_path, None)
        assert complete is False
        assert len(notes) == 1

    def test_accepted_it_is_still_named_but_does_not_make_the_scan_incomplete(
        self, tmp_path
    ) -> None:
        complete, notes = self.scan(tmp_path, "policy:\n  accept_no_feed: [homebrew]\n")
        assert complete is True
        assert len(notes) == 1 and "accept_no_feed" in notes[0]

    def test_accepting_another_ecosystem_changes_nothing(self, tmp_path) -> None:
        complete, _ = self.scan(tmp_path, "policy:\n  accept_no_feed: [nix]\n")
        assert complete is False
