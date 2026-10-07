"""Tutorials 25 and 26 are rendered from what ships, and must match it (`tests/tutorial_reference.py`)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))

from tutorial_reference import (  # noqa: E402
    AgentTutorial,
    CommandTutorial,
    EcosystemTutorial,
    RuleTutorial,
)


class TestTheReferenceIsCurrent:
    def test_every_ecosystem(self) -> None:
        on_disk = (ROOT / "tutorials" / "25-every-ecosystem.md").read_text(encoding="utf-8")
        assert on_disk == EcosystemTutorial.render(), (
            "tutorials/25-every-ecosystem.md is out of date. Regenerate it:\n"
            "  python tests/tutorial_reference.py ecosystems > tutorials/25-every-ecosystem.md"
        )

    def test_every_command(self) -> None:
        on_disk = (ROOT / "tutorials" / "26-every-command.md").read_text(encoding="utf-8")
        assert on_disk == CommandTutorial.render(), (
            "tutorials/26-every-command.md is out of date. Regenerate it:\n"
            "  python tests/tutorial_reference.py commands > tutorials/26-every-command.md"
        )

    def test_every_agent_location(self) -> None:
        on_disk = (ROOT / "tutorials" / "27-every-agent-location.md").read_text(encoding="utf-8")
        assert on_disk == AgentTutorial.render(), (
            "tutorials/27-every-agent-location.md is out of date. Regenerate it:\n"
            "  python tests/tutorial_reference.py agents > tutorials/27-every-agent-location.md"
        )

    def test_every_rule(self) -> None:
        on_disk = (ROOT / "tutorials" / "28-every-rule.md").read_text(encoding="utf-8")
        assert on_disk == RuleTutorial.render(), (
            "tutorials/28-every-rule.md is out of date. Regenerate it:\n"
            "  python tests/tutorial_reference.py rules > tutorials/28-every-rule.md"
        )

    def test_every_shipped_rule_is_listed(self) -> None:
        from cordon_scanner.intel.atr import AtrEngine

        text = RuleTutorial.render()
        for rule_id, *_ in RuleTutorial.declared():
            assert f"`{rule_id}`" in text
        for rule in AtrEngine.catalogue().rules:
            assert f"`{rule.rule_id}`" in text

    def test_every_registered_ecosystem_has_a_section(self) -> None:
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        text = EcosystemTutorial.render()
        for ecosystem_id in EcosystemRegistry.BY_ID:
            assert f"Ecosystem id `{ecosystem_id}`" in text

    def test_every_language_has_a_row(self) -> None:
        from cordon_scanner.langs.registry import LanguageRegistry

        text = EcosystemTutorial.render()
        for _suffix, language in LanguageRegistry.EXTENSIONS:
            assert f"| {EcosystemTutorial.LANGUAGE_NAMES[language]} |" in text

    def test_every_command_has_a_section(self) -> None:
        from cordon_scanner.cli.main import CommandLine

        text = CommandTutorial.render()
        for name in CommandTutorial.subparsers(CommandLine.build_parser()):
            assert f"\n## {name}\n" in text
