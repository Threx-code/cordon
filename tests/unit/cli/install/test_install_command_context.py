"""The guarded-install command and the context every tool shares: how an install that cannot be checked
or is blocked is reported, and what the exit code says (`cli/commands/install/command.py`,
`context.py`)."""

from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from install_kit import GuardKit

from cordon_scanner.cli.commands.install.command import InstallGuardCommand
from cordon_scanner.cli.commands.install.context import InstallContext, SdistBlocked
from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.foundation.models import Severity
from cordon_scanner.sources.install.guard import InstallGuard
from cordon_scanner.sources.install.plan import (
    InstallPlan,
    InstallRefused,
    InstallVerdict,
    Subprocesses,
)


class TestTheCommand:
    @staticmethod
    def _table(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
        monkeypatch.setattr(
            InstallGuardCommand,
            "_table",
            classmethod(lambda cls: {"npm": (lambda rest: True, handler)}),
        )
        monkeypatch.setattr(
            Subprocesses, "executable", staticmethod(lambda tool: f"/usr/bin/{tool}")
        )
        monkeypatch.setattr(
            InstallContext, "made", classmethod(lambda cls, own: GuardKit.context())
        )

    def test_a_package_the_scan_blocked_while_building_ends_with_the_findings_exit_code(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        finding = SimpleNamespace(
            rule_id="MAL.X.001", severity="critical", message="m", location=None
        )

        def handler(executable: str, rest: list[str], context: Any) -> int:
            raise SdistBlocked("pkg==1.0", (finding,))

        self._table(monkeypatch, handler)
        assert InstallGuardCommand.main("npm", ["install", "pkg"]) == int(ExitCode.FINDINGS)
        err = capsys.readouterr().err
        assert "nothing was installed; npm never built pkg==1.0." in err

    def test_an_install_that_cannot_be_checked_says_why_and_ends_as_a_scanner_error(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        def handler(executable: str, rest: list[str], context: Any) -> int:
            raise InstallRefused("a hash did not match")

        self._table(monkeypatch, handler)
        assert InstallGuardCommand.main("npm", ["install"]) == int(ExitCode.SCANNER_ERROR)
        err = capsys.readouterr().err
        assert "a hash did not match\nNothing was installed." in err

    def test_a_refusal_with_a_hint_shows_the_hint_after_the_message(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        def handler(executable: str, rest: list[str], context: Any) -> int:
            raise InstallRefused("no lock", hint="Run npm install first.")  # type: ignore[call-arg]

        self._table(monkeypatch, handler)
        assert InstallGuardCommand.main("npm", ["ci"]) == int(ExitCode.SCANNER_ERROR)
        assert "no lock\nRun npm install first.\nNothing was installed." in capsys.readouterr().err

    def test_every_guarded_tool_has_a_subcommand_and_the_notes_are_in_its_help(self) -> None:
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        InstallGuardCommand.add_parser(sub)
        assert sorted(sub.choices) == sorted(InstallGuardCommand.TOOLS)
        for tool, note in InstallGuardCommand.NOTES.items():
            assert note in sub.choices[tool].description
        assert InstallGuardCommand.NOTES.keys() <= set(InstallGuardCommand.TOOLS)
        parsed = parser.parse_args(["npm", "install", "x"])
        assert parsed.arguments == ["install", "x"]

    def test_the_table_names_a_handler_for_every_tool(self) -> None:
        table = InstallGuardCommand._table()
        assert set(table) == set(InstallGuardCommand.TOOLS)
        for guarded, handler in table.values():
            assert callable(guarded) and callable(handler)


class TestTheContext:
    def test_an_option_without_its_value_stops_the_command(self) -> None:
        with pytest.raises(SystemExit, match="--cordon-config needs a value"):
            InstallContext.options(["--cordon-config"])

    def test_the_last_value_given_for_an_option_wins_in_the_context(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CORDON_INSTALL_CACHE", "0")
        context = InstallContext.made({"fail-on": ["high", "medium"]})
        assert context.config.policy.fail_on_severity == Severity.MEDIUM
        assert InstallContext.made({"no-cache": ["1"]}).cache is None

    @staticmethod
    def _check(monkeypatch: pytest.MonkeyPatch, verdict: Any) -> InstallContext:
        monkeypatch.setattr(
            InstallGuard,
            "check",
            staticmethod(lambda plan, scan, fetch, scratch, cache: verdict(plan)),
        )
        return InstallContext(
            config=None,  # type: ignore[arg-type]
            scan=lambda d: (),
            registries=SimpleNamespace(fetch=lambda *a: b""),  # type: ignore[arg-type]
            cache=None,
            out=io.StringIO(),
        )

    def test_a_resolve_that_found_packages_says_how_many_and_how_many_were_remembered(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = self._check(monkeypatch, lambda plan: InstallVerdict(plan, {}, remembered=2))
        plan = InstallPlan("npm", [GuardKit.file("a"), GuardKit.file("b")])
        assert context.check(plan, tmp_path).ok
        said = context.out.getvalue()  # type: ignore[attr-defined]
        assert "resolved 2 packages; fetching and scanning them" in said
        assert "2 packages passed (2 remembered clean); installing exactly those" in said

    def test_one_package_is_singular_and_nothing_remembered_is_not_mentioned(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = self._check(monkeypatch, lambda plan: InstallVerdict(plan, {}))
        context.check(InstallPlan("npm", [GuardKit.file("a")]), tmp_path)
        said = context.out.getvalue()  # type: ignore[attr-defined]
        assert "resolved 1 package;" in said and "1 package passed; installing" in said

    def test_what_a_tool_fetched_into_the_project_is_scanned_and_reported_as_such(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = self._check(monkeypatch, lambda plan: InstallVerdict(plan, {}))
        assert context.check(InstallPlan("terraform", local=[tmp_path]), tmp_path).ok
        said = context.out.getvalue()  # type: ignore[attr-defined]
        assert "scanning what terraform fetched, before anything runs it" in said
        assert "what terraform fetched passed" in said

    def test_a_block_of_known_vulnerabilities_says_it_is_not_malware(self, tmp_path: Path) -> None:
        vulnerable = SimpleNamespace(
            rule_id="VULN.X",
            severity="critical",
            message="CVE",
            category="vulnerable",
            location=None,
        )
        malicious = SimpleNamespace(
            rule_id="MAL.X", severity="critical", message="bad", category="malicious", location=None
        )
        plan = InstallPlan("npm", [GuardKit.file("a")])
        file = plan.files[0]
        context = GuardKit.context()
        assert context.blocked(InstallVerdict(plan, {file.filename: (vulnerable,)})) == 1
        said = GuardKit.said(context)
        assert "None of this is malware: these are known critical vulnerabilities" in said
        assert f"{file.label}" in said and "VULN.X" in said
        mixed = GuardKit.context()
        mixed.blocked(InstallVerdict(plan, {file.filename: (vulnerable, malicious)}))
        assert "None of this is malware" not in GuardKit.said(mixed)

    def test_a_blocking_file_that_is_not_in_the_plan_is_named_by_its_file_name(self) -> None:
        context = GuardKit.context()
        finding = SimpleNamespace(rule_id="R", severity="high", message="m", location=None)
        context.blocked(InstallVerdict(InstallPlan("npm"), {"x.tgz": (finding,)}))
        assert "\n  x.tgz\n" in GuardKit.said(context)

    def test_a_tool_is_run_as_the_person_typed_it_and_its_exit_code_returned(self) -> None:
        assert InstallContext.run([sys.executable, "-c", "raise SystemExit(3)"]) == 3
        assert InstallContext.run([sys.executable, "-c", "pass"], Path.cwd(), {"A": "1"}) == 0
