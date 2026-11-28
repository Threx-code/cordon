"""`guard verify | install | update | shims | incoming`: what is printed and the exit code of each
(`cli/commands/guard.py`)."""

from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cordon_scanner.cli.commands.guard import GuardCommand
from cordon_scanner.engine.guard import Guard
from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.sources.install.plan import SHIM_MARKER


class _Kit:
    @staticmethod
    def run(action: str | None, **over: Any) -> int:
        base: dict[str, Any] = {
            "guard_command": action,
            "path": ".",
            "global_": False,
            "force": False,
        }
        return GuardCommand.run(argparse.Namespace(**{**base, **over}))


run = _Kit.run


class TestHooksAndManifest:
    def test_installing_hooks_in_a_repository_names_each_and_says_they_fail_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        seen: list[Any] = []
        monkeypatch.setattr(
            Guard,
            "install_hooks",
            staticmethod(
                lambda root, force: seen.append((root, force)) or ["pre-commit", "pre-push"]
            ),
        )
        assert run("install", path=str(tmp_path), force=True) == int(ExitCode.CLEAN)
        out = capsys.readouterr().out
        assert seen == [(tmp_path, True)]
        assert "installed .git/hooks/pre-commit\ninstalled .git/hooks/pre-push\n" in out
        assert "Each fails closed" in out

    def test_a_global_install_goes_to_gits_template_directory(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(
            Guard,
            "install_global",
            staticmethod(lambda force: (tmp_path / "template", ["post-checkout"])),
        )
        assert run("install", global_=True) == int(ExitCode.CLEAN)
        out = capsys.readouterr().out
        assert f"installed {tmp_path / 'template' / 'hooks' / 'post-checkout'}" in out
        assert "Every repository cloned or created from now on starts with these hooks" in out

    def test_update_writes_the_manifest_and_asks_for_it_to_be_reviewed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(
            Guard, "write_manifest", staticmethod(lambda root: tmp_path / ".cordon-guard.sha256")
        )
        assert run("update", path=str(tmp_path)) == int(ExitCode.CLEAN)
        out = capsys.readouterr().out
        assert f"wrote {tmp_path / '.cordon-guard.sha256'}" in out
        assert "Commit this file" in out

    def test_a_guard_that_verifies_is_intact_and_one_that_does_not_lists_each_problem(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        asked: list[Any] = []
        report = SimpleNamespace(ok=True, problems=[])
        monkeypatch.setattr(
            Guard,
            "verify",
            staticmethod(lambda root, manifest_only: asked.append(manifest_only) or report),
        )
        assert run(None, manifest_only=True) == int(ExitCode.CLEAN), "verify is the default"
        assert asked == [True] and capsys.readouterr().out == "guard intact\n"
        problem = SimpleNamespace(
            status="MODIFIED", detail="hook changed", remediation="rerun install"
        )
        report.ok, report.problems = False, [problem]
        assert run("verify") == int(ExitCode.FINDINGS)
        err = capsys.readouterr().err
        assert err == "MODIFIED: hook changed\n  fix: rerun install\n"

    def test_an_unknown_action_is_a_config_error(self) -> None:
        with pytest.raises(ConfigError, match="unknown guard action: purge"):
            run("purge")

    def test_the_hidden_incoming_action_goes_to_the_hook_runner(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.incoming import IncomingCommand

        monkeypatch.setattr(IncomingCommand, "run_hook", classmethod(lambda cls, args: 77))
        assert run("incoming", hook="post-merge", git_args=[]) == 77


class TestShims:
    def test_shims_are_written_and_the_path_instruction_shown_when_the_directory_is_not_on_it(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setenv("PATH", "/usr/bin")
        target = tmp_path / "shims"
        assert run("shims", shim_dir=str(target), remove=False) == int(ExitCode.CLEAN)
        out = capsys.readouterr().out
        assert (target / "npm").read_text(encoding="utf-8").count(SHIM_MARKER) == 1
        assert f"into {target}" in out
        assert f'export PATH="{target}:$PATH"' in out

    def test_a_file_that_is_not_a_cordon_shim_is_left_alone_and_a_directory_on_path_needs_no_note(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        target = tmp_path / "shims"
        target.mkdir()
        (target / "npm").write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
        monkeypatch.setenv("PATH", str(target))
        assert run("shims", shim_dir=str(target), remove=False) == int(ExitCode.CLEAN)
        captured = capsys.readouterr()
        assert f"left {target / 'npm'} alone: it is not a Cordon shim" in captured.err
        assert "export PATH" not in captured.out
        assert (target / "npm").read_text(encoding="utf-8") == "#!/bin/sh\necho mine\n"

    def test_removing_deletes_only_the_shims_cordon_wrote(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setenv("PATH", "/usr/bin")
        target = tmp_path / "shims"
        run("shims", shim_dir=str(target), remove=False)
        (target / "npm").write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
        capsys.readouterr()
        assert run("shims", shim_dir=str(target), remove=True) == int(ExitCode.CLEAN)
        assert (target / "npm").exists() and not (target / "pip").exists()
        assert f"shims from {target}" in capsys.readouterr().out

    def test_without_a_directory_the_default_one_is_used(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from cordon_scanner.sources.install.shims import Shims

        monkeypatch.setattr(Shims, "default_directory", staticmethod(lambda: tmp_path / "d"))
        monkeypatch.setenv("PATH", "/usr/bin")
        assert run("shims", shim_dir=None, remove=False) == int(ExitCode.CLEAN)
        assert (tmp_path / "d" / "pip").is_file()
        assert f"into {tmp_path / 'd'}" in capsys.readouterr().out
