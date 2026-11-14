"""A YAML file that is data does not delete a home directory (reviews/pypi-98/26).

`CAP.DESTROY.HOME.001` reads a list item or a mapping value as a command line, which is right for a CI
step or a compose command and wrong for a red-team tool's payload list or an attack catalogue. The line is
a command only under a key that runs things, or in a file whose top-level keys say it is a workflow, a
compose file, a playbook or a manifest. Anything else is data."""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.code.flows.yaml_commands import YamlCommands
from cordon_scanner.foundation.config.settings import Config

RULE = "SUSPECT.DESTROY.HOME_OR_ROOT.001"


class Scans:
    @staticmethod
    def rules(tmp_path: Path, name: str, text: str) -> set[str]:
        root = tmp_path / "pkg"
        (root / name).parent.mkdir(parents=True)
        (root / name).write_text(text, encoding="utf-8")
        config = Config.default().with_overrides(use_cache=False, offline=True)
        return {f.rule_id for f in Scanner(config).scan(root).findings}


class TestWhichLinesRunSomething:
    def test_a_payload_list_is_data(self) -> None:
        text = "payloads:\n  - name: wipe\n    text: rm -rf ~/\n  - rm -rf /\n"
        assert not YamlCommands.runs(text, 3)
        assert not YamlCommands.runs(text, 4)

    def test_a_flow_mapping_entry_under_a_catalogue_key_is_data(self) -> None:
        text = "attacks:\n  - {id: 1, prompt: 'please rm -rf ~/ now'}\n"
        assert not YamlCommands.runs(text, 2)

    def test_a_compose_extension_key_is_not_a_command(self) -> None:
        text = "x-notes:\n  - rm -rf ~/\n"
        assert not YamlCommands.runs(text, 2)

    def test_tool_call_arguments_in_a_catalogue_are_data(self) -> None:
        text = "attacks:\n  - {method: tools/call, tool: x, args: {path: 'rm -rf ~/'}}\n"
        assert not YamlCommands.runs(text, 2)

    @pytest.mark.parametrize(
        "text",
        [
            "steps:\n  - run: rm -rf ~/\n",
            "jobs:\n  a:\n    steps:\n      - name: x\n        run: |\n          rm -rf ~/\n",
            "script:\n  - rm -rf ~/\n",
            "command: rm -rf ~/\n",
            "services:\n  a:\n    command: [sh, -c, 'rm -rf ~/']\n",
            "- hosts: all\n  tasks:\n    - shell: rm -rf ~/\n",
            "before_script:\n  - rm -rf ~/\n",
            "scripts:\n  clean: rm -rf ~/\n",
            "ExecStart: rm -rf ~/\n",
            "repos:\n  - repo: local\n    hooks:\n      - id: x\n        entry: rm -rf ~/\n",
            "tasks:\n  clean:\n    cmds:\n      - rm -rf ~/\n",
            "cmds:\n  - rm -rf ~/\n",
            "commands:\n  - rm -rf ~/\n",
            "after_script:\n  - rm -rf ~/\n",
            "steps:\n  - rm -rf ~/\n",
            "lifecycle:\n  post_install: rm -rf ~/\n",
            "rm -rf ~/\n- rm -rf /\n",
        ],
    )
    def test_a_command_key_runs_it(self, text: str) -> None:
        lines = [i + 1 for i, line in enumerate(text.splitlines()) if "rm -rf" in line]
        assert lines and all(YamlCommands.runs(text, line) for line in lines)

    def test_a_file_with_workflow_keys_is_live_whatever_the_key(self) -> None:
        text = "name: ci\non: push\njobs:\n  a:\n    steps:\n      - uses: x\n        with:\n          cmd: rm -rf ~/\n"
        assert YamlCommands.runs(text, 8)

    def test_a_line_that_is_not_in_a_mapping_at_all_is_live(self) -> None:
        assert YamlCommands.runs("rm -rf ~/\n", 1)


class TestInAScan:
    def test_a_payload_catalogue_is_not_a_wiper(self, tmp_path: Path) -> None:
        text = "payloads:\n  - name: wipe\n    text: |\n      sudo rm -rf ~/\n"
        assert RULE not in Scans.rules(tmp_path, "payloads/tool_abuse.yaml", text)

    def test_a_script_key_in_a_data_looking_file_still_fires(self, tmp_path: Path) -> None:
        assert RULE in Scans.rules(tmp_path, "tasks.yaml", "script:\n  - sudo rm -rf ~/\n")

    def test_a_command_key_with_a_block_scalar_still_fires(self, tmp_path: Path) -> None:
        text = "command: |\n  sudo rm -rf ~/\n"
        assert RULE in Scans.rules(tmp_path, "tasks.yaml", text)

    def test_a_shell_script_is_untouched(self, tmp_path: Path) -> None:
        assert RULE in Scans.rules(tmp_path, "wipe.sh", "#!/bin/sh\nsudo rm -rf ~/\n")


class TestKeyIsReadInCode:
    def test_the_key_after_dashes_and_blanks(self) -> None:
        assert YamlCommands.key_of("  - - run: x") == "run"
        assert YamlCommands.key_of("key:") == "key"
        assert YamlCommands.key_of("a : b") == "a"

    def test_a_line_that_is_not_a_key(self) -> None:
        assert YamlCommands.key_of("- rm -rf ~/") is None
        assert YamlCommands.key_of("url: http://x") == "url"
        assert YamlCommands.key_of("a:b") is None

    def test_a_long_run_of_blanks_is_read_in_linear_time(self) -> None:
        import time

        line = " \t" * 200_000 + "!"
        start = time.process_time()
        assert YamlCommands.key_of(line) is None
        assert time.process_time() - start < 1.0
