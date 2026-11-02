"""SUSPECT.OBFUSCATION.MANGLED.001 (notes/js-mangling.md): obfuscator.io's `_0x` naming, 20 distinct
names, in a file the package does not keep as build output. Fixtures are inert: generated names
assigned zero, no code that does anything."""

from __future__ import annotations

import io
import json
import tarfile
import types
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.code.obfuscation import packing
from cordon_scanner.detect.code.obfuscation.packing import PackingFindings
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.models import Severity

RULE = "SUSPECT.OBFUSCATION.MANGLED.001"


class MangledKit:
    @staticmethod
    def names(count: int) -> str:
        """`count` distinct obfuscator-style names, each assigned zero."""
        return "".join(f"var _0x{0xA000 + i:04x} = 0;\n" for i in range(count))

    @staticmethod
    def package(
        tmp_path: Path, files: dict[str, str], scripts: dict[str, str] | None = None
    ) -> Path:
        buffer = io.BytesIO()
        manifest = {"name": "p", "version": "1.0.0", "scripts": scripts or {}}
        members = {"package/package.json": json.dumps(manifest)}
        members.update({f"package/{name}": text for name, text in files.items()})
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, text in members.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "p-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return target

    @staticmethod
    def found(  # type: ignore[type-arg]
        tmp_path: Path, files: dict[str, str], scripts: dict[str, str] | None = None
    ) -> list:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(
            MangledKit.package(tmp_path, files, scripts)
        )
        return [f for f in result.findings if f.rule_id == RULE]

    @staticmethod
    def rules(tmp_path: Path, files: dict[str, str]) -> set[str]:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(
            MangledKit.package(tmp_path, files)
        )
        return {f.rule_id for f in result.findings}


class TestTwentyNames:
    def test_twenty_distinct_names_are_mangled_and_graded_high(
        self, tmp_path: Path, verdict_off: None
    ) -> None:
        found = MangledKit.found(tmp_path, {"index.js": MangledKit.names(20)})
        assert found and all(f.severity >= Severity.HIGH for f in found)

    def test_blocks_with_the_verdict_on(self, tmp_path: Path) -> None:
        # As a user sees it. This minimal package is not one the verdict holds; on real packages it
        # held PACKED below the gate (34 of 36 measured misses), which the keep entry is for.
        found = MangledKit.found(tmp_path, {"index.js": MangledKit.names(20)})
        assert found and all(f.severity >= Severity.HIGH for f in found)

    def test_packed_is_reported_beside_it(self, tmp_path: Path, verdict_off: None) -> None:
        rules = MangledKit.rules(tmp_path, {"index.js": MangledKit.names(20)})
        assert {RULE, "SUSPECT.OBFUSCATION.PACKED.001"} <= rules

    def test_nineteen_are_not(self, tmp_path: Path, verdict_off: None) -> None:
        assert not MangledKit.found(tmp_path, {"index.js": MangledKit.names(19)})

    def test_one_name_repeated_is_one_name(self, tmp_path: Path, verdict_off: None) -> None:
        assert not MangledKit.found(tmp_path, {"index.js": "var _0xa000 = 0;\n" * 200})

    def test_names_in_a_comment_only_are_not(self, tmp_path: Path, verdict_off: None) -> None:
        text = "/*\n" + MangledKit.names(30) + "*/\nmodule.exports = 1;\n"
        assert not MangledKit.found(tmp_path, {"index.js": text})


class TestTheBuildRoots:
    @pytest.mark.parametrize(
        "path", ["dist/app.js", "build/app.js", "vendor/app.js", "node_modules/x/index.js"]
    )
    def test_build_output_is_packed_only(
        self, tmp_path: Path, path: str, verdict_off: None
    ) -> None:
        rules = MangledKit.rules(tmp_path, {path: MangledKit.names(20)})
        assert RULE not in rules

    @pytest.mark.parametrize(
        "path", ["lib/app.js", "src/dist/app.js", "Dist-tools/app.js", "lib/app.min.js"]
    )
    def test_only_the_first_directory_counts(
        self, tmp_path: Path, path: str, verdict_off: None
    ) -> None:
        # And at its grade: `**/dist/**` and `*.min.js` are generated output to the obfuscation
        # ceiling, which no bundler's output this is (ObfuscationText._obfuscator_io).
        found = MangledKit.found(tmp_path, {path: MangledKit.names(20)})
        assert found and all(f.severity >= Severity.HIGH for f in found)

    @pytest.mark.parametrize(
        ("path", "inside"),
        [
            ("p-1.0.0.tgz!package/dist/app.js", True),
            ("p-1.0.0.tgz!package/index.js", False),
            ("p-1.0.0.tgz!package/lib/dist/app.js", False),
            ("dist/app.js", True),
            ("app.js", False),
            ("dist", False),
        ],
    )
    def test_the_root_is_read_inside_the_package(self, path: str, inside: bool) -> None:
        assert PackingFindings.build_root(path) is inside


class TestBuildOutputAnInstallHookRuns:
    """The exemption is for bundles nobody runs on install: moving the payload under dist/ and
    running it from postinstall keeps the finding (0 benign, 0 misses on rows a3b9c5f1:
    jsm/pair-cprime.txt)."""

    def test_a_hook_run_file_under_dist_blocks_with_the_verdict_on(self, tmp_path: Path) -> None:
        found = MangledKit.found(
            tmp_path, {"dist/app.js": MangledKit.names(20)}, {"postinstall": "node dist/app.js"}
        )
        assert found and all(f.severity >= Severity.HIGH for f in found)

    def test_a_dist_main_nothing_installs_is_not(self, tmp_path: Path, verdict_off: None) -> None:
        assert not MangledKit.found(
            tmp_path, {"dist/app.js": MangledKit.names(20)}, {"build": "node dist/app.js"}
        )


class TestTheCountIsBounded:
    def test_it_stops_reading_at_twenty_names(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A large obfuscated payload costs no more than its first 20 names: counted, not timed."""
        consumed: list[int] = []
        pattern = packing.MANGLED_NAME

        class Counting:
            @staticmethod
            def finditer(raw: bytes):  # type: ignore[no-untyped-def]
                for match in pattern.finditer(raw):
                    consumed.append(1)
                    yield match

        monkeypatch.setattr(packing, "MANGLED_NAME", Counting)
        content = FileContent.from_bytes("index.js", MangledKit.names(5_000).encode())
        ctx = types.SimpleNamespace(in_install_hook=lambda path: False)
        hits = list(PackingFindings.mangled(content, ctx, "javascript"))  # type: ignore[arg-type]
        assert hits and len(consumed) == 20
