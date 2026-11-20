"""How each code file of a package is reached from a place that runs (`FileReach`, learning-loop row LL-1c).

Each fixture is a few lines of inert JavaScript or Python naming files that are never run; the classes are the facts' vocabulary:
placed, hook_command, require_chain (with its depth), path_string, stem_only and unreached.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from cordon_scanner.decide.reach import MAX_DEPTH, MAX_PARSE, FileReach
from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.foundation.content import FileContent


class Package:
    @staticmethod
    def units(files: dict[str, str]) -> list[FileUnit]:
        return [
            FileUnit(content=FileContent.from_bytes(path, text.encode()))
            for path, text in files.items()
        ]

    @staticmethod
    def context(**places: tuple[str, ...]) -> SimpleNamespace:
        values = {
            attribute: frozenset(places.get(attribute, ()))
            for attribute in ScanContext.PLACES.values()
        }
        return SimpleNamespace(PLACES=ScanContext.PLACES, **values)

    @staticmethod
    def reach(files: dict[str, str], **places: tuple[str, ...]) -> dict[str, tuple[str, int]]:
        return FileReach.of(Package.units(files), Package.context(**places))


class TestPlacedAndNamedByAHook:
    def test_a_file_in_a_place_set_is_placed(self) -> None:
        got = Package.reach(
            {"index.js": "x();\n", "lib/a.js": "y();\n"}, import_entry_paths=("index.js",)
        )
        assert got["index.js"] == ("placed", 0)
        assert got["lib/a.js"] == ("unreached", 0)

    @pytest.mark.parametrize("place", sorted(ScanContext.PLACES.values()))
    def test_every_place_counts(self, place: str) -> None:
        assert Package.reach({"a.js": "x();\n"}, **{place: ("a.js",)})["a.js"] == ("placed", 0)

    def test_an_install_hook_command_names_its_file(self) -> None:
        manifest = json.dumps({"scripts": {"postinstall": "node ./scripts/setup.js --quiet"}})
        got = Package.reach(
            {"package.json": manifest, "scripts/setup.js": "x();\n", "scripts/other.js": "y();\n"}
        )
        assert got["scripts/setup.js"] == ("hook_command", 0)
        assert got["scripts/other.js"] == ("unreached", 0)

    def test_the_script_an_npm_run_alias_runs_is_named_too(self) -> None:
        manifest = json.dumps(
            {"scripts": {"install": "npm run build", "build": "node tools/build.js"}}
        )
        assert Package.reach({"package.json": manifest, "tools/build.js": "x();\n"})[
            "tools/build.js"
        ] == ("hook_command", 0)

    def test_a_script_that_is_not_an_install_hook_does_not_name_a_file(self) -> None:
        manifest = json.dumps({"scripts": {"test": "node tests/run.js"}})
        assert Package.reach({"package.json": manifest, "tests/run.js": "x();\n"})[
            "tests/run.js"
        ] == ("unreached", 0)


class TestADeclaredEntry:
    """A repository has no import-entry set: the files its package.json names are its entries, and the roots of its chains."""

    def test_main_bin_and_exports_targets_are_declared_entries(self) -> None:
        manifest = json.dumps(
            {
                "main": "./dist/server",
                "bin": {"tool": "./bin/tool.js"},
                "exports": {".": {"import": "./esm/index.mjs"}},
            }
        )
        files = {
            "package.json": manifest,
            "dist/server.js": "x();\n",
            "bin/tool.js": "x();\n",
            "esm/index.mjs": "x();\n",
            "lib/other.js": "x();\n",
        }
        got = Package.reach(files)
        assert [got[name] for name in ("dist/server.js", "bin/tool.js", "esm/index.mjs")] == [
            ("declared_entry", 0)
        ] * 3
        assert got["lib/other.js"] == ("unreached", 0)

    def test_a_chain_starts_at_a_declared_entry(self) -> None:
        files = {
            "package.json": json.dumps({"main": "index.js"}),
            "index.js": 'require("./lib/a");\n',
            "lib/a.js": "x();\n",
        }
        assert Package.reach(files)["lib/a.js"] == ("require_chain", 1)

    def test_a_placed_file_stays_placed_whatever_package_json_says(self) -> None:
        files = {"package.json": json.dumps({"main": "index.js"}), "index.js": "x();\n"}
        assert Package.reach(files, import_entry_paths=("index.js",))["index.js"] == ("placed", 0)


class TestAStaticChain:
    def test_a_relative_require_is_one_hop(self) -> None:
        files = {"index.js": 'const a = require("./lib/a");\n', "lib/a.js": "x();\n"}
        assert Package.reach(files, import_entry_paths=("index.js",))["lib/a.js"] == (
            "require_chain",
            1,
        )

    def test_the_hops_are_counted_down_the_chain(self) -> None:
        files = {
            "index.js": 'require("./a");\n',
            "a.js": 'import { b } from "./b.js";\n',
            "b.js": 'export * from "./c";\n',
            "c.js": 'import("./d");\n',
            "d.js": "x();\n",
        }
        got = Package.reach(files, import_entry_paths=("index.js",))
        assert [got[name][1] for name in ("a.js", "b.js", "c.js", "d.js")] == [1, 2, 3, 4]
        assert all(got[name][0] == "require_chain" for name in ("a.js", "b.js", "c.js", "d.js"))

    def test_the_chain_stops_at_the_depth_limit(self) -> None:
        files = {"f0.js": 'require("./f1");\n'}
        files |= {f"f{i}.js": f'require("./f{i + 1}");\n' for i in range(1, MAX_DEPTH + 2)}
        files[f"f{MAX_DEPTH + 2}.js"] = "x();\n"
        got = Package.reach(files, import_entry_paths=("f0.js",))
        assert got[f"f{MAX_DEPTH}.js"] == ("require_chain", MAX_DEPTH)
        assert got[f"f{MAX_DEPTH + 2}.js"] == ("unreached", 0)

    def test_a_directory_index_is_resolved(self) -> None:
        files = {"index.js": 'require("./lib");\n', "lib/index.js": "x();\n"}
        assert Package.reach(files, import_entry_paths=("index.js",))["lib/index.js"] == (
            "require_chain",
            1,
        )

    def test_a_require_of_a_computed_path_is_not_a_static_edge(self) -> None:
        files = {"index.js": 'require("./lib/" + name);\n', "lib/a.js": "x();\n"}
        assert Package.reach(files, import_entry_paths=("index.js",))["lib/a.js"][0] == "unreached"

    def test_python_relative_and_absolute_imports(self) -> None:
        files = {
            "pkg/__init__.py": "from .sibling import run\nimport pkg.deep.mod\n",
            "pkg/sibling.py": "x = 1\n",
            "pkg/deep/mod.py": "y = 2\n",
            "pkg/orphan.py": "z = 3\n",
        }
        got = Package.reach(files, import_entry_paths=("pkg/__init__.py",))
        assert got["pkg/sibling.py"] == ("require_chain", 1)
        assert got["pkg/deep/mod.py"] == ("require_chain", 1)
        assert got["pkg/orphan.py"] == ("unreached", 0)

    def test_an_archive_member_resolves_inside_its_archive(self) -> None:
        root = "pkg.tgz!package/"
        files = {root + "index.js": 'require("./lib/a");\n', root + "lib/a.js": "x();\n"}
        assert Package.reach(files, import_entry_paths=(root + "index.js",))[root + "lib/a.js"] == (
            "require_chain",
            1,
        )


class TestAPathString:
    def test_a_joined_path_names_a_file(self) -> None:
        files = {
            "index.js": 'spawn("node", [path.join(__dirname, "lib/runner.js")]);\n',
            "lib/runner.js": "x();\n",
        }
        assert Package.reach(files, import_entry_paths=("index.js",))["lib/runner.js"] == (
            "path_string",
            1,
        )

    def test_an_escaped_name_is_read_as_the_parser_reads_it(self) -> None:
        files = {"index.js": 'f("\\u006cib/\\u0072unner.js");\n', "lib/runner.js": "x();\n"}
        assert Package.reach(files, import_entry_paths=("index.js",))["lib/runner.js"] == (
            "path_string",
            1,
        )

    def test_a_concatenated_name_is_folded(self) -> None:
        files = {"index.js": 'f("lib/run" + "ner.js");\n', "lib/runner.js": "x();\n"}
        assert Package.reach(files, import_entry_paths=("index.js",))["lib/runner.js"] == (
            "path_string",
            1,
        )

    def test_a_name_in_a_python_string(self) -> None:
        files = {
            "main.py": 'subprocess.run(["python", "tools/helper.py"])\n',
            "tools/helper.py": "x = 1\n",
        }
        assert Package.reach(files, import_entry_paths=("main.py",))["tools/helper.py"] == (
            "path_string",
            1,
        )

    def test_the_mentioning_files_depth_counts(self) -> None:
        files = {
            "index.js": 'require("./a");\n',
            "a.js": 'f("deep/target.js");\n',
            "deep/target.js": "x();\n",
        }
        assert Package.reach(files, import_entry_paths=("index.js",))["deep/target.js"] == (
            "path_string",
            2,
        )

    def test_a_stem_without_an_extension_is_a_weaker_reading(self) -> None:
        files = {
            "index.js": 'require(path.join(__dirname, "lib", "worker"));\n',
            "lib/worker.js": "x();\n",
        }
        assert Package.reach(files, import_entry_paths=("index.js",))["lib/worker.js"] == (
            "stem_only",
            1,
        )

    def test_a_short_stem_is_not_a_reading(self) -> None:
        files = {"index.js": 'f("app");\n', "lib/app.js": "x();\n"}
        assert Package.reach(files, import_entry_paths=("index.js",))["lib/app.js"] == (
            "unreached",
            0,
        )

    def test_a_string_of_an_unreached_file_names_nothing(self) -> None:
        files = {"index.js": "x();\n", "lib/a.js": 'f("lib/b.js");\n', "lib/b.js": "y();\n"}
        got = Package.reach(files, import_entry_paths=("index.js",))
        assert got["lib/b.js"] == ("unreached", 0)


class TestWhatIsClassed:
    def test_a_file_that_is_not_code_has_no_entry(self) -> None:
        got = Package.reach(
            {"index.js": "x();\n", "README.md": "# hi\n", "data.json": "{}\n"},
            import_entry_paths=("index.js",),
        )
        assert set(got) == {"index.js"}

    def test_a_package_with_no_code_has_none(self) -> None:
        assert Package.reach({"README.md": "# hi\n"}) == {}

    def test_a_file_past_the_parse_limit_has_no_edges_of_its_own(self) -> None:
        big = FileUnit(
            content=FileContent(path="index.js", raw=b'require("./a");\n', size=MAX_PARSE + 1)
        )
        other = FileUnit(content=FileContent.from_bytes("a.js", b"x();\n"))
        got = FileReach.of([big, other], Package.context(import_entry_paths=("index.js",)))
        assert got["index.js"] == ("placed", 0)
        assert got["a.js"] == ("unreached", 0)

    def test_a_file_that_does_not_parse_has_no_edges(self) -> None:
        files = {"index.js": "this is ((( not javascript\n", "a.js": "x();\n"}
        assert Package.reach(files, import_entry_paths=("index.js",))["a.js"] == ("unreached", 0)

    def test_the_kinds_are_the_documented_ones(self) -> None:
        assert FileReach.KINDS == (
            "placed",
            "declared_entry",
            "hook_command",
            "require_chain",
            "path_string",
            "stem_only",
            "unreached",
        )
