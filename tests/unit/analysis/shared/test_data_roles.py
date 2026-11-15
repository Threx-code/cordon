"""Data files that only a parser ever reads (`DataRoles`): named beside a parser and beside nothing that runs, loads or
spawns, and naming one file of the tree. Everything else stays what it was."""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.shared.data_roles import DataRoles
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.foundation.content import FileContent

DATA = '{"hosts": ["a.example"], "paths": ["~/x"]}\n'


def unit(path: str, text: str) -> FileUnit:
    return FileUnit(content=FileContent.from_bytes(path, text.encode()))


def only_parsed(files: dict[str, str]) -> set[str]:
    return set(DataRoles.only_parsed([unit(p, t) for p, t in files.items()]))


class TestAFileOnlyParsed:
    @pytest.mark.parametrize(
        "loader",
        [
            'import json\nwith open("denylist.json") as fh:\n    DENY = json.load(fh)\n',
            'import json\nDENY = json.loads(open("denylist.json").read())\n',
            'import yaml\nCONFIG = yaml.safe_load(open("denylist.json"))\n',
            'import pandas as pd\nFRAME = pd.read_json("denylist.json")\n',
            'const DENY = JSON.parse(fs.readFileSync("denylist.json", "utf8"));\n',
            'const DENY = require("./denylist.json");\n',
            # the name assigned once and parsed where it is used
            'import json\nimport os\nPATH = os.path.join(HERE, "denylist.json")\n\n\ndef load():\n    with open(PATH) as fh:\n        return json.load(fh)\n',
        ],
        ids=["json.load", "json.loads", "yaml", "pandas", "JSON.parse", "require", "assigned-name"],
    )
    def test_it_is_data(self, loader: str) -> None:
        suffix = ".js" if "require" in loader or "JSON.parse" in loader else ".py"
        found = only_parsed({"pkg/denylist.json": DATA, f"pkg/guard{suffix}": loader})
        assert found == {"pkg/denylist.json"}

    def test_a_compressed_one_is(self) -> None:
        loader = 'import gzip\nimport json\nwith gzip.open("table.json.gz") as fh:\n    TABLE = json.load(fh)\n'
        assert only_parsed({"pkg/table.json.gz": DATA, "pkg/t.py": loader}) == {"pkg/table.json.gz"}

    def test_every_naming_counts(self) -> None:
        both = 'import json\nA = json.load(open("denylist.json"))\n\n\n\n\n\n\n\n\nsubprocess.run(["tool", "denylist.json"])\n'
        assert only_parsed({"pkg/denylist.json": DATA, "pkg/g.py": both}) == set()


class TestAFileNotOnlyParsed:
    @pytest.mark.parametrize(
        "code",
        [
            'exec(open("denylist.json").read())\n',
            'import json\ncode = json.load(open("denylist.json"))["code"]\nexec(code)\n',
            'import subprocess\nsubprocess.run(["tool", "denylist.json"])\n',
            'import importlib\nimportlib.import_module("denylist.json")\n',
            'const x = JSON.parse(fs.readFileSync("denylist.json")); eval(x.code);\n',
            'child_process.execSync("cat denylist.json");\n',
            # named, but nothing parses it
            'print("see denylist.json")\n',
            'PATH = "denylist.json"\n',
            # the assigned name is used for something else too
            'PATH = "denylist.json"\njson.load(open(PATH))\n\n\n\n\n\n\n\n\nsend(open(PATH).read())\n',
        ],
        ids=[
            "exec",
            "exec-a-field",
            "subprocess",
            "import",
            "eval",
            "execSync",
            "printed",
            "assigned-unused",
            "assigned-and-sent",
        ],
    )
    def test_it_is_not_data(self, code: str) -> None:
        suffix = ".js" if ("eval" in code or "execSync" in code) else ".py"
        assert only_parsed({"pkg/denylist.json": DATA, f"pkg/guard{suffix}": code}) == set()

    def test_one_nothing_names(self) -> None:
        assert only_parsed({"pkg/denylist.json": DATA, "pkg/guard.py": "import json\n"}) == set()

    def test_a_name_two_files_share_proves_neither(self) -> None:
        loader = 'import json\nDENY = json.load(open("denylist.json"))\n'
        files = {"pkg/a/denylist.json": DATA, "pkg/b/denylist.json": DATA, "pkg/g.py": loader}
        assert only_parsed(files) == set()

    def test_a_directory_in_the_name_picks_one(self) -> None:
        loader = 'import json\nDENY = json.load(open("a/denylist.json"))\n'
        files = {"pkg/a/denylist.json": DATA, "pkg/b/denylist.json": DATA, "pkg/g.py": loader}
        assert only_parsed(files) == {"pkg/a/denylist.json"}

    def test_a_manifest_is_never_data(self) -> None:
        loader = 'import json\nMANIFEST = json.load(open("package.json"))\n'
        assert only_parsed({"pkg/package.json": '{"scripts": {}}', "pkg/g.py": loader}) == set()

    def test_a_computed_name_proves_nothing(self) -> None:
        loader = 'import json\nDENY = json.load(open(NAME + ".json"))\n'
        assert only_parsed({"pkg/denylist.json": DATA, "pkg/g.py": loader}) == set()

    def test_a_dotfile_keeps_its_dot(self) -> None:
        loader = 'import json\nCFG = json.load(open("./.mcp-data.json"))\n'
        assert only_parsed({"pkg/.mcp-data.json": DATA, "pkg/g.py": loader}) == {
            "pkg/.mcp-data.json"
        }


class TestATreeWithNoDataFileIsUntouched:
    """The precondition for measuring the exemption on the units that can be touched: a tree no code names a data file in, or with no data file at all, has none."""

    def test_no_data_file_at_all(self) -> None:
        assert (
            only_parsed({"pkg/g.py": 'import json\nDENY = json.load(open("denylist.json"))\n'})
            == set()
        )

    def test_data_files_no_code_names(self) -> None:
        assert (
            only_parsed({"pkg/a.json": DATA, "pkg/b.yaml": "a: 1\n", "pkg/g.py": "print(1)\n"})
            == set()
        )

    def test_code_that_names_no_data_file(self) -> None:
        assert only_parsed({"pkg/a.json": DATA, "pkg/g.js": "const x = require('fs');\n"}) == set()
