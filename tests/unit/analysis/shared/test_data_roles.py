"""Data files that only a parser ever reads (`DataRoles`): named beside a parser and beside nothing that runs, loads or
spawns, and naming one file of the tree. Everything else stays what it was. And what that does in a scan: a JSON of credential-store
paths and paste-service hosts, parsed by the package's own guard module, was `SUSPECT.EXFIL.CREDENTIAL_STORE`, `CREDENTIAL_SWEEP` and
`DROP_POINT` at HIGH -- three rules reading the names in a denylist as acts. The same file, run by something, still is."""

from __future__ import annotations

import io
import json
import tarfile

import pytest

from cordon_scanner import Scanner
from cordon_scanner.analysis.shared.data_roles import DataRoles
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.models import Severity
from kits.padding import Padding

DATA = '{"hosts": ["a.example"], "paths": ["~/x"]}\n'


class DataRolesKit:
    @staticmethod
    def unit(path: str, text: str) -> FileUnit:
        return FileUnit(content=FileContent.from_bytes(path, text.encode()))

    @staticmethod
    def only_parsed(files: dict[str, str]) -> set[str]:
        return set(DataRoles.only_parsed([DataRolesKit.unit(p, t) for p, t in files.items()]))


only_parsed = DataRolesKit.only_parsed


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


DENYLIST = json.dumps(
    {
        "paths": [
            "~/.ssh/id_rsa",
            "~/.aws/credentials",
            "~/.docker/config.json",
            "~/.npmrc",
            "~/.kube/config",
        ],
        "hosts": ["webhook.site", "pastebin.com", "transfer.sh", "requestbin.net"],
    },
    indent=2,
)
PARSER = (
    "import json\nimport os\n\n"
    'with open(os.path.join(os.path.dirname(__file__), "denylist.json")) as fh:\n'
    "    DENY = json.load(fh)\n\n\n"
    "def blocked(path):\n    return any(path.endswith(p) for p in DENY['paths'])\n"
)
CAPABILITY = {
    "SUSPECT.EXFIL.CREDENTIAL_STORE.001",
    "SUSPECT.EXFIL.CREDENTIAL_SWEEP.001",
    "SUSPECT.EXFIL.DROP_POINT.001",
}


class DataKit:
    @staticmethod
    def findings(tmp_path, guard: str | None, extra: dict[str, str] | None = None):
        members = {
            "pkg-1.0.0/PKG-INFO": "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0.0\n",
            "pkg-1.0.0/pyproject.toml": '[project]\nname = "pkg"\nversion = "1.0.0"\n',
            "pkg-1.0.0/pkg/__init__.py": "from . import guard\n",
            "pkg-1.0.0/pkg/denylist.json": DENYLIST,
        }
        if guard is not None:
            members["pkg-1.0.0/pkg/guard.py"] = guard
        for name, text in (extra or {}).items():
            members[f"pkg-1.0.0/pkg/{name}"] = text
        archive = tmp_path / "pkg-1.0.0.tar.gz"
        with tarfile.open(archive, "w:gz") as out:
            for name, text in members.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                out.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return [
            f
            for f in result.findings
            if f.rule_id in CAPABILITY and f.location.path.endswith("denylist.json")
        ]


class TestAParsedDataFile:
    def test_the_names_in_a_denylist_are_not_acts(self, tmp_path) -> None:
        assert DataKit.findings(tmp_path, PARSER) == []

    def test_a_file_nothing_names_is_read_as_before(self, tmp_path) -> None:
        assert {f.rule_id for f in DataKit.findings(tmp_path, None)} == CAPABILITY

    @pytest.mark.parametrize(
        "guard",
        [
            PARSER + "\nexec(open('denylist.json').read())\n",
            PARSER + "\nimport subprocess\nsubprocess.run(['tool', 'denylist.json'])\n",
            "import json\nprint('denylist.json')\n",
        ],
        ids=["run-by-exec", "handed-to-a-process", "named-and-not-parsed"],
    )
    def test_one_something_runs_or_nothing_parses_is_read_as_before(
        self, tmp_path, guard: str
    ) -> None:
        found = DataKit.findings(tmp_path, guard)
        assert found and all(f.rule_id in CAPABILITY for f in found)
        assert any(f.severity >= Severity.MEDIUM for f in found)


class TestACodeFileBeyondWhatTheTestOnceReadNamesTheFile:
    """A code file longer than two million characters was left out of the test, so what it did with a data file
    could not veto the exemption: one small file that parses the data, one large file that runs it, and the data
    was read as data. The size of a file must not decide whether it counts."""

    RUNNER = "exec(open('denylist.json').read())\n"

    def test_the_large_file_that_runs_it_vetoes_the_exemption(self) -> None:
        files = {
            "pkg/denylist.json": DATA,
            "pkg/guard.py": 'import json\nDENY = json.load(open("denylist.json"))\n',
            "pkg/large.py": self.RUNNER + Padding.lines(2_100_000, "#"),
        }
        assert only_parsed(files) == set()

    def test_the_same_file_under_the_old_limit_vetoes_it_too(self) -> None:
        files = {
            "pkg/denylist.json": DATA,
            "pkg/guard.py": 'import json\nDENY = json.load(open("denylist.json"))\n',
            "pkg/large.py": self.RUNNER + Padding.lines(1_000, "#"),
        }
        assert only_parsed(files) == set()

    def test_a_large_file_that_only_parses_it_does_not_veto(self) -> None:
        parser = 'import json\nDENY = json.load(open("denylist.json"))\n'
        files = {"pkg/denylist.json": DATA, "pkg/large.py": parser + Padding.lines(2_100_000, "#")}
        assert only_parsed(files) == {"pkg/denylist.json"}

    def test_a_scan_still_reads_the_data_as_before(self, tmp_path) -> None:
        extra = {"large.py": self.RUNNER + Padding.lines(2_100_000, "#")}
        found = DataKit.findings(tmp_path, PARSER, extra)
        assert found and all(f.rule_id in CAPABILITY for f in found)
