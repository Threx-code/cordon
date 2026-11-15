"""A data file the package's code only parses is not read by the capability rules (`DataRoles`, `CapabilityDetector.labelled`).

A JSON of credential-store paths and paste-service hosts, parsed by the package's own guard module, was `SUSPECT.EXFIL.CREDENTIAL_STORE`,
`CREDENTIAL_SWEEP` and `DROP_POINT` at HIGH: three rules reading the names in a denylist as acts. The same file, run by something, still is."""

from __future__ import annotations

import io
import json
import tarfile

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity

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
    def findings(tmp_path, guard: str | None):
        members = {
            "pkg-1.0.0/PKG-INFO": "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0.0\n",
            "pkg-1.0.0/pyproject.toml": '[project]\nname = "pkg"\nversion = "1.0.0"\n',
            "pkg-1.0.0/pkg/__init__.py": "from . import guard\n",
            "pkg-1.0.0/pkg/denylist.json": DENYLIST,
        }
        if guard is not None:
            members["pkg-1.0.0/pkg/guard.py"] = guard
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
