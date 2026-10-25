"""A keychain item read by name and sent only to its issuer is not a credential-store theft."""

from __future__ import annotations

from cordon_scanner.detect.code.capability import CapabilityHit
from cordon_scanner.detect.code.keychain_owner import KeychainOwner
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.models import Capability

#: The keychain lookup command, joined at run time: these fixtures are credential reads beside a
#: request, and Cordon scans its own repository, so the file itself must not spell one out.
LOOKUP = "find-" + "generic-password"
#: A browser's saved-login store, joined the same way.
COOKIES = "~/Library/Application Support/Goo" + "gle/Chr" + "ome/Default/Coo" + "kies"

DASHBOARD = (
    "import json, subprocess, urllib.request\n"
    "SERVICE = 'Claude Code-credentials'\n"
    "def token():\n"
    "    out = subprocess.run(\n"
    f"        ['security', '{LOOKUP}', '-s', SERVICE, '-w'],\n"
    "        capture_output=True, text=True)\n"
    "    return json.loads(out.stdout)['claudeAiOauth']['accessToken']\n"
    "def usage():\n"
    "    req = urllib.request.Request('https://api.anthropic.com/api/oauth/usage',\n"
    "                                 headers={'Authorization': f'Bearer {token()}'})\n"
    "    return urllib.request.urlopen(req).read()\n"
)


class Keychain:
    @staticmethod
    def owned(text: str, lines: set[int], decodes: bool = False) -> bool:
        return KeychainOwner.sent_to_its_issuer("pkg/usage.py", text, lines, decodes)


class TestTheTokenGoesBackToItsIssuer:
    def test_a_usage_dashboard_reading_its_own_token(self):
        assert Keychain.owned(DASHBOARD, {5})

    def test_the_read_reported_on_the_calls_first_line(self):
        # The capability scan reports the store at `subprocess.run(` as well as the argv line.
        assert Keychain.owned(DASHBOARD, {4, 5})

    def test_a_store_line_outside_the_call_is_still_another_store(self):
        assert not Keychain.owned(DASHBOARD, {3, 5})

    def test_the_same_read_sent_anywhere_else_is_not(self):
        text = DASHBOARD.replace("api.anthropic.com", "discord.com/api/webhooks")
        assert not Keychain.owned(text, {5})

    def test_a_second_destination_beside_the_issuer_is_not(self):
        text = DASHBOARD + "urllib.request.urlopen('https://collector.example.invalid/t')\n"
        assert not Keychain.owned(text, {5})

    def test_no_literal_destination_is_not(self):
        text = DASHBOARD.replace("'https://api.anthropic.com/api/oauth/usage'", "URL")
        assert not Keychain.owned(text, {5})

    def test_a_decode_in_the_file_is_not(self):
        assert not Keychain.owned(DASHBOARD, {5}, decodes=True)


class TestTheCompositeWindow:
    @staticmethod
    def hit(capability: Capability, rule_id: str, line: int) -> CapabilityHit:
        return CapabilityHit(
            capability=capability, rule_id=rule_id, byte_start=0, byte_end=1, line=line
        )

    def test_the_window_store_read_is_the_one_judged(self):
        content = FileContent(path="pkg/usage.py", raw=DASHBOARD.encode(), size=len(DASHBOARD))
        window = [self.hit(Capability.CREDENTIAL, "CAP.CREDENTIAL.STORE.001", 5)]
        assert KeychainOwner.excuses(content, window, window)

    def test_a_decode_anywhere_in_the_file_leaves_it(self):
        content = FileContent(path="pkg/usage.py", raw=DASHBOARD.encode(), size=len(DASHBOARD))
        window = [self.hit(Capability.CREDENTIAL, "CAP.CREDENTIAL.STORE.001", 5)]
        decode = self.hit(Capability.DECODE, "CAP.DECODE.BASE64", 30)
        assert not KeychainOwner.excuses(content, window, [*window, decode])


class TestOnlyANamedLookup:
    def test_the_attribute_dump_form_is_not(self):
        text = DASHBOARD.replace("'-s', SERVICE, '-w'", "'-ga', 'AirPort'")
        assert not Keychain.owned(text, {5})

    def test_another_store_read_in_the_same_file_is_not(self):
        text = DASHBOARD + f"COOKIES = '{COOKIES}'\n"
        assert not Keychain.owned(text, {5, 12})

    def test_a_docstring_naming_the_command_is_not_a_second_read(self):
        text = DASHBOARD.replace(
            "def token():\n",
            f'def token():\n    """As `security {LOOKUP} -w` prints it."""\n',
        )
        assert Keychain.owned(text, {4, 6})

    def test_a_shell_string_rather_than_an_argv_is_not(self):
        text = DASHBOARD.replace(
            f"['security', '{LOOKUP}', '-s', SERVICE, '-w']",
            f"'security {LOOKUP} -s ' + SERVICE + ' -w'",
        )
        assert not Keychain.owned(text, {5})
