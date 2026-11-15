"""Abuse tooling is policy, not malware: a tool run on purpose against a third-party platform.

Family 1 is the platform app's request signature: several signing parameters written down beside
the platform's API host. A client of a public API, a scraper reading one cookie, and an extractor
that names the host without the signature are not it.
"""

from __future__ import annotations

from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.analysis.python.pyast import PythonAnalyzer
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Category

RULE = "POLICY.ABUSE_TOOLING.PLATFORM_FORGERY.001"

SIGNED = (
    "import requests\n"
    "HOST = 'https://log-va.tiktokv.com/service/2/device_register/'\n"
    "def sign(params):\n"
    "    return {'X-Gorgon': params, 'X-Khronos': '1', 'X-Argus': 'a'}\n"
)


class Facts:
    @staticmethod
    def of(source: str) -> list[str]:
        return [h.detail for h in PythonAnalyzer.analyse(source) if h.detail.startswith("platform")]


class TestThePlatformSignature:
    def test_several_signing_parameters_beside_the_platform_host(self):
        assert Facts.of(SIGNED) == ["platform request signed: 3 signing parameters"]

    def test_separators_and_case_do_not_hide_the_names(self):
        source = "u = 'https://x.snssdk.com/a'\nh = {'x_bogus': 1, 'MSTOKEN': 2}\n"
        assert Facts.of(source) == ["platform request signed: 2 signing parameters"]

    def test_one_signing_name_is_a_cookie_read_not_a_signature(self):
        source = "u = 'https://www.tiktok.com/api'\nc = cookies.get('msToken')\n"
        assert Facts.of(source) == []

    def test_the_signature_without_the_platform_host_is_not_this_label(self):
        assert Facts.of("h = {'X-Gorgon': 1, 'X-Argus': 2}\n") == []

    def test_a_downloader_naming_the_host_and_device_fields_is_not_this_label(self):
        source = (
            "u = 'https://api16-normal-c-useast1a.tiktokv.com/aweme/v1/feed/'\n"
            "q = {'device_id': 1, 'iid': 2, 'cdid': 3, 'openudid': 4, 'os_version': 5, 'dpi': 6}\n"
        )
        assert Facts.of(source) == []


class TestTheRule:
    def test_it_is_a_policy_rule_outside_the_malicious_categories(self):
        from cordon_scanner.rules.loader import RuleLoader

        compiled = {c.rule.id: c for pack in RuleLoader.load_builtin() for c in pack.rules}
        rule = compiled[RULE].rule
        assert rule.category is Category.POLICY
        assert rule.severity.name == "MEDIUM"
        assert "AST.PY.PLATFORM_FORGERY" in repr(compiled[RULE])

    def test_a_scanned_package_gets_the_policy_finding_and_nothing_malicious(self, tmp_path: Path):
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "sign.py").write_text(SIGNED, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        found = [f for f in result.findings if f.rule_id == RULE]
        assert found
        assert all(f.category is Category.POLICY for f in found)
        assert not [f for f in result.findings if f.category is Category.MALICIOUS]
