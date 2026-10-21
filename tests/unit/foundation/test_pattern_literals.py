"""A regex pattern names paths to match; nothing reads or writes them (`pyast._pattern_literals`).

Cordon's own tool-call guard lists every startup file it refuses and was read as persistence
(review 98). The fixture here is that shape, so this file is on the self-scan's list of attack
text by construction, beside the guard's own tests.
"""

from __future__ import annotations

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config

GUARD = (
    "import base64\n"
    "import re\n"
    "REFUSED = re.compile(\n"
    '    r"/etc/(?:rc\\.local|systemd/system|init\\.d|cron\\.d)"\n'
    '    r"|~/\\.(?:ssh|bashrc|zshrc|profile)"\n'
    ")\n"
    "def refused(value):\n"
    "    text = base64.b64decode(value).decode('utf-8', 'replace')\n"
    "    return bool(REFUSED.search(value) or REFUSED.search(text))\n"
)


class Kit:
    @staticmethod
    def persistence(tmp_path, source: str) -> list[str]:
        (tmp_path / "guard.py").write_text(source, encoding="utf-8")
        findings = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path).findings
        return [f.rule_id for f in findings if f.rule_id.endswith("PERSIST.001")]


class TestAPatternIsNotAWrite:
    def test_a_guard_pattern(self, tmp_path) -> None:
        assert Kit.persistence(tmp_path, GUARD) == []

    def test_the_same_paths_outside_a_pattern_still_report(self, tmp_path) -> None:
        """The control: the identical text, handed to a call outside the file rather than
        `re.compile`. (Kept only in a variable and compared, it is named and never written, which
        `analysis/python/py_persist.py` excuses too.)"""
        source = GUARD.replace("REFUSED = re.compile(", "REFUSED = install(")
        assert Kit.persistence(tmp_path, source)
