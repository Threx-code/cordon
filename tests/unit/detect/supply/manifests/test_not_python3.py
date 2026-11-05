"""A Python 2 `setup.py` is said to be Python 2, not left "unparsed": the scan is complete, and every
text rule still read the file, so Python 2 cannot be used to hide a payload (item 27)."""

from __future__ import annotations

import hashlib
import io
import tarfile

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


class NotPython3Kit:
    @staticmethod
    def token() -> str:
        digest = hashlib.sha256(b"item 27, a Python 2 setup.py").digest()
        return "ghp_" + "".join(ALPHABET[b % 62] for b in digest[:36])

    @staticmethod
    def sdist(tmp_path, setup: str):
        path = tmp_path / "legacy-1.0.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            data = setup.encode()
            info = tarfile.TarInfo("legacy-1.0/setup.py")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        return Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(path)


class TestAPythonTwoSetupPy:
    def test_is_said_to_be_python_2_and_the_scan_is_complete(self, tmp_path) -> None:
        setup = 'from distutils.core import setup\nprint "building"\nsetup(name="legacy")\n'
        result = NotPython3Kit.sdist(tmp_path, setup)
        rules = {f.rule_id for f in result.findings}
        assert "OPERATIONAL.MANIFEST.NOT_PYTHON3" in rules
        assert "OPERATIONAL.MANIFEST.UNPARSED" not in rules
        assert result.content_complete

    def test_every_text_rule_still_reads_it(self, tmp_path) -> None:
        setup = (
            "from distutils.core import setup\n"
            f'TOKEN = "{NotPython3Kit.token()}"\n'
            'print "building"\nsetup(name="legacy")\n'
        )
        result = NotPython3Kit.sdist(tmp_path, setup)
        assert any(f.rule_id.startswith("SECRET.") for f in result.findings)

    def test_newer_syntax_is_still_unparsed(self, tmp_path) -> None:
        """Syntax this interpreter refuses but a newer Python runs keeps the scan incomplete."""
        setup = "from distutils.core import setup\nx = t'{name}'\nsetup(name='x'\n"
        result = NotPython3Kit.sdist(tmp_path, setup)
        rules = {f.rule_id for f in result.findings}
        assert "OPERATIONAL.MANIFEST.UNPARSED" in rules
        assert not result.content_complete
