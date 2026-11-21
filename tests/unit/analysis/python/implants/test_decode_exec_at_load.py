"""Decoded data run as code when a package is imported (`flows/implants/decode_exec_at_load.py`).

Every source is assembled for the test and only parsed or scanned; the encoded text is a harmless
assignment written out in the test itself."""

from __future__ import annotations

import base64
import io
import tarfile
from typing import TYPE_CHECKING

from cordon_scanner import Scanner
from cordon_scanner.analysis.python.pyast import PythonAnalyzer
from cordon_scanner.foundation.config.settings import Config

if TYPE_CHECKING:
    from pathlib import Path

BLOB = base64.b64encode(b"X = 1\n").decode()


class DecodeExecKit:
    DETAIL = "decode and run at load"
    RULE = "MALWARE.IMPORT.DECODE_EXEC.001"

    @staticmethod
    def details(source: str) -> list[str]:
        return [
            h.detail for h in PythonAnalyzer.analyse(source) if h.detail == DecodeExecKit.DETAIL
        ]

    @staticmethod
    def rules(tmp_path: Path, init: str, name: str = "__init__.py") -> set[str]:
        archive = tmp_path / "demo-1.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tgz:
            for member, text in (
                ("PKG-INFO", "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n"),
                ("setup.py", "from setuptools import setup\nsetup(name='demo', version='1.0')\n"),
                (f"demo/{name}", init),
            ):
                data = text.encode("utf-8")
                info = tarfile.TarInfo(f"demo-1.0/{member}")
                info.size = len(data)
                tgz.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        return {f.rule_id for f in result.findings}


class TestDecodedAndRunAtLoad:
    def test_a_decoded_string_executed_at_module_level(self) -> None:
        source = f"import base64\nexec(base64.b64decode('{BLOB}'))\n"
        assert DecodeExecKit.details(source) == [DecodeExecKit.DETAIL]

    def test_through_a_name(self) -> None:
        source = f"import base64\ncode = base64.b64decode('{BLOB}')\nexec(code)\n"
        assert DecodeExecKit.details(source) == [DecodeExecKit.DETAIL]

    def test_through_an_alias_and_a_decompress(self) -> None:
        source = (
            "from base64 import b64decode as d\nimport zlib\n"
            f"payload = zlib.decompress(d('{BLOB}'))\n"
            "exec(compile(payload, '<x>', 'exec'))\n"
        )
        assert DecodeExecKit.details(source) == [DecodeExecKit.DETAIL]

    def test_in_a_helper_the_module_calls(self) -> None:
        source = f"import base64\ndef _boot():\n    exec(base64.b64decode('{BLOB}'))\n_boot()\n"
        assert DecodeExecKit.details(source) == [DecodeExecKit.DETAIL]

    def test_a_marshalled_code_object(self) -> None:
        source = "import marshal\nexec(marshal.loads(DATA))\n"
        assert DecodeExecKit.details(source) == [DecodeExecKit.DETAIL]


class TestNotThis:
    def test_a_decode_alone_at_load(self) -> None:
        # An embedded asset or key decoded into data is ordinary.
        source = f"import base64\nICON = base64.b64decode('{BLOB}')\n"
        assert DecodeExecKit.details(source) == []

    def test_an_exec_of_plain_text_at_load(self) -> None:
        source = "SRC = open('plugin.py').read()\nexec(SRC)\n"
        assert DecodeExecKit.details(source) == []

    def test_both_in_a_function_nothing_calls(self) -> None:
        source = f"import base64\ndef run():\n    exec(base64.b64decode('{BLOB}'))\n"
        assert DecodeExecKit.details(source) == []

    def test_both_under_the_main_guard(self) -> None:
        source = (
            f"import base64\nif __name__ == '__main__':\n    exec(base64.b64decode('{BLOB}'))\n"
        )
        assert DecodeExecKit.details(source) == []

    def test_a_decoded_value_beside_an_unrelated_exec(self) -> None:
        source = f"import base64\nKEY = base64.b64decode('{BLOB}')\nexec('X = 1')\n"
        assert DecodeExecKit.details(source) == []


class TestTheRule:
    def test_importing_the_package_blocks(self, tmp_path: Path) -> None:
        init = f"import base64\nexec(base64.b64decode('{BLOB}'))\n"
        assert DecodeExecKit.RULE in DecodeExecKit.rules(tmp_path, init)

    def test_the_same_in_a_test_file_is_not_reported(self, tmp_path: Path) -> None:
        init = f"import base64\nexec(base64.b64decode('{BLOB}'))\n"
        assert DecodeExecKit.RULE not in DecodeExecKit.rules(tmp_path, init, name="test_boot.py")
