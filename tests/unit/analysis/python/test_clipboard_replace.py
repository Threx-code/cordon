"""A clipper: the clipboard read, matched against a pattern, and set to a value the package carries
(`flows/clipboard_replace.py`).

Every source is assembled for the test and only parsed. The twins reformat what they read, write what
the user chose, or only read."""

from __future__ import annotations

import io
import tarfile
from typing import TYPE_CHECKING

from cordon_scanner import Scanner
from cordon_scanner.analysis.python.pyast import PythonAnalyzer
from cordon_scanner.foundation.config.settings import Config

if TYPE_CHECKING:
    from pathlib import Path

ADDRESS = "bc1" + "q" + "x" * 30


class Kit:
    @staticmethod
    def replaced(source: str) -> list[str]:
        return [h.detail for h in PythonAnalyzer.analyse(source) if h.detail == "clipboard replaced"]


class TestAClipperInAnyLibrary:
    def test_pyperclip(self) -> None:
        source = (
            "import re, pyperclip\n"
            f"MINE = '{ADDRESS}'\n"
            "def watch():\n"
            "    text = pyperclip.paste()\n"
            "    if re.match(r'^(bc1|[13])[a-zA-Z0-9]{25,39}$', text):\n"
            "        pyperclip.copy(MINE)\n"
        )
        assert Kit.replaced(source) == ["clipboard replaced"]

    def test_win32clipboard(self) -> None:
        source = (
            "import re, win32clipboard\n"
            "def watch():\n"
            "    win32clipboard.OpenClipboard()\n"
            "    data = win32clipboard.GetClipboardData()\n"
            "    if re.search(r'0x[a-fA-F0-9]{40}', data):\n"
            f"        win32clipboard.SetClipboardText('{ADDRESS}')\n"
        )
        assert Kit.replaced(source) == ["clipboard replaced"]

    def test_tkinter(self) -> None:
        source = (
            "import re, tkinter\n"
            "root = tkinter.Tk()\n"
            "def watch():\n"
            "    text = root.clipboard_get()\n"
            "    if re.fullmatch(r'[A-Za-z0-9]{34}', text):\n"
            "        root.clipboard_clear()\n"
            f"        root.clipboard_append('{ADDRESS}')\n"
        )
        assert Kit.replaced(source) == ["clipboard replaced"]

    def test_a_replacement_decoded_from_a_constant(self) -> None:
        source = (
            "import base64, re, pyperclip\n"
            "BLOB = 'YmMxcXg='\n"
            "def watch():\n"
            "    t = pyperclip.paste().strip()\n"
            "    if re.match('^bc1', t):\n"
            "        pyperclip.copy(base64.b64decode(BLOB).decode())\n"
        )
        assert Kit.replaced(source) == ["clipboard replaced"]

    def test_the_command_line_clipboards(self) -> None:
        source = (
            "import re, subprocess\n"
            "def watch():\n"
            "    t = subprocess.check_output(['pbpaste']).decode()\n"
            "    if re.match('^bc1', t):\n"
            f"        subprocess.run(['pbcopy'], input=b'{ADDRESS}')\n"
        )
        assert Kit.replaced(source) == ["clipboard replaced"]


class TestOrdinaryClipboardTools:
    def test_a_tool_that_reformats_what_it_read(self) -> None:
        source = (
            "import re, pyperclip\n"
            "def clean():\n"
            "    text = pyperclip.paste()\n"
            "    pyperclip.copy(re.sub(r'\\s+', ' ', text))\n"
        )
        assert Kit.replaced(source) == []

    def test_a_manager_that_copies_what_the_user_chose(self) -> None:
        source = (
            "import re, pyperclip\n"
            "def restore(entry):\n"
            "    current = pyperclip.paste()\n"
            "    if re.match('^x', current):\n"
            "        return\n"
            "    pyperclip.copy(entry)\n"
        )
        assert Kit.replaced(source) == []

    def test_a_reader_with_no_write(self) -> None:
        source = "import re, pyperclip\ndef find():\n    return re.findall(r'\\d+', pyperclip.paste())\n"
        assert Kit.replaced(source) == []

    def test_a_writer_with_no_read(self) -> None:
        source = f"import pyperclip\ndef share():\n    pyperclip.copy('{ADDRESS}')\n"
        assert Kit.replaced(source) == []


class TestTheRule:
    def test_the_clipper_blocks(self, tmp_path: Path) -> None:
        module = (
            "import re, pyperclip\n"
            f"MINE = '{ADDRESS}'\n"
            "def watch():\n"
            "    text = pyperclip.paste()\n"
            "    if re.match(r'^(bc1|[13])[a-zA-Z0-9]{25,39}$', text):\n"
            "        pyperclip.copy(MINE)\n"
        )
        files = {
            "PKG-INFO": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
            "pyproject.toml": "[project]\nname = 'demo'\nversion = '1.0'\n",
            "src/demo/__init__.py": "",
            "src/demo/watch.py": module,
        }
        archive = tmp_path / "demo-1.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tgz:
            for name, text in files.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(f"demo-1.0/{name}")
                info.size = len(data)
                tgz.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        assert "MALWARE.CLIPPER.001" in {f.rule_id for f in result.findings}
