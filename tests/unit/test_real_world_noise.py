"""False positives found by scanning code nobody here wrote.

Every case below was produced by scanning five widely used Python packages --
click, Flask, Jinja2, PyYAML, requests -- and reading what came back. That is a
different test from the corpus: a corpus sample is written alongside its rule
and tends to be shaped the way the rule expects, so it demonstrates that a rule
can fire rather than that it fires on the right things.

Thirty-nine findings came back. Seventeen were wrong, and each cause is
reproduced here so it cannot come back.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.models import Category
from cordon_scanner.detect.obfuscation import BIDI_AND_INVISIBLE
from cordon_scanner.detect.secrets import NOT_A_SECRET
from support import assemble

BOM = chr(0xFEFF)
"""Written as a code point, not embedded. A literal byte-order mark in this file
would make it the thing it is testing for."""


def flagged(root) -> set[str]:
    return {
        f.rule_id
        for f in Scanner().scan(root).findings
        if f.category in (Category.MALICIOUS, Category.SUSPICIOUS)
    }


class TestTheByteOrderMarkGuardActuallyGuards:
    """`(?!\\A)` placed after the BOM bytes tests the position *after* them,
    where it is always true. Written that way the guard excluded nothing, and
    every file a Windows editor saved with a byte-order mark was reported as a
    Trojan Source attack -- fourteen of them in PyYAML's own UTF-8 corpus."""

    def test_a_leading_bom_is_ordinary(self) -> None:
        assert BIDI_AND_INVISIBLE.search(f"{BOM}--- UTF-8\n".encode()) is None

    def test_a_bom_later_in_the_file_is_not(self) -> None:
        assert BIDI_AND_INVISIBLE.search(f"x = 1\n{BOM}y = 2\n".encode()) is not None

    def test_a_real_override_still_fires(self) -> None:
        assert BIDI_AND_INVISIBLE.search(f"if user {chr(0x202E)} admin".encode()) is not None

    def test_a_bom_prefixed_file_scans_clean(self, tmp_path) -> None:
        (tmp_path / "conf.yaml").write_bytes(f"{BOM}name: example\nvalue: 1\n".encode())
        assert flagged(tmp_path) == set()


class TestAssignmentBetweenNames:
    """The unquoted branch of the assignment pattern exists to catch
    `PASSWORD=hunter2` in a dotenv file. It read the right-hand side of
    `token = TOKEN_BLOCK_BEGIN` as a value, and three of five packages reported
    a credential for it."""

    @pytest.mark.parametrize(
        "value",
        [
            b"TOKEN_BLOCK_BEGIN",
            b"TOKEN_VARIABLE_END",
            b"parent.token_normalize_func",
            b"self.stream.current",
        ],
    )
    def test_an_identifier_is_not_a_credential(self, value: bytes) -> None:
        assert NOT_A_SECRET.match(value)

    @pytest.mark.parametrize(
        "value",
        [
            # Assembled: this file is scanned by the tool it tests.
            assemble("kR9mT2nQ8vL4", "xW7yZ3bC6dF1").encode(),
            assemble("AKIA", "Q7XKLMNPQRSTUVWX").encode(),
        ],
    )
    def test_key_material_is_still_key_material(self, value: bytes) -> None:
        assert not NOT_A_SECRET.match(value)

    def test_a_lexer_scans_clean(self, tmp_path) -> None:
        (tmp_path / "lexer.py").write_text(
            "TOKEN_BLOCK_BEGIN = 'block_begin'\n"
            "def read(self):\n"
            "    token = TOKEN_BLOCK_BEGIN\n"
            "    token_normalize_func = self.parent.token_normalize_func\n"
            "    return token, token_normalize_func\n",
            encoding="utf-8",
        )
        assert flagged(tmp_path) == set()


class TestImagesAreNotExecutables:
    """The strings pass exists for things that might run. A PNG containing
    "https://" is a screenshot of a browser, and Flask's documentation images
    were reported as binaries carrying a URL."""

    def test_a_png_with_a_url_in_it_is_not_reported(self, tmp_path) -> None:
        (tmp_path / "screenshot.png").write_bytes(
            b"\x89PNG\r\n\x1a\n" + b"\x00" * 32 + b"https://example.com/docs\x00" + b"\x00" * 64
        )
        assert flagged(tmp_path) == set()

    def test_an_unidentified_binary_with_a_url_still_is(self, tmp_path) -> None:
        """What the pass is for: bytes that are not text and not a format we
        recognise, which is what a prepended payload looks like."""
        (tmp_path / "blob").write_bytes(
            b"\x00\x01\x02\x03" * 8 + b"https://c2.invalid/beacon\x00/bin/sh\x00" + b"\x00" * 32
        )
        assert "SUSPECT.BINARY.STRINGS.001" in flagged(tmp_path)


class TestLazyAttributeLookupIsNotAnAttack:
    """`globals()[name]` is the ordinary lazy-attribute idiom, and pairing it
    with an environment read -- which appears in a large share of all Python --
    reported click, Flask and PyYAML as suspicious."""

    def test_computed_lookup_plus_an_env_read_is_quiet(self, tmp_path) -> None:
        (tmp_path / "utils.py").write_text(
            "import os\n\n"
            "def resolve(name):\n"
            "    return globals()[name]\n\n"
            "def colour():\n"
            "    return os.environ.get('NO_COLOR')\n",
            encoding="utf-8",
        )
        assert "SUSPECT.DYNAMIC_DISPATCH.001" not in flagged(tmp_path)

    def test_computed_lookup_plus_decoding_still_fires(self, tmp_path) -> None:
        """What the rule is for: a target that cannot be read from the source,
        next to a payload that arrives encoded."""
        (tmp_path / "loader.py").write_text(
            "import base64, os\n\n"
            "name = base64.b64decode(os.environ['B']).decode()\n"
            "getattr(os, name)('id')\n",
            encoding="utf-8",
        )
        assert "SUSPECT.DYNAMIC_DISPATCH.001" in flagged(tmp_path)
