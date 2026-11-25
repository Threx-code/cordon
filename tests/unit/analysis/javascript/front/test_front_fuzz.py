"""No text, however hostile, makes the JavaScript lexer or parser raise, and none takes long.

Invented text is drawn from the language's own pieces (template heads, comment openers, escapes, byte order marks, unterminated
quotes), from arbitrary Unicode, and from a few pieces repeated hundreds of times. The lexer must reach the end of the text and
`Parser(...).program()` must return a program, for plain, TypeScript and JSX readings. The number of examples is
`CORDON_FRONT_FUZZ_EXAMPLES` (small by default; the recorded run used 3000).
"""

from __future__ import annotations

import os
import time

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner.analysis.javascript.front.lexer import Lexer
from cordon_scanner.analysis.javascript.front.parser import Parser

EXAMPLES = int(os.environ.get("CORDON_FRONT_FUZZ_EXAMPLES", "40"))
PIECES = [
    "function", "class", "const", "let", "var", "return", "if", "else", "for", "while", "async", "await", "new", "import",
    "export", "default", "from", "yield", "=>", "...", "?.", "??", "**", "${", "}", "{", "(", ")", "[", "]", ";", ",", ".",
    "`", "'", '"', "/", "/*", "*/", "//", "\n", " ", "\\", "\\u{", "0x", "1e", "1_0", "#priv", "@dec", "<T>", "</", "<div>",
    "x", "y", "eval", "require", "a${b}c", "`${`${", "\u2028", "\ufeff", "\x00", "é", "\U0001d4b3", "<!--", "-->", "#!",
]  # fmt: skip
TEXT = st.one_of(
    st.text(max_size=300),
    st.lists(st.sampled_from(PIECES), max_size=120).map("".join),
    st.lists(st.sampled_from(PIECES), min_size=1, max_size=6).flatmap(
        lambda parts: st.integers(1, 400).map(lambda n: "".join(parts) * n)
    ),
)


class TestTheFrontEndNeverRaises:
    @settings(
        max_examples=EXAMPLES,
        deadline=None,
        database=None,
        suppress_health_check=list(HealthCheck),
        derandomize=True,
    )
    @given(TEXT, st.booleans(), st.booleans())
    def test_lexer_and_parser_end_on_any_text(self, text: str, typescript: bool, jsx: bool) -> None:
        began = time.perf_counter()
        lexer = Lexer(text)
        for _ in range(len(text) * 2 + 10):
            if lexer.next(regex=False).kind == "eof":
                break
        else:
            raise AssertionError("the lexer did not reach the end of the text")
        Parser(text, typescript=typescript, jsx=jsx).program()
        assert time.perf_counter() - began < 5.0
