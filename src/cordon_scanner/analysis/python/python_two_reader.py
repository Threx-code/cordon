"""A Python 2 file read as code: its text rewritten to the Python 3 that means the same (09 3a).

A file this Python will not parse was skipped by every reader. When it is Python 2 (or Python 3.6
or older, where `async` was a name), a Python 3 that runs it does not exist -- but what it does is
still what the package says, and a Python 2 payload is still a payload. So it is not exempted; it
is rewritten, line for line, into Python 3 that parses, and that text is what the detectors read
(a reading of the file, `Units`'s `#as-python.py`). Line numbers are kept: every rewrite stays on
its lines, a neutralised statement keeps its line count.

```
  text that does not parse
     │ 1. lexical, outside strings and comments: leading tabs at 8 columns, 0L -> 0, 0777 -> 0o777,
     │    <> -> !=, `x` -> repr(x), ur'' -> r''
     │ 2. statements, one token pass: print x -> print(x), exec c in g -> exec(c, g),
     │    except A, e -> except A as e, raise E, v -> raise E(v)
     ▼ 3. what still fails, one statement at a time (bounded by the line count): tuple parameters,
  parses?   `async`/`await` as names, or a Python 2 construct on the failing line -> that whole
     │      logical statement neutralised; anything else -> not Python 2: no reading (`stuck`)
     ▼
  the reading (str), or None
```
"""

from __future__ import annotations

import contextlib
import io
import re
import tokenize
from dataclasses import dataclass

#: One rewrite: from (line, column) to (line, column), the text that replaces it.
Edit = tuple[tuple[int, int], tuple[int, int], str]


@dataclass(frozen=True, slots=True)
class Reading:
    """What reading a file as Python 2 gave: the Python 3 text (None when it is not Python 2), and
    where it stopped: the 1-based line of the failure no rewrite explains, in `partial`, the text as
    far as it was rewritten (what the gap guard reads)."""

    text: str | None
    stuck_line: int | None = None
    partial: str = ""


class PythonTwoReader:
    #: Parses after the one-pass rewrites, each fixing one statement the passes did not. Bounded so
    #: a file padded with failures costs a fixed number of parses, not one per line.
    RETRIES = 64
    #: A number Python 2 wrote with a long suffix, or an octal with a bare leading zero.
    LONG: re.Pattern[str] = re.compile(r"(?<![\w.])((?:0[xX][0-9a-fA-F]+)|(?:\d+))[lL]\b")
    OCTAL: re.Pattern[str] = re.compile(r"(?<![\w.])0([0-7]+)\b(?![.eEjJxXoObB])")
    BACKTICK: re.Pattern[str] = re.compile(r"`([^`\n]*)`")
    #: Tuple parameters: `def f(self, (a, b)):` and `lambda (x, y): ...`.
    TUPLE_PARAMETER: re.Pattern[str] = re.compile(r"(?<=[(,])(\s*)\(([\w\s,]+)\)")
    TUPLE_LAMBDA: re.Pattern[str] = re.compile(r"\blambda\s*\(([\w\s,]+)\)")
    #: `async` and `await` used as names (Python 3.6 and older): an attribute, a definition, an
    #: assignment, a module, a condition (`if async:`) -- never the keyword opening
    #: `async def/for/with`. Applied only to the line the parse failed on.
    OLD_NAME: re.Pattern[str] = re.compile(
        r"(?:(?<=\.)|(?<=\bdef )|(?<=\bimport )|(?<=\bfrom \.))(async|await)\b"
        r"|\b(async|await)\b(?=\s*(?:=[^=]|[,:)\]]|\.|$|(?:is|in|and|or|not|if|else)\b|[!=<>+*/%-]))"
    )
    #: A definition's own type-parameter list: `def f[T = int](...)`, `class C[T = int]`, `type A[T = int]`.
    TYPE_PARAMETERS: re.Pattern[str] = re.compile(
        r"^(\s*(?:async\s+)?(?:def|class|type)\s+\w+\s*)\["
    )
    #: `x.None`: Python 2 let `None` be an attribute name.
    NONE_ATTRIBUTE: re.Pattern[str] = re.compile(r"(?<=\.)None\b")

    @staticmethod
    def read(text: str) -> Reading:
        """`text`, which this Python refused, read as Python 2: see the module docstring."""
        from cordon_scanner.analysis.python.pysyntax import PythonSyntax
        from cordon_scanner.analysis.python.statements import PythonTwo

        lines = PythonTwoReader.source_lines(PythonTwoReader.lexical(text))
        lines = PythonTwoReader.statements(lines)
        for _ in range(PythonTwoReader.RETRIES):
            joined = "".join(lines)
            try:
                PythonSyntax.parse(joined)
            except SyntaxError as exc:
                # S2: a fallback; the next reader (or SOURCE.UNPARSED for running files) reads it
                at = exc.lineno
                if at is None or not 1 <= at <= len(lines):
                    return Reading(None, at, joined)
                if PythonTwoReader.targeted(lines, at, exc.msg or ""):
                    continue
                if PythonTwo.construct(joined, at) is None:
                    return Reading(None, at, joined)
                before = list(lines)
                PythonTwoReader.neutralise(lines, at)
                if lines == before:
                    return Reading(None, None, joined)
                continue
            except (ValueError, RecursionError, MemoryError):
                # S2: a fallback; the next reader (or SOURCE.UNPARSED for running files) reads it
                return Reading(None, None, joined)
            return Reading(joined)
        # Past the bound: an attacker can pad a file with failures, so this is never "not Python
        # 2" -- no line is named, and the caller keeps the file a gap (fail closed).
        return Reading(None, None, "".join(lines))

    @staticmethod
    def source_lines(text: str) -> list[str]:
        """`text`'s lines as Python's tokenizer counts them, ends kept: broken at `\\n`, `\\r\\n` and
        `\\r` only. `str.splitlines` also breaks at a form feed, `\\x0b`, `\\x1c`-`\\x1e`, `\\x85`,
        U+2028 and U+2029, and each rewrite after one landed on the wrong line (lava-test 0.14)."""
        return io.StringIO(text, newline="").readlines()

    @staticmethod
    def wholly(text: str) -> bool:
        """Whether a file Python 3 refuses is Python 2 through and through with no rewrite at all,
        not merely a file with one Python 2 token in it: every line the parse fails on carries a
        Python-2-only construct (`PythonTwo.construct`). The whole logical statement holding each
        such line is neutralised (`neutralise`) and the parse retried, at most once per line; a
        failure with no Python 2 construct on its line ends it (09 3a)."""
        from cordon_scanner.analysis.python.pysyntax import PythonSyntax
        from cordon_scanner.analysis.python.statements import PythonTwo

        lines = PythonTwoReader.source_lines(text)
        changed = False
        for _ in range(len(lines) + 1):
            joined = "".join(lines)
            try:
                PythonSyntax.parse(joined)
            except SyntaxError as exc:
                # S2: a fallback; the next reader (or SOURCE.UNPARSED for running files) reads it
                at = exc.lineno
                if (
                    at is None
                    or not 1 <= at <= len(lines)
                    or PythonTwo.construct(joined, at) is None
                ):
                    return False
                before = list(lines)
                PythonTwoReader.neutralise(lines, at)
                if lines == before:
                    return False
                changed = True
                continue
            except (ValueError, RecursionError):
                # S2: a fallback; the next reader (or SOURCE.UNPARSED for running files) reads it
                return False
            return changed
        return False

    # -- 1. lexical ------------------------------------------------------------------------------

    @staticmethod
    def lexical(text: str) -> str:
        """The rewrites that need no statement: tabs in indentation at Python 2's 8 columns, and
        the literals and operators only Python 2 has, outside strings and comments."""
        out: list[str] = []
        code: list[str] = []
        i, n = 0, len(text)
        at_line_start = True
        unicode_literals = PythonTwoReader.UNICODE_LITERALS.search(text) is not None

        def flush() -> None:
            if code:
                out.append(PythonTwoReader.literals("".join(code)))
                code.clear()

        while i < n:
            char = text[i]
            if at_line_start:
                end = i
                while end < n and text[end] in " \t\f":
                    end += 1
                code.append(text[i:end].replace("\f", "").expandtabs(8))
                i, at_line_start = end, False
                continue
            if char == "#":
                flush()
                end = text.find("\n", i)
                end = n if end < 0 else end
                out.append(text[i:end])
                i = end
                continue
            if char in "'\"":
                prefix = PythonTwoReader._prefix(code).lower()  # before the flush: still in `code`
                flush()
                end = PythonTwoReader._string_end(text, i)
                literal = text[i:end]
                if not set(prefix) & set("rf"):
                    unicode = "u" in prefix or (unicode_literals and "b" not in prefix)
                    literal = PythonTwoReader.escapes(literal, unicode=unicode)
                out.append(literal)
                i = end
                continue
            code.append(char)
            if char == "\n":
                at_line_start = True
            i += 1
        flush()
        return "".join(out)

    @staticmethod
    def _prefix(code: list[str]) -> str:
        """The string prefix just before a quote, and `ur` turned to `r` in place."""
        tail = "".join(code[-3:])
        found = re.search(r"(?<![\w])([uUbBrRfF]{1,2})$", tail)
        if found is None:
            return ""
        prefix = found.group(1)
        if prefix.lower() == "ur":
            del code[len(code) - 2 :]
            code.append(prefix[1])
        return prefix

    UNICODE_LITERALS: re.Pattern[str] = re.compile(
        r"^\s*from\s+__future__\s+import\b[^\n]*\bunicode_literals\b", re.MULTILINE
    )

    #: The escapes Python 2 defines in a str; a unicode string adds `\u`, `\U` and `\N`.
    STR_ESCAPES = frozenset("\n\r\\'\"abfnrtv01234567x")

    @staticmethod
    def escapes(literal: str, *, unicode: bool) -> str:
        """A Python 2 string literal with the value Python 2 gave it: an escape Python 2 does not
        define is not one, and its backslash is kept -- so it is doubled here (`"C:\\Users"` in a
        str), which Python 3 would refuse or warn about."""
        known = PythonTwoReader.STR_ESCAPES | (frozenset("uUN") if unicode else frozenset())
        out: list[str] = []
        i = 0
        while i < len(literal):
            if literal[i] == "\\" and i + 1 < len(literal):
                pair = literal[i : i + 2]
                out.append(pair if pair[1] in known else "\\" + pair)
                i += 2
                continue
            out.append(literal[i])
            i += 1
        return "".join(out)

    @staticmethod
    def _string_end(text: str, start: int) -> int:
        quote = text[start]
        triple = text.startswith(quote * 3, start)
        closing = quote * 3 if triple else quote
        i = start + len(closing)
        while i < len(text):
            if text[i] == "\\":
                i += 2
                continue
            if text.startswith(closing, i):
                return i + len(closing)
            if text[i] == "\n" and not triple:
                return i  # an unterminated string ends at its line, as the tokenizer says
            i += 1
        return len(text)

    @staticmethod
    def literals(code: str) -> str:
        code = PythonTwoReader.LONG.sub(r"\1", code)
        code = PythonTwoReader.OCTAL.sub(r"0o\1", code)
        code = code.replace("<>", "!=")
        return PythonTwoReader.BACKTICK.sub(r"repr(\1)", code)

    # -- 2. statements ---------------------------------------------------------------------------

    @staticmethod
    def statements(lines: list[str]) -> list[str]:
        """print, exec, except and raise statements rewritten, in one pass over the tokens. A file
        the tokenizer refuses part-way keeps the edits found before that point."""
        edits: list[Edit] = []
        with contextlib.suppress(tokenize.TokenError, SyntaxError, IndentationError):
            PythonTwoReader._collect(lines, edits)
        for start, end, new in sorted(edits, reverse=True):
            (sl, sc), (el, ec) = start, end
            if sl != el:
                continue
            line = lines[sl - 1]
            lines[sl - 1] = line[:sc] + new + line[ec:]
        return lines

    @staticmethod
    def _collect(lines: list[str], edits: list[Edit]) -> None:
        """Split the token stream into simple statements -- at a NEWLINE, a top-level `;`, and the
        `:` ending a compound statement's header (`if x: print y`) -- and rewrite each."""
        tokens = tokenize.generate_tokens(io.StringIO("".join(lines)).readline)
        statement: list[tokenize.TokenInfo] = []
        depth = 0
        for token in tokens:
            if token.type in (tokenize.NL, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT):
                continue
            ends = token.type in (tokenize.NEWLINE, tokenize.ENDMARKER) or (
                token.type == tokenize.OP and token.string == ";" and depth == 0
            )
            if ends:
                PythonTwoReader._simple(statement, edits)
                statement, depth = [], 0
                continue
            if (
                token.type == tokenize.OP
                and token.string == ":"
                and depth == 0
                and statement
                and statement[0].string in PythonTwoReader.COMPOUND
            ):
                PythonTwoReader._simple([*statement, token], edits)
                statement = []
                continue
            if token.type == tokenize.OP and token.string in ("(", "[", "{"):
                depth += 1
            elif token.type == tokenize.OP and token.string in (")", "]", "}"):
                depth = max(depth - 1, 0)
            statement.append(token)

    COMPOUND = frozenset(
        {"if", "elif", "else", "for", "while", "try", "except", "finally", "with", "def", "class"}
    )

    @staticmethod
    def _simple(statement: list[tokenize.TokenInfo], edits: list[Edit]) -> None:
        if not statement:
            return
        first = statement[0]
        word = first.string
        if word in ("print", "exec") and len(statement) > 1:
            following = statement[1]
            if following.type == tokenize.OP and following.string in ("(", "=", ".", ",", ")", "["):
                return  # print(x), print = f, print.x: already Python 3
            last = statement[-1]
            edits.append((first.end, following.start, "("))
            edits.append((last.end, last.end, ")"))
            for token in statement[1:]:
                if token.type == tokenize.OP and token.string == ">>" and token is following:
                    edits.append((token.start, token.end, ""))
                if word == "exec" and token.type == tokenize.NAME and token.string == "in":
                    edits.append((token.start, token.end, ","))
            return
        if word == "except" and statement[-1].string == ":":
            comma = PythonTwoReader._top_comma(statement)
            if comma is not None and comma == len(statement) - 3:
                # Up to the name, so `except E,e:` (no space) is `except E as e:` too.
                token, name = statement[comma], statement[comma + 1]
                edits.append((token.start, name.start, " as "))
                return
            PythonTwoReader._tuple_target(statement, comma, edits)
            return
        if word == "raise":
            comma = PythonTwoReader._top_comma(statement)
            if comma is not None:
                token, last = statement[comma], statement[-1]
                edits.append((token.start, token.end, "("))
                edits.append((last.end, last.end, ")"))

    @staticmethod
    def _tuple_target(
        statement: list[tokenize.TokenInfo], comma: int | None, edits: list[Edit]
    ) -> None:
        """`except E, (a, b):` and `except E as (a, b):`: Python 2 unpacked the exception into a
        tuple; Python 3 binds one name only. The target is dropped (`except E:`), the handler kept."""
        separator = comma
        if separator is None:
            separator = next(
                (
                    i
                    for i, t in enumerate(statement)
                    if t.type == tokenize.NAME and t.string == "as"
                ),
                None,
            )
        if (
            separator is not None
            and separator + 1 < len(statement) - 2
            and statement[separator + 1].string == "("
            and statement[-2].string == ")"
        ):
            edits.append((statement[separator].start, statement[-2].end, ""))

    @staticmethod
    def _top_comma(statement: list[tokenize.TokenInfo]) -> int | None:
        depth = 0
        for index, token in enumerate(statement):
            if token.type != tokenize.OP:
                continue
            if token.string in "([{":
                depth += 1
            elif token.string in ")]}":
                depth -= 1
            elif token.string == "," and depth == 0:
                return index
        return None

    # -- 3. what still fails ---------------------------------------------------------------------

    @staticmethod
    def targeted(lines: list[str], at: int, message: str) -> bool:
        """A rewrite for the failure at line `at` that keeps the statement: tuple parameters, and
        `async`/`await` as names. True when the line changed."""
        line = lines[at - 1]
        new = line
        if "parameters cannot be parenthesized" in message:
            new = PythonTwoReader.TUPLE_LAMBDA.sub(r"lambda \1", new)
            new = PythonTwoReader.TUPLE_PARAMETER.sub(r"\1\2", new)
        elif (stripped := PythonTwoReader.without_type_defaults(line)) != line:
            new = stripped
        else:
            code = PythonTwoReader.NONE_ATTRIBUTE.sub("None_", new.split("#", 1)[0])
            new = PythonTwoReader.OLD_NAME.sub(
                lambda m: (m.group(1) or m.group(2)) + "_", code
            ) + (("#" + new.split("#", 1)[1]) if "#" in new else "")
        if new == line:
            return False
        lines[at - 1] = new
        return True

    @staticmethod
    def without_type_defaults(line: str) -> str:
        """`line` with the defaults of its type parameters taken out (Python 3.13 syntax this Python
        does not parse): what the definition does is what it does without them."""
        found = PythonTwoReader.TYPE_PARAMETERS.match(line)
        if found is None:
            return line
        out: list[str] = [line[: found.end()]]
        depth, skipping = 1, False
        for char in line[found.end() :]:
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            if depth == 0:
                skipping = False
            if depth == 1 and char == "=" and not skipping:
                skipping = True
            elif depth == 1 and char == "," and skipping:
                skipping = False
            if not skipping:
                out.append(char)
        return "".join(out)

    @staticmethod
    def neutralise(lines: list[str], at: int) -> None:
        """The whole logical statement holding line `at`, made inert: its first line becomes
        `except Exception:`, `if True:` or `pass` (indentation kept), its continuation lines empty,
        so the statement's line count and every line after it stay where they were. Each line keeps
        its own ending -- `\\n`, `\\r\\n`, `\\r`, or none on a file's last line, which a `\\n` written
        there would have turned into one line more (found by tests/fuzz: a lone backquote)."""
        start, end = PythonTwoReader.span(lines, at)
        original = lines[start - 1]
        indent = original[: len(original) - len(original.lstrip())]
        body = original.split("#", 1)[0].strip()
        whole = "".join(lines[start - 1 : end]).split("#", 1)[0].rstrip()
        if body.startswith("except"):
            neutral = "except Exception:"
        elif whole.endswith(":"):
            neutral = "if True:"
        else:
            neutral = "pass"
        lines[start - 1] = f"{indent}{neutral}{PythonTwoReader._ending(original)}"
        for index in range(start, end):
            lines[index] = PythonTwoReader._ending(lines[index])

    @staticmethod
    def _ending(line: str) -> str:
        """The line break `line` ends with, as `source_lines` kept it: empty for a last line."""
        return line[len(line.rstrip("\r\n")) :]

    @staticmethod
    def span(lines: list[str], at: int) -> tuple[int, int]:
        """The 1-based first and last line of the logical statement holding line `at`: back while the
        line before continues (a trailing backslash, an open bracket), forward while this one does."""
        depth_before = PythonTwoReader._depths(lines)
        start = at
        while start > 1 and (
            depth_before[start - 1] > 0 or lines[start - 2].rstrip().endswith("\\")
        ):
            start -= 1
        end = at
        while end < len(lines) and (
            depth_before[end] > 0 or lines[end - 1].rstrip("\r\n").endswith("\\")
        ):
            end += 1
        return start, end

    @staticmethod
    def _depths(lines: list[str]) -> list[int]:
        """Bracket depth at the start of each line (index i = before line i+1), strings and
        comments skipped; the last entry is after the last line."""
        depths = [0]
        depth = 0
        text = "".join(lines)
        i, n = 0, len(text)
        while i < n:
            char = text[i]
            if char == "#":
                end = text.find("\n", i)
                i = n if end < 0 else end
                continue
            if char in "'\"":
                end = PythonTwoReader._string_end(text, i)
                depths.extend([depth] * text.count("\n", i, end))
                i = end
                continue
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth = max(depth - 1, 0)
            elif char == "\n":
                depths.append(depth)
            i += 1
        while len(depths) < len(lines) + 1:
            depths.append(depth)
        return depths


__all__ = ["PythonTwoReader", "Reading"]
