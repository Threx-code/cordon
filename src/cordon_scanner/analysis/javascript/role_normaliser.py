"""A file's code as tokens that renaming, re-hosting and re-wording do not change (programme 3A, release
item 59, notes/59-role-normaliser.md): the shape campaign similarity compares.

One linear pass over `JsEval.tokens`, never a parser:

- an identifier becomes its role, decided where the name is bound (after var/let/const/function/class:
  LOCAL; in a parameter list: PARAM; as what require or import binds: IMPORT) and taken by each later
  use from the nearest earlier binding of that spelling; a property after `.` is PROP; anything else
  FREE;
- platform API names, keywords and operators are kept, as cf1 keeps them (`CodeFeatures`), and a
  computed member that names one (`x['exec']`, `x?.exec`) reads as `x.exec`;
- a string or number becomes a class token: cf1's literal classes, plus S:SHELL for a command line, or
  the string itself where it names a platform module;
- comments and blanks are gone with the tokenizer.

Its own version (rn1): item 47's model reads cf1 and is never mixed with this. Text only: nothing is
decoded, evaluated or run.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.javascript.code_model import CodeFeatures

if TYPE_CHECKING:
    from collections.abc import Iterable


class RoleNormaliser:
    """Bytes to normalised token strings and their 32-bit ids."""

    VERSION: ClassVar[str] = "rn1"
    MAX_BYTES: ClassVar[int] = 2_000_000
    MAX_TOKENS: ClassVar[int] = CodeFeatures.MAX_TOKENS

    ROLES: ClassVar[tuple[str, ...]] = ("LOCAL", "PARAM", "IMPORT", "PROP", "FREE")
    LITERALS: ClassVar[tuple[str, ...]] = (
        "S:URL",
        "S:IP",
        "S:PATH",
        "S:SHELL",
        "S:HEX",
        "S:B64",
        "S:SHORT",
        "S:LONG",
        "N",
        "R",  # a regular expression literal
    )
    #: The tokenizer's punctuation and operators, every one kept as itself.
    PUNCT: ClassVar[tuple[str, ...]] = (
        "===", "!==", "...", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=", "=>", "==", "!=", "<=",
        ">=", "&&", "||", "??", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>",
        "**", "?.", "{", "}", "(", ")", "[", "]", ";", ",", "<", ">", "+", "-", "*", "/", "%", "&",
        "|", "^", "!", "~", "?", ":", "=", ".", "@", "#",
    )  # fmt: skip
    #: A token outside the closed vocabulary (an operator the list above lacks) reads as this.
    OTHER: ClassVar[str] = "P:OTHER"

    _DECLARES: ClassVar[frozenset[str]] = frozenset({"var", "let", "const", "function", "class"})
    #: First words of a command line (notes/59, review change 2): POSIX and Windows.
    _COMMANDS: ClassVar[frozenset[str]] = frozenset(
        {
            "curl", "wget", "sh", "bash", "zsh", "dash", "chmod", "chown", "nc", "ncat", "netcat",
            "python", "python3", "perl", "node", "nohup", "rm", "mkdir", "cp", "mv", "cat", "echo",
            "tar", "unzip", "base64", "openssl", "sudo", "crontab", "launchctl", "systemctl", "osascript",
            "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "reg", "schtasks", "start",
            "certutil", "bitsadmin", "mshta", "rundll32", "regsvr32", "wscript", "cscript",
        }
    )  # fmt: skip
    _CHAIN: ClassVar[re.Pattern[str]] = re.compile(r"&&|;\s*\S|`|\$\(")
    _PIPED: ClassVar[re.Pattern[str]] = re.compile(r"(?:\||>{1,2})\s*(\S+)")

    @classmethod
    def vocabulary(cls) -> tuple[str, ...]:
        """Every token string `tokens` can produce: closed, so its ids can be checked for collisions."""
        kept = sorted(CodeFeatures.PLATFORM | CodeFeatures.KEYWORDS)
        modules = [f"S:{m}" for m in sorted(CodeFeatures.PLATFORM)]
        return (*cls.ROLES, *cls.LITERALS, *cls.PUNCT, cls.OTHER, *kept, *modules)

    @classmethod
    def vocabulary_hash(cls) -> str:
        """What an index built from these ids was made with (its header carries it, review change 5)."""
        spec = json.dumps(
            [cls.VERSION, cls.MAX_TOKENS, sorted(cls._COMMANDS), list(cls.vocabulary())]
        )
        return hashlib.sha256(spec.encode()).hexdigest()[:16]

    @staticmethod
    def token_id(token: str) -> int:
        return int.from_bytes(hashlib.blake2b(token.encode(), digest_size=4).digest(), "big")

    @classmethod
    def ids(cls, data: bytes) -> list[int]:
        """The file's normalised tokens as ids: what the fingerprints shingle."""
        return [cls.token_id(t) for t in cls.tokens(data)]

    @classmethod
    def tokens(cls, data: bytes) -> list[str]:
        from cordon_scanner.analysis.javascript.js_eval import JsEval

        text = data[: cls.MAX_BYTES].decode("utf-8", "replace")
        toks = JsEval.tokens(text, templates=True)[: cls.MAX_TOKENS]
        return list(cls._normalise(toks))

    @classmethod
    def _normalise(cls, toks: list[Any]) -> Iterable[str]:
        bound: dict[str, str] = {}  # spelling -> role of its nearest earlier binding
        params = 0  # depth inside a function's parameter list
        i, n = 0, len(toks)
        while i < n:
            tok = toks[i]
            kind, value = tok.kind, tok.value
            if kind == "punct":
                if (
                    value == "?"
                    and i + 1 < n
                    and toks[i + 1].kind == "punct"
                    and toks[i + 1].value == "."
                ):
                    i += 1  # `?.` reads as `.`
                    continue
                if (
                    value == "["
                    and i + 2 < n
                    and toks[i + 1].kind == "str"
                    and toks[i + 2].kind == "punct"
                    and toks[i + 2].value == "]"
                    and str(toks[i + 1].value) in CodeFeatures.PLATFORM
                ):
                    yield "."  # `x['exec']` reads as `x.exec`
                    yield str(toks[i + 1].value)
                    i += 3
                    continue
                params = cls._parameters(toks, i, params)
                yield value if value in cls.PUNCT else cls.OTHER
            elif kind == "name":
                yield cls._name(toks, i, bound, params)
            elif kind in ("str", "longstr", "tmpl"):
                yield cls._literal(str(value))
            elif kind == "num":
                yield "N"
            elif kind == "regex":
                yield "R"
            else:
                yield cls.OTHER
            i += 1

    @staticmethod
    def _parameters(toks: list[Any], i: int, depth: int) -> int:
        """The parameter-list depth after the punctuation at `i`: `(` opens one after `function name?`
        or before an arrow's `)` `=>`; `)` closes it."""
        value = toks[i].value
        if value == "(":
            if depth:
                return depth + 1
            before = toks[i - 1] if i else None
            before2 = toks[i - 2] if i > 1 else None
            if (
                before is not None
                and before.kind == "name"
                and (
                    before.value == "function"
                    or (before2 is not None and before2.value == "function")
                )
            ):
                return 1
            if RoleNormaliser._arrow_follows(toks, i):
                return 1
            return 0
        if value == ")" and depth:
            return depth - 1
        return depth

    @staticmethod
    def _arrow_follows(toks: list[Any], i: int) -> bool:
        """Whether the `(` at `i` opens an arrow function's parameters: its matching `)` precedes `=>`."""
        depth = 0
        for j in range(i, min(len(toks), i + 256)):
            if toks[j].kind != "punct":
                continue
            if toks[j].value == "(":
                depth += 1
            elif toks[j].value == ")":
                depth -= 1
                if depth == 0:
                    nxt = toks[j + 1] if j + 1 < len(toks) else None
                    return nxt is not None and nxt.kind == "punct" and nxt.value == "=>"
        return False

    @classmethod
    def _name(cls, toks: list[Any], i: int, bound: dict[str, str], params: int) -> str:
        value = str(toks[i].value)
        prev = toks[i - 1] if i else None
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        if value in CodeFeatures.PLATFORM or value in CodeFeatures.KEYWORDS:
            return value
        if prev is not None and prev.kind == "punct" and prev.value == ".":
            return "PROP"
        role = cls._binding(toks, i, params, nxt)
        if role is not None:
            bound[value] = role
            return role
        return bound.get(value, "FREE")

    @staticmethod
    def _binding(toks: list[Any], i: int, params: int, nxt: Any) -> str | None:
        """The role the name at `i` is bound in here, or None for a use."""
        prev = toks[i - 1] if i else None
        if params:
            return "PARAM"
        if (
            nxt is not None
            and nxt.kind == "punct"
            and nxt.value == "=>"
            and (prev is None or prev.value != ".")
        ):
            return "PARAM"  # `x => ...`
        if prev is not None and prev.kind == "name" and prev.value in ("import",):
            return "IMPORT"
        if nxt is not None and nxt.kind == "name" and nxt.value == "from":
            return "IMPORT"  # `import x from`
        if nxt is not None and nxt.kind == "punct" and nxt.value == "=":
            after = toks[i + 2] if i + 2 < len(toks) else None
            if after is not None and after.kind == "name" and after.value in ("require", "import"):
                return "IMPORT"  # `cp = require(...)`
        if prev is not None and prev.kind == "name" and prev.value in RoleNormaliser._DECLARES:
            return "LOCAL"
        return None

    @classmethod
    def _literal(cls, value: str) -> str:
        if value in CodeFeatures.PLATFORM:
            return "S:" + value
        if cls._shell(value):
            return "S:SHELL"
        return CodeFeatures.literal_class(value)

    @classmethod
    def _shell(cls, value: str) -> bool:
        """A command line (review change 2): a listed first word; or a chain marker, or a pipe or
        redirection into a listed command, /dev/ or a path. A bare `|` or `>` in prose is not one."""
        words = value.strip().split(None, 1)
        if not words:
            return False
        if words[0].lower() in cls._COMMANDS and len(words) > 1:
            return True
        for piped in cls._PIPED.finditer(value):
            target = piped.group(1).lower()
            if target in cls._COMMANDS or target.startswith(("/dev/", "/", "./", "~/", "%")):
                return True
        return bool(cls._CHAIN.search(value)) and any(
            w.lower() in cls._COMMANDS for w in re.split(r"[\s;&|`$()]+", value)
        )


__all__ = ["RoleNormaliser"]
