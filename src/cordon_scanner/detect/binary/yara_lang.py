"""The YARA rule language, compiled and matched by the project's own code.

`--yara` matches every file against a rules file: Cordon's own pack, or an operator's. A native
library reading attacker-supplied bytes is the attack surface this project refuses, so the
language is implemented here, from the YARA documentation, and held to YARA's own behaviour by its
test suite's cases and by a differential over the measured corpus
(`tests/unit/detect/binary/test_yara_lang.py`).

What is read:

- **Rules**: `global` and `private` rules, tags, `meta`, `strings`, `condition`, rule references
  (including `prefix*` sets of rules), `include` refused unless asked (it is not, by `YaraEngine`).
- **Strings**: text with the modifiers `nocase`, `wide`, `ascii`, `fullword`, `private`,
  `xor[(lo-hi)]`, `base64[("alphabet")]` and `base64wide`; hex strings with `??`, nibble
  wildcards, `~` negation, jumps `[n]`, `[n-m]`, `[n-]`, `[-]` and alternatives; regular
  expressions with `i` and `s`, and the text modifiers that apply to them.
- **Conditions**: `and`/`or`/`not`, comparisons, the arithmetic and bitwise operators, `$a`,
  `#a`, `#a in (lo..hi)`, `@a[i]`, `!a[i]`, `$a at x`, `$a in (lo..hi)`, `filesize`, the integer
  readers (`uint32be(x)` and the rest), `true`/`false`, string sets (`them`, `($a, $b*)`),
  quantifiers (`any`, `all`, `none`, a number, a percentage) `of` a set, with `at`/`in`, and both
  `for` loops; `defined`; the string operators `contains`, `icontains`, `startswith`,
  `istartswith`, `endswith`, `iendswith`, `iequals`, `matches`.
- **Undefined values** propagate as YARA's do: an out-of-range read or a missing match is
  undefined, undefined in arithmetic stays undefined, and is false as a condition.
- **Modules**: `math` and `hash`. A rule that imports any other module is refused when the rules
  load, by name -- never compiled to something that silently cannot match.

Matching is bounded: at most `MAX_MATCHES` matches per string, as YARA bounds them, and regular
expressions are checked by the engine's own pattern validator before use.
"""

from __future__ import annotations

import binascii
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_builtin import Builtin
from cordon_scanner.detect.binary.rule_values import (
    UNDEFINED,
    Array,
    Dictionary,
    Function,
    Struct,
    TypedUndefined,
    Values,
)


class YaraError(ValueError):
    """The rules do not compile."""


INT64_MAX, INT64_MIN = 2**63 - 1, -(2**63)
MAX_MATCHES = 1_000_000
#: The longest match a regular expression or a hex string may make from one start, as YARA's own
#: scan limit bounds it: no file can make one start cost more than this.
SCAN_LIMIT = 4096
#: Matching walks the file in windows of this size, checking the deadline between them.
WINDOW = 1 << 16


# -- lexer ------------------------------------------------------------------


@dataclass
class Tok:
    kind: str  # name, string, regex, hex, int, float, punct, text-id ($a, #a, @a, !a), eof
    value: Any
    line: int


class Lexer:
    PUNCT: ClassVar[tuple[str, ...]] = (
        "..", "<<", ">>", "<=", ">=", "==", "!=", "(", ")", "{", "}", "[", "]", ":", ",", "=",
        "+", "-", "*", "\\", "%", "&", "|", "^", "~", "<", ">", ".",
    )  # fmt: skip

    #: A hex string: hex digits, its punctuation, white space and comments, between braces.
    HEX: ClassVar[re.Pattern[str]] = re.compile(
        r"\{(?:(?:[0-9a-fA-F]|[ \-|~?\[\]()\n\r\t]|/\*(?:/|\**[^*/])*\*+/)+|//[^\n]*\n)+\}"
    )

    def __init__(self, text: str) -> None:
        self.text, self.pos, self.line = text, 0, 1
        self.hex_next = False

    def error(self, what: str) -> YaraError:
        return YaraError(f"line {self.line}: {what}")

    def _skip(self) -> None:
        t, n = self.text, len(self.text)
        while self.pos < n:
            c = t[self.pos]
            if c == "\n":
                self.line += 1
                self.pos += 1
            elif c in " \t\r":
                self.pos += 1
            elif t.startswith("//", self.pos):
                end = t.find("\n", self.pos)
                self.pos = n if end < 0 else end
            elif t.startswith("/*", self.pos):
                end = t.find("*/", self.pos + 2)
                if end < 0:
                    raise self.error("an unterminated comment")
                self.line += t.count("\n", self.pos, end)
                self.pos = end + 2
            else:
                break

    def tokens(self) -> list[Tok]:
        out: list[Tok] = []
        while True:
            self._skip()
            if self.pos >= len(self.text):
                out.append(Tok("eof", None, self.line))
                return out
            out.append(self._one(out))

    def _one(self, before: list[Tok]) -> Tok:
        t, start = self.text, self.pos
        c = t[start]
        line = self.line
        if c == '"':
            return Tok("string", self._string(), line)
        if c == "{":
            m = Lexer.HEX.match(t, start)
            if m is not None:
                body = m.group()[1:-1]
                self.line += body.count("\n")
                self.pos = m.end()
                return Tok("hex", body, line)
        if c == "/":  # comments were skipped; YARA divides with `\\`, so `/` opens a regex
            return Tok("regex", self._regex(), line)
        nxt = t[start + 1] if start + 1 < len(t) else ""
        if c in "$#@" or (c == "!" and nxt != "="):
            # `#`, `@` and `!` alone are the string a `for ... of` is at, as `$` is; `!=` stays
            # the operator
            m = re.compile(r"[$#@!][A-Za-z0-9_]*\*?").match(t, start)
            assert m is not None  # noqa: S101 - the first character matched above
            self.pos = m.end()
            return Tok("textid", m.group(), line)
        m = re.compile(r"0x[0-9a-fA-F]+|0o[0-7]+|\d+\.\d+|\d+(?:KB|MB)?").match(t, start)
        if m:
            self.pos = m.end()
            s = m.group()
            if "." in s:
                return Tok("float", float(s), line)
            if s.endswith("KB"):
                value = int(s[:-2]) * 1024
            elif s.endswith("MB"):
                value = int(s[:-2]) * 1024 * 1024
            else:
                value = int(s, 0) if s[:2] in ("0x", "0o") else int(s)
            if value > INT64_MAX:
                raise self.error(f"an integer {s} beyond 64 bits")
            return Tok("int", value, line)
        m = re.compile(r"[A-Za-z_][A-Za-z0-9_]*").match(t, start)
        if m:
            self.pos = m.end()
            return Tok("name", m.group(), line)
        for p in Lexer.PUNCT:
            if t.startswith(p, start):
                self.pos = start + len(p)
                return Tok("punct", p, line)
        raise self.error(f"an unexpected character {c!r}")

    def _string(self) -> bytes:
        t = self.text
        self.pos += 1
        out = bytearray()
        while True:
            if self.pos >= len(t) or t[self.pos] == "\n":
                raise self.error("an unterminated string")
            c = t[self.pos]
            if c == '"':
                self.pos += 1
                return bytes(out)
            if c == "\\":
                e = t[self.pos + 1 : self.pos + 2]
                if e == "x":
                    digits = t[self.pos + 2 : self.pos + 4]
                    if not re.fullmatch(r"[0-9a-fA-F]{2}", digits):
                        raise self.error("a \\x escape without two hex digits")
                    out.append(int(digits, 16))
                    self.pos += 4
                    continue
                mapped = {"n": 10, "t": 9, "r": 13, "\\": 92, '"': 34}.get(e)
                if mapped is None:
                    raise self.error(f"an unknown escape \\{e}")
                out.append(mapped)
                self.pos += 2
                continue
            out += c.encode("utf-8")
            self.pos += 1

    def _regex(self) -> tuple[str, str]:
        t = self.text
        self.pos += 1
        body = []
        while True:
            if self.pos >= len(t) or t[self.pos] == "\n":
                raise self.error("an unterminated regular expression")
            c = t[self.pos]
            if c == "\\" and self.pos + 1 < len(t):
                body.append(t[self.pos : self.pos + 2])
                self.pos += 2
                continue
            if c == "/":
                self.pos += 1
                break
            body.append(c)
            self.pos += 1
        m = re.compile(r"[is]*").match(t, self.pos)
        flags = m.group() if m else ""
        self.pos += len(flags)
        return "".join(body), flags


# -- the tree -----------------------------------------------------------------


@dataclass
class StringDef:
    name: str
    kind: str  # text, hex, regex
    value: Any
    modifiers: dict[str, Any]
    #: The string ready to be searched for (`rule_scan.Search`).
    search: Any = None
    #: The one offset the string can count at, when the condition only asks `$a at <constant>`.
    fixed: int | None = None

    @property
    def private(self) -> bool:
        return "private" in self.modifiers


@dataclass
class Rule:
    name: str
    tags: list[str]
    meta: dict[str, Any]
    strings: list[StringDef]
    condition: Any
    private: bool = False
    is_global: bool = False


@dataclass
class Match:
    """What a matching rule reports, in the shape yara-python's match object has."""

    rule: str
    tags: list[str]
    meta: dict[str, Any]
    strings: list[tuple[int, str, bytes]]


# -- the parser ---------------------------------------------------------------


class Parser:
    def __init__(
        self,
        text: str,
        externals: dict[str, Any] | None = None,
        modules: frozenset[str] = frozenset(),
    ) -> None:
        self.modules = modules
        self.toks = Lexer(text).tokens()
        self.i = 0
        self.rules: list[Rule] = []
        self.imports: set[str] = set()
        self.externals = dict(externals or {})
        #: The strings of the rule being parsed, and which of them its condition names.
        self.strings: list[StringDef] = []
        self.referenced: set[str] = set()
        #: Rule-name patterns (`a*`) conditions have used: a rule defined later that matches one
        #: is refused, as YARA refuses it.
        self.rule_patterns: list[str] = []
        self.current = ""

    @property
    def tok(self) -> Tok:
        return self.toks[self.i]

    def at(self, value: str) -> bool:
        return self.tok.kind in ("punct", "name") and self.tok.value == value

    def eat(self, value: str) -> bool:
        if self.at(value):
            self.i += 1
            return True
        return False

    def expect(self, value: str) -> Tok:
        if not self.at(value):
            raise YaraError(f"line {self.tok.line}: expected {value!r}, found {self.tok.value!r}")
        tok = self.tok
        self.i += 1
        return tok

    def name(self) -> str:
        if self.tok.kind != "name":
            raise YaraError(f"line {self.tok.line}: expected a name, found {self.tok.value!r}")
        self.i += 1
        return str(self.toks[self.i - 1].value)

    def parse(self) -> list[Rule]:
        while self.tok.kind != "eof":
            if self.eat("import"):
                module = self.tok.value
                if self.tok.kind != "string":
                    raise YaraError(f"line {self.tok.line}: import needs a module name")
                self.i += 1
                name = module.decode()
                if name not in self.modules:
                    raise YaraError(f"the {name!r} module is not supported by Cordon's YARA engine")
                self.imports.add(name)
                continue
            if self.at("include"):
                raise YaraError(f"line {self.tok.line}: include is not allowed")
            self.rules.append(self.rule())
        names = [r.name for r in self.rules]
        if len(set(names)) != len(names):
            raise YaraError("a rule name defined twice")
        return self.rules

    def rule(self) -> Rule:
        private = is_global = False
        while self.at("private") or self.at("global"):
            if self.eat("private"):
                private = True
            elif self.eat("global"):
                is_global = True
        self.expect("rule")
        name = self.name()
        self.current = name
        if any(name.startswith(p) for p in self.rule_patterns):
            raise YaraError(f"rule {name} matches a rule set an earlier rule already used")
        tags: list[str] = []
        if self.eat(":"):
            while self.tok.kind == "name" and not self.at("{"):
                tag = self.name()
                if tag in tags:
                    raise YaraError(f"rule {name}: the tag {tag} twice")
                tags.append(tag)
        self.expect("{")
        meta: dict[str, Any] = {}
        strings: list[StringDef] = []
        if self.eat("meta"):
            self.expect(":")
            while self.tok.kind == "name" and self.toks[self.i + 1].value == "=":
                key = self.name()
                self.expect("=")
                meta[key] = self._meta_value()
        if self.eat("strings"):
            self.expect(":")
            anonymous = 0
            while self.tok.kind == "textid" and self.tok.value.startswith("$"):
                sname = self.tok.value
                if sname == "$":
                    anonymous += 1
                    sname = f"$#anonymous{anonymous}"
                self.i += 1
                self.expect("=")
                strings.append(self._string_def(sname))
            seen = [s.name for s in strings]
            if len(set(seen)) != len(seen):
                raise YaraError(f"rule {name}: a string defined twice")
        self.strings, self.referenced = strings, set()
        self.expect("condition")
        self.expect(":")
        cond = self.expr()
        self.expect("}")
        for s in strings:
            if s.name not in self.referenced:
                raise YaraError(f"rule {name}: the string {s.name} is never used")
        rule = Rule(name, tags, meta, strings, cond, private, is_global)
        Strings.place_fixed(rule)
        return rule

    def _meta_value(self) -> Any:
        tok = self.tok
        if tok.kind == "string":
            self.i += 1
            return tok.value.decode("utf-8", "replace")
        if self.eat("-"):
            return -int(self.tok.value) if self._int() else 0
        if tok.kind == "int":
            self.i += 1
            return tok.value
        if self.at("true") or self.at("false"):
            self.i += 1
            return tok.value == "true"
        raise YaraError(f"line {tok.line}: a meta value must be a string, number or boolean")

    def _int(self) -> bool:
        if self.tok.kind == "int":
            self.i += 1
            return True
        return False

    def _string_def(self, name: str) -> StringDef:
        tok = self.tok
        if tok.kind == "string":
            kind, value = "text", tok.value
        elif tok.kind == "hex":
            kind, value = "hex", tok.value
        elif tok.kind == "regex":
            kind, value = "regex", tok.value
        else:
            raise YaraError(f"line {tok.line}: a string definition must be text, hex or a regex")
        self.i += 1
        mods: dict[str, Any] = {}
        while self.tok.kind == "name" and self.tok.value in (
            "nocase", "wide", "ascii", "fullword", "private", "xor", "base64", "base64wide",
        ):  # fmt: skip
            mod = self.name()
            arg: Any = True
            if mod == "xor" and self.eat("("):
                lo = int(self.tok.value)
                self.i += 1
                hi = lo
                if self.eat("-"):
                    hi = int(self.tok.value)
                    self.i += 1
                self.expect(")")
                if not 0 <= lo <= hi <= 255:
                    raise YaraError(f"string {name}: an xor range out of 0-255")
                arg = (lo, hi)
            elif mod == "xor":
                arg = (0, 255)
            elif mod in ("base64", "base64wide") and self.eat("("):
                alphabet = self.tok.value
                self.i += 1
                self.expect(")")
                if not isinstance(alphabet, bytes) or len(alphabet) != 64:
                    raise YaraError(f"string {name}: a base64 alphabet must be 64 bytes")
                arg = alphabet
            if mod in mods:
                raise YaraError(f"string {name}: the modifier {mod} twice")
            mods[mod] = arg
        b64 = [mods.get(m) for m in ("base64", "base64wide") if m in mods]
        if len(b64) == 2 and b64[0] != b64[1]:
            raise YaraError(f"string {name}: base64 and base64wide with different alphabets")
        Strings.check(name, kind, mods)
        s = StringDef(name, kind, value, mods)
        Strings.compile(s)
        return s

    # -- expressions (lowest precedence first) -----------------------------

    def expr(self) -> Any:
        left = self._and()
        while self.eat("or"):
            left = ("or", left, self._and())
        return left

    def _and(self) -> Any:
        left = self._not()
        while self.eat("and"):
            left = ("and", left, self._not())
        return left

    def _not(self) -> Any:
        if self.eat("not"):
            return ("not", self._not())
        if self.eat("defined"):
            return ("defined", self._not())
        return self._compare()

    COMPARE: ClassVar[tuple[str, ...]] = (
        "==", "!=", "<=", ">=", "<", ">", "contains", "icontains", "startswith", "istartswith",
        "endswith", "iendswith", "iequals", "matches",
    )  # fmt: skip

    def _compare(self) -> Any:
        left = self._bitor()
        while self.tok.kind in ("punct", "name") and self.tok.value in Parser.COMPARE:
            op = self.tok.value
            self.i += 1
            if op == "matches":
                tok = self.tok
                if tok.kind != "regex":
                    raise YaraError(f"line {tok.line}: matches needs a regular expression")
                self.i += 1
                left = ("matches", left, Strings.matcher(tok.value[0], tok.value[1]))
                continue
            left = (op, left, self._bitor())
        return left

    def _binary(self, ops: tuple[str, ...], nxt: Any) -> Any:
        left = nxt()
        while self.tok.kind == "punct" and self.tok.value in ops:
            op = self.tok.value
            self.i += 1
            left = (op, left, nxt())
        return left

    def _bitor(self) -> Any:
        return self._binary(("|",), self._bitxor)

    def _bitxor(self) -> Any:
        return self._binary(("^",), self._bitand)

    def _bitand(self) -> Any:
        return self._binary(("&",), self._shift)

    def _shift(self) -> Any:
        return self._binary(("<<", ">>"), self._add)

    def _add(self) -> Any:
        return self._binary(("+", "-"), self._mul)

    def _mul(self) -> Any:
        left = self._unary()
        while self.tok.kind == "punct" and self.tok.value in ("*", "\\", "%"):
            if self.tok.value == "%" and self.toks[self.i + 1].value == "of":
                # `<expression>% of <set>`: a percentage quantifier, not a modulo.
                self.i += 1
                return self._of(("percent", left))
            op = self.tok.value
            self.i += 1
            left = (op, left, self._unary())
        return left

    def _unary(self) -> Any:
        if self.eat("-"):
            if self.tok.kind in ("int", "float") and self.toks[self.i + 1].value == "of":
                raise YaraError(f"line {self.tok.line}: a negative quantifier")
            return ("neg", self._unary())
        if self.eat("~"):
            return ("bnot", self._unary())
        return self._primary()

    BINARY: ClassVar[frozenset[str]] = frozenset(
        {"+", "-", "*", "\\", "%", "&", "|", "^", "<<", ">>", "==", "!=", "<", ">", "<=", ">="}
    )
    READERS: ClassVar[frozenset[str]] = frozenset(
        f"{s}int{b}{e}" for s in ("", "u") for b in (8, 16, 32) for e in ("", "be")
    )

    def _primary(self) -> Any:
        tok = self.tok
        if tok.kind == "int":
            self.i += 1
            if self.at("of"):
                return self._of(Parser._quantity(("num", tok.value)))
            return ("num", tok.value)
        if tok.kind == "float":
            self.i += 1
            return ("num", tok.value)
        if tok.kind == "string":
            self.i += 1
            return ("str", tok.value)
        if tok.kind == "textid":
            return self._text_id()
        if self.eat("("):
            inner = self.expr()
            self.expect(")")
            if self.at("of"):
                return self._of(inner)
            return inner
        if tok.kind == "name":
            v = tok.value
            if v in ("true", "false"):
                self.i += 1
                return ("bool", v == "true")
            if v == "filesize":
                self.i += 1
                return ("filesize",)
            if v == "entrypoint":
                self.i += 1
                return ("undefined",)
            if v in ("any", "all", "none"):
                self.i += 1
                return self._of(("quant", v))
            if v == "for":
                return self._for()
            if v in Parser.READERS:
                self.i += 1
                self.expect("(")
                arg = self.expr()
                self.expect(")")
                return ("read", v, arg)
            if v in self.imports:
                self.i += 1
                chain = ("chain", ("module", v), self._ops())
                return self._of(chain) if self.at("of") else chain
            self.i += 1
            if self.at(".") or self.at("["):
                chain = ("chain", ("rule", v), self._ops())
                return self._of(chain) if self.at("of") else chain
            if v in self.externals:
                return ("ext", v) if not self.at("of") else self._of(("ext", v))
            if self.at("of"):
                return self._of(("rule", v))  # a loop variable or rule as the quantity
            return ("rule", v)
        raise YaraError(f"line {tok.line}: an unexpected {tok.value!r} in a condition")

    def _ops(self) -> list[Any]:
        """`.field`, `[index]` and `(arguments)`, as many as follow."""
        ops: list[Any] = []
        while True:
            if self.eat("."):
                ops.append(("attr", self.name()))
            elif self.eat("["):
                ops.append(("index", self.expr()))
                self.expect("]")
            elif self.at("("):
                self.i += 1
                args: list[Any] = []
                while not self.at(")"):
                    if self.tok.kind == "regex":
                        args.append(("regex", Strings.matcher(*self.tok.value)))
                        self.i += 1
                    else:
                        args.append(self.expr())
                    if not self.eat(","):
                        break
                self.expect(")")
                ops.append(("call", args))
            else:
                return ops

    def _text_id(self) -> Any:
        tok = self.tok
        self.i += 1
        sigil, name = tok.value[0], "$" + tok.value[1:]
        if name != "$":
            if name not in {s.name for s in self.strings}:
                raise YaraError(f"line {tok.line}: an undefined string {name}")
            self.referenced.add(name)
        if sigil == "$":
            if self.eat("at"):
                return ("at", name, self._unary())
            if self.eat("in"):
                return ("in", name, self._range())
            return ("found", name)
        if sigil == "#":
            if self.eat("in"):
                return ("count_in", name, self._range())
            return ("count", name)
        index: Any = ("num", 1)
        if self.eat("["):
            index = self.expr()
            self.expect("]")
        return ("offset" if sigil == "@" else "length", name, index)

    def _range(self) -> Any:
        self.expect("(")
        lo = self.expr()
        self.expect("..")
        hi = self.expr()
        self.expect(")")
        if (lo[0] == "neg" and lo[1][0] == "num") or (lo[0] == "num" and lo[1] < 0):
            raise YaraError("a range whose lower bound is negative")
        if lo[0] == "num" and hi[0] == "num" and lo[1] > hi[1]:
            raise YaraError("a range whose lower bound is above its upper")
        return (lo, hi)

    def _set(self) -> Any:
        if self.eat("them"):
            if not self.strings:
                raise YaraError(f"line {self.tok.line}: 'them' in a rule with no strings")
            self.referenced.update(s.name for s in self.strings)
            return ("them",)
        self.expect("(")
        items = [self._set_item()]
        while self.eat(","):
            items.append(self._set_item())
        self.expect(")")
        return ("set", items)

    def _set_item(self) -> str:
        tok = self.tok
        if tok.kind == "textid" and tok.value.startswith("$"):
            self.i += 1
            item = str(tok.value)
            if item.endswith("*"):
                hits = [s.name for s in self.strings if s.name.startswith(item[:-1])]
            else:
                hits = [s.name for s in self.strings if s.name == item]
            if not hits:
                raise YaraError(f"line {tok.line}: {item} names no string of the rule")
            self.referenced.update(hits)
            return item
        if tok.kind == "name":
            self.i += 1
            item = tok.value + ("*" if self.eat("*") else "")
            defined = [r.name for r in self.rules] + [self.current]
            hits = [
                r for r in defined if (r.startswith(item[:-1]) if item.endswith("*") else r == item)
            ]
            if not hits:
                raise YaraError(f"line {tok.line}: {item} names no rule defined before it")
            if item.endswith("*"):
                self.rule_patterns.append(item[:-1])
            return str(item)
        raise YaraError(f"line {tok.line}: a string set holds string or rule names")

    @staticmethod
    def _quantity(quant: Any) -> Any:
        """A constant quantifier checked as YARA checks it: a whole number of at least 0, or a
        percentage from 1 to 100."""
        if quant[0] == "num" and (not isinstance(quant[1], int) or quant[1] < 0):
            raise YaraError(f"a quantifier must be a whole number of at least 0, not {quant[1]}")
        if quant[0] == "neg" and quant[1][0] == "num":
            raise YaraError("a negative quantifier")
        if quant[0] == "percent" and quant[1][0] == "num" and not 1 <= quant[1][1] <= 100:
            raise YaraError(f"a percentage must be from 1 to 100, not {quant[1][1]}")
        return quant

    def _of(self, quant: Any) -> Any:
        quant = Parser._quantity(quant)
        self.expect("of")
        target = self._set()
        if self.eat("at"):
            return ("of_at", quant, target, self._unary())
        if self.eat("in"):
            return ("of_in", quant, target, self._range())
        return ("of", quant, target)

    def _for(self) -> Any:
        self.expect("for")
        tok = self.tok
        if tok.kind == "int":
            self.i += 1
            if self.at("%"):
                self.i += 1
                quant: Any = Parser._quantity(("percent", ("num", tok.value)))
            else:
                quant = Parser._quantity(("num", tok.value))
        elif tok.kind == "name" and tok.value in ("any", "all", "none"):
            self.i += 1
            quant = ("quant", tok.value)
        else:
            quant = Parser._quantity(self._primary())
        if self.eat("of"):
            target = self._set()
            self.expect(":")
            self.expect("(")
            body = self.expr()
            self.expect(")")
            return ("for_of", quant, target, body)
        names = [self.name()]
        while self.eat(","):
            names.append(self.name())
        self.expect("in")
        if not self.at("("):
            target = self._primary()
            self.expect(":")
            self.expect("(")
            body = self.expr()
            self.expect(")")
            return ("for_in", quant, names, ("iter", target), body)
        if self.at("("):
            self.i += 1
            first = self.expr()
            if self.eat(".."):
                hi = self.expr()
                self.expect(")")
                for bound in (first, hi):
                    if bound[0] in ("str", "bool") or (
                        bound[0] == "num" and not isinstance(bound[1], int)
                    ):
                        raise YaraError("a for range needs integer bounds")
                if first[0] == "num" and hi[0] == "num" and first[1] > hi[1]:
                    raise YaraError("a for range whose lower bound is above its upper")
                domain: Any = ("range", first, hi)
            else:
                items = [first]
                while self.eat(","):
                    items.append(self.expr())
                self.expect(")")
                kinds = {"str" if i[0] == "str" else "int" for i in items}
                if len(kinds) > 1 or any(i[0] == "bool" for i in items):
                    raise YaraError("a for list holds integers, or strings, not both")
                domain = ("enum", items)
        else:
            raise YaraError(f"line {self.tok.line}: a for loop iterates over a range or a list")
        self.expect(":")
        self.expect("(")
        body = self.expr()
        self.expect(")")
        return ("for_in", quant, names, domain, body)


# -- strings ------------------------------------------------------------------


class Strings:
    @staticmethod
    def check(name: str, kind: str, mods: dict[str, Any]) -> None:
        if kind == "hex" and set(mods) - {"private"}:
            raise YaraError(f"string {name}: a hex string takes no modifier but private")
        if kind == "regex" and set(mods) & {"xor", "base64", "base64wide"}:
            raise YaraError(f"string {name}: a regular expression takes no xor or base64")
        if set(mods) & {"base64", "base64wide"} and set(mods) & {"nocase", "xor", "fullword"}:
            raise YaraError(
                f"string {name}: base64 cannot be combined with nocase, xor or fullword"
            )
        if "xor" in mods and "nocase" in mods:
            raise YaraError(f"string {name}: xor and nocase together")

    @staticmethod
    def compile(s: StringDef) -> None:
        from cordon_scanner.detect.binary.rule_pattern import PatternError
        from cordon_scanner.detect.binary.rule_scan import Search

        try:
            s.search = Search(s.kind, s.value, s.modifiers)
        except PatternError as exc:
            raise YaraError(f"string {s.name}: {exc}") from exc

    @staticmethod
    def matcher(source: str, marks: str) -> Any:
        """A regular expression a condition tests text with (`matches`, a function argument)."""
        from cordon_scanner.detect.binary.rule_pattern import PatternError
        from cordon_scanner.detect.binary.rule_scan import Matcher

        try:
            return Matcher(source.encode("utf-8", "surrogateescape"), marks)
        except PatternError as exc:
            raise YaraError(f"a regular expression that does not compile: {exc}") from exc

    @staticmethod
    def find(
        s: StringDef,
        data: bytes,
        deadline: float | None = None,
        seen: dict[bytes, list[int]] | None = None,
    ) -> list[tuple[int, int]]:
        """(offset, length) of every match of `s`, by offset, at most `rule_scan.MAX_HITS`."""
        from cordon_scanner.detect.binary.rule_pattern import RunError

        try:
            found: list[tuple[int, int]] = s.search.find(data, s.fixed, deadline, seen)
            return found
        except TimeoutError as exc:
            raise YaraError("matching took longer than the time allowed") from exc
        except RunError as exc:
            raise YaraError(f"string {s.name}: {exc}") from exc

    @staticmethod
    def place_fixed(rule: Rule) -> None:
        """Marks each string whose first part is plain bytes and whose every use is `$a at
        <constant>` (one constant): it counts only there, as the search records it only there."""
        fixed: dict[str, Any] = {s.name: None for s in rule.strings}
        cleared: set[str] = set()

        def at(name: str, where: Any) -> None:
            value = where[1] if where[0] == "num" and isinstance(where[1], int) else None
            names = [s.name for s in rule.strings] if name == "$" else [name]
            for n in names:
                if n not in fixed:
                    continue
                if fixed[n] is None:
                    fixed[n] = value
                if value is None or fixed[n] != value:
                    cleared.add(n)

        def walk(node: Any) -> None:
            if isinstance(node, tuple):
                if node and node[0] == "at" and isinstance(node[1], str):
                    at(node[1], node[2])
                    walk(node[2])
                    return
                if node and node[0] == "them":
                    cleared.update(fixed)
                for item in node:
                    walk(item)
            elif isinstance(node, list):
                for item in node:
                    walk(item)
            elif isinstance(node, str) and node.startswith("$"):
                if node == "$":
                    cleared.update(fixed)
                elif node.endswith("*"):
                    cleared.update(n for n in fixed if n.startswith(node[:-1]))
                else:
                    cleared.add(node)

        walk(rule.condition)
        for s in rule.strings:
            # a linked string counts from its first part, so that part decides
            text_like = s.search is not None and s.search.parts[0].text is not None
            if text_like and s.name not in cleared and fixed[s.name] is not None:
                s.fixed = fixed[s.name]


# -- evaluation ---------------------------------------------------------------


class Scan:
    """One file's evaluation: the matches of every string, rules decided in order."""

    def __init__(
        self,
        rules: list[Rule],
        data: bytes,
        deadline: float | None = None,
        externals: dict[str, Any] | None = None,
        *,
        compiling: bool = False,
    ) -> None:
        self.rules, self.data, self.deadline = rules, data, deadline
        self.externals = {
            k: v.encode() if isinstance(v, str) else v for k, v in (externals or {}).items()
        }
        #: The check `Rules.compile` runs: a constant expression YARA refuses is refused here.
        self.compiling = compiling
        self.factories: dict[str, Any] = {}
        self.roots: dict[str, Struct] = {}
        self.decided: dict[str, bool] = {}
        #: Where each anchor occurs in the data, shared by every string (`Search.find`).
        self.seen: dict[bytes, list[int]] = {}
        self.vars: list[dict[str, Any]] = []

    def run(self) -> list[Match]:
        out: list[Match] = []
        global_ok = True
        found_by_rule: dict[str, dict[str, list[tuple[int, int]]]] = {}
        for rule in self.rules:
            self.rule = rule
            self.found = {
                s.name: Strings.find(s, self.data, self.deadline, self.seen) for s in rule.strings
            }
            found_by_rule[rule.name] = self.found
            result = Scan.truth(self.eval(rule.condition))
            self.decided[rule.name] = result
            if rule.is_global and not result:
                global_ok = False
        for rule in self.rules:
            if self.decided[rule.name] and global_ok and not rule.private:
                strings = []
                for s in rule.strings:
                    if s.private:
                        continue
                    for at, n in found_by_rule[rule.name][s.name]:
                        strings.append((at, s.name, self.data[at : at + n]))
                out.append(Match(rule.name, list(rule.tags), dict(rule.meta), strings))
        return out

    @staticmethod
    def truth(v: Any) -> bool:
        if Values.undefined(v):
            return False
        if isinstance(v, bytes):
            return bool(v)
        return bool(v)

    def names(self, target: Any) -> list[str]:
        if target[0] == "them":
            return [s.name for s in self.rule.strings]
        out: list[str] = []
        for item in target[1]:
            if item.startswith("$"):
                if item.endswith("*"):
                    out += [s.name for s in self.rule.strings if s.name.startswith(item[:-1])]
                elif item in self.found:
                    out.append(item)
                else:
                    raise YaraError(f"rule {self.rule.name}: an undefined string {item}")
            else:
                prefix = item[:-1] if item.endswith("*") else None
                out += [
                    r.name
                    for r in self.rules
                    if (r.name.startswith(prefix) if prefix is not None else r.name == item)
                ]
        return out

    def _items(self, target: Any) -> list[Any]:
        """For an `of`: each item's truth source -- a string name or a rule name."""
        return self.names(target)

    def _item_true(self, name: str, at: Any = None, rng: Any = None) -> bool:
        if name.startswith("$"):
            hits = self.found.get(name, [])
            if at is not None:
                return any(o == at for o, _ in hits)
            if rng is not None:
                return any(rng[0] <= o <= rng[1] for o, _ in hits)
            return bool(hits)
        return self.decided.get(name, False)

    def _quant_ok(self, quant: Any, count: int, total: int) -> bool:
        kind = quant[0]
        if kind == "quant":
            q = quant[1]
            return count >= 1 if q == "any" else count == total if q == "all" else count == 0
        if kind == "percent":
            pct = self.eval(quant[1])
            if Values.undefined(pct):
                return False
            if not isinstance(pct, int) or not 0 < pct <= 100:
                raise YaraError(f"a percentage must be from 1 to 100, not {pct}")
            return total > 0 and count * 100 >= pct * total
        n = self.eval(quant)
        if Values.undefined(n):
            return False
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            raise YaraError(f"a quantifier must be a whole number of at least 0, not {n}")
        return count >= n if n > 0 else count == 0

    def eval(self, node: Any) -> Any:
        op = node[0]
        if op == "num":
            return node[1]
        if op == "str":
            return node[1]
        if op == "bool":
            return node[1]
        if op == "undefined":
            return UNDEFINED
        if op == "ext":
            return self.externals[node[1]]
        if op == "filesize":
            return len(self.data)
        if op == "or":
            return Scan.truth(self.eval(node[1])) or Scan.truth(self.eval(node[2]))
        if op == "and":
            return Scan.truth(self.eval(node[1])) and Scan.truth(self.eval(node[2]))
        if op == "not":
            v = self.eval(node[1])
            return UNDEFINED if Values.undefined(v) else not Scan.truth(v)
        if op == "defined":
            return not Values.undefined(self.eval(node[1]))
        if op == "found":
            return bool(self._hits(node[1]))
        if op == "count":
            return len(self._hits(node[1]))
        if op == "count_in":
            lo, hi = self.eval(node[2][0]), self.eval(node[2][1])
            if Values.undefined(lo) or Values.undefined(hi):
                return UNDEFINED
            return sum(1 for o, _ in self._hits(node[1]) if lo <= o <= hi)
        if op == "at":
            at = self.eval(node[2])
            return (
                UNDEFINED if Values.undefined(at) else any(o == at for o, _ in self._hits(node[1]))
            )
        if op == "in":
            lo, hi = self.eval(node[2][0]), self.eval(node[2][1])
            if Values.undefined(lo) or Values.undefined(hi):
                return UNDEFINED
            return any(lo <= o <= hi for o, _ in self._hits(node[1]))
        if op in ("offset", "length"):
            i = self.eval(node[2])
            hits = self._hits(node[1])
            if Values.undefined(i) or not isinstance(i, int) or not 1 <= i <= len(hits):
                return UNDEFINED
            return hits[i - 1][0] if op == "offset" else hits[i - 1][1]
        if op == "read":
            return self._read(node[1], self.eval(node[2]))
        if op == "rule":
            if node[1] in self.decided:
                return self.decided[node[1]]
            for scope in reversed(self.vars):
                if node[1] in scope:
                    return scope[node[1]]
            raise YaraError(f"an undefined identifier {node[1]}")
        if op == "rules":
            return any(
                self.decided.get(r.name, False) for r in self.rules if r.name.startswith(node[1])
            )
        if op in ("of", "of_at", "of_in"):
            names = self._items(node[2])
            at = rng = None
            if op == "of_at":
                at = self.eval(node[3])
                if Values.undefined(at):
                    return False
                if not isinstance(at, int):
                    raise YaraError("'at' needs an integer offset")
            if op == "of_in":
                rng = (self.eval(node[3][0]), self.eval(node[3][1]))
                if any(Values.undefined(v) for v in rng):
                    return False
            count = sum(1 for n in names if self._item_true(n, at, rng))
            return self._quant_ok(node[1], count, len(names))
        if op == "for_of":
            names = self.names(node[2])
            count = 0
            for n in names:
                self.vars.append({"$": n})
                try:
                    if Scan.truth(self.eval(node[3])):
                        count += 1
                finally:
                    self.vars.pop()
            return self._quant_ok(node[1], count, len(names))
        if op == "for_in":
            values = self._domain(node[3], len(node[2]))
            if Values.undefined(values):
                return False
            if not values and self.compiling and node[3][0] == "iter":
                # An empty collection still has a type: the body is checked against one undefined
                # element of it, so `i == "foo"` over integers is refused here, as YARA refuses it.
                self._check_body(node, self._prototype(node[3][1], len(node[2])))
            count = 0
            for value in values:
                scope = dict(
                    zip(node[2], value if isinstance(value, tuple) else (value,), strict=False)
                )
                self.vars.append(scope)
                try:
                    if Scan.truth(self.eval(node[4])):
                        count += 1
                finally:
                    self.vars.pop()
            return self._quant_ok(node[1], count, len(values))
        if op == "chain":
            return self._chain(node)
        if op == "regex":
            return node[1]
        if op == "matches":
            v = self.eval(node[1])
            if not isinstance(v, bytes):
                return UNDEFINED
            from cordon_scanner.detect.binary.rule_pattern import RunError

            try:
                return node[2].test(v)
            except RunError as exc:
                raise YaraError(f"rule {self.rule.name}: {exc}") from exc
        if op == "neg":
            v = self.eval(node[1])
            if Values.undefined(v):
                return UNDEFINED
            if isinstance(v, int) and -v > INT64_MAX:
                if self.compiling and Scan.constant(node):
                    raise YaraError("integer overflow in a constant expression")
                return UNDEFINED
            return -v
        if op == "bnot":
            v = self.eval(node[1])
            return UNDEFINED if Values.undefined(v) else ~int(v)
        left, right = self.eval(node[1]), self.eval(node[2])
        if (
            op in ("<<", ">>")
            and isinstance(right, int)
            and right < 0
            and self.compiling
            and Scan.constant(node)
        ):
            raise YaraError("a negative shift count")
        value = Scan._binary(op, left, right)
        low = INT64_MIN + 1 if op == "*" else INT64_MIN  # YARA's multiplication check is symmetric
        if isinstance(value, int) and not isinstance(value, bool) and not low <= value <= INT64_MAX:
            if self.compiling and Scan.constant(node):
                raise YaraError("integer overflow in a constant expression")
            return UNDEFINED
        return value

    @staticmethod
    def constant(node: Any) -> bool:
        """Whether `node` is computed from literals alone, as YARA folds it when it compiles."""
        if node[0] in ("num", "str", "bool"):
            return True
        if node[0] in ("neg", "bnot"):
            return Scan.constant(node[1])
        if node[0] in Parser.BINARY and len(node) == 3:
            return Scan.constant(node[1]) and Scan.constant(node[2])
        return False

    def _hits(self, name: str) -> list[tuple[int, int]]:
        if name == "$" and self.vars:
            for scope in reversed(self.vars):
                if "$" in scope:
                    return self.found.get(scope["$"], [])
        if name not in self.found:
            raise YaraError(f"rule {self.rule.name}: an undefined string {name}")
        return self.found[name]

    def _domain(self, node: Any, names: int = 1) -> Any:
        if node[0] == "range":
            if names != 1:
                raise YaraError("a for loop over a range takes one variable")
            lo, hi = self.eval(node[1]), self.eval(node[2])
            if Values.undefined(lo) or Values.undefined(hi):
                return UNDEFINED
            return list(range(int(lo), int(hi) + 1))
        if node[0] == "iter":
            value = self.eval(node[1])
            if isinstance(value, Dictionary):
                if names != 2:
                    raise YaraError("a for loop over a dictionary takes a key and a value")
                return [(k, Values.int64(v)) for k, v in value.items.items()]
            if isinstance(value, Array):
                if names != 1:
                    raise YaraError("a for loop over an array takes one variable")
                return [Values.int64(v) for v in value.values()]
            if Values.undefined(value):
                return UNDEFINED
            raise YaraError("a for loop iterates over a range, a list, an array or a dictionary")
        if names != 1:
            raise YaraError("a for loop over a list takes one variable")
        return [self.eval(e) for e in node[1]]

    def _prototype(self, target: Any, names: int) -> Any:
        value = self.eval(target)
        if isinstance(value, Dictionary):
            return (b"", Values.undefined_like(value.proto))
        if isinstance(value, Array):
            return Values.undefined_like(value.proto)
        return UNDEFINED

    def _check_body(self, node: Any, element: Any) -> None:
        scope = dict(
            zip(node[2], element if isinstance(element, tuple) else (element,), strict=False)
        )
        self.vars.append(scope)
        try:
            self.eval(node[4])
        finally:
            self.vars.pop()

    def _root(self, name: str) -> Struct:
        if name not in self.roots:
            self.roots[name] = self.factories[name](self.data)
        return self.roots[name]

    def _chain(self, node: Any) -> Any:
        base = node[1]
        if base[0] == "module":
            value: Any = self._root(base[1])
        else:
            value = self.eval(base)
        for step in node[2]:
            if step[0] == "attr":
                if isinstance(value, Struct):
                    try:
                        value = value.get(step[1])
                    except KeyError:
                        raise YaraError(f"an undefined identifier {step[1]}") from None
                elif Values.undefined(value):
                    return UNDEFINED
                else:
                    raise YaraError(f"{step[1]} is not a field of a {Values.kind_of(value)}")
            elif step[0] == "index":
                key = self.eval(step[1])
                if isinstance(value, Array):
                    if Values.kind_of(key) not in ("int", None):
                        raise YaraError("an array is indexed with an integer")
                    value = (
                        Values.undefined_like(value.proto)
                        if Values.undefined(key)
                        else value.element(key)
                    )
                elif isinstance(value, Dictionary):
                    if Values.kind_of(key) not in ("str", None):
                        raise YaraError("a dictionary is indexed with a string")
                    value = (
                        Values.undefined_like(value.proto)
                        if Values.undefined(key)
                        else value.element(key)
                    )
                elif Values.undefined(value):
                    return UNDEFINED
                else:
                    raise YaraError(f"a {Values.kind_of(value)} cannot be indexed")
            else:
                if not isinstance(value, Function):
                    raise YaraError("only a function can be called")
                args = [self.eval(a) for a in step[1]]
                from cordon_scanner.detect.binary.rule_scan import Matcher

                kinds = tuple("r" if isinstance(a, Matcher) else Values.kind_of(a) for a in args)
                target = value.resolve(kinds)
                if target is None:
                    raise YaraError(f"no function takes arguments of types {kinds}")
                call, returns = target
                if any(Values.undefined(a) for a in args):
                    return TypedUndefined(returns)
                result = call(*args)
                value = TypedUndefined(returns) if result is None else result
        return Values.int64(value)

    def _read(self, name: str, at: Any) -> Any:
        if Values.undefined(at) or not isinstance(at, int):
            return UNDEFINED
        size = int(name.split("int")[1].rstrip("be")) // 8
        if at < 0 or at + size > len(self.data):
            return UNDEFINED
        return int.from_bytes(
            self.data[at : at + size],
            "big" if name.endswith("be") else "little",
            signed=not name.startswith("u"),
        )

    @staticmethod
    def _binary(op: str, a: Any, b: Any) -> Any:
        ka, kb = Values.kind_of(a), Values.kind_of(b)
        numbers = ("int", "float", "bool")
        if ka and kb and ((ka == "str") != (kb == "str")) and {ka, kb} <= {"str", *numbers}:
            raise YaraError(f"{op} combines a string with a number")
        if ka in ("struct", "array", "dict", "function") or kb in (
            "struct",
            "array",
            "dict",
            "function",
        ):
            raise YaraError(
                f"{op} on a {ka if ka in ('struct', 'array', 'dict', 'function') else kb}"
            )
        if Values.undefined(a) or Values.undefined(b):
            return UNDEFINED
        if op in (
            "contains",
            "icontains",
            "startswith",
            "istartswith",
            "endswith",
            "iendswith",
            "iequals",
        ):
            if not isinstance(a, bytes) or not isinstance(b, bytes):
                raise YaraError(f"{op} compares strings")
            if op.startswith("i"):
                a, b = a.lower(), b.lower()
                op = op[1:] if op != "iequals" else "equals"
            return {
                "contains": b in a,
                "startswith": a.startswith(b),
                "endswith": a.endswith(b),
                "equals": a == b,
            }[op]
        if op in ("==", "!=", "<", ">", "<=", ">=") and isinstance(a, bytes) != isinstance(
            b, bytes
        ):
            raise YaraError(f"{op} compares a string with a number")
        if op == "==":
            return a == b
        if op == "!=":
            return a != b
        if op == "<":
            return a < b
        if op == ">":
            return a > b
        if op == "<=":
            return a <= b
        if op == ">=":
            return a >= b
        if op == "+":
            return a + b
        if op == "-":
            return a - b
        if op == "*":
            return a * b
        if op == "\\":
            if b == 0:
                return UNDEFINED
            if isinstance(a, int) and isinstance(b, int):
                if a == INT64_MIN and b == -1:
                    return UNDEFINED
                q = abs(a) // abs(b)  # C truncates toward zero, exactly, at any size
                return q if (a < 0) == (b < 0) else -q
            return a / b
        if op == "%":
            if b == 0 or (a == INT64_MIN and b == -1):
                return UNDEFINED
            if isinstance(a, int) and isinstance(b, int):
                r = abs(a) % abs(b)  # C's remainder takes the dividend's sign
                return r if a >= 0 else -r
            return math.fmod(a, b)
        if op == "&":
            return int(a) & int(b)
        if op == "|":
            return int(a) | int(b)
        if op == "^":
            return int(a) ^ int(b)
        if op in ("<<", ">>") and b < 0:
            return UNDEFINED  # refused when constant (`Scan.eval`); undefined from a file's data
        if op == "<<":
            return (int(a) << int(b)) & ((1 << 64) - 1) if b < 64 else 0
        if op == ">>":
            return int(a) >> int(b) if b < 64 else 0
        raise YaraError(f"an unknown operator {op}")


class Rules:
    """Compiled rules: `Rules.compile(text)`, then `rules.match(data)`."""

    def __init__(
        self,
        rules: list[Rule],
        externals: dict[str, Any] | None = None,
        modules: dict[str, Any] | None = None,
    ) -> None:
        self.rules, self.externals = rules, dict(externals or {})
        self.modules = modules or {}

    def _scan(
        self, data: bytes, deadline: float | None, *, compiling: bool = False, console: Any = None
    ) -> Scan:
        scan = Scan(self.rules, data, deadline, self.externals, compiling=compiling)
        scan.factories = self.modules
        if console is not None:
            scan.factories = {**self.modules, "console": lambda d: Builtin.console(d, console)}
        return scan

    @staticmethod
    def compile(
        text: str, externals: dict[str, Any] | None = None, modules: dict[str, Any] | None = None
    ) -> Rules:
        """`modules` adds module factories (`name -> data -> Struct`) to the built-in ones."""
        factories = Builtin.modules() | dict(modules or {})
        try:
            rules = Parser(text, externals, frozenset(factories)).parse()
        except (IndexError, ValueError, binascii.Error) as exc:
            if isinstance(exc, YaraError):
                raise
            raise YaraError(f"the rules do not parse: {exc}") from exc
        compiled = Rules(rules, externals, factories)
        # Every identifier a condition names must exist, and every constant expression YARA would
        # refuse is refused: checked once, on empty data.
        try:
            compiled._scan(b"", None, compiling=True).run()
        except YaraError:
            raise
        except (
            ValueError,
            TypeError,
            IndexError,
            KeyError,
            OverflowError,
            ZeroDivisionError,
        ) as exc:
            raise YaraError(f"the rules do not compile: {type(exc).__name__}: {exc}") from exc
        return compiled

    def match(
        self, data: bytes, timeout: float | None = None, console: Callable[[str], Any] | None = None
    ) -> list[Match]:
        """The rules `data` matches; a `YaraError` once `timeout` seconds have passed. `console`
        receives each `console.log`/`console.hex` message, as yara-python's `console_callback`."""
        import time

        deadline = time.monotonic() + timeout if timeout is not None else None
        return self._scan(data, deadline, console=console).run()


__all__ = ["UNDEFINED", "Match", "Rules", "YaraError"]
