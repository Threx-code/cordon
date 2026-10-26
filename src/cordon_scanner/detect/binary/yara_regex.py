"""A regular-expression engine that cannot backtrack: for the YARA expressions `re` must not run.

Python's `re` backtracks, and an expression with a repeat inside a repeat
(`(\\s*,\\s*\\d{1,3}){19,}`) can take time exponential in the input on a crafted file. The rules
loader's validator refuses such shapes for Cordon's own rules; a YARA pack may still carry them
(two in the bundled pack do). They run here instead: compiled to a program for a Pike virtual
machine (Thompson's construction, as YARA's own engine and RE2 run), whose time is the input's
length times the program's size, whatever the input.

The syntax is YARA's: literals and escapes, `.`, classes with ranges and negation, `\\d \\w \\s`
and their negations, `\\b \\B ^ $`, groups, alternation, `* + ?` and `{n}`, `{n,}`, `{n,m}` (greedy
or lazy). Every match from a given start is found, and the longest is reported, as YARA reports it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar


class RegexError(ValueError):
    pass


@dataclass
class _Node:
    kind: str  # set, cat, alt, star, plus, opt, rep, bol, eol, wordb, nwordb, empty
    value: Any = None
    children: tuple[_Node, ...] = ()


class _Parse:
    MAX_REPEAT: ClassVar[int] = 1000
    WORD: ClassVar[frozenset[int]] = frozenset(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
    )
    DIGIT: ClassVar[frozenset[int]] = frozenset(b"0123456789")
    SPACE: ClassVar[frozenset[int]] = frozenset(b" \t\n\r\x0b\x0c")
    ALL: ClassVar[frozenset[int]] = frozenset(range(256))

    def __init__(
        self, source: str, *, nocase: bool, dotall: bool, max_repeat: int | None = None
    ) -> None:
        self.s, self.i, self.nocase, self.dotall = source, 0, nocase, dotall
        self.max_repeat = _Parse.MAX_REPEAT if max_repeat is None else max_repeat

    def parse(self) -> _Node:
        node = self._alt()
        if self.i != len(self.s):
            raise RegexError(f"an unexpected {self.s[self.i]!r} in a regular expression")
        return node

    def _alt(self) -> _Node:
        branches = [self._cat()]
        while self.i < len(self.s) and self.s[self.i] == "|":
            self.i += 1
            branches.append(self._cat())
        if len(branches) > 1 and branches[0].kind == "empty":
            raise RegexError(
                "an alternative that begins empty"
            )  # `(|a)`; `a|` and `a||b` are YARA's
        return branches[0] if len(branches) == 1 else _Node("alt", children=tuple(branches))

    def _cat(self) -> _Node:
        items: list[_Node] = []
        while self.i < len(self.s) and self.s[self.i] not in "|)":
            items.append(self._repeat())
        return (
            _Node("empty")
            if not items
            else items[0]
            if len(items) == 1
            else _Node("cat", children=tuple(items))
        )

    def _repeat(self) -> _Node:
        atom = self._atom()
        while self.i < len(self.s) and self.s[self.i] in "*+?{":
            c = self.s[self.i]
            if c == "{":
                close = self.s.find("}", self.i)
                body = self.s[self.i + 1 : close] if close > 0 else ""
                parts = body.split(",")
                if (
                    close < 0
                    or not all(p.isdigit() or p == "" for p in parts)
                    or len(parts) > 2
                    or not parts[0]
                ):
                    raise RegexError("a malformed {n,m} repeat")
                lo = int(parts[0])
                hi = lo if len(parts) == 1 else (int(parts[1]) if parts[1] else None)
                if lo > self.max_repeat or (hi is not None and (hi > self.max_repeat or hi < lo)):
                    raise RegexError("a repeat bound out of range")
                self.i = close + 1
                atom = _Node("rep", (lo, hi), (atom,))
            else:
                self.i += 1
                atom = _Node({"*": "star", "+": "plus", "?": "opt"}[c], children=(atom,))
            if self.i < len(self.s) and self.s[self.i] == "?":
                self.i += 1  # lazy: the longest match is reported regardless, as YARA reports it
        return atom

    def _fold(self, chars: frozenset[int]) -> frozenset[int]:
        """With `nocase`, each ASCII letter together with its other case."""
        if not self.nocase:
            return chars
        other = {c + 32 for c in chars if 65 <= c <= 90} | {c - 32 for c in chars if 97 <= c <= 122}
        return chars | frozenset(other)

    def _atom(self) -> _Node:
        s = self.s
        c = s[self.i]
        if c == "(":
            self.i += 1
            if s.startswith("?:", self.i):
                self.i += 2
            node = self._alt()
            if self.i >= len(s) or s[self.i] != ")":
                raise RegexError("an unclosed group")
            self.i += 1
            return node
        if c == "[":
            return _Node("set", self._class())
        if c == ".":
            self.i += 1
            return _Node("set", _Parse.ALL if self.dotall else _Parse.ALL - {10})
        if c == "^":
            self.i += 1
            return _Node("bol")
        if c == "$":
            self.i += 1
            return _Node("eol")
        if c == "\\":
            kind, value = self._escape()
            if kind == "assert":
                return _Node(str(value))
            return _Node("set", self._fold(value))
        if c in "*+?{":
            raise RegexError(f"a repeat with nothing to repeat at {self.i}")
        self.i += 1
        return _Node("set", self._fold(frozenset(c.encode("latin-1"))))

    def _escape(self) -> tuple[str, Any]:
        s = self.s
        if self.i + 1 >= len(s):
            raise RegexError("a trailing backslash")
        e = s[self.i + 1]
        self.i += 2
        classes = {"d": _Parse.DIGIT, "w": _Parse.WORD, "s": _Parse.SPACE}
        if e in classes:
            return "set", classes[e]
        if e.lower() in classes:
            return "set", _Parse.ALL - classes[e.lower()]
        if e == "b":
            return "assert", "wordb"
        if e == "B":
            return "assert", "nwordb"
        if e == "x":
            digits = s[self.i : self.i + 2]
            if len(digits) != 2 or any(d not in "0123456789abcdefABCDEF" for d in digits):
                raise RegexError("a \\x escape without two hex digits")
            self.i += 2
            return "set", frozenset({int(digits, 16)})
        mapped = {"n": 10, "t": 9, "r": 13, "f": 12, "v": 11, "a": 7, "e": 27}.get(e)
        if mapped is not None:
            return "set", frozenset({mapped})
        if e.isalnum():
            raise RegexError(f"an unknown escape \\{e}")
        return "set", frozenset(e.encode("latin-1"))

    def _class(self) -> frozenset[int]:
        s = self.s
        self.i += 1
        negate = s.startswith("^", self.i)
        if negate:
            self.i += 1
        chars: set[int] = set()
        first = True
        while self.i < len(s) and (s[self.i] != "]" or first):
            first = False
            if s[self.i] == "\\":
                kind, value = self._escape()
                if kind != "set":
                    raise RegexError("an assertion inside a class")
                lo_set = value
                if (
                    len(lo_set) == 1
                    and s.startswith("-", self.i)
                    and not s.startswith("-]", self.i)
                ):
                    lo = next(iter(lo_set))
                    self.i += 1
                    hi = self._class_char()
                    chars.update(range(lo, hi + 1))
                else:
                    chars.update(lo_set)
                continue
            lo = ord(s[self.i])
            self.i += 1
            if s.startswith("-", self.i) and not s.startswith("-]", self.i):
                self.i += 1
                hi = self._class_char()
                if hi < lo:
                    raise RegexError("a class range out of order")
                chars.update(range(lo, hi + 1))
            else:
                chars.add(lo)
        if self.i >= len(s):
            raise RegexError("an unclosed class")
        self.i += 1
        folded = self._fold(frozenset(chars))
        return _Parse.ALL - folded if negate else folded

    def _class_char(self) -> int:
        if self.s[self.i] == "\\":
            kind, value = self._escape()
            if kind != "set" or len(value) != 1:
                raise RegexError("a class range ending in a class")
            return int(next(iter(value)))
        c = ord(self.s[self.i])
        self.i += 1
        return c


class Program:
    """Instructions: ("set", chars), ("split", a, b), ("jmp", a), ("assert", kind), ("match",)."""

    MAX_INSTRUCTIONS: ClassVar[int] = 200_000

    def __init__(self, source: str, *, nocase: bool = False, dotall: bool = False) -> None:
        self.code: list[tuple[Any, ...]] = []
        self._emit(_Parse(source, nocase=nocase, dotall=dotall).parse())
        self.code.append(("match",))
        self.first = self._first()

    def _add(self, ins: tuple[Any, ...]) -> int:
        if len(self.code) >= Program.MAX_INSTRUCTIONS:
            raise RegexError("a regular expression too large to compile")
        self.code.append(ins)
        return len(self.code) - 1

    def _emit(self, node: _Node) -> None:
        k = node.kind
        if k == "set":
            self._add(("set", node.value))
        elif k in ("bol", "eol", "wordb", "nwordb"):
            self._add(("assert", k))
        elif k == "empty":
            pass
        elif k == "cat":
            for child in node.children:
                self._emit(child)
        elif k == "alt":
            jumps = []
            for child in node.children[:-1]:
                split = self._add(("split", 0, 0))
                self._emit(child)
                jumps.append(self._add(("jmp", 0)))
                self.code[split] = ("split", split + 1, len(self.code))
            self._emit(node.children[-1])
            for j in jumps:
                self.code[j] = ("jmp", len(self.code))
        elif k == "star":
            split = self._add(("split", 0, 0))
            self._emit(node.children[0])
            self._add(("jmp", split))
            self.code[split] = ("split", split + 1, len(self.code))
        elif k == "plus":
            start = len(self.code)
            self._emit(node.children[0])
            self._add(("split", start, len(self.code) + 1))
        elif k == "opt":
            split = self._add(("split", 0, 0))
            self._emit(node.children[0])
            self.code[split] = ("split", split + 1, len(self.code))
        elif k == "rep":
            lo, hi = node.value
            for _ in range(lo):
                self._emit(node.children[0])
            if hi is None:
                self._emit(_Node("star", children=node.children))
            else:
                for _ in range(hi - lo):
                    self._emit(_Node("opt", children=node.children))

    def _closure(self, pcs: list[int], at: int, data: bytes) -> list[int]:
        out: list[int] = []
        seen: set[int] = set()
        stack = list(reversed(pcs))
        while stack:
            pc = stack.pop()
            if pc in seen:
                continue
            seen.add(pc)
            ins = self.code[pc]
            op = ins[0]
            if op == "jmp":
                stack.append(ins[1])
            elif op == "split":
                stack.append(ins[2])
                stack.append(ins[1])
            elif op == "assert":
                if Program._holds(ins[1], data, at):
                    stack.append(pc + 1)
            else:
                out.append(pc)
        return out

    @staticmethod
    def _word(data: bytes, at: int) -> bool:
        return 0 <= at < len(data) and data[at] in _Parse.WORD

    @staticmethod
    def _holds(kind: str, data: bytes, at: int) -> bool:
        if kind == "bol":
            return at == 0 or data[at - 1] == 10
        if kind == "eol":
            return at == len(data) or data[at] == 10
        boundary = Program._word(data, at - 1) != Program._word(data, at)
        return boundary if kind == "wordb" else not boundary

    def _first(self) -> frozenset[int] | None:
        """The bytes a match can begin with, or None when it can be empty (then every start is
        tried)."""
        chars: set[int] = set()
        for pc in self._closure_static([0]):
            ins = self.code[pc]
            if ins[0] == "set":
                chars |= ins[1]
            else:
                return None
        return frozenset(chars)

    def _closure_static(self, pcs: list[int]) -> list[int]:
        out, seen, stack = [], set(), list(pcs)
        while stack:
            pc = stack.pop()
            if pc in seen:
                continue
            seen.add(pc)
            ins = self.code[pc]
            if ins[0] == "jmp":
                stack.append(ins[1])
            elif ins[0] == "split":
                stack += [ins[1], ins[2]]
            elif ins[0] == "assert":
                stack.append(pc + 1)  # zero-width: the first byte is the next instruction's
            else:
                out.append(pc)
        return out

    def longest(self, data: bytes, start: int, limit: int) -> int:
        """The length of the longest match beginning at `start` and ending by `start + limit`, or
        -1. Time: the bytes read times the program's size."""
        threads = self._closure([0], start, data)
        end = min(len(data), start + limit)
        best, at = -1, start
        while True:
            nxt: list[int] = []
            for pc in threads:
                ins = self.code[pc]
                if ins[0] == "match":
                    best = at - start
                elif ins[0] == "set" and at < end and data[at] in ins[1]:
                    nxt.append(pc + 1)
            if not nxt:
                return best
            at += 1
            threads = self._closure(nxt, at, data)


class Atoms:
    """The literal every match of an expression must contain -- its *atom*, as YARA calls it --
    and how far before it a match can begin. Matching then starts only near the atom's
    occurrences, which a C search finds: a file without the atom costs nothing."""

    @staticmethod
    def span(node: _Node) -> tuple[int, int | None]:
        """The fewest and most bytes `node` matches (None: no bound)."""
        k = node.kind
        if k == "set":
            return 1, 1
        if k in ("bol", "eol", "wordb", "nwordb", "empty"):
            return 0, 0
        if k == "cat":
            lo: int = 0
            hi: int | None = 0
            for child in node.children:
                a, b = Atoms.span(child)
                lo += a
                hi = None if hi is None or b is None else hi + b
            return lo, hi
        if k == "alt":
            spans = [Atoms.span(c) for c in node.children]
            bounded = [b for _, b in spans if b is not None]
            most = None if len(bounded) < len(spans) else max(bounded)
            return min(a for a, _ in spans), most
        a, b = Atoms.span(node.children[0])
        if k == "star":
            return 0, None
        if k == "plus":
            return a, None
        if k == "opt":
            return 0, b
        lo, hi = node.value
        return a * lo, None if hi is None or b is None else b * hi

    @staticmethod
    def _literal(node: _Node) -> int | None:
        """The byte a set matches when it matches only one (or one letter in either case)."""
        if node.kind != "set":
            return None
        chars = node.value
        if len(chars) == 1:
            return int(next(iter(chars)))
        if len(chars) == 2:
            a, b = sorted(chars)
            if b - a == 32 and 65 <= a <= 90:
                return int(b)  # the lower-case letter; the search runs over lowered data
        return None

    @staticmethod
    def find(
        source: str, *, nocase: bool, dotall: bool
    ) -> tuple[bytes, bool, int, int | None] | None:
        """(atom, search lowered, fewest bytes before it, most bytes before it or None)."""
        try:
            tree = _Parse(
                source, nocase=nocase, dotall=dotall, max_repeat=Syntax.MAX_REPEAT
            ).parse()
        except RegexError:
            return None
        items = list(tree.children) if tree.kind == "cat" else [tree]
        best: tuple[int, int] | None = None  # (start index, length)
        i = 0
        while i < len(items):
            if Atoms._literal(items[i]) is None:
                i += 1
                continue
            j = i
            while j < len(items) and Atoms._literal(items[j]) is not None:
                j += 1
            if best is None or j - i > best[1]:
                best = (i, j - i)
            i = j
        if best is None:
            return None
        start, length = best
        before_lo: int = 0
        before_hi: int | None = 0
        lowered = any(len(items[k].value) == 2 for k in range(start, start + length))
        atom = bytes(Atoms._literal(items[k]) or 0 for k in range(start, start + length))
        for node in items[:start]:
            a, b = Atoms.span(node)
            before_lo += a
            before_hi = None if before_hi is None or b is None else before_hi + b
        return atom, lowered, before_lo, before_hi


class Syntax:
    """YARA's regular-expression syntax, checked whichever engine then runs the expression."""

    #: YARA's bound on a repeat count (`RE_MAX_RANGE`).
    MAX_REPEAT: ClassVar[int] = 32767

    @staticmethod
    def check(source: str, *, nocase: bool = False, dotall: bool = False) -> None:
        _Parse(source, nocase=nocase, dotall=dotall, max_repeat=Syntax.MAX_REPEAT).parse()


__all__ = ["Program", "RegexError", "Syntax"]
