"""cordon-rule syntax: rule files read into rules, and conditions into trees.

Reading happens in two steps. `Tokens` cuts the text into words, numbers, text, hex and regular
expression literals and punctuation. `Grammar` reads those into `RuleDef`s whose conditions are
trees of the node classes below.

Conditions have two layers, and the tree keeps them apart. A *test* is true or false: `true`, a
string found (`$a`, `$a at 10`), a comparison, `and`/`or`/`not`, a quantifier over a set, a loop. A
*value* is a number or text: a literal, `filesize`, a count or offset of matches, a read of the
file, a module field, and arithmetic over values. Operators say which layer they take: arithmetic
and comparisons take values (so `1 + true` and `(1 == 1) == 1` do not read), `and`/`or`/`not` take
either, and a value standing alone is a test of whether it is nonzero (or nonempty). Whether the
values have the right types is checked afterwards, against the modules' declarations
(`rule_check`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_engine.tokens import Includes, RuleError, Token, Tokens


class Node:
    """A condition's node. `TEST` says which layer it is in: a test (True) or a value."""

    __slots__ = ()
    TEST: ClassVar[bool] = False


class Test(Node):
    __slots__ = ()
    TEST: ClassVar[bool] = True


@dataclass(slots=True)
class Literal(Node):
    value: int | float | bytes


@dataclass(slots=True)
class Truth(Test):
    value: bool


@dataclass(slots=True)
class FileSize(Node):
    pass


@dataclass(slots=True)
class EntryPoint(Node):
    """`entrypoint`: no longer given a value; always undefined."""


@dataclass(slots=True)
class External(Node):
    name: str


@dataclass(slots=True)
class Name(Node):
    """A bare identifier: a rule (a test), or a loop variable -- resolved when checked."""

    name: str


@dataclass(slots=True)
class Field:
    name: str


@dataclass(slots=True)
class Index:
    key: Node


@dataclass(slots=True)
class Invoke:
    args: list[Any]  # nodes, or `Pattern`s for regex arguments


@dataclass(slots=True)
class Pattern(Node):
    """A regular expression where a value goes (a function's argument)."""

    matcher: Any


@dataclass(slots=True)
class Path(Node):
    """A module's field (`root` is the module) or a loop variable's (`module` False), then
    fields, indexes and calls."""

    root: str
    module: bool
    steps: list[Any]


@dataclass(slots=True)
class Count(Node):
    """`#a`, or `#a in (lo..hi)`."""

    string: str
    span: tuple[Node, Node] | None = None


@dataclass(slots=True)
class Place(Node):
    """`@a[i]` (where the i-th match starts) or `!a[i]` (its length)."""

    string: str
    nth: Node
    length: bool


@dataclass(slots=True)
class Read(Node):
    """`uint32be(at)` and the rest: an integer read from the file."""

    width: int
    signed: bool
    big: bool
    at: Node


@dataclass(slots=True)
class Arith(Node):
    op: str
    left: Node
    right: Node


@dataclass(slots=True)
class Minus(Node):
    operand: Node


@dataclass(slots=True)
class Invert(Node):
    operand: Node


@dataclass(slots=True)
class Found(Test):
    """`$a`, `$a at x` or `$a in (lo..hi)`."""

    string: str
    at: Node | None = None
    span: tuple[Node, Node] | None = None


@dataclass(slots=True)
class Compare(Test):
    """`==` and the other comparisons, and the text tests (`contains` and the rest)."""

    op: str
    left: Node
    right: Node


@dataclass(slots=True)
class Matches(Test):
    subject: Node
    matcher: Any


@dataclass(slots=True)
class Both(Test):
    left: Node
    right: Node


@dataclass(slots=True)
class Either(Test):
    left: Node
    right: Node


@dataclass(slots=True)
class Negate(Test):
    operand: Node


@dataclass(slots=True)
class Defined(Test):
    operand: Node


@dataclass(slots=True)
class Quantity:
    """How many of a set must hold: `any`, `all`, `none`, a number (`amount`), or a percentage
    (`amount`, `percent`)."""

    word: str | None
    amount: Node | None = None
    percent: bool = False


@dataclass(slots=True)
class Members:
    """A set of strings or rules: `them` (`names` None), or names with optional `*`."""

    names: list[str] | None


@dataclass(slots=True)
class Of(Test):
    quantity: Quantity
    members: Members
    at: Node | None = None
    span: tuple[Node, Node] | None = None


@dataclass(slots=True)
class EachString(Test):
    """`for <quantity> of <set> : (<test>)`, the body run with `$` as each string."""

    quantity: Quantity
    members: Members
    body: Node


@dataclass(slots=True)
class Span:
    lo: Node
    hi: Node


@dataclass(slots=True)
class Listed:
    items: list[Node]


@dataclass(slots=True)
class Over:
    """A module array or dictionary a loop goes through."""

    source: Node


@dataclass(slots=True)
class Loop(Test):
    """`for <quantity> <names> in <domain> : (<test>)`."""

    quantity: Quantity
    names: list[str]
    domain: Span | Listed | Over
    body: Node


@dataclass(slots=True)
class StringDef:
    name: str
    kind: str  # text, hex, regex
    value: Any
    modifiers: dict[str, Any]
    #: The string ready to be searched for (`rule_engine.scan.Search`).
    search: Any = None
    #: The one offset the string can count at, when the condition only asks `$a at <constant>`.
    fixed: int | None = None

    @property
    def private(self) -> bool:
        return "private" in self.modifiers


@dataclass
class RuleDef:
    name: str
    tags: list[str]
    meta: dict[str, Any]
    strings: list[StringDef]
    condition: Node
    private: bool = False
    is_global: bool = False
    #: The condition, ready to run (`rule_engine.build`).
    run: Any = None
    #: The condition is false whenever none of the rule's strings matched, and calls nothing:
    #: it needs no running then.
    needs_match: bool = False
    #: How many loop variables the condition holds at once (`rule_engine.build`).
    width: int = 0
    #: What the compiler decided for the rule where the rule did not say (`rule_engine.build`): a
    #: field with two shapes read in the reference's, for one. Part of the rule set's load result.
    notes: list[str] = field(default_factory=list)
    #: The condition's top-level parts that read no string, each ready to run (`rule_engine.gates`).
    gates: list[Any] = field(default_factory=list)
    #: Sets of strings of which one must match for the condition to hold (`rule_engine.gates`).
    clauses: list[frozenset[str]] = field(default_factory=list)


class _TokenStream:
    """The token stream a rule file is read from, and the parser's state (`Grammar`)."""

    toks: list[Token]
    i: int
    modules: frozenset[str]
    externals: dict[str, Any]
    imports: set[str]
    rules: list[RuleDef]
    current: str
    strings: list[StringDef]
    used: set[str]
    prefixes: list[str]

    # -- reading tokens --

    @property
    def tok(self) -> Token:
        return self.toks[self.i]

    def peek(self, ahead: int = 1) -> Token:
        return self.toks[min(self.i + ahead, len(self.toks) - 1)]

    def sees(self, word: str) -> bool:
        tok = self.tok
        return tok.kind in ("mark", "word") and tok.value == word

    def take(self, word: str) -> bool:
        if self.sees(word):
            self.i += 1
            return True
        return False

    def need(self, word: str) -> None:
        if not self.take(word):
            raise RuleError(f"line {self.tok.line}: expected {word!r}, found {self.tok.value!r}")

    def word(self) -> str:
        tok = self.tok
        if tok.kind != "word":
            raise RuleError(f"line {tok.line}: expected a name, found {tok.value!r}")
        self.i += 1
        return str(tok.value)

    def fail(self, what: str) -> RuleError:
        tok = self.tok
        where = f"{tok.chain[-1].name} " if tok.chain else ""
        return RuleError(f"{where}line {tok.line}: {what}")


class _ConditionGrammar(_TokenStream):
    """Conditions, read by precedence (`Grammar`'s strengths and layers)."""

    # -- conditions --

    def condition(self, floor: int = 0) -> Node:
        """A condition of operators stronger than `floor`."""
        left = self._prefixed()
        while True:
            tok = self.tok
            op = tok.value if tok.kind in ("mark", "word") else None
            level = Grammar.LEVELS.get(op) if isinstance(op, str) else None
            if level is None or level <= floor:
                return left
            if op == "%" and self.peek().value == "of":
                # `<value>% of <set>`: everything read so far at this strength is the percentage
                if left.TEST:
                    raise self.fail("a percentage is a value")
                self.i += 1
                left = self._of(Grammar._quantity(Quantity(None, left, percent=True)))
                continue
            self.i += 1
            if op == "matches":
                left = self._matches(left)
                continue
            right = self.condition(level)
            left = self._join(str(op), left, right)

    def _join(self, op: str, left: Node, right: Node) -> Node:
        if op in ("and", "or"):
            return Both(left, right) if op == "and" else Either(left, right)
        if left.TEST or right.TEST:
            raise self.fail(f"{op} takes values, not tests")
        if op in Grammar.COMPARE:
            return Compare(op, left, right)
        return Arith(op, left, right)

    def _matches(self, subject: Node) -> Node:
        if subject.TEST:
            raise self.fail("matches takes a value")
        if self.tok.kind != "regex":
            raise self.fail("matches needs a regular expression")
        source, flags = self.tok.value
        self.i += 1
        return Matches(subject, Grammar.matcher(source, flags))

    @staticmethod
    def matcher(source: str, flags: str) -> Any:
        from cordon_scanner.detect.binary.rule_engine.pattern import PatternError
        from cordon_scanner.detect.binary.rule_engine.search_parts import Matcher

        try:
            return Matcher(source.encode("utf-8", "surrogateescape"), flags)
        except PatternError as exc:
            raise RuleError(f"a regular expression that does not compile: {exc}") from exc

    def _prefixed(self) -> Node:
        if self.take("not"):
            return Negate(self.condition(Grammar.PREFIX_LEVEL))
        if self.take("defined"):
            return Defined(self.condition(Grammar.PREFIX_LEVEL))
        return self._unary()

    def _unary(self) -> Node:
        if self.take("-"):
            if self.tok.kind in ("int", "float") and self.peek().value == "of":
                raise self.fail("a negative quantifier")
            operand = self._unary()
            if operand.TEST:
                raise self.fail("- takes a value")
            return Minus(operand)
        if self.take("~"):
            operand = self._unary()
            if operand.TEST:
                raise self.fail("~ takes a value")
            return Invert(operand)
        return self._quantified(self._atom())

    def _quantified(self, node: Node) -> Node:
        """`node` as the quantity of a following `of`, else itself (a percentage, `% of`, is read
        where `%` is)."""
        if self.sees("of") and not node.TEST:
            return self._of(Grammar._quantity(Quantity(None, node)))
        return node

    def _atom(self) -> Node:
        tok = self.tok
        if tok.kind in ("int", "float", "text"):
            self.i += 1
            return Literal(tok.value)
        if tok.kind == "sigil":
            return self._sigil()
        if self.take("("):
            inner = self.condition()
            self.need(")")
            return inner
        if tok.kind != "word":
            raise self.fail(f"an unexpected {tok.value!r} in a condition")
        word = tok.value
        if word in ("true", "false"):
            self.i += 1
            return Truth(word == "true")
        if word in ("any", "all", "none"):
            self.i += 1
            return self._of(Quantity(word))
        if word == "for":
            return self._for()
        self.i += 1
        if word == "filesize":
            return FileSize()
        if word == "entrypoint":
            return EntryPoint()
        if word in Grammar.READS:
            width, signed, big = Grammar.READS[word]
            self.need("(")
            at = self.condition()
            self.need(")")
            if at.TEST:
                raise self.fail(f"{word} reads at a value")
            return Read(width, signed, big, at)
        if word in self.imports:
            return Path(word, True, self._steps())
        if self.sees(".") or self.sees("["):
            return Path(word, False, self._steps())
        if word in self.externals:
            return External(word)
        return Name(word)

    def _steps(self) -> list[Any]:
        """`.field`, `[index]` and `(arguments)`, as many as follow."""
        steps: list[Any] = []
        while True:
            if self.take("."):
                steps.append(Field(self.word()))
            elif self.take("["):
                steps.append(Index(self.condition()))
                self.need("]")
            elif self.take("("):
                args: list[Any] = []
                while not self.sees(")"):
                    if self.tok.kind == "regex":
                        args.append(Pattern(Grammar.matcher(*self.tok.value)))
                        self.i += 1
                    else:
                        args.append(self.condition())
                    if not self.take(","):
                        break
                self.need(")")
                steps.append(Invoke(args))
            else:
                return steps

    def _sigil(self) -> Node:
        tok = self.tok
        self.i += 1
        mark, name = tok.value[0], "$" + tok.value[1:]
        if name != "$":
            if name not in {s.name for s in self.strings}:
                raise RuleError(f"line {tok.line}: an undefined string {name}")
            self.used.add(name)
        if mark == "$":
            if self.take("at"):
                return Found(name, at=self._offset())
            if self.take("in"):
                return Found(name, span=self._span())
            return Found(name)
        if mark == "#":
            return Count(name, self._span() if self.take("in") else None)
        nth: Node = Literal(1)
        if self.take("["):
            nth = self.condition()
            self.need("]")
            if nth.TEST:
                raise self.fail("a match's index is a value")
        return Place(name, nth, mark == "!")

    def _offset(self) -> Node:
        """The offset after `at`: a whole arithmetic expression, as the reference reads it
        (`$a at @b[1] + 16` is `$a at (@b[1] + 16)`); a comparison ends it."""
        offset = self.condition(Grammar.LEVELS["=="])
        if offset.TEST:
            raise self.fail("at takes a value")
        return offset

    def _span(self) -> tuple[Node, Node]:
        self.need("(")
        lo = self.condition()
        self.need("..")
        hi = self.condition()
        self.need(")")
        lo_value = Grammar.constant(lo)
        hi_value = Grammar.constant(hi)
        if isinstance(lo, Minus) and isinstance(lo.operand, Literal):
            raise RuleError("a range whose lower bound is negative")
        if isinstance(lo_value, (int, float)) and lo_value < 0:
            raise RuleError("a range whose lower bound is negative")
        if (
            isinstance(lo, Literal)
            and isinstance(hi, Literal)
            and isinstance(lo_value, (int, float))
            and isinstance(hi_value, (int, float))
            and lo_value > hi_value
        ):
            raise RuleError("a range whose lower bound is above its upper")
        return (lo, hi)

    @staticmethod
    def constant(node: Node) -> Any:
        return node.value if isinstance(node, Literal) else None

    def _members(self) -> Members:
        if self.take("them"):
            if not self.strings:
                raise self.fail("'them' in a rule with no strings")
            self.used.update(s.name for s in self.strings)
            return Members(None)
        self.need("(")
        names = [self._member()]
        while self.take(","):
            names.append(self._member())
        self.need(")")
        return Members(names)

    def _member(self) -> str:
        tok = self.tok
        if tok.kind == "sigil" and tok.value.startswith("$"):
            self.i += 1
            item = str(tok.value)
            hits = [
                s.name
                for s in self.strings
                if (s.name.startswith(item[:-1]) if item.endswith("*") else s.name == item)
            ]
            if not hits:
                raise RuleError(f"line {tok.line}: {item} names no string of the rule")
            self.used.update(hits)
            return item
        if tok.kind == "word":
            self.i += 1
            item = tok.value + ("*" if self.take("*") else "")
            known = [r.name for r in self.rules] + [self.current]
            prefix = item[:-1] if item.endswith("*") else None
            if not any(r.startswith(prefix) if prefix is not None else r == item for r in known):
                raise RuleError(f"line {tok.line}: {item} names no rule defined before it")
            if prefix is not None:
                self.prefixes.append(prefix)
            return str(item)
        raise self.fail("a string set holds string or rule names")

    @staticmethod
    def _quantity(q: Quantity) -> Quantity:
        """A constant quantity checked now: a whole number of at least 0, or a percentage from 1
        to 100."""
        amount = q.amount
        value = Grammar.constant(amount) if amount is not None else None
        if isinstance(amount, Minus) and isinstance(amount.operand, Literal):
            raise RuleError("a negative quantifier")
        if q.percent:
            if isinstance(value, (int, float)) and not 1 <= value <= 100:
                raise RuleError(f"a percentage must be from 1 to 100, not {value}")
        elif isinstance(value, (int, float)) and (not isinstance(value, int) or value < 0):
            raise RuleError(f"a quantifier must be a whole number of at least 0, not {value}")
        return q

    def _of(self, quantity: Quantity) -> Node:
        self.need("of")
        members = self._members()
        if self.take("at"):
            return Of(quantity, members, at=self._offset())
        if self.take("in"):
            return Of(quantity, members, span=self._span())
        return Of(quantity, members)

    def _loop_quantity(self) -> Quantity:
        tok = self.tok
        if tok.kind == "word" and tok.value in ("any", "all", "none"):
            self.i += 1
            return Quantity(tok.value)
        if tok.kind == "int" and self.peek().value == "%":
            self.i += 2
            return Grammar._quantity(Quantity(None, Literal(tok.value), percent=True))
        amount = self._atom()
        if amount.TEST:
            raise self.fail("a loop's quantity is a value")
        if self.sees("%"):
            self.i += 1
            return Grammar._quantity(Quantity(None, amount, percent=True))
        return Grammar._quantity(Quantity(None, amount))

    def _body(self) -> Node:
        self.need(":")
        self.need("(")
        body = self.condition()
        self.need(")")
        return body

    def _for(self) -> Node:
        self.need("for")
        quantity = self._loop_quantity()
        if self.take("of"):
            members = self._members()
            return EachString(quantity, members, self._body())
        names = [self.word()]
        while self.take(","):
            names.append(self.word())
        self.need("in")
        if not self.sees("("):
            source = self._atom()
            return Loop(quantity, names, Over(source), self._body())
        self.i += 1
        first = self.condition()
        domain: Span | Listed
        if self.take(".."):
            hi = self.condition()
            self.need(")")
            for bound in (first, hi):
                value = Grammar.constant(bound)
                if bound.TEST or isinstance(value, (bytes, float)):
                    raise RuleError("a for range needs integer bounds")
            lo_value, hi_value = Grammar.constant(first), Grammar.constant(hi)
            if isinstance(lo_value, int) and isinstance(hi_value, int) and lo_value > hi_value:
                raise RuleError("a for range whose lower bound is above its upper")
            domain = Span(first, hi)
        else:
            items = [first]
            while self.take(","):
                items.append(self.condition())
            self.need(")")
            if any(item.TEST for item in items):
                raise RuleError("a for list holds integers, or strings, not both")
            kinds = {isinstance(Grammar.constant(i), bytes) for i in items}
            if len(kinds) > 1:
                raise RuleError("a for list holds integers, or strings, not both")
            domain = Listed(items)
        return Loop(quantity, names, domain, self._body())


class Grammar(_ConditionGrammar):
    """Tokens read into rules.

    Conditions are read by precedence: each binary operator has a strength, and an operand is
    read with everything stronger. `LEVELS` gives the strengths, weakest first; `not` and
    `defined` take an operand of comparison strength, `-` and `~` one of their own. `OPERANDS`
    says which layer an operator's operands must be in.
    """

    COMPARE: ClassVar[tuple[str, ...]] = (
        "==", "!=", "<", ">", "<=", ">=", "contains", "icontains", "startswith", "istartswith",
        "endswith", "iendswith", "iequals", "matches",
    )  # fmt: skip
    LEVELS: ClassVar[dict[str, int]] = {
        "or": 1, "and": 2, **dict.fromkeys(COMPARE, 4), "|": 5, "^": 6, "&": 7, "<<": 8,
        ">>": 8, "+": 9, "-": 9, "*": 10, "\\": 10, "%": 10,
    }  # fmt: skip
    PREFIX_LEVEL: ClassVar[int] = 3
    UNARY_LEVEL: ClassVar[int] = 11
    TEXT_MODIFIERS: ClassVar[frozenset[str]] = frozenset(
        {"nocase", "wide", "ascii", "fullword", "private", "xor", "base64", "base64wide"}
    )
    READS: ClassVar[dict[str, tuple[int, bool, bool]]] = {
        f"{'' if signed else 'u'}int{bits}{'be' if big else ''}": (bits // 8, signed, big)
        for signed in (True, False)
        for bits in (8, 16, 32)
        for big in (False, True)
    }

    def __init__(
        self,
        text: str,
        externals: dict[str, Any],
        modules: frozenset[str],
        includes: Includes | None = None,
    ) -> None:
        self.toks = Tokens(text).all()
        #: Where `include` reads from; None refuses every include.
        self.includes = includes
        self.i = 0
        self.modules, self.externals = modules, externals
        self.imports: set[str] = set()
        self.rules: list[RuleDef] = []
        #: The rule being read: its name, its strings, and the strings its condition names.
        self.current = ""
        self.strings: list[StringDef] = []
        self.used: set[str] = set()
        #: Prefixes (`a*`) rule sets have named: a rule defined after, whose name has one, is
        #: refused -- the set was decided without it.
        self.prefixes: list[str] = []

    # -- rules --

    def read(self) -> list[RuleDef]:
        while self.tok.kind != "end":
            if self.take("import"):
                if self.tok.kind != "text":
                    raise self.fail("import needs a module name")
                name = self.tok.value.decode()
                self.i += 1
                if name not in self.modules:
                    raise RuleError(f"the {name!r} module is not one cordon-rule provides")
                self.imports.add(name)
            elif self.sees("include"):
                self._include()
            else:
                self.rules.append(self._rule())
        names = [r.name for r in self.rules]
        if len(set(names)) != len(names):
            raise RuleError("a rule name defined twice")
        return self.rules

    def _include(self) -> None:
        """`include "name"`: the named file's tokens in place of the directive."""
        tok, name = self.tok, self.peek()
        if self.includes is None:
            raise self.fail("include is not allowed")
        if name.kind != "text":
            raise self.fail("include needs a file name")
        text = name.value.decode("utf-8", "surrogateescape")
        self.toks[self.i : self.i + 2] = self.includes.tokens(text, tok.chain, tok.line)

    def _rule(self) -> RuleDef:
        private = is_global = False
        while self.sees("private") or self.sees("global"):
            private |= self.take("private")
            is_global |= self.take("global")
        self.need("rule")
        name = self.current = self.word()
        if any(name.startswith(p) for p in self.prefixes):
            raise RuleError(f"rule {name} matches a rule set an earlier rule already used")
        tags: list[str] = []
        if self.take(":"):
            while self.tok.kind == "word" and not self.sees("{"):
                tag = self.word()
                if tag in tags:
                    raise RuleError(f"rule {name}: the tag {tag} twice")
                tags.append(tag)
        self.need("{")
        meta = self._meta() if self.take("meta") else {}
        strings = self._strings(name) if self.take("strings") else []
        self.strings, self.used = strings, set()
        self.need("condition")
        self.need(":")
        condition = self.condition()
        self.need("}")
        for s in strings:
            if s.name not in self.used:
                raise RuleError(f"rule {name}: the string {s.name} is never used")
        return RuleDef(name, tags, meta, strings, condition, private, is_global)

    def _meta(self) -> dict[str, Any]:
        self.need(":")
        meta: dict[str, Any] = {}
        while self.tok.kind == "word" and self.peek().value == "=":
            key = self.word()
            self.need("=")
            tok = self.tok
            if tok.kind == "text":
                value: Any = tok.value.decode("utf-8", "replace")
            elif self.sees("-"):
                self.i += 1
                tok = self.tok
                value = -int(tok.value) if tok.kind == "int" else 0
                if tok.kind != "int":
                    self.i -= 1
            elif tok.kind == "int":
                value = tok.value
            elif self.sees("true") or self.sees("false"):
                value = tok.value == "true"
            else:
                raise self.fail("a meta value must be a string, number or boolean")
            self.i += 1
            meta[key] = value
        return meta

    def _strings(self, rule: str) -> list[StringDef]:
        self.need(":")
        out: list[StringDef] = []
        unnamed = 0
        while self.tok.kind == "sigil" and self.tok.value.startswith("$"):
            name = self.tok.value
            if name == "$":
                unnamed += 1
                name = f"$#anonymous{unnamed}"
            self.i += 1
            self.need("=")
            out.append(self._string(name))
        if len({s.name for s in out}) != len(out):
            raise RuleError(f"rule {rule}: a string defined twice")
        return out

    def _string(self, name: str) -> StringDef:
        tok = self.tok
        kinds = {"text": "text", "hex": "hex", "regex": "regex"}
        if tok.kind not in kinds:
            raise self.fail("a string definition must be text, hex or a regex")
        self.i += 1
        mods: dict[str, Any] = {}
        while self.tok.kind == "word" and self.tok.value in Grammar.TEXT_MODIFIERS:
            mod = self.word()
            if mod in mods:
                raise RuleError(f"string {name}: the modifier {mod} twice")
            mods[mod] = self._modifier(name, mod)
        alphabets = [mods[m] for m in ("base64", "base64wide") if m in mods]
        if len(alphabets) == 2 and alphabets[0] != alphabets[1]:
            raise RuleError(f"string {name}: base64 and base64wide with different alphabets")
        Grammar._modifiers_fit(name, kinds[tok.kind], mods)
        return StringDef(name, kinds[tok.kind], tok.value, mods)

    def _modifier(self, name: str, mod: str) -> Any:
        if mod == "xor":
            if not self.take("("):
                return (0, 255)
            lo = hi = int(self.tok.value)
            self.i += 1
            if self.take("-"):
                hi = int(self.tok.value)
                self.i += 1
            self.need(")")
            if not 0 <= lo <= hi <= 255:
                raise RuleError(f"string {name}: an xor range out of 0-255")
            return (lo, hi)
        if mod in ("base64", "base64wide") and self.take("("):
            alphabet = self.tok.value
            self.i += 1
            self.need(")")
            if not isinstance(alphabet, bytes) or len(alphabet) != 64:
                raise RuleError(f"string {name}: a base64 alphabet must be 64 bytes")
            return alphabet
        return True

    @staticmethod
    def _modifiers_fit(name: str, kind: str, mods: dict[str, Any]) -> None:
        given = set(mods)
        refusals = (
            (kind == "hex" and bool(given - {"private"}), "a hex string takes no modifier but private"),
            (kind == "regex" and bool(given & {"xor", "base64", "base64wide"}), "a regular expression takes no xor or base64"),
            (bool(given & {"base64", "base64wide"}) and bool(given & {"nocase", "xor", "fullword"}), "base64 cannot be combined with nocase, xor or fullword"),
            ("xor" in given and "nocase" in given, "xor and nocase together"),
        )  # fmt: skip
        for refused, why in refusals:
            if refused:
                raise RuleError(f"string {name}: {why}")


__all__ = [
    "Arith",
    "Both",
    "Compare",
    "Count",
    "Defined",
    "EachString",
    "Either",
    "EntryPoint",
    "External",
    "Field",
    "FileSize",
    "Found",
    "Grammar",
    "Index",
    "Invert",
    "Invoke",
    "Listed",
    "Literal",
    "Loop",
    "Matches",
    "Members",
    "Minus",
    "Name",
    "Negate",
    "Node",
    "Of",
    "Over",
    "Path",
    "Pattern",
    "Place",
    "Quantity",
    "Read",
    "RuleDef",
    "Span",
    "StringDef",
    "Test",
    "Truth",
]
