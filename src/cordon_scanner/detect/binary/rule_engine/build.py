"""cordon-rule's condition compiler: each condition checked against the modules' declarations and
built into Python closures, once, when the rules compile.

`Builder.test` takes a condition tree (`rule_engine.syntax`) and returns a function of a `Frame` -- one
file's state: its bytes, the matches of each string, the rules already decided, the loop
variables, the module data read so far. Every node is built with its type: a value's is a
`Scalar` or a module declaration (`modules.values`), a test's is `Scalar.BOOL`. Types are checked as
the tree is built, every branch of it, so a rule that could fail on some file is refused before
any file is read. Expressions made of literals alone are worked out once: one that cannot be valid
(an overflow, a division by zero, a negative shift) is refused.

Undefined is None. It propagates through arithmetic and comparisons, and a test reads it as false.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterator
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.values import (
    Call,
    Data,
    Dual,
    Keyed,
    Module,
    Record,
    Scalar,
    Seq,
)
from cordon_scanner.detect.binary.rule_engine.shapes import Shapes
from cordon_scanner.detect.binary.rule_engine.syntax import (
    Arith,
    Both,
    Compare,
    Count,
    Defined,
    EachString,
    Either,
    EntryPoint,
    External,
    Field,
    FileSize,
    Found,
    Index,
    Invert,
    Invoke,
    Listed,
    Literal,
    Loop,
    Matches,
    Members,
    Minus,
    Name,
    Negate,
    Node,
    Of,
    Over,
    Path,
    Pattern,
    Place,
    Quantity,
    Read,
    RuleDef,
    Span,
    Truth,
)
from cordon_scanner.detect.binary.rule_engine.tokens import RuleError

INT64_MAX, INT64_MIN = 2**63 - 1, -(2**63)
INT, FLOAT, TEXT, BOOL = Scalar.INT, Scalar.FLOAT, Scalar.TEXT, Scalar.BOOL
NUMBERS = (INT, FLOAT)

Fn = Callable[["Frame"], Any]


class Frame:
    """One file's state while its rules are decided."""

    __slots__ = ("data", "decided", "env", "found", "loaded", "modules", "size")

    def __init__(self, data: bytes, modules: dict[str, Module]) -> None:
        self.data, self.size = data, len(data)
        self.modules = modules
        #: Module data read from this file, by module name.
        self.loaded: dict[str, Any] = {}
        #: The matches of each string of the rule being decided: (offset, length), by offset.
        self.found: dict[str, list[tuple[int, int]]] = {}
        self.decided: dict[str, bool] = {}
        #: Loop variables, by the slot the builder gave each.
        self.env: list[Any] = []

    def module(self, name: str) -> Any:
        data = self.loaded.get(name)
        if data is None:
            data = self.loaded[name] = self.modules[name].data(self.data)
        return data


class Elements:
    """An array's elements as a loop goes through them, index 0 up to its length: each read as
    the loop reaches it, so a table that decodes its rows on access decodes each once, in turn,
    and none is held after the loop has moved past it."""

    __slots__ = ("convert", "items", "length")

    def __init__(self, items: Any, convert: Callable[[Any], Any]) -> None:
        self.items, self.convert = items, convert
        self.length = Data.length(items)

    def __len__(self) -> int:
        return int(self.length)

    def __iter__(self) -> Iterator[Any]:
        get, convert = self.items.get, self.convert
        for i in range(self.length):
            yield convert(get(i))


class Fold:
    """Arithmetic as conditions do it: on 64-bit integers and floats, undefined (None) in,
    undefined out; an integer result out of 64 bits is undefined."""

    TEXT_TESTS: ClassVar[dict[str, Callable[[bytes, bytes], bool]]] = {
        "contains": lambda a, b: b in a,
        "icontains": lambda a, b: b.lower() in a.lower(),
        "startswith": lambda a, b: a.startswith(b),
        "istartswith": lambda a, b: a.lower().startswith(b.lower()),
        "endswith": lambda a, b: a.endswith(b),
        "iendswith": lambda a, b: a.lower().endswith(b.lower()),
        "iequals": lambda a, b: a.lower() == b.lower(),
    }
    ORDER: ClassVar[dict[str, Callable[[Any, Any], bool]]] = {
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
        "<": lambda a, b: a < b,
        ">": lambda a, b: a > b,
        "<=": lambda a, b: a <= b,
        ">=": lambda a, b: a >= b,
    }

    @staticmethod
    def divide(a: Any, b: Any) -> Any:
        if b == 0:
            return None
        if type(a) is int and type(b) is int:
            if a == INT64_MIN and b == -1:
                return None
            q = abs(a) // abs(b)  # toward zero, exactly
            return q if (a < 0) == (b < 0) else -q
        return a / b

    @staticmethod
    def remainder(a: Any, b: Any) -> Any:
        if b == 0 or (a == INT64_MIN and b == -1):
            return None
        r = abs(a) % abs(b)  # the dividend's sign
        return r if a >= 0 else -r

    @staticmethod
    def shift_left(a: Any, b: Any) -> Any:
        if b < 0:
            return None
        return (a << b) & ((1 << 64) - 1) if b < 64 else 0

    @staticmethod
    def shift_right(a: Any, b: Any) -> Any:
        if b < 0:
            return None
        return a >> b if b < 64 else 0

    ARITH: ClassVar[dict[str, Callable[[Any, Any], Any]]] = {
        "+": lambda a, b: a + b,
        "-": lambda a, b: a - b,
        "*": lambda a, b: a * b,
        "&": lambda a, b: a & b,
        "|": lambda a, b: a | b,
        "^": lambda a, b: a ^ b,
    }

    @staticmethod
    def op(op: str) -> Callable[[Any, Any], Any]:
        special = {
            "\\": Fold.divide,
            "%": Fold.remainder,
            "<<": Fold.shift_left,
            ">>": Fold.shift_right,
        }
        return special.get(op) or Fold.ARITH[op]

    @staticmethod
    def fits(op: str, value: Any) -> bool:
        """Whether an integer result is one 64 bits hold (a product's bound is symmetric)."""
        if type(value) is not int:
            return True
        low = INT64_MIN + 1 if op == "*" else INT64_MIN
        return low <= value <= INT64_MAX


class Scope:
    """What names mean while one rule is built: its loop variables (by slot), whether `$` is
    bound by an enclosing `for ... of`, and the rules decided before it."""

    __slots__ = ("bound", "rule", "slots", "strings_bound", "width")

    def __init__(self, rule: RuleDef) -> None:
        self.rule = rule
        self.bound: list[tuple[str, int, Any]] = []  # (name, slot, type), innermost last
        self.slots = 0
        self.width = 0  # slots the rule needs
        self.strings_bound = 0  # the slot holding `$`'s string name, +1; 0: not bound

    def lookup(self, name: str) -> tuple[int, Any] | None:
        for bound, slot, kind in reversed(self.bound):
            if bound == name:
                return slot, kind
        return None

    def push(self, name: str, kind: Any) -> int:
        slot = self.slots
        self.slots += 1
        self.width = max(self.width, self.slots)
        self.bound.append((name, slot, kind))
        return slot

    def pop(self, count: int) -> None:
        del self.bound[len(self.bound) - count :]
        self.slots -= count


class _BuilderValues:
    """What a condition's parts are (their kinds), and the literals worked out at build time."""

    rules: list[RuleDef]
    modules: dict[str, Module]
    externals: dict[str, Any]
    scope: Scope
    before: set[str]

    def node(self, node: Node) -> tuple[Any, Fn]:
        """`Builder.node`: every part builds its sub-conditions through it."""
        raise NotImplementedError

    # -- types --

    @staticmethod
    def as_test(kind: Any, what: str) -> None:
        if not isinstance(kind, Scalar):
            raise RuleError(f"wrong use of {Builder.describe(kind)} as {what}")

    @staticmethod
    def describe(kind: Any) -> str:
        if isinstance(kind, Scalar):
            return {"int": "an integer", "float": "a float", "text": "a string"}.get(
                kind.name, "a boolean"
            )
        return {
            Record: "a structure", Seq: "an array", Keyed: "a dictionary", Call: "a function",
            Dual: "a field with two shapes",
        }[type(kind)]  # fmt: skip

    @staticmethod
    def scalar(kind: Any, what: str) -> Scalar:
        if not isinstance(kind, Scalar):
            raise RuleError(f"wrong use of {Builder.describe(kind)} in {what}")
        return kind

    @staticmethod
    def integer(kind: Any, what: str) -> None:
        if Builder.scalar(kind, what) is not INT:
            raise RuleError(f"{what} needs an integer, not {Builder.describe(kind)}")

    @staticmethod
    def truth(fn: Fn) -> Fn:
        def test(f: Frame) -> bool:
            v = fn(f)
            return v is not None and bool(v)

        return test

    def constant(self, node: Node) -> tuple[bool, Any]:
        """(True, its value) when `node` is made of literals alone, worked out now; one that
        cannot be valid is refused."""
        if isinstance(node, Literal):
            return True, node.value
        if isinstance(node, (Minus, Invert)):
            known, value = self.constant(node.operand)
            if not known:
                return False, None
            if isinstance(node, Invert):
                return True, ~value
            if type(value) is int and -value > INT64_MAX:
                raise RuleError("integer overflow in a constant expression")
            return True, -value
        if isinstance(node, Arith):
            k1, a = self.constant(node.left)
            if not k1:
                return False, None
            k2, b = self.constant(node.right)
            if not k2:
                return False, None
            op = node.op
            if op in ("\\", "%") and b == 0:
                raise RuleError("division by zero in a constant expression")
            if op in ("<<", ">>") and b < 0:
                raise RuleError("a negative shift count")
            v = Fold.op(op)(a, b)
            if v is None or not Fold.fits(op, v):
                raise RuleError("integer overflow in a constant expression")
            return True, v
        return False, None

    def _literal(self, node: Literal) -> tuple[Any, Fn]:
        v = node.value
        kind = TEXT if isinstance(v, bytes) else FLOAT if isinstance(v, float) else INT
        return kind, lambda f: v

    def _truth(self, node: Truth) -> tuple[Any, Fn]:
        v = node.value
        return BOOL, lambda f: v

    def _filesize(self, node: FileSize) -> tuple[Any, Fn]:
        return INT, lambda f: f.size

    def _entrypoint(self, node: EntryPoint) -> tuple[Any, Fn]:
        return INT, lambda f: None

    @staticmethod
    def fixed(value: Any) -> Fn:
        return lambda f: value


class _BuilderStrings(_BuilderValues):
    """Conditions over a string's matches: found, counted, placed, read."""

    def _hits(self, name: str) -> Callable[[Frame], list[tuple[int, int]]]:
        if name != "$":
            return lambda f: f.found[name]
        if not self.scope.strings_bound:
            raise RuleError(f"rule {self.scope.rule.name}: an undefined string $")
        slot = self.scope.strings_bound - 1
        return lambda f: f.found[f.env[slot]]

    def _span(self, span: tuple[Node, Node], what: str) -> tuple[Fn, Fn]:
        lo_kind, lo = self.node(span[0])
        hi_kind, hi = self.node(span[1])
        Builder.integer(lo_kind, what)
        Builder.integer(hi_kind, what)
        return lo, hi

    def _found(self, node: Found) -> tuple[Any, Fn]:
        hits = self._hits(node.string)
        if node.at is not None:
            at_kind, at = self.node(node.at)
            Builder.integer(at_kind, "'at'")

            def found_at(f: Frame) -> Any:
                where = at(f)
                if where is None:
                    return None
                return any(o == where for o, _ in hits(f))

            return BOOL, found_at
        if node.span is not None:
            lo, hi = self._span(node.span, "a range")

            def found_in(f: Frame) -> Any:
                a, b = lo(f), hi(f)
                if a is None or b is None:
                    return None
                return any(a <= o <= b for o, _ in hits(f))

            return BOOL, found_in
        return BOOL, lambda f: bool(hits(f))

    def _count(self, node: Count) -> tuple[Any, Fn]:
        hits = self._hits(node.string)
        if node.span is None:
            return INT, lambda f: len(hits(f))
        lo, hi = self._span(node.span, "a range")

        def count_in(f: Frame) -> Any:
            a, b = lo(f), hi(f)
            if a is None or b is None:
                return None
            return sum(1 for o, _ in hits(f) if a <= o <= b)

        return INT, count_in

    def _place(self, node: Place) -> tuple[Any, Fn]:
        hits = self._hits(node.string)
        nth_kind, nth = self.node(node.nth)
        Builder.scalar(nth_kind, "a match's index")  # any value: one not an integer is undefined
        part = 1 if node.length else 0

        def place(f: Frame) -> Any:
            i = nth(f)
            found = hits(f)
            if type(i) is not int or not 1 <= i <= len(found):
                return None
            return found[i - 1][part]

        return INT, place

    def _read(self, node: Read) -> tuple[Any, Fn]:
        at_kind, at = self.node(node.at)
        Builder.integer(at_kind, "a read")
        width, signed, big = node.width, node.signed, node.big

        def read(f: Frame) -> Any:
            where = at(f)
            if where is None or where < 0 or where + width > f.size:
                return None
            raw = f.data[where : where + width]
            return int.from_bytes(raw, "big" if big else "little", signed=signed)

        return INT, read


class _BuilderOperators(_BuilderStrings):
    """Arithmetic, comparison and boolean conditions."""

    def _arith(self, node: Arith) -> tuple[Any, Fn]:
        lk, left = self.node(node.left)
        rk, right = self.node(node.right)
        op = node.op
        a_kind, b_kind = Builder.scalar(lk, op), Builder.scalar(rk, op)
        if op in ("+", "-", "*", "\\"):
            if a_kind not in NUMBERS or b_kind not in NUMBERS:
                raise RuleError(
                    f"{op} on {Builder.describe(a_kind)} and {Builder.describe(b_kind)}"
                )
            kind = FLOAT if FLOAT in (a_kind, b_kind) else INT
        else:
            for k in (a_kind, b_kind):
                if k is not INT:
                    raise RuleError(f"wrong type {Builder.describe(k)} for {op}")
            kind = INT
        apply = Fold.op(op)
        known, value = self.constant(node)
        if known:
            return kind, lambda f: value

        def arith(f: Frame) -> Any:
            a = left(f)
            if a is None:
                return None
            b = right(f)
            if b is None:
                return None
            v = apply(a, b)
            return v if Fold.fits(op, v) else None

        return kind, arith

    def _minus(self, node: Minus) -> tuple[Any, Fn]:
        kind, fn = self.node(node.operand)
        if Builder.scalar(kind, "-") not in NUMBERS:
            raise RuleError(f"- on {Builder.describe(kind)}")
        known, value = self.constant(node)
        if known:
            return kind, lambda f: value

        def minus(f: Frame) -> Any:
            v = fn(f)
            if v is None:
                return None
            v = -v
            return None if type(v) is int and v > INT64_MAX else v

        return kind, minus

    def _invert(self, node: Invert) -> tuple[Any, Fn]:
        kind, fn = self.node(node.operand)
        if Builder.scalar(kind, "~") is not INT:
            raise RuleError(f"wrong type {Builder.describe(kind)} for ~")
        known, value = self.constant(node)
        if known:
            return INT, lambda f: value

        def invert(f: Frame) -> Any:
            v = fn(f)
            return None if v is None else ~v

        return INT, invert

    def _compare(self, node: Compare) -> tuple[Any, Fn]:
        lk, left = self.node(node.left)
        rk, right = self.node(node.right)
        op = node.op
        if isinstance(lk, Dual) or isinstance(rk, Dual):
            rule = self.scope.rule
            lk, left = Shapes.settle(rule, lk, left, Shapes.decide(lk, rk, node.right), node.left)
            rk, right = Shapes.settle(rule, rk, right, Shapes.decide(rk, lk, node.left), node.right)
        a_kind, b_kind = Builder.scalar(lk, op), Builder.scalar(rk, op)
        if op in Fold.TEXT_TESTS:
            for k in (a_kind, b_kind):
                if k is not TEXT:
                    raise RuleError(f"wrong type {Builder.describe(k)} for {op}")
            test = Fold.TEXT_TESTS[op]
        else:
            if (a_kind is TEXT) != (b_kind is TEXT):
                raise RuleError(f"{op} compares a string with a number")
            test = Fold.ORDER[op]

        def compare(f: Frame) -> Any:
            a = left(f)
            if a is None:
                return None
            b = right(f)
            if b is None:
                return None
            return test(a, b)

        return BOOL, compare

    def _matches(self, node: Matches) -> tuple[Any, Fn]:
        kind, fn = Shapes.settle(self.scope.rule, *self.node(node.subject), None, node.subject)
        if Builder.scalar(kind, "matches") is not TEXT:
            raise RuleError(f"matches needs a string, not {Builder.describe(kind)}")
        matcher, rule = node.matcher, self.scope.rule.name

        def matches(f: Frame) -> Any:
            v = fn(f)
            if v is None:
                return None
            from cordon_scanner.detect.binary.rule_engine.pattern import RunError

            try:
                return matcher.test(v)
            except RunError as exc:
                raise RuleError(f"rule {rule}: {exc}") from exc

        return BOOL, matches

    def _both(self, node: Both) -> tuple[Any, Fn]:
        lk, left = self.node(node.left)
        rk, right = self.node(node.right)
        Builder.as_test(lk, "a test")
        Builder.as_test(rk, "a test")
        a, b = Builder.truth(left), Builder.truth(right)
        return BOOL, lambda f: a(f) and b(f)

    def _either(self, node: Either) -> tuple[Any, Fn]:
        lk, left = self.node(node.left)
        rk, right = self.node(node.right)
        Builder.as_test(lk, "a test")
        Builder.as_test(rk, "a test")
        a, b = Builder.truth(left), Builder.truth(right)
        return BOOL, lambda f: a(f) or b(f)

    def _negate(self, node: Negate) -> tuple[Any, Fn]:
        kind, fn = self.node(node.operand)
        Builder.as_test(kind, "a test")

        def negate(f: Frame) -> Any:
            v = fn(f)
            return None if v is None else not v

        return BOOL, negate

    def _defined(self, node: Defined) -> tuple[Any, Fn]:
        kind, fn = Shapes.settle(self.scope.rule, *self.node(node.operand), None, node.operand)
        Builder.as_test(kind, "a test")
        return BOOL, lambda f: fn(f) is not None


class _BuilderQuantifiers(_BuilderOperators):
    """Quantified conditions: `N of`, a condition for each string, `for` loops and their domains."""

    # -- sets and quantities --

    def members(self, members: Members) -> list[str]:
        rule = self.scope.rule
        if members.names is None:
            return [s.name for s in rule.strings]
        out: list[str] = []
        known = [r.name for r in self.rules]
        for item in members.names:
            prefix = item[:-1] if item.endswith("*") else None
            if item.startswith("$"):
                out += [
                    s.name
                    for s in rule.strings
                    if (s.name.startswith(prefix) if prefix is not None else s.name == item)
                ]
            else:
                out += [
                    r for r in known if (r.startswith(prefix) if prefix is not None else r == item)
                ]
        return out

    def quantity(self, q: Quantity) -> Callable[[Frame, int, int], bool]:
        """Whether `count` of `total` meets the quantity. A quantity worked out from the file
        is taken as it is: a negative one is always met, a percentage over 100 never is."""
        if q.word == "any":
            return lambda f, count, total: count >= 1
        if q.word == "all":
            return lambda f, count, total: count == total
        if q.word == "none":
            return lambda f, count, total: count == 0
        assert q.amount is not None  # noqa: S101 - a quantity is a word or an amount
        kind, amount = self.node(q.amount)
        if q.amount.TEST:
            raise RuleError("a quantity is a value")
        Builder.integer(kind, "a quantity")
        if q.percent:

            def percent(f: Frame, count: int, total: int) -> bool:
                pct = amount(f)
                return pct is not None and total > 0 and count * 100 >= pct * total

            return percent

        def number(f: Frame, count: int, total: int) -> bool:
            n = amount(f)
            if n is None:
                return False
            return count == 0 if n == 0 else count >= n

        return number

    def _of(self, node: Of) -> tuple[Any, Fn]:
        names = self.members(node.members)
        meets = self.quantity(node.quantity)
        total = len(names)
        texts = [n for n in names if n.startswith("$")]
        rules = [n for n in names if not n.startswith("$")]
        if node.at is not None:
            at_kind, at = self.node(node.at)
            Builder.integer(at_kind, "'at'")

            def of_at(f: Frame) -> bool:
                where = at(f)
                if where is None:
                    return False
                count = sum(1 for n in texts if any(o == where for o, _ in f.found.get(n, ())))
                count += sum(1 for n in rules if f.decided.get(n, False))
                return meets(f, count, total)

            return BOOL, of_at
        if node.span is not None:
            lo, hi = self._span(node.span, "a range")

            def of_in(f: Frame) -> bool:
                a, b = lo(f), hi(f)
                if a is None or b is None:
                    return False
                count = sum(1 for n in texts if any(a <= o <= b for o, _ in f.found.get(n, ())))
                count += sum(1 for n in rules if f.decided.get(n, False))
                return meets(f, count, total)

            return BOOL, of_in

        def of(f: Frame) -> bool:
            found, decided = f.found, f.decided
            count = sum(1 for n in texts if found.get(n))
            count += sum(1 for n in rules if decided.get(n, False))
            return meets(f, count, total)

        return BOOL, of

    def _each_string(self, node: EachString) -> tuple[Any, Fn]:
        names = [n for n in self.members(node.members) if n.startswith("$")]
        meets = self.quantity(node.quantity)
        scope = self.scope
        outer = scope.strings_bound
        slot = scope.push("$", None)
        scope.strings_bound = slot + 1
        try:
            kind, body = self.node(node.body)
            Builder.as_test(kind, "a loop's body")
        finally:
            scope.strings_bound = outer
            scope.pop(1)
        test = Builder.truth(body)
        total = len(names)

        def each(f: Frame) -> bool:
            env = f.env
            count = 0
            for n in names:
                env[slot] = n
                if test(f):
                    count += 1
            return meets(f, count, total)

        return BOOL, each

    def _loop(self, node: Loop) -> tuple[Any, Fn]:
        meets = self.quantity(node.quantity)
        domain, kinds = self._domain(node)
        scope = self.scope
        slots = [scope.push(name, kind) for name, kind in zip(node.names, kinds, strict=True)]
        try:
            body_kind, body = self.node(node.body)
            Builder.as_test(body_kind, "a loop's body")
        finally:
            scope.pop(len(slots))
        test = Builder.truth(body)

        if len(slots) == 1:
            slot = slots[0]

            def loop(f: Frame) -> bool:
                values = domain(f)
                if values is None:
                    return False
                env = f.env
                count = 0
                for v in values:
                    env[slot] = v
                    if test(f):
                        count += 1
                return meets(f, count, len(values))

            return BOOL, loop

        key_slot, value_slot = slots

        def pairs(f: Frame) -> bool:
            values = domain(f)
            if values is None:
                return False
            env = f.env
            count = 0
            for k, v in values:
                env[key_slot], env[value_slot] = k, v
                if test(f):
                    count += 1
            return meets(f, count, len(values))

        return BOOL, pairs

    def _domain(self, node: Loop) -> tuple[Callable[[Frame], Any], list[Any]]:
        names, domain = node.names, node.domain
        if isinstance(domain, Span):
            if len(names) != 1:
                raise RuleError("a for loop over a range takes one variable")
            lo, hi = self._span((domain.lo, domain.hi), "a for range")

            def span(f: Frame) -> Any:
                a, b = lo(f), hi(f)
                # a range whose lower bound is above its upper when the rule runs is no domain:
                # the loop is false whatever its quantifier (`all`, `none`, `0`), as the
                # reference engines answer -- not an empty loop, which `all` would satisfy
                if a is None or b is None or a > b:
                    return None
                return range(a, b + 1)

            return span, [INT]
        if isinstance(domain, Listed):
            if len(names) != 1:
                raise RuleError("a for loop over a list takes one variable")
            built = [self.node(item) for item in domain.items]
            kinds = {Builder.scalar(k, "a for list") for k, _ in built}
            if len(kinds) != 1 or kinds - {INT, TEXT}:
                raise RuleError("a for list holds integers, or strings, not both")
            fns = [fn for _, fn in built]
            return (lambda f: [fn(f) for fn in fns]), [kinds.pop()]
        assert isinstance(domain, Over)  # noqa: S101 - the grammar gives only these three
        kind, source = self.node(domain.source)
        if isinstance(kind, Keyed):
            if len(names) != 2:
                raise RuleError("a for loop over a dictionary takes a key and a value")
            item = kind.item
            convert = Data.signed if item is INT else (lambda v: v)

            def keyed(f: Frame) -> Any:
                d = source(f)
                if d is None:
                    return None
                return [(k, convert(v)) for k, v in d.items()]

            return keyed, [TEXT, item]
        if isinstance(kind, Seq):
            if len(names) != 1:
                raise RuleError("a for loop over an array takes one variable")
            item = kind.item
            convert = Data.signed if item is INT else (lambda v: v)

            def seq(f: Frame) -> Any:
                d = source(f)
                if d is None:
                    return None
                return Elements(d, convert)

            return seq, [item]
        raise RuleError("a for loop iterates over a range, a list, an array or a dictionary")


class Builder(_BuilderQuantifiers):
    """Conditions built into closures for one rule set."""

    def __init__(
        self,
        rules: list[RuleDef],
        modules: dict[str, Module],
        externals: dict[str, Any],
    ) -> None:
        self.rules, self.modules, self.externals = rules, modules, externals
        self.scope: Scope = Scope(rules[0]) if rules else None  # type: ignore[assignment]
        self.before: set[str] = set()

    def build(self) -> None:
        """Every rule's `run` and `sets`, in order: a rule may name only rules before it."""
        for rule in self.rules:
            self.scope = Scope(rule)
            kind, fn = self.node(rule.condition)
            Builder.as_test(kind, "a condition")
            rule.run = Builder.truth(fn)
            rule.width = self.scope.width
            self.before.add(rule.name)

    def lazily(self) -> None:
        """Each rule built the first time it runs: for rules a pack cache kept, which were built
        once without error when they were kept. Most of a large pack's rules never run on a given
        file (their strings do not occur), so a load builds only what a scan needs."""
        names = [rule.name for rule in self.rules]
        for position, rule in enumerate(self.rules):
            rule.width = 0
            rule.run = self._built_on_first_run(rule, names, position)

    def _built_on_first_run(
        self, rule: RuleDef, names: list[str], position: int
    ) -> Callable[[Frame], bool]:
        def run(frame: Frame) -> bool:
            builder = Builder(self.rules, self.modules, self.externals)
            builder.before, builder.scope = set(names[:position]), Scope(rule)
            kind, fn = builder.node(rule.condition)
            Builder.as_test(kind, "a condition")
            rule.run, rule.width = Builder.truth(fn), builder.scope.width
            frame.env = [None] * rule.width
            return bool(rule.run(frame))

        return run

    # -- nodes --

    def node(self, node: Node) -> tuple[Any, Fn]:
        build = Builder.BUILDS.get(type(node))
        if build is None:
            raise RuleError(f"a condition of an unknown kind: {type(node).__name__}")
        result: tuple[Any, Fn] = build(self, node)
        return result

    def _external(self, node: External) -> tuple[Any, Fn]:
        v = self.externals[node.name]
        if isinstance(v, str):
            v = v.encode()
        kind = (
            BOOL
            if isinstance(v, bool)
            else TEXT
            if isinstance(v, bytes)
            else FLOAT
            if isinstance(v, float)
            else INT
        )
        return kind, lambda f: v

    def _name(self, node: Name) -> tuple[Any, Fn]:
        name = node.name
        if name in self.before:
            return BOOL, lambda f: f.decided.get(name, False)
        found = self.scope.lookup(name)
        if found is None:
            raise RuleError(f"an undefined identifier {name}")
        slot, kind = found
        return kind, lambda f: f.env[slot]

    def _path(self, node: Path) -> tuple[Any, Fn]:
        if node.module:
            kind: Any = self.modules[node.root].schema
            root = node.root
            fn: Fn = lambda f: f.module(root)  # noqa: E731
        else:
            if node.root in self.before:
                raise RuleError(f"{node.root} is a rule, not a structure")
            found = self.scope.lookup(node.root)
            if found is None:
                raise RuleError(f"an undefined identifier {node.root}")
            slot, kind = found
            fn = lambda f: f.env[slot]  # noqa: E731
        for step in node.steps:
            kind, fn = self._step(kind, fn, step)
        if isinstance(kind, Scalar) and kind is INT:
            inner = fn

            def signed(f: Frame) -> Any:
                return Data.signed(inner(f))

            return kind, signed
        if isinstance(kind, Scalar) and kind is FLOAT:
            inner_float = fn

            def number(f: Frame) -> Any:
                v = inner_float(f)
                return None if v is None or (type(v) is float and math.isnan(v)) else v

            return kind, number
        return kind, fn

    def _step(self, kind: Any, fn: Fn, step: Any) -> tuple[Any, Fn]:
        if isinstance(step, Field):
            if not isinstance(kind, Record):
                raise RuleError(f"{step.name} is not a field of {Builder.describe(kind)}")
            if step.name not in kind.fields:
                raise RuleError(f"an undefined identifier {step.name}")
            name = step.name

            def field(f: Frame) -> Any:
                d = fn(f)
                return None if d is None else d.get(name)

            return kind.fields[name], field
        if isinstance(step, Index):
            key_kind, key = self.node(step.key)
            if isinstance(kind, Seq):
                if key_kind not in (INT,):
                    raise RuleError("an array is indexed with an integer")
            elif isinstance(kind, Keyed):
                if key_kind is not TEXT:
                    raise RuleError("a dictionary is indexed with a string")
            else:
                raise RuleError(f"{Builder.describe(kind)} cannot be indexed")

            def index(f: Frame) -> Any:
                d = fn(f)
                if d is None:
                    return None
                k = key(f)
                return None if k is None else d.get(k)

            return kind.item, index
        assert isinstance(step, Invoke)  # noqa: S101 - the grammar gives only these three
        if not isinstance(kind, Call):
            raise RuleError("only a function can be called")
        built: list[Fn] = []
        kinds: list[str | None] = []
        duals: list[tuple[int, Any, Fn, Node]] = []
        for arg in step.args:
            if isinstance(arg, Pattern):
                matcher = arg.matcher
                kinds.append("regex")
                built.append(Builder.fixed(matcher))
                continue
            arg_kind, arg_fn = self.node(arg)  # a test is a boolean argument
            if isinstance(arg_kind, Dual):  # offered in its first shape, then its second
                duals.append((len(kinds), arg_kind, arg_fn, arg))
                kinds.append(arg_kind.first.name)
                built.append(arg_fn)
                continue
            kinds.append(Builder.scalar(arg_kind, "a function's argument").name)
            built.append(arg_fn)
        choice = kind.pick(tuple(kinds))
        if duals:
            other_kinds = list(kinds)
            for pos, dual, _fn, _arg in duals:
                other_kinds[pos] = dual.second.name
            other = kind.pick(tuple(other_kinds))
            if choice is None:
                choice = other
            elif other is not None and other != choice:
                for _pos, dual, _fn, arg in duals:
                    self.scope.rule.notes.append(
                        f"{Shapes.spell(arg)} has two shapes and the function takes either: "
                        f"passed as {dual.labels[0]}, not {dual.labels[1]}"
                    )
        if choice is None:
            raise RuleError(f"no function takes arguments of types {tuple(kinds)}")
        result = kind.sigs[choice].result
        for pos, dual, dual_fn, arg in duals:
            wanted = Builder.SCALARS.get(kind.sigs[choice].params[pos])
            shape = None if wanted is None else dual.index_of(wanted)
            settled: tuple[Any, Fn] = Shapes.settle(self.scope.rule, dual, dual_fn, shape, arg)
            built[pos] = settled[1]

        def invoke(f: Frame) -> Any:
            impls = fn(f)
            if impls is None:
                return None
            args = [a(f) for a in built]
            if any(a is None for a in args):
                return None
            return impls[choice](*args)

        return result, invoke

    BUILDS: ClassVar[dict[type, Callable[..., tuple[Any, Fn]]]] = {}
    SCALARS: ClassVar[dict[str, Scalar]] = {"int": INT, "float": FLOAT, "text": TEXT, "bool": BOOL}


Builder.BUILDS.update({
    Literal: Builder._literal, Truth: Builder._truth, FileSize: Builder._filesize,
    EntryPoint: Builder._entrypoint, External: Builder._external, Name: Builder._name,
    Path: Builder._path, Found: Builder._found, Count: Builder._count, Place: Builder._place,
    Read: Builder._read, Arith: Builder._arith, Minus: Builder._minus, Invert: Builder._invert,
    Compare: Builder._compare, Matches: Builder._matches, Both: Builder._both,
    Either: Builder._either, Negate: Builder._negate, Defined: Builder._defined, Of: Builder._of,
    EachString: Builder._each_string, Loop: Builder._loop,
})  # fmt: skip


__all__ = ["Builder", "Fold", "Frame", "Scope"]
