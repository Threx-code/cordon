"""What the regular-expression scaling checks share: every compiled pattern in detect/ and analysis/,
how its owner's code calls it, inputs built from its own structure, a static reading of its shape, and
the timing ladder that confirms or clears that reading.

The per-file budget is checked between detectors and cannot interrupt a running expression, so one
long line of the right shape in a file an attacker writes stalls the scan until the total timeout and
the scan ends incomplete: a way to keep malware unread (review 98, 27-PERFORMANCE, 5). Two tiers use
this kit. The unit suite reads every pattern's shape (`Shape`), which costs milliseconds; the prepush
performance step times every pattern whose shape is flagged (`Ladder`).
"""

from __future__ import annotations

import ast
import contextlib
import functools
import importlib
import inspect
import multiprocessing
import pkgutil
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from re import _parser as sre_parse  # type: ignore[attr-defined]
from typing import ClassVar

import cordon_scanner
import cordon_scanner.analysis
import cordon_scanner.detect

Node = tuple[object, object]
AnyPattern = re.Pattern[str] | re.Pattern[bytes]


@dataclass(frozen=True)
class Found:
    """One compiled pattern, where it is defined, and the modes its owner's code calls it in."""

    label: str
    pattern: AnyPattern
    modes: frozenset[str]
    called: bool


class Sources:
    """Every compiled pattern in detect/ and analysis/, with the modes its owner's code calls it in."""

    SRC = Path(cordon_scanner.__file__).parent
    SCANNING = frozenset({"search", "finditer", "findall", "sub", "subn", "split"})
    ANCHORED = frozenset({"match", "fullmatch"})

    @staticmethod
    @functools.cache
    def texts() -> dict[str, str]:
        out: dict[str, str] = {}
        for path in Sources.SRC.rglob("*.py"):
            parts = path.relative_to(Sources.SRC).with_suffix("").parts
            name = ".".join(parts[:-1] if parts[-1] == "__init__" else parts)
            out[name] = path.read_text(encoding="utf-8")
        return out

    @staticmethod
    @functools.cache
    def trees() -> dict[str, ast.Module]:
        return {name: ast.parse(text) for name, text in Sources.texts().items()}

    @staticmethod
    def calls(module: str, owner: str, name: str) -> set[str]:
        """The methods code calls on this pattern, read from the syntax tree (a docstring naming it is
        not a call): through its owner (a class, `self`, `cls`) in its own module or through the owner
        elsewhere, or bare in its own module or in a module that imports it by name."""
        wanted = Sources.SCANNING | Sources.ANCHORED
        found: set[str] = set()
        for other, tree in Sources.trees().items():
            here = other == module
            if not here:
                text = Sources.texts()[other]
                if name not in text or (owner and owner not in text):
                    continue
                if not owner and not any(
                    isinstance(node, ast.ImportFrom)
                    and node.module == f"cordon_scanner.{module}"
                    and any(alias.name == name for alias in node.names)
                    for node in ast.walk(tree)
                ):
                    continue
            holders = ({owner, "self", "cls"} if here else {owner}) if owner else set()
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                    continue
                if node.func.attr not in wanted:
                    continue
                target = node.func.value
                if (not owner and isinstance(target, ast.Name) and target.id == name) or (
                    owner
                    and isinstance(target, ast.Attribute)
                    and target.attr == name
                    and isinstance(target.value, ast.Name)
                    and target.value.id in holders
                ):
                    found.add(node.func.attr)
        return found

    @staticmethod
    def found(module: str, owner: str, name: str, pattern: AnyPattern) -> Found:
        label = f"{module}:{owner + '.' if owner else ''}{name}"
        used = Sources.calls(module, owner, name)
        modes = {"search" if m in Sources.SCANNING else m for m in used}
        # Never called by name (passed on, or kept as the specification of code that replaced it):
        # timed in every scanning mode.
        return Found(label, pattern, frozenset(modes or {"search"}), bool(used))

    @staticmethod
    def defines(text: str, name: str) -> bool:
        return re.search(rf"^{re.escape(name)}\s*(?::[^=\n]*)?=", text, re.M) is not None

    @staticmethod
    @functools.cache
    def patterns() -> tuple[Found, ...]:
        out: list[Found] = []
        for package in (cordon_scanner.detect, cordon_scanner.analysis):
            for info in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
                module = importlib.import_module(info.name)
                short = info.name.removeprefix("cordon_scanner.")
                text = Sources.texts().get(short, "")
                for name, value in vars(module).items():
                    if isinstance(value, re.Pattern) and Sources.defines(text, name):
                        out.append(Sources.found(short, "", name, value))
                for owner, cls in inspect.getmembers(module, inspect.isclass):
                    if cls.__module__ != info.name:
                        continue
                    for name, value in vars(cls).items():
                        if isinstance(value, re.Pattern):
                            out.append(Sources.found(short, owner, name, value))
        return tuple(out)

    @staticmethod
    def by_label() -> dict[str, Found]:
        return {found.label: found for found in Sources.patterns()}


class Parsed:
    """A pattern's parse tree, and which characters each of its nodes can take."""

    ALPHABET = (
        *(chr(c) for c in range(32, 127)),
        "\t",
        "\n",
        "\r",
        chr(0xA0),
        chr(0xE9),
        chr(0x2003),
    )
    REPEATS = frozenset({"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"})
    ATOMS = frozenset({"LITERAL", "NOT_LITERAL", "IN", "ANY", "CATEGORY"})
    MAXREPEAT = sre_parse.MAXREPEAT

    def __init__(self, pattern: AnyPattern) -> None:
        self.bytes = isinstance(pattern.pattern, bytes)
        source = pattern.pattern.decode("latin-1") if self.bytes else pattern.pattern
        self.tree = sre_parse.parse(source, pattern.flags)
        self.memo: dict[int, frozenset[str]] = {}

    def accepts(self, node: Node) -> list[str]:
        """The alphabet's characters this one atom matches."""
        try:
            single = re._compiler.compile(sre_parse.SubPattern(self.tree.state, [node]), 0)  # type: ignore[attr-defined]
        except (re.error, TypeError, ValueError, IndexError, KeyError, RecursionError):
            return list(Parsed.ALPHABET)
        if self.bytes:
            return [
                c for c in Parsed.ALPHABET if ord(c) < 256 and single.fullmatch(c.encode("latin-1"))
            ]
        return [c for c in Parsed.ALPHABET if single.fullmatch(c)]

    def chars(self, node: Node) -> frozenset[str]:
        """Every character this node can consume at any position."""
        key = id(node)
        if key not in self.memo:
            if str(node[0]) in Parsed.ATOMS:
                self.memo[key] = frozenset(self.accepts(node))
            else:
                out: set[str] = set()
                for child in Parsed.children(node):
                    out |= self.chars(child)
                self.memo[key] = frozenset(out)
        return self.memo[key]

    @staticmethod
    def children(node: Node) -> list[Node]:
        op, arg = node
        name = str(op)
        if name in Parsed.REPEATS:
            return list(arg[2])  # type: ignore[index]
        if name == "SUBPATTERN":
            return list(arg[-1])  # type: ignore[index]
        if name == "ATOMIC_GROUP":
            return list(arg)  # type: ignore[call-overload]
        if name == "BRANCH":
            return [item for branch in arg[1] for item in branch]  # type: ignore[index]
        return []

    @staticmethod
    def high(node: Node) -> int:
        return int(node[1][1]) if str(node[0]) in Parsed.REPEATS else 1  # type: ignore[index]

    def optional(self, node: Node) -> bool:
        op, arg = node
        name = str(op)
        if name in Parsed.REPEATS:
            return bool(arg[0] == 0)  # type: ignore[index]
        if name in ("AT", "ASSERT", "ASSERT_NOT"):
            return True
        if name == "SUBPATTERN":
            return all(self.optional(c) for c in arg[-1])  # type: ignore[index]
        if name == "BRANCH":
            return any(all(self.optional(c) for c in b) for b in arg[1])  # type: ignore[index]
        return False


class Shape:
    """Superlinear shapes read from a pattern's parse tree, without running it.

    1. Adjacent overlap (every mode): a non-possessive unbounded repeat, then -- through items that are
       optional or that it could take itself -- another repeat over characters it also takes. The
       text between them can be split every way: `[ \\t]*-?[ \\t]*`, `\\S+[^\\n]{0,80}`, `[^/]*?[-_]v?\\d+`.
    2. A re-read start (scanning modes): a path opens with items an unbounded repeat right after them
       also takes, and nothing stops a match from starting inside a run an earlier attempt read (`^`,
       a lookbehind, `\\b` before a word-only run): `[A-Za-z_]\\w*\\s*\\.`, `\\{[\\s\\S]*\\}`, `<[^>]{3,}>`.
    3. A long bounded repeat opening a match (scanning modes): every start can read that far, so it is
       linear but no cheaper on a line that long than a quadratic one: `[^\\n]{1,2000}?`.
    4. A lookahead that reads on, reached from a repeat that gives back: each character given back runs
       it again, `cd\\s+(?!.*\\.\\.)`.
    The check over-reads (a tail that cannot fail makes rule 1 harmless); the ladder decides those.
    """

    PATH_LIMIT = 4000
    LARGE = 1000
    WORD = frozenset(c for c in Parsed.ALPHABET if re.fullmatch(r"\w", c))

    def __init__(self, pattern: AnyPattern) -> None:
        self.parsed = Parsed(pattern)

    @staticmethod
    def of(pattern: AnyPattern, scanning: bool) -> list[str]:
        try:
            shape = Shape(pattern)
        except (re.error, RecursionError):
            return []
        found: list[str] = []
        shape.check(list(shape.parsed.tree), scanning, found, top=True)
        return found

    def paths(self, items: list[Node]) -> list[list[Node]]:
        """Every sequence of items through the pattern: groups opened, each branch one way."""
        out: list[list[Node]] = [[]]
        for node in items:
            op, arg = node
            name = str(op)
            if name == "SUBPATTERN":
                tails = self.paths(list(arg[-1]))  # type: ignore[index]
            elif name == "BRANCH":
                tails = [p for b in arg[1] for p in self.paths(list(b))]  # type: ignore[index]
            else:
                tails = [[node]]
            out = [p + t for p in out for t in tails][: Shape.PATH_LIMIT]
        return out

    def check(self, items: list[Node], scanning: bool, found: list[str], top: bool) -> None:
        for path in self.paths(items):
            self.adjacent(path, found)
            if top and scanning:
                self.start(path, found)
            for node in path:
                if str(node[0]) in Parsed.REPEATS or str(node[0]) == "ATOMIC_GROUP":
                    self.check(Parsed.children(node), scanning, found, top=False)
                elif str(node[0]) in ("ASSERT", "ASSERT_NOT"):
                    self.check(list(node[1][1]), False, found, top=False)  # type: ignore[index]

    def unbounded_inside(self, items: list[Node]) -> bool:
        for node in items:
            if str(node[0]) in Parsed.REPEATS and Parsed.high(node) == Parsed.MAXREPEAT:
                return True
            if self.unbounded_inside(Parsed.children(node)):
                return True
        return False

    def adjacent(self, path: list[Node], found: list[str]) -> None:
        parsed = self.parsed
        for i, node in enumerate(path):
            if (
                str(node[0]) not in ("MAX_REPEAT", "MIN_REPEAT")
                or Parsed.high(node) != Parsed.MAXREPEAT
            ):
                continue
            takes = parsed.chars(node)
            for later in path[i + 1 :]:
                name = str(later[0])
                if (
                    name in Parsed.REPEATS
                    and Parsed.high(later) > 1
                    and parsed.chars(later) & takes
                ):
                    found.append("rule 1: adjacent repeats over the same characters")
                    return
                if (
                    name in ("ASSERT", "ASSERT_NOT")
                    and later[1][0] == 1  # type: ignore[index]
                    and self.unbounded_inside(list(later[1][1]))  # type: ignore[index]
                ):
                    found.append(
                        "rule 4: a lookahead that reads on, after a repeat that gives back"
                    )
                    return
                if parsed.optional(later) or (
                    name in Parsed.ATOMS and parsed.chars(later) <= takes
                ):
                    continue
                break

    def start(self, path: list[Node], found: list[str]) -> None:
        if not path:
            return
        parsed = self.parsed
        first = path[0]
        if str(first[0]) == "AT" and str(first[1]) in (
            "AT_BEGINNING",
            "AT_BEGINNING_STRING",
            "AT_BEGINNING_LINE",
        ):
            return
        if str(first[0]) == "ASSERT_NOT" and first[1][0] == -1:  # type: ignore[index]
            return
        boundary = str(first[0]) == "AT" and str(first[1]) == "AT_BOUNDARY"
        before: set[str] = set()
        for node in path[1:] if boundary else path:
            name = str(node[0])
            high = Parsed.high(node)
            if name in Parsed.REPEATS and Shape.LARGE <= high < Parsed.MAXREPEAT:
                if not before or before <= parsed.chars(node):
                    found.append("rule 3: a long bounded repeat read from every start")
                return
            if name in Parsed.REPEATS and high == Parsed.MAXREPEAT:
                takes = parsed.chars(node)
                if (not before or before <= takes) and not (boundary and takes <= Shape.WORD):
                    found.append("rule 2: a match can start inside a run an earlier attempt read")
                return
            if name in Parsed.ATOMS or name in Parsed.REPEATS:
                before |= parsed.chars(node)
                continue
            return


class Inputs:
    """Adversarial inputs from a pattern's own structure, each a (prefix, repeated unit, suffix).

    The pattern is walked in order; the prefix is a sample of what it has matched so far. At each
    repeat, what the repeat takes is repeated, then followed by nothing, by a character nothing takes,
    or by one the repeat does not take: the shapes runs alone cannot reach, such as a dash, a word and
    blanks before a stray character for a lazy value before trailing blanks.
    """

    LIMIT = 240
    NEVER = "\x01"

    @staticmethod
    def literals(sequence: list[Node]) -> set[str]:
        out: set[str] = set()
        for op, arg in sequence:
            if str(op) == "LITERAL":
                out.add(chr(arg))  # type: ignore[arg-type]
            for child in arg if isinstance(arg, (list, tuple)) else ():
                if isinstance(child, sre_parse.SubPattern):
                    out |= Inputs.literals(list(child))
                elif isinstance(child, list):
                    for branch in child:
                        if isinstance(branch, sre_parse.SubPattern):
                            out |= Inputs.literals(list(branch))
        return out

    @staticmethod
    def shapes(pattern: AnyPattern) -> list[tuple[str, str, str]]:
        try:
            parsed = Parsed(pattern)
        except (re.error, RecursionError):
            return [("", c, "") for c in "a0 -/."]
        own = Inputs.literals(list(parsed.tree))
        shapes: list[tuple[str, str, str]] = []

        def favour(chars: list[str] | tuple[str, ...]) -> list[str]:
            return sorted(chars, key=lambda c: (c not in own, c != " ", c))

        def walk(sequence: list[Node], prefix: str) -> str:
            for node in sequence:
                op, arg = node
                name = str(op)
                if name in Parsed.REPEATS:
                    low, high, body = arg  # type: ignore[misc]
                    items = list(body)
                    if len(items) == 1 and str(items[0][0]) in Parsed.ATOMS:
                        takes = favour(parsed.accepts(items[0]))
                        # A blank too, when the repeat takes one: it is what a following `\s*` also
                        # takes, and the pattern's own letters are favoured ahead of it.
                        units = takes[:2] + [" "] * (" " in takes[2:])
                    else:
                        takes = []
                        units = [unit for unit in (walk(items, "")[:8],) if unit]
                    if high > 1:
                        other = next(
                            (c for c in favour(Parsed.ALPHABET) if c not in takes), Inputs.NEVER
                        )
                        for unit in units:
                            for suffix in ("", Inputs.NEVER, other):
                                shapes.append((prefix, unit, suffix))
                    prefix += (units[0] if units else "") * low
                elif name == "SUBPATTERN":
                    prefix = walk(list(arg[-1]), prefix)  # type: ignore[index]
                elif name == "ATOMIC_GROUP":
                    prefix = walk(list(arg), prefix)  # type: ignore[call-overload]
                elif name == "BRANCH":
                    ends = [walk(list(branch), prefix) for branch in arg[1]]  # type: ignore[index]
                    prefix = ends[0]
                elif name in Parsed.ATOMS:
                    prefix += (favour(parsed.accepts(node)) or [""])[0]
            return prefix

        with contextlib.suppress(RecursionError):
            walk(list(parsed.tree), "")
        pieces = favour(sorted(own | {" ", "a", "0"}))
        shapes += [("", c, "") for c in pieces[:12]]
        shapes += [("", a + b, "") for i, a in enumerate(pieces[:6]) for b in pieces[i + 1 : 6]]
        return list(dict.fromkeys(shapes))[: Inputs.LIMIT]

    @staticmethod
    def build(shape: tuple[str, str, str], n: int) -> str:
        prefix, unit, suffix = shape
        return prefix + unit * max(n // len(unit), 1) + suffix


class Growth:
    """Time a call at n and 4n against a linear reference timed in the same loop.

    A linear call grows as the reference does (1), a quadratic one four times as fast (4); above 2.5
    with the 4n run over 0.1 s of CPU is superlinear. (At n and 2n the two are 1 and 2, too close on a loaded
    machine: a known quadratic measured 1.5-2.2.) The reference is `[a-z]b` searched over "a" * n,
    which checks two characters at each position with no literal fast path; `a+b` is not linear (with
    no `b` it retries `a+` from every start) and as a reference it hid every quadratic pattern.
    """

    REFERENCE = re.compile(r"[a-z]b")
    REFERENCE_REPEAT = 500
    THRESHOLD = 2.5
    FLOOR = 0.1

    @staticmethod
    def best(call: Callable[[], object], times: int = 5) -> float:
        """The least CPU time of `times` calls. CPU time, not wall time: each check runs in its own
        forked child, so other work on a busy machine does not stretch it -- a wall-clock bound
        failed a prepush with a linear pattern at 0.80 s on 64,000 characters that takes 0.14 s of
        CPU (the lesson TestScale and the parser test learned too)."""
        least = float("inf")
        for _ in range(times):
            start = time.process_time()
            call()
            least = min(least, time.process_time() - start)
        return least

    @staticmethod
    def reference(n: int) -> float:
        text = "a" * n
        search = Growth.REFERENCE.search
        return Growth.best(lambda: [search(text) for _ in range(Growth.REFERENCE_REPEAT)])

    @staticmethod
    def of(
        run: Callable[[str | bytes], object], small: str | bytes, big: str | bytes
    ) -> tuple[float, float]:
        """(relative growth, seconds at 4n)."""
        first = Growth.best(functools.partial(run, small))
        second = Growth.best(functools.partial(run, big))
        base = Growth.reference(len(big)) / max(Growth.reference(len(small)), 1e-7)
        return (second / max(first, 1e-7)) / base, second


class Ladder:
    """Time a pattern in its callers' modes on its structure-built inputs.

    Each input is screened at 250, 1,000 and 4,000 characters; one that takes over 0.5 s, or grows
    more than 8x for 4x, is confirmed by `Growth` at a size where its 4n run takes about a quarter of a
    second. One that is fast in growth but over 0.01 s at 4,000 is timed once on 64,000 characters:
    a bounded repeat read from every start grows no faster than its input, so only a time on a long
    input can see it. Each pattern runs in a forked child under a time limit; a pattern that runs out
    of time is checked again one input at a time, each with its own limit, so a slow machine is not
    taken for a slow pattern.
    """

    SCREEN = (250, 1_000, 4_000)
    LONG = 64_000
    ABSOLUTE = 0.5
    PATTERN_LIMIT = 240.0
    SHAPE_LIMIT = 60.0

    @staticmethod
    def runner(pattern: AnyPattern, mode: str) -> Callable[[str | bytes], object]:
        return getattr(pattern, mode)  # type: ignore[no-any-return]

    @staticmethod
    def encoder(pattern: AnyPattern) -> Callable[[str], str | bytes]:
        if isinstance(pattern.pattern, bytes):
            return lambda s: s.encode("latin-1", "replace")
        return lambda s: s

    @staticmethod
    def one(pattern: AnyPattern, mode: str, shape: tuple[str, str, str]) -> str | None:
        """What is wrong with this input in this mode, or None."""
        run, encode = Ladder.runner(pattern, mode), Ladder.encoder(pattern)
        times: list[float] = []
        for n in Ladder.SCREEN:
            times.append(Growth.best(functools.partial(run, encode(Inputs.build(shape, n))), 1))
            if times[-1] > 0.5:
                break
        grew = len(times) > 1 and times[-1] > 0.002 and times[-1] / max(times[-2], 1e-7) > 8
        head = Inputs.build(shape, 4)[:24]
        if not (times[-1] > 0.5 or grew):
            if times[-1] > 0.01:
                large = Growth.best(
                    functools.partial(run, encode(Inputs.build(shape, Ladder.LONG))), 1
                )
                if large > Ladder.ABSOLUTE:
                    return f"slow: {large:.3f}s on {Ladder.LONG:,} characters, {mode}, {head!r}"
            return None
        size = Ladder.SCREEN[len(times) - 1]
        # Toward a 4n run of about a quarter of a second, stopping at a reversal: a superlinear call
        # can take under 0.015 s at one size and over 0.06 s at twice it, and bounce between them.
        direction = 0
        while True:
            took = Growth.best(functools.partial(run, encode(Inputs.build(shape, size))), 1)
            if took >= 0.06 and size > 100 and direction <= 0:
                size, direction = size // 2, -1
            elif took < 0.015 and size < Ladder.LONG and direction >= 0:
                size, direction = size * 2, 1
            else:
                break
        growth, seconds = Growth.of(
            run, encode(Inputs.build(shape, size)), encode(Inputs.build(shape, 4 * size))
        )
        if growth > Growth.THRESHOLD and seconds > Growth.FLOOR:
            return f"superlinear: growth {growth:.2f} at n={size}, {mode}, {head!r}"
        # A bounded repeat grows as a square only up to its bound and then as the input, so growth
        # measured across the bound can fall short; the time on one long input still tells.
        large = Growth.best(functools.partial(run, encode(Inputs.build(shape, Ladder.LONG))), 1)
        if large > Ladder.ABSOLUTE:
            return f"slow: {large:.3f}s on {Ladder.LONG:,} characters, {mode}, {head!r}"
        return None

    @staticmethod
    def verdict(pattern: AnyPattern, modes: frozenset[str]) -> str | None:
        for mode in sorted(modes):
            for shape in Inputs.shapes(pattern):
                found = Ladder.one(pattern, mode, shape)
                if found:
                    return found
        return None

    @staticmethod
    def _child(target: Callable[..., str | None], args: tuple[object, ...], out: object) -> None:
        try:
            out.put(("ok", target(*args)))  # type: ignore[attr-defined]
        except Exception as error:  # noqa: BLE001 - a child that fails says so; it is never waited on
            out.put(("error", f"{type(error).__name__}: {error}"))  # type: ignore[attr-defined]

    @staticmethod
    def limited(
        target: Callable[..., str | None], args: tuple[object, ...], limit: float
    ) -> tuple[str, str | None]:
        """("ok", result), ("error", why) or ("timeout", None), from a forked child."""
        context = multiprocessing.get_context("fork")
        out = context.Queue()
        child = context.Process(target=Ladder._child, args=(target, args, out))
        child.start()
        child.join(limit)
        if child.is_alive():
            child.kill()
            child.join()
            return "timeout", None
        if out.empty():
            return "error", f"the child exited {child.exitcode} without a result"
        status, result = out.get()
        return str(status), result

    @staticmethod
    def check(found: Found) -> str | None:
        """What is wrong with this pattern, or None; a whole-pattern timeout is checked input by input."""
        status, result = Ladder.limited(
            Ladder.verdict, (found.pattern, found.modes), Ladder.PATTERN_LIMIT
        )
        if status == "ok":
            return result
        if status == "error":
            return f"error: {result}"
        for mode in sorted(found.modes):
            for shape in Inputs.shapes(found.pattern):
                status, result = Ladder.limited(
                    Ladder.one, (found.pattern, mode, shape), Ladder.SHAPE_LIMIT
                )
                if status == "timeout":
                    return f"superlinear: one input did not finish in {Ladder.SHAPE_LIMIT:.0f} s, {mode}, {Inputs.build(shape, 4)[:24]!r}"
                if status == "ok" and result:
                    return result
        return None


class Listed:
    """The patterns the static check flags, each in one list; a pattern it flags that no list names
    fails the unit suite, and an entry the ladder contradicts fails the prepush."""

    #: Superlinear today and being rewritten, with who owns the fix; each fix removes its own line.
    OPEN: ClassVar[dict[str, str]] = {
        "detect.code.features:CodeFeatures._URL": "modelling team (measurement-only, every-literal proof)",
    }
    #: Kept as the specification of code that replaced them: superlinear, and called by nothing.
    SPECIFICATIONS: ClassVar[dict[str, str]] = {
        "detect.agents.mcp_servers.source:_SENTENCE": "McpServerSource.sentences",
        "detect.agents.skills:_DECODE_CALL": "SkillScripts.decode_calls",
        "detect.agents.language_model.review:VerdictParser._OBJECT": "VerdictParser.json_object",
        "detect.supply.provenance:_GITHUB_OWNER_REPO": "ProvenanceDetector._github_owner_repo",
    }
    #: Flagged by the static check, and linear by the ladder: what follows the overlap cannot fail, or
    #: the runs are bounded short.
    LINEAR: ClassVar[frozenset[str]] = frozenset(
        {
            "analysis.formats.documents:_RTF_CLASS",
            "analysis.go.go_eval:_ASSIGN",
            "analysis.go.go_eval:_HELPER",
            "analysis.go.go_eval:_TABLE",
            "analysis.javascript.flow.vocabulary:_URL",
            "analysis.javascript.front.lexer:Lexer.ASCII_NAME",
            "analysis.javascript.front.lexer:Lexer.LINE_REST",
            "analysis.javascript.front.lexer:Lexer.SPACE_RUN",
            "analysis.nix.nix_code:RUNS_BEFORE",
            "analysis.shared.deobfuscation:Layers._INVISIBLE_RUN",
            "analysis.shared.deobfuscation:ObfuscatorIo._ROTATION",
            "analysis.shared.render_diff:HiddenInstruction._DESTINATION",
            "analysis.shared.render_diff:RenderDiff._COMMENT",
            "detect.agents.ci_workflows:_BROAD_TOOLS",
            "detect.agents.instruction_files:_REMOTE_INSTRUCTIONS",
            "detect.agents.instruction_intent:_MARKDOWN_IMAGE",
            "detect.agents.instruction_intent:_SENTENCE_END",
            "detect.agents.instructions:_CODE_SPANS",
            "detect.agents.instructions:_DOWNLOAD_URL",
            "detect.agents.mcp_servers.declarations:_YAML_ITEM",
            "detect.agents.mcp_servers.declarations:_YAML_KEY",
            "detect.agents.mcp_servers.handlers:McpCode._INSTALL",
            "detect.agents.mcp_servers.source:ServerSources.NOT_A_SERVER_PATH",
            "detect.agents.mcp_servers.source:_ORDERS_A_REQUEST",
            "detect.agents.semantics:TRAILER",
            "detect.agents.skills:_DECODE_BUFFER",
            "detect.agents.skills:_DOTTED_RUN",
            "detect.agents.text_patterns:FETCH_EXEC",
            "detect.agents.text_patterns:ORDERS_A_COMMAND",
            "detect.binary.features:BinaryFeatures._ASCII",
            "detect.binary.features:BinaryFeatures._RUN",
            "detect.binary.features:BinaryFeatures._WIDE",
            "detect.binary.rule_engine.chain:Chain.RUNS",
            "detect.code.capability.labelling:Labelling.COURTESY_GATE",
            "detect.code.features:CodeFeatures._BASE64",
            "detect.code.features:CodeFeatures._HEX",
            "detect.code.features:CodeFeatures._SHELL_TOKEN",
            "detect.code.install_payload:InstallPayload._PATH_TOKEN",
            "detect.code.js_campaigns:JsCampaigns._AGENT_CONFIG_MEMBER",
            "detect.code.obfuscation.concealment:TAG_RUN",
            "detect.code.obfuscation.encoding:ESCAPE_RUN",
            "detect.code.obfuscation.text:ObfuscationText.NON_ASCII",
            "detect.code.secretflow:JavaScriptCommandFlow._HELPER",
            "detect.code.secretflow:JavaScriptFlow._BIND",
            "detect.code.secretflow:JavaScriptLeak._ALIAS",
            "detect.code.secretflow:JavaScriptLeak._NAME",
            "detect.code.store_flow:_ARGUMENT",
            "detect.code.store_flow:_IDENTIFIER",
            "detect.infra.ci_rules:UNTRUSTED_TRIGGER",
            "detect.infra.config_files:ConfigDetector._SHELL_KEY",
            "detect.infra.config_paths:VERIFIED_FETCH",
            "detect.secrets.values:URL_RUN",
            "detect.source.submodules:GitModules.ENTRY",
            "detect.supply.manifests.identity_findings:IdentityFindings._WINNING_VERSION",
            "detect.supply.manifests.scripts:FILE_OP_INSIDE",
        }
    )
