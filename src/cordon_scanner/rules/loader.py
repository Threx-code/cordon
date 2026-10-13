"""Rule pack loading, validation and compilation.

Detection rules are data, not code. They are authored in YAML, versioned
independently of the engine, and reviewable by a security team without reading
Python. That separation lets detection content ship on its own cadence and be
approved by the people qualified to approve it.

Two properties of this module carry most of its weight.

**Rules must prove they work at load time.** Detection rules fail silently by
nature: a path filter that stops matching, a pattern invalidated by a syntax
change, an escape mangled in a refactor. The rule matches nothing, the scan
still succeeds, and the gate looks green precisely because the check is broken.
So every rule ships with samples that must match and samples that must not, and
a pack whose rules cannot demonstrate this refuses to load.

**Patterns are validated before they can run.** Organisations author their own
rules, and a pattern with nested unbounded quantifiers turns any file into a
CPU-exhaustion vector. Validation happens at load rather than at match time,
because a pattern that can hang the scanner must never reach a worker.
"""

from __future__ import annotations

import functools
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.config import RestrictedYamlParser
from cordon_scanner.core.errors import RulePackError, UnsafePatternError
from cordon_scanner.core.literals import LiteralGate
from cordon_scanner.core.models import (
    Capability,
    Category,
    Confidence,
    MatchKind,
    RedactionMode,
    Rule,
    RuleProvenance,
    RuleTests,
    Severity,
)
from cordon_scanner.version import ENGINE_API_VERSION

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping

RULE_ID = re.compile(r"^[A-Z][A-Z0-9]{0,31}(?:\.[A-Z0-9_]{1,31}){1,7}$")
"""Rule identifiers are dotted, uppercase and hierarchical.

The shape is enforced because identifiers appear in suppressions, baselines,
SARIF output and policy files, all of which outlive the rule. A namespace makes
them greppable and lets a policy target a family.
"""

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")

_PACK_KEYS = frozenset({"id", "version", "license", "source", "requires_engine", "description"})

_ENGINE_REQUIREMENT = re.compile(r"(>=|<=|==|>|<)\s*(\d{1,9}(?:\.\d{1,9}){0,3})")
"""One comparator clause in a `requires_engine` string."""
_RULE_KEYS = frozenset(
    {
        "id",
        "version",
        "category",
        "severity",
        "confidence",
        "title",
        "message",
        "remediation",
        "match",
        "languages",
        "ecosystems",
        "paths",
        "evidence_policy",
        "capability",
        "provenance",
        "tests",
        "references",
        "enabled",
        "baseline_hits",
    }
)
_MATCH_KEYS = frozenset(
    {
        "kind",
        "pattern",
        "patterns",
        "literal",
        "literals",
        "scope",
        "proximity",
        "all",
        "any",
        "unless",
        "capability",
        "threshold",
        "window",
        "query",
        "field",
        "value",
        # `kind: ast`. See `RuleLoader._compile_ast`.
        "calls",
        "argument_matches",
        "argument_index",
        "argument_constructed",
    }
)


# ---------------------------------------------------------------------------
# Pattern safety
# ---------------------------------------------------------------------------

# `_RISKY_GROUP` and `_UNBOUNDED_INSIDE` lived here. They matched the *source
# text* of a pattern with another pattern, which is the approach
# `PatternCompiler._reject_unsafe` replaced with a walk over the parsed
# structure after one extra pair of parentheses was found to defeat them. They
# were dead, and they were themselves the alternation-inside-a-quantifier shape
# the validator refuses -- which is how the sweep over every engine pattern
# found them.

_MAXREPEAT = 4294967295
"""`re`'s sentinel for "no upper bound" on a repeat."""

_BACKREFERENCE = re.compile(r"\\[1-9]|\(\?P=")


UNIMPLEMENTED_KINDS: frozenset[MatchKind] = frozenset({MatchKind.STRUCTURAL, MatchKind.GRAPH})
"""Match kinds the vocabulary declares and no code implements.

Kept in `MatchKind` because they are the planned vocabulary and removing them
would make the roadmap unreadable, and refused at load because accepting one
produces a rule that cannot fire. Delete an entry here when its detector lands,
and the loader starts accepting it with no other change.
"""


class PatternCompiler:
    """Turns a rule's pattern text into something safe and fast to run.

    Two jobs that belong together because they read the same pattern and reach
    opposite conclusions about it: what makes a pattern dangerous to run, and
    what makes it cheap to skip.

    Both fail closed, in opposite directions. Validation rejects anything it
    cannot prove safe; prefilter extraction returns nothing whenever it is
    unsure. A wrong answer from the first is a hung scanner; a wrong answer from
    the second is a missed match -- the one error class this project treats as
    unacceptable.
    """

    # Beyond this many unbounded wildcards in one pattern, matching a
    # non-matching input becomes polynomial in the input length. Three is
    # generous for a detection rule; `a.*a.*a.*a.*a.*a.*a.*a.*b` needs eight and
    # is the shape that motivated the cap.
    MAX_UNBOUNDED_WILDCARDS = 3

    LARGE_REPEAT = 16
    """Above this, a bounded repeat is treated as unbounded for nesting.

    `(a{1,100}){1,100}` has no unbounded quantifier anywhere and backtracks
    exactly as catastrophically as `(a+)+`: the nesting test asked whether both
    levels were unbounded, and neither was, so it was accepted. It takes about a
    second on 24 bytes and nineteen on 28.

    Sixteen is chosen to sit above the repeats real rules use -- `{0,4}`,
    `{4,9}`, `{22,}` -- and far below where the product of two nested bounds
    becomes expensive.
    """

    MAX_NESTED_REPEAT_PRODUCT = 1000
    """Ceiling on the product of nested repeat bounds.

    Catches the shapes the flat threshold misses: `{1,20}` inside `{1,20}` is
    four hundred, fine; `{1,50}` inside `{1,50}` is two and a half thousand and
    is not.
    """

    @staticmethod
    def _parse(pattern: str, *, rule_id: str) -> Any:
        """Parse a pattern into `re`'s internal structure, or None.

        Uses a private module deliberately. There is no public API for this, the
        alternative is inspecting regex source with more regex, and that is the
        approach this replaced -- it was bypassed by one pair of parentheses.
        Returning None on any surprise keeps a future CPython change from
        turning a validation failure into an import error.
        """
        try:
            # The error code differs by platform and stub set, so both are
            # named: Linux CI reports import-not-found where macOS reports
            # import-untyped, and a single code fails on the other.
            import re._parser as parser  # type: ignore[import-not-found,import-untyped,unused-ignore]
        except ImportError:  # pragma: no cover - CPython < 3.11 layout
            try:
                import sre_parse as parser
            except ImportError:
                return None
        try:
            return parser.parse(pattern)
        except re.error:
            # An unparseable pattern is reported by the compile below, which
            # produces a better message than anything reconstructable here.
            return None
        except Exception:  # pragma: no cover - parser internals changed
            return None

    @staticmethod
    def _is_wildcard(sub: Any) -> bool:
        """Whether a repeat body is a `.`-style match-anything node.

        These are what make `a.*a.*a.*...b` polynomial: each one can start
        anywhere, so the engine tries every split of the input. A repeat over a
        narrow class cannot.
        """
        try:
            if len(sub) != 1:
                return False
            opcode, argument = sub[0]
        except (TypeError, ValueError):
            return False
        name = str(opcode)
        if name == "ANY":
            return True
        # A negated class over a single common separator -- `[^"]*`, `[^\s]*` --
        # is nearly as broad as `.` in practice.
        if name == "IN" and isinstance(argument, list) and argument:
            return str(argument[0][0]) == "NEGATE" and len(argument) <= 2
        return False

    @classmethod
    def _reject_unsafe(cls, parsed: Any, *, pattern: str, rule_id: str) -> None:
        """Refuse the shapes that backtrack catastrophically."""
        wildcards = 0

        def walk(node: Any, *, inside_unbounded: bool, outer_bound: int = 1) -> None:
            nonlocal wildcards
            for opcode, argument in node:
                name = str(opcode)

                if name == "GROUPREF" or name.startswith("GROUPREF"):
                    raise UnsafePatternError(
                        f"rule {rule_id}: pattern uses a backreference",
                        hint=(
                            "Backreferences force a backtracking engine. Detection "
                            "rules do not need them; restructure the pattern."
                        ),
                    )

                if name in {"MAX_REPEAT", "MIN_REPEAT"}:
                    _low, high, sub = argument
                    truly_unbounded = high >= _MAXREPEAT
                    # A large bounded repeat is unbounded for this purpose. The
                    # engine's backtracking does not care that the ceiling is
                    # written down, only how many ways the input can be split.
                    unbounded = truly_unbounded or high > cls.LARGE_REPEAT

                    bound = 1 if truly_unbounded else max(1, int(high))
                    product = outer_bound * bound
                    if outer_bound > 1 and product > cls.MAX_NESTED_REPEAT_PRODUCT:
                        raise UnsafePatternError(
                            f"rule {rule_id}: nested repeats multiply to {product}, "
                            f"over the {cls.MAX_NESTED_REPEAT_PRODUCT} allowed",
                            hint=(
                                "Bounded repeats nest just as badly as unbounded ones. "
                                "Flatten the pattern or lower the bounds."
                            ),
                        )

                    if truly_unbounded and cls._is_wildcard(sub):
                        # Only `.`-like repeats are counted. `\d+` and `\s+`
                        # are unbounded too, but they are anchored to a narrow
                        # character class and do not produce the polynomial
                        # blowup this cap exists for. Counting them rejected
                        # `\bnc\s+(?:-[a-z]+\s+){0,4}\S+\s+\d+`, a shipped
                        # rule that is entirely safe.
                        wildcards += 1
                    if inside_unbounded and unbounded:
                        # (a+)+ and every disguise of it, at any depth.
                        raise UnsafePatternError(
                            f"rule {rule_id}: pattern applies an unbounded quantifier to "
                            f"something that itself repeats without bound, which can "
                            f"backtrack catastrophically",
                            hint=(
                                "Shapes like (a+)+ and ((a+))+ let a crafted input "
                                "consume unbounded CPU. Rewrite so no unbounded "
                                "quantifier encloses another."
                            ),
                        )
                    walk(
                        sub,
                        inside_unbounded=inside_unbounded or unbounded,
                        outer_bound=product,
                    )
                    continue

                if name == "BRANCH":
                    _, branches = argument
                    if inside_unbounded:
                        # (a|aa)+ . Whether it actually backtracks depends on
                        # whether the branches can match the same text, which is
                        # undecidable in general, so it is refused
                        # conservatively: rejecting a safe pattern costs the
                        # author one rewrite, accepting an unsafe one costs every
                        # user of the pack a hung scan.
                        raise UnsafePatternError(
                            f"rule {rule_id}: pattern applies an unbounded quantifier to "
                            f"a group containing an alternation, which can backtrack "
                            f"catastrophically",
                            hint=("Rewrite so no unbounded quantifier encloses an alternation."),
                        )
                    for branch in branches:
                        walk(
                            branch,
                            inside_unbounded=inside_unbounded,
                            outer_bound=outer_bound,
                        )
                    continue

                if name == "SUBPATTERN":
                    walk(
                        argument[-1],
                        inside_unbounded=inside_unbounded,
                        outer_bound=outer_bound,
                    )
                    continue

                if name in {"ASSERT", "ASSERT_NOT"}:
                    # A lookahead is a group for backtracking purposes, and
                    # `(?=(a+))+` was accepted by the textual check for exactly
                    # this reason.
                    walk(argument[1], inside_unbounded=inside_unbounded)
                    continue

                if name == "ATOMIC_GROUP":
                    walk(argument, inside_unbounded=False)
                    continue

        walk(parsed, inside_unbounded=False)

        if wildcards > cls.MAX_UNBOUNDED_WILDCARDS:
            # No nesting, so no exponential blowup -- but `a.*a.*a.*...b`
            # is polynomial in the input length, which on a large file is the
            # same outcome by a slower route.
            raise UnsafePatternError(
                f"rule {rule_id}: pattern contains {wildcards} unbounded quantifiers, "
                f"more than the {cls.MAX_UNBOUNDED_WILDCARDS} allowed",
                hint=(
                    "Each unbounded wildcard multiplies the work done on a "
                    "non-matching line. Anchor the pattern or bound the repeats."
                ),
            )

    @classmethod
    def validate_pattern(cls, pattern: str, *, rule_id: str) -> re.Pattern[bytes]:
        """Compile a rule pattern, refusing anything that could hang the scanner.

        Rejected constructs and why:

        * **Nested unbounded quantifiers** (``(a+)+``, ``(a*)*``, ``(a|aa)+``). These
          are the classic catastrophic-backtracking shapes. A single crafted file
          turns one of these into an unbounded CPU burn on every worker that touches
          it.
        * **Backreferences**. They force a backtracking engine and are never needed
          for the kind of matching a detection rule does.

        This is the primary control, and it has to be, because there is no
        second one that works. Python's `re` cannot be interrupted mid-match:
        a single call holds the interpreter until it returns, so no timeout in
        this process can bound one pathological regex. An earlier version of
        this docstring named a per-file timeout as the backstop. That timeout
        was never implemented, and had it been, it could not have stopped the
        case it was named for.

        Analysis is structural rather than textual. The previous implementation
        matched the *source text* of the pattern with another regex, looking for
        a quantified group whose body contained no parentheses -- so one extra
        pair defeated it completely:

            (a+)+$      rejected
            ((a+))+$    accepted, and burns 90 seconds on 31 bytes of input

        Walking the parsed structure instead means nesting depth, lookahead
        wrappers and non-capturing groups cannot hide the shape.
        """
        parsed = cls._parse(pattern, rule_id=rule_id)
        if parsed is not None:
            cls._reject_unsafe(parsed, pattern=pattern, rule_id=rule_id)
        elif _BACKREFERENCE.search(pattern):
            # Only reachable if the parser internals move under us. The textual
            # check is kept as a floor rather than removed, because degrading to
            # "no validation at all" is the one outcome not worth risking.
            raise UnsafePatternError(
                f"rule {rule_id}: pattern uses a backreference",
                hint=(
                    "Backreferences force a backtracking engine. Detection rules do not "
                    "need them; restructure the pattern."
                ),
            )

        try:
            # Compiled against bytes: matching happens on raw file content so that
            # the ~99 percent of files with no match are never decoded at all.
            return re.compile(pattern.encode("utf-8"), re.MULTILINE)
        except re.error as exc:
            hint = None
            if "global flags" in str(exc):
                hint = (
                    "Inline global flags such as (?m) or (?i) cannot be used: a rule's "
                    "patterns are combined into one alternation, where a flag would "
                    "apply to all of them. MULTILINE is already enabled; use (?i:...) "
                    "for a scoped case-insensitive group."
                )
            raise UnsafePatternError(f"rule {rule_id}: invalid pattern: {exc}", hint=hint) from exc

    # ---------------------------------------------------------------------------
    # Compiled rule
    # ---------------------------------------------------------------------------

    @staticmethod
    def required_literals(
        pattern: str, shortest: int = 3, adjacent: bool = False, fold: bool = True
    ) -> tuple[bytes, ...]:
        """Lower-cased literals at least one of which every match of `pattern` contains, or ().

        Read from Python's own parse of the pattern (`re._parser`), so alternation groups and
        `(?i:...)` yield their literals:
        `\\b(?:xmrig|minerd|cgminer)\\b` requires one of the three names. The derivation is sound
        construct by construct:

            literal run          that string
            concatenation        the strongest requirement of any one element (a match has all)
            alternation          the union of every branch's requirement; one branch without -> none
            group, (?i:...)      the inner requirement
            repeat, min >= 1     the item's requirement; min 0 -> none (it can match without it)
            anything else        none

        Literals are lower-cased because a `(?i:...)` literal may appear in any case; callers test
        them against the file lower-cased, which over-admits a case-sensitive literal and never
        under-admits. Any literal under three bytes, or any failure to parse, gives (): the rule
        is then run on every file, as before.
        `shortest` lowers that floor for a pattern that has no three-byte literal: a weaker filter,
        but still a sound one.

        `adjacent` also reads what sits next to a literal run. A small character class or an
        alternation of plain strings is a finite set of strings, and a run of such sets is the set
        of their concatenations: `rm\\s+-(?:rf|fr)` requires `rm` followed by one whitespace byte,
        and `-rf` or `-fr`. A zero-width assertion (`\\b`, `^`) consumes nothing and does not break
        a run. A repeat of a set at least once contributes it once and ends the run, which resumes
        with the same set (its last repetition touches what follows). Sets beyond `PRODUCT_LIMIT`
        strings, and negated classes, break the run as before.

        `fold=False` gives the literals in their own case, for a test against the file as it
        is (`_extract_prefilter`). A `(?i:...)` group then requires nothing -- its literals
        match in any case, so no one spelling of them is required -- and a pattern that is
        case-insensitive as a whole gives ().
        """
        try:
            import importlib

            sre = importlib.import_module("re._constants")
            parser = importlib.import_module("re._parser")
            tree = parser.parse(pattern.encode("utf-8"))
        except Exception:  # any doubt means no prefilter, never a wrong one
            return ()
        ignorecase = sre.SRE_FLAG_IGNORECASE
        if not fold and tree.state.flags & ignorecase:
            return ()

        def any_case(av: Any) -> bool:
            """Whether a group's own flags make its literals match in any case."""
            return not fold and bool(av[1] & ignorecase)

        def sequence(items: Any) -> set[bytes] | None:
            candidates: list[set[bytes]] = []
            if adjacent:
                run_set: set[bytes] | None = None

                def close() -> None:
                    nonlocal run_set
                    if run_set:
                        candidates.append(run_set)
                    run_set = None

                def extend(piece: set[bytes]) -> None:
                    nonlocal run_set
                    if run_set is None:
                        run_set = set(piece)
                    elif len(run_set) * len(piece) <= RequiredLiterals.PRODUCT_LIMIT:
                        run_set = {a + b for a in run_set for b in piece}
                    else:
                        close()
                        run_set = set(piece)

                for op, av in items:
                    if op is sre.AT:
                        continue
                    piece = finite(op, av)
                    if piece is not None:
                        extend(piece)
                        continue
                    if op in (
                        sre.MAX_REPEAT,
                        sre.MIN_REPEAT,
                        getattr(sre, "POSSESSIVE_REPEAT", None),
                    ):
                        low, _, item = av
                        inner = finite_items(item) if low >= 1 else None
                        if inner is not None:
                            extend(inner)
                            close()
                            run_set = set(inner)
                            continue
                    close()
                    found = node(op, av)
                    if found is not None:
                        candidates.append(found)
                close()
            else:
                run = bytearray()
                for op, av in items:
                    if op is sre.LITERAL:
                        run.append(av)
                        continue
                    if run:
                        candidates.append({bytes(run)})
                        run = bytearray()
                    found = node(op, av)
                    if found is not None:
                        candidates.append(found)
                if run:
                    candidates.append({bytes(run)})
            usable = [c for c in candidates if c and min(len(x) for x in c) >= shortest]
            if not usable:
                return None
            return max(usable, key=lambda c: (min(len(x) for x in c), -len(c)))

        def finite(op: Any, av: Any) -> set[bytes] | None:
            """The exact strings one item can match, when there are few; else None."""
            if op is sre.LITERAL:
                return {bytes([av])}
            if op is sre.IN:
                chars: set[int] = set()
                for kind, value in av:
                    if kind is sre.LITERAL:
                        chars.add(value)
                    elif kind is sre.RANGE and value[1] - value[0] < RequiredLiterals.CLASS_LIMIT:
                        chars.update(range(value[0], value[1] + 1))
                    elif kind is sre.CATEGORY and value is sre.CATEGORY_SPACE:
                        chars.update(b" \t\n\r\x0b\x0c")
                    else:
                        return None
                if not chars or len(chars) > RequiredLiterals.CLASS_LIMIT:
                    return None
                return {bytes([c]) for c in chars}
            if op is sre.SUBPATTERN:
                return None if any_case(av) else finite_items(av[3])
            if op is sre.BRANCH:
                union: set[bytes] = set()
                for branch in av[1]:
                    found = finite_items(branch)
                    if found is None:
                        return None
                    union |= found
                return union if len(union) <= RequiredLiterals.PRODUCT_LIMIT else None
            return None

        def finite_items(items: Any) -> set[bytes] | None:
            """The exact strings a sequence can match, when every item is finite and few."""
            result: set[bytes] = {b""}
            for op, av in items:
                if op is sre.AT:
                    return None  # an assertion inside an alternative: keep it simple, no set
                piece = finite(op, av)
                if piece is None or len(result) * len(piece) > RequiredLiterals.PRODUCT_LIMIT:
                    return None
                result = {a + b for a in result for b in piece}
            return result

        def node(op: Any, av: Any) -> set[bytes] | None:
            if op is sre.SUBPATTERN:
                return None if any_case(av) else sequence(av[3])
            if op is sre.ATOMIC_GROUP:
                return sequence(av)
            if op is sre.BRANCH:
                union: set[bytes] = set()
                for branch in av[1]:
                    found = sequence(branch)
                    if found is None:
                        return None
                    union |= found
                return union
            if op in (sre.MAX_REPEAT, sre.MIN_REPEAT, getattr(sre, "POSSESSIVE_REPEAT", None)):
                low, _, item = av
                return sequence(item) if low >= 1 else None
            return None

        found = sequence(tree)
        if not found or min(len(x) for x in found) < shortest:
            return ()
        return tuple(sorted({x.lower() if fold else x for x in found}))

    @staticmethod
    def _extract_prefilter(pattern: bytes) -> tuple[bytes, ...]:
        """Literals for which at least one must be present for the rule to match.

        The single most effective performance measure in the engine. Running a cheap
        substring scan before any regex lets the large majority of files skip the
        expensive pass entirely, which is what turns O(files x rules) into something
        a commit-time hook can afford.

        For an alternation `A|B|C`, a match requires a literal from *some* branch, so
        the prefilter is the set of per-branch literals. It is only usable if every
        branch yields one: a single branch with no extractable literal means that
        branch could match a file the prefilter would have skipped, so the whole
        prefilter is discarded.

        Derived from Python's own parse of the pattern (`required_literals`, in the file's
        case), construct by construct. It was a hand-written scan of the pattern text, which
        read past a nested alternation: for a pattern ending in `(?:sys.exit|...|return)` it
        required `return`, and a file that exits by `sys.exit` was never shown to the rule.
        """
        return PatternCompiler.required_literals(pattern.decode("utf-8"), fold=False)

    # ---------------------------------------------------------------------------
    # Rule pack
    # ---------------------------------------------------------------------------


class RequiredLiterals:
    """Bounds for `PatternCompiler.required_literals(adjacent=True)`."""

    CLASS_LIMIT: ClassVar[int] = 8
    """A character class larger than this is not expanded into its characters."""
    PRODUCT_LIMIT: ClassVar[int] = 64
    """A run's set of strings is not grown beyond this many."""


@dataclass(frozen=True, slots=True)
class CompiledMatch:
    """A rule's matching strategy, resolved at load time."""

    kind: MatchKind
    regex: re.Pattern[bytes] | None = None
    literals: tuple[bytes, ...] = ()
    capability: Capability | None = None
    scope: str = "file"
    proximity: int = 0
    """How many lines may separate the capabilities a composite requires.

    Zero means the whole file, which is what every composite meant before
    this existed. That is right for a fifty-line install script and wrong
    for Node's Makefile, where a `curl -o` on line 1268 and a `$(shell
    uname)` on line 15 were read as one dropper. A composite is a claim
    that a file does one thing; a distance makes it a claim that one part
    of the file does it."""

    all_of: tuple[Any, ...] = ()
    any_of: tuple[Any, ...] = ()
    unless: tuple[Any, ...] = ()
    threshold: float = 0.0
    window: int = 0
    ast_query: Any = None
    """The compiled query for a `kind: ast` match. See `detect/astquery.py`.

    Typed loosely to keep this module free of a detector import at module
    scope: the loader knows how to build one, and the detector knows how to
    run it."""
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    prefilter: tuple[bytes, ...] = ()
    """Literals for which at least one must be present for this rule to match.

    Computed once at load time (see :func:`_extract_prefilter`). Empty means no
    prefilter is possible and the rule is evaluated against every candidate
    file."""
    prefilter_folded: tuple[bytes, ...] = ()
    """Lower-cased literals from `PatternCompiler.required_literals`, used only when `prefilter`
    is empty: one must appear in the file lower-cased. See `admits`."""

    branches: tuple[tuple[LiteralGate | None, LiteralGate | None], ...] = field(
        default=(), compare=False
    )
    """Per pattern, in order: two gates over the lower-cased file, each on lower-cased literals at
    least one of which every match of that pattern contains -- the required literals, then a
    sharper set tested only once the first passes. None is no condition; a pattern with neither
    always runs. See `regex_for`."""
    sources: tuple[str, ...] = field(default=(), compare=False, repr=False)
    """The patterns themselves, to compile the subset a file needs."""
    rule_id: str = field(default="", compare=False, repr=False)
    folds: bool = field(default=False, compare=False)
    """Whether any branch has a gate, which reads the lower-cased file."""
    subsets: dict[tuple[int, ...], re.Pattern[bytes]] = field(
        default_factory=dict, compare=False, repr=False
    )
    """Compiled alternations of the patterns a file can match, keyed by their positions."""

    SUBSETS_KEPT: ClassVar[int] = 256

    def regex_for(self, data: bytes, folded: bytes | None = None) -> re.Pattern[bytes] | None:
        """The regex that finds exactly this rule's matches in `data`, cheapest first; None when
        nothing can match.

        Only the patterns that can match somewhere in `data` run. A pattern whose every match
        contains one of its literals cannot match a file holding none of them, and an alternation
        tries its branches in order at each position: a branch that cannot match anywhere changes
        neither which branch matches there nor where scanning resumes. So the alternation of the
        remaining patterns, in their order, finds the same matches in the same order -- and the
        engine stops trying seventeen branches at every byte of a file where one of them had a
        literal present. Callers read only a match's span and text, never its group numbers.
        """
        if not self.branches:
            return self.regex if self.admits(data, folded) else None
        # Without gates nothing reads it, so the file is not lowered for nothing.
        lowered = folded if folded is not None else (data.lower() if self.folds else data)
        chosen: list[int] = []
        for position, (required, sharper) in enumerate(self.branches):
            if required is not None and not required.present(lowered):
                continue
            if sharper is not None and not sharper.present(lowered):
                continue
            chosen.append(position)
        if not chosen:
            return None
        if len(chosen) == len(self.branches):
            return self.regex
        key = tuple(chosen)
        found: re.Pattern[bytes] | None = self.subsets.get(key)
        if found is None:
            found = self._subset(key)
            if found is not None and len(self.subsets) < self.SUBSETS_KEPT:
                self.subsets[key] = found
        return found

    def _subset(self, positions: tuple[int, ...]) -> re.Pattern[bytes] | None:
        """The alternation of the patterns at `positions`, compiled as the whole rule was; the
        whole rule's regex if that cannot be done identically."""
        try:
            subset = PatternCompiler.validate_pattern(
                "|".join(f"(?:{self.sources[i]})" for i in positions), rule_id=self.rule_id
            )
        except (re.error, RulePackError, UnsafePatternError):
            return self.regex
        if self.regex is None or subset.flags != self.regex.flags:
            return self.regex
        return subset

    def admits(self, data: bytes, folded: bytes | None = None) -> bool:
        """Whether this rule could match `data` at all; False means its regex need not run.

        `folded` is `data.lower()`, passed by a caller that tests many rules against one file so
        it is computed once; computed here otherwise.
        """
        if self.prefilter:
            return any(literal in data for literal in self.prefilter)
        if self.prefilter_folded:
            lowered = data.lower() if folded is None else folded
            return any(literal in lowered for literal in self.prefilter_folded)
        return True


@dataclass(frozen=True, slots=True)
class CompiledRule:
    """A rule plus its resolved matching strategy."""

    rule: Rule
    match: CompiledMatch

    @property
    def id(self) -> str:
        return self.rule.id


@dataclass(frozen=True, slots=True)
class RulePack:
    """A named, versioned collection of rules."""

    id: str
    version: str
    license: str
    rules: tuple[CompiledRule, ...]
    source: str = ""
    description: str = ""
    content_hash: str = ""

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self) -> Iterator[CompiledRule]:
        return iter(self.rules)


class RuleLoader:
    """Loads and validates rule packs.

    Validation is strict and happens entirely at load time. A malformed rule is a
    configuration error the author sees immediately, never a rule that silently
    does nothing in production.
    """

    def __init__(self, *, require_tests: bool = True, strict_baseline: bool = True) -> None:
        self.require_tests = require_tests
        """A pack whose rules carry no samples fails to load. Disabled only for
        the loader's own unit tests."""

        self.strict_baseline = strict_baseline
        """A rule may not declare confidence: high if it has a recorded non-zero
        baseline against the benign corpus. This turns false-positive discipline
        from a review-time opinion into a load-time invariant."""

    def load_file(self, path: str | Path) -> RulePack:
        p = Path(path)
        if not p.is_file():
            raise RulePackError(f"rule pack not found: {p}")
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise RulePackError(f"cannot read rule pack {p}: {exc}") from exc
        return self.load_text(text, source=str(p))

    def load_text(self, text: str, *, source: str = "<string>") -> RulePack:
        data = RestrictedYamlParser._load_yaml_subset(text, source=source)
        pack = self._parse_pack_header(data, source=source)
        rules = self._parse_rules(data, pack_id=pack["id"], source=source)

        return RulePack(
            id=pack["id"],
            version=pack["version"],
            license=pack["license"],
            source=pack.get("source", ""),
            description=pack.get("description", ""),
            rules=tuple(rules),
            content_hash=hashlib.sha256(text.encode("utf-8")).hexdigest()[:16],
        )

    def load_dir(self, directory: str | Path) -> tuple[RulePack, ...]:
        d = Path(directory)
        if not d.is_dir():
            raise RulePackError(f"rule directory not found: {d}")
        # Sorted so that load order, and therefore any ordering-dependent
        # behaviour, is reproducible.
        return tuple(self.load_file(p) for p in sorted(d.glob("*.yaml")))

    # -- Parsing -------------------------------------------------------

    def _parse_pack_header(self, data: Mapping[str, Any], *, source: str) -> dict[str, Any]:
        pack = data.get("pack")
        if not isinstance(pack, dict):
            raise RulePackError(f"{source}: missing required `pack` header")

        unknown = set(pack) - _PACK_KEYS
        if unknown:
            raise RulePackError(f"{source}: unknown pack key(s): {', '.join(sorted(unknown))}")

        for required in ("id", "version", "license"):
            if not pack.get(required):
                raise RulePackError(
                    f"{source}: pack.{required} is required",
                    hint=(
                        "Every pack declares its own licence and source so that rule "
                        "data with incompatible terms is never silently bundled into "
                        "an Apache-2.0 distribution."
                        if required == "license"
                        else None
                    ),
                )

        if not SEMVER.match(str(pack["version"])):
            raise RulePackError(
                f"{source}: pack.version must be semantic (x.y.z), got {pack['version']!r}"
            )

        requirement = pack.get("requires_engine")
        if requirement:
            RuleLoader._check_engine_requirement(str(requirement), source=source)

        return {k: str(v) for k, v in pack.items()}

    @staticmethod
    def _check_engine_requirement(requirement: str, *, source: str) -> None:
        """Refuse a pack this engine does not satisfy.

        version.py promises exactly this: "the loader refuses a pack whose
        requirement this engine does not satisfy rather than loading it and
        silently skipping the rules it cannot compile". The key was accepted and
        discarded, so a pack declaring `requires_engine: ">=99.0"` loaded and
        ran -- and the rules it contained that this engine cannot express were
        skipped without a word, which is the outcome the promise names.

        A deliberately small comparator set: `>=`, `>`, `<=`, `<`, `==`, joined
        by commas. Anything else is refused rather than guessed at, because a
        misread requirement silently runs a pack that was not meant for this
        engine.
        """
        engine = tuple(int(part) for part in ENGINE_API_VERSION.split("."))

        for clause in (c.strip() for c in requirement.split(",")):
            if not clause:
                continue
            match = _ENGINE_REQUIREMENT.fullmatch(clause)
            if match is None:
                raise RulePackError(
                    f"{source}: pack.requires_engine clause {clause!r} is not understood",
                    hint="Use comparators >=, >, <=, <, ==, joined by commas.",
                )
            operator, wanted_text = match.group(1), match.group(2)
            wanted = tuple(int(part) for part in wanted_text.split("."))
            width = max(len(engine), len(wanted))
            left = engine + (0,) * (width - len(engine))
            right = wanted + (0,) * (width - len(wanted))

            satisfied = {
                ">=": left >= right,
                ">": left > right,
                "<=": left <= right,
                "<": left < right,
                "==": left == right,
            }[operator]
            if not satisfied:
                raise RulePackError(
                    f"{source}: pack requires engine {requirement!r}, "
                    f"but this engine is {ENGINE_API_VERSION}",
                    hint=(
                        "Upgrade cordon, or use a pack built for this engine. Loading "
                        "it anyway would silently skip the rules it cannot compile."
                    ),
                )

    def _parse_rules(
        self, data: Mapping[str, Any], *, pack_id: str, source: str
    ) -> list[CompiledRule]:
        raw_rules = data.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise RulePackError(f"{source}: `rules` must be a non-empty list")

        seen: set[str] = set()
        out: list[CompiledRule] = []

        for index, raw in enumerate(raw_rules):
            where = f"{source}: rules[{index}]"
            if not isinstance(raw, dict):
                raise RulePackError(f"{where} must be a mapping")

            unknown = set(raw) - _RULE_KEYS
            if unknown:
                raise RulePackError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")

            rule_id = str(raw.get("id", ""))
            if not RULE_ID.match(rule_id):
                raise RulePackError(
                    f"{where}: invalid rule id {rule_id!r}",
                    hint=(
                        "Rule ids are dotted and uppercase, for example "
                        "MALWARE.EXFIL.001. They appear in suppressions, baselines "
                        "and SARIF output, all of which outlive the rule."
                    ),
                )
            if rule_id in seen:
                raise RulePackError(f"{where}: duplicate rule id {rule_id!r}")
            seen.add(rule_id)

            out.append(self._parse_rule(raw, rule_id=rule_id, pack_id=pack_id, where=where))

        return out

    def _parse_rule(
        self, raw: Mapping[str, Any], *, rule_id: str, pack_id: str, where: str
    ) -> CompiledRule:
        for required in ("category", "severity", "confidence", "title", "message", "match"):
            if required not in raw:
                raise RulePackError(f"{where}: `{required}` is required")

        try:
            category = Category(str(raw["category"]))
            severity = Severity.parse(raw["severity"])
            confidence = Confidence.parse(raw["confidence"])
        except ValueError as exc:
            raise RulePackError(f"{where}: {exc}") from exc

        provenance = self._parse_provenance(raw.get("provenance"), where=where)

        # Provenance is mandatory for malicious rules. A rule asserting evidence
        # of intent to harm must record where that assertion came from, because
        # it is the class of rule most likely to be challenged and the class
        # whose removal matters most.
        if category is Category.MALICIOUS and provenance is None:
            raise RulePackError(
                f"{where}: rules with category `malicious` must declare provenance",
                hint=(
                    "Record where the rule came from: kind is one of incident, "
                    "research, advisory, community or synthetic. Incident-derived "
                    "rules become protected against silent removal."
                ),
            )

        tests = self._parse_tests(raw.get("tests"), where=where)

        # Inline samples are only meaningful for kinds that match text directly.
        # A composite rule's input is other findings, and a graph rule's input is
        # a dependency tree; neither can be expressed as a string, so demanding
        # one would only produce placeholder samples that assert nothing. Those
        # kinds are covered by the corpus suite instead, and a separate test
        # asserts that every one of them has a corpus sample.
        inline_testable = str((raw.get("match") or {}).get("kind", "regex")) in {
            "regex",
            "literal",
            "entropy",
            # An `ast` rule's input is a source snippet, which is a string. It
            # is held to the same standard for a sharper reason than the others:
            # the whole claim of the kind is that it sees through a refactor, and
            # a sample is how that claim is checked rather than asserted.
            "ast",
        }
        if self.require_tests and inline_testable and (not tests.positive or not tests.negative):
            raise RulePackError(
                f"{where}: every text-matching rule must declare at least one positive "
                f"and one negative test sample",
                hint=(
                    "Detection rules fail silently: a broken pattern matches nothing, "
                    "the scan still succeeds, and the gate looks green precisely "
                    "because the check is broken. Samples make that impossible."
                ),
            )

        baseline_hits = int(raw.get("baseline_hits", 0))
        # Capability primitives are exempt, and must be. A primitive is a label,
        # not a finding: it never reaches a report on its own, only a composite
        # built from several of them does. Benign code decodes, spawns and makes
        # network calls constantly, so a primitive that matched no benign file
        # would be a primitive that does not work. Requiring a zero baseline of
        # them would either be always violated or force every primitive down to
        # `confidence: medium`, which says nothing about the composite.
        #
        # The invariant applies where it means something: a rule that can
        # produce a finding.
        surfaces = raw.get("capability") is None
        if (
            self.strict_baseline
            and surfaces
            and baseline_hits > 0
            and confidence >= Confidence.HIGH
        ):
            raise RulePackError(
                f"{where}: confidence `{confidence}` requires a zero baseline, but "
                f"{baseline_hits} match(es) were recorded against the benign corpus",
                hint=(
                    "Either narrow the rule until it stops matching benign code, or "
                    "declare confidence: medium and let correlation raise it."
                ),
            )

        paths = raw.get("paths") or {}
        if not isinstance(paths, dict):
            raise RulePackError(f"{where}: `paths` must be a mapping with include/exclude")
        RuleLoader._validate_globs(paths, where=where)

        evidence_raw = str(raw.get("evidence_policy", "masked"))
        try:
            evidence_policy = RedactionMode(evidence_raw)
        except ValueError:
            raise RulePackError(
                f"{where}: evidence_policy must be one of: "
                f"{', '.join(m.value for m in RedactionMode)}"
            ) from None

        capability = None
        if raw.get("capability"):
            try:
                capability = Capability(str(raw["capability"]))
            except ValueError:
                raise RulePackError(
                    f"{where}: unknown capability {raw['capability']!r}; expected one of: "
                    f"{', '.join(c.value for c in Capability)}"
                ) from None

        compiled_match = self._compile_match(raw["match"], rule_id, where)

        rule = Rule(
            id=rule_id,
            category=category,
            severity=severity,
            confidence=confidence,
            title=str(raw["title"]),
            message=RuleLoader._clean(str(raw["message"])),
            remediation=RuleLoader._clean(str(raw.get("remediation", ""))),
            match_kind=compiled_match.kind,
            version=str(raw.get("version", "1.0.0")),
            rulepack=pack_id,
            languages=RuleLoader._str_tuple(raw.get("languages")),
            ecosystems=RuleLoader._str_tuple(raw.get("ecosystems")),
            paths_include=RuleLoader._str_tuple(paths.get("include")),
            paths_exclude=RuleLoader._str_tuple(paths.get("exclude")),
            evidence_policy=evidence_policy,
            capability=capability,
            provenance=provenance,
            tests=tests,
            references=RuleLoader._str_tuple(raw.get("references")),
            enabled=bool(raw.get("enabled", True)),
            baseline_hits=baseline_hits,
            raw=dict(raw),
        )

        return CompiledRule(rule=rule, match=compiled_match)

    def _compile_match(self, raw: Any, rule_id: str, where: str) -> CompiledMatch:
        if not isinstance(raw, dict):
            raise RulePackError(f"{where}: `match` must be a mapping")

        unknown = set(raw) - _MATCH_KEYS
        if unknown:
            raise RulePackError(f"{where}: unknown match key(s): {', '.join(sorted(unknown))}")

        try:
            kind = MatchKind(str(raw.get("kind", "regex")))
        except ValueError:
            raise RulePackError(
                f"{where}: unknown match kind {raw.get('kind')!r}; expected one of: "
                f"{', '.join(k.value for k in MatchKind)}"
            ) from None

        if kind is MatchKind.REGEX:
            patterns = RuleLoader._str_tuple(raw.get("patterns")) or (
                (str(raw["pattern"]),) if raw.get("pattern") else ()
            )
            if not patterns:
                raise RulePackError(f"{where}: regex match requires `pattern` or `patterns`")
            # Multiple patterns become one alternation, compiled once. Matching
            # cost is then independent of how many alternatives a rule declares.
            combined = "|".join(f"(?:{p})" for p in patterns)
            regex = PatternCompiler.validate_pattern(combined, rule_id=rule_id)
            # Extract from the individual patterns rather than the combined one:
            # wrapping each in (?:...) puts every literal inside a group, where
            # the conservative walker will not read it.
            prefilter: tuple[bytes, ...] = ()
            per_pattern = [PatternCompiler._extract_prefilter(p.encode("utf-8")) for p in patterns]
            if all(per_pattern):
                prefilter = tuple(sorted({lit for group in per_pattern for lit in group}))
            # Where the scanner above found none, the parsed derivation may: every pattern must
            # yield a requirement, or the rule keeps no prefilter at all.
            folded: tuple[bytes, ...] = ()
            required = [PatternCompiler.required_literals(p) for p in patterns]
            if not prefilter and all(required):
                folded = tuple(sorted({lit for group in required for lit in group}))
            # And per pattern, for `regex_for`: its required literals, lower-cased, else two-byte
            # ones, else none (always run). Tested against the lower-cased file, which the per-
            # pattern gates share; the exact-case prefilter above is the same derivation.
            branches: list[tuple[LiteralGate | None, LiteralGate | None]] = []
            for pattern, needed in zip(patterns, required, strict=True):
                coarse = needed or PatternCompiler.required_literals(pattern, shortest=2)
                # And a second, sharper gate where the adjacent-set derivation finds longer
                # literals: `rm\\s+-rf` also needs whitespace then `-rf`, not only `rm`, which half
                # of all English prose contains. Tested only once the coarse gate passes, so a
                # file without `rm` pays for one substring search, not twelve.
                sharper = PatternCompiler.required_literals(pattern, shortest=3, adjacent=True)
                if not (sharper and (not coarse or min(map(len, sharper)) > min(map(len, coarse)))):
                    sharper = ()
                branches.append(
                    (
                        LiteralGate(coarse) if coarse else None,
                        LiteralGate(sharper) if sharper else None,
                    )
                )
            return CompiledMatch(
                kind=kind,
                regex=regex,
                prefilter=prefilter,
                prefilter_folded=folded,
                branches=tuple(branches),
                sources=tuple(patterns),
                rule_id=rule_id,
                folds=any(gate is not None for pair in branches for gate in pair),
                raw=dict(raw),
            )

        if kind is MatchKind.LITERAL:
            literals = RuleLoader._str_tuple(raw.get("literals")) or (
                (str(raw["literal"]),) if raw.get("literal") else ()
            )
            if not literals:
                raise RulePackError(f"{where}: literal match requires `literal` or `literals`")
            encoded = tuple(s.encode("utf-8") for s in literals)
            return CompiledMatch(kind=kind, literals=encoded, prefilter=encoded, raw=dict(raw))

        if kind is MatchKind.ENTROPY:
            return CompiledMatch(
                kind=kind,
                threshold=float(raw.get("threshold", 4.5)),
                window=int(raw.get("window", 64)),
                raw=dict(raw),
            )

        if kind is MatchKind.COMPOSITE:
            scope = str(raw.get("scope", "file"))
            if scope not in {"file", "package", "repository", "function"}:
                raise RulePackError(f"{where}: unknown composite scope {scope!r}")
            if not raw.get("all") and not raw.get("any"):
                raise RulePackError(f"{where}: composite match requires `all` or `any`")
            proximity = int(raw.get("proximity", 0))
            if proximity < 0:
                raise RulePackError(f"{where}: proximity must not be negative")
            return CompiledMatch(
                kind=kind,
                scope=scope,
                proximity=proximity,
                all_of=tuple(raw.get("all") or ()),
                any_of=tuple(raw.get("any") or ()),
                unless=tuple(raw.get("unless") or ()),
                raw=dict(raw),
            )

        if kind is MatchKind.AST:
            return RuleLoader._compile_ast(raw, where=where)

        # `structural` and `graph` are declared in `MatchKind` and
        # implemented by nothing. The comment here used to say they were
        # "resolved by their detectors, which own the query language for their
        # layer", and no detector consumes any of them.
        #
        # So a pack author could write `kind: ast`, have it accepted without a
        # word, and ship a rule that can never match anything. A rule that
        # silently never fires is the rule-level form of the failure this whole
        # project is built to prevent: it looks exactly like a rule that found
        # nothing. Refused until something implements them -- an error naming
        # the reason costs an author a minute, and a silent no-op costs them
        # whatever the rule was written to catch.
        if kind in UNIMPLEMENTED_KINDS:
            raise RulePackError(
                f"{where}: match kind {kind.value!r} is declared but not implemented, "
                f"so a rule using it could never match. Implemented kinds: "
                f"{', '.join(sorted(k.value for k in MatchKind if k not in UNIMPLEMENTED_KINDS))}."
            )

        return CompiledMatch(kind=kind, raw=dict(raw))

    @staticmethod
    def _compile_ast(raw: Mapping[str, Any], *, where: str) -> CompiledMatch:
        """Compile `kind: ast` into a query `detect/astquery.py` can run.

        Validated as strictly as every other kind, and for the reason the
        refusal this replaces gave: the cost of a rule that cannot fire is that
        it looks exactly like a rule that found nothing.
        """
        from cordon_scanner.detect.astquery import AstQuery

        names = raw.get("calls")
        if not isinstance(names, list) or not names:
            raise RulePackError(f"{where}: an `ast` match requires a non-empty `calls` list")
        calls: set[str] = set()
        for name in names:
            if not isinstance(name, str) or not name.strip():
                raise RulePackError(f"{where}: every entry in `calls` must be a dotted name")
            # A bare name resolves to itself, so `eval` is as valid as
            # `os.system`. What is refused is a name with nothing in it, and a
            # name written as a call -- `os.system()` is a mistake that would
            # match nothing and look like it should match everything.
            if "(" in name or ")" in name:
                raise RulePackError(f"{where}: `calls` takes names, not call expressions: {name!r}")
            calls.add(name.strip())

        pattern: re.Pattern[str] | None = None
        raw_pattern = raw.get("argument_matches")
        if raw_pattern is not None:
            if not isinstance(raw_pattern, str) or not raw_pattern:
                raise RulePackError(f"{where}: `argument_matches` must be a non-empty string")
            # The same safety gate the regex kind goes through. An `ast` rule
            # that could smuggle in catastrophic backtracking would make the
            # validator a formality.
            PatternCompiler.validate_pattern(raw_pattern, rule_id=where)
            pattern = re.compile(raw_pattern)

        index = raw.get("argument_index")
        if index is not None and (
            not isinstance(index, int) or isinstance(index, bool) or index < 0
        ):
            raise RulePackError(f"{where}: `argument_index` must be a non-negative integer")
        if index is not None and pattern is None:
            raise RulePackError(
                f"{where}: `argument_index` narrows `argument_matches`, which is absent"
            )

        constructed = raw.get("argument_constructed", False)
        if not isinstance(constructed, bool):
            raise RulePackError(f"{where}: `argument_constructed` must be true or false")

        return CompiledMatch(
            kind=MatchKind.AST,
            ast_query=AstQuery(
                calls=frozenset(calls),
                argument_matches=pattern,
                argument_index=index,
                argument_constructed=constructed,
            ),
            raw=dict(raw),
        )

    @staticmethod
    def _parse_provenance(raw: Any, *, where: str) -> RuleProvenance | None:
        if raw is None:
            return None
        if not isinstance(raw, dict):
            raise RulePackError(f"{where}: `provenance` must be a mapping")
        kind = str(raw.get("kind", ""))
        valid = {"incident", "research", "advisory", "community", "synthetic"}
        if kind not in valid:
            raise RulePackError(
                f"{where}: provenance.kind must be one of: {', '.join(sorted(valid))}"
            )
        return RuleProvenance(
            kind=kind,
            reference=str(raw.get("reference", "")),
            note=RuleLoader._clean(str(raw.get("note", ""))),
        )

    @staticmethod
    def _parse_tests(raw: Any, *, where: str) -> RuleTests:
        if raw is None:
            return RuleTests()
        if not isinstance(raw, dict):
            raise RulePackError(f"{where}: `tests` must be a mapping")
        unknown = set(raw) - {"positive", "negative"}
        if unknown:
            raise RulePackError(f"{where}: unknown tests key(s): {', '.join(sorted(unknown))}")
        return RuleTests(
            positive=RuleLoader._str_tuple(raw.get("positive")),
            negative=RuleLoader._str_tuple(raw.get("negative")),
        )

    # ---------------------------------------------------------------------------
    # Self-tests
    # ---------------------------------------------------------------------------

    @staticmethod
    def _validate_globs(paths: Mapping[str, Any], *, where: str) -> None:
        """Compile every path glob now, so a broken one cannot reach a scan.

        A malformed glob -- `[z-a]`, an unbalanced class -- was only discovered
        when a file was matched against it, where it raised inside
        `detector.inspect`. The handler there turns any exception into an
        OPERATIONAL finding and continues, so one bad character in one rule
        removed the entire capability detector's coverage for every file in the
        repository, reported at MEDIUM, under a default gate that fails at HIGH.

        A rule that cannot be evaluated is a broken pack, and a broken pack
        should not load. Failing here names the rule instead.
        """
        from cordon_scanner.core.errors import ConfigError
        from cordon_scanner.core.walker import PathGlob

        for key in ("include", "exclude"):
            for pattern in RuleLoader._str_tuple(paths.get(key)):
                try:
                    PathGlob.compile(pattern)
                except ConfigError as exc:
                    raise RulePackError(
                        f"{where}: paths.{key} pattern {pattern!r} is not valid: {exc.message}",
                        hint=(
                            "A rule whose path filter cannot be compiled disables its "
                            "whole detector at scan time. Fix the pattern."
                        ),
                    ) from exc

    @staticmethod
    def _str_tuple(value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            return (value,)
        if isinstance(value, list):
            return tuple(str(v) for v in value)
        return ()

    @staticmethod
    def _clean(text: str) -> str:
        """Collapse whitespace from folded YAML block scalars."""
        return " ".join(text.split())

    @staticmethod
    def builtin_pack_dir() -> Path:
        """Where the packs that ship with the tool live."""
        return Path(__file__).parent / "builtin"

    MIN_BUILTIN_RULES = 20
    """Floor on the bundled rule count.

    Not a checksum -- there is no signature over the packs, and the threat model
    should not claim one until there is. What this catches is the case that
    actually happens: the packs are absent, unreadable, or emptied, and the
    scanner runs anyway with most of its detection missing.
    """

    @classmethod
    def load_builtin(cls, loader: RuleLoader | None = None) -> tuple[RulePack, ...]:
        """Load the packs bundled with the installed tool.

        Refuses an installation that has none. It used to return `()` on the
        reasoning that "the caller reports that far more usefully" -- and no
        caller reported it at all. Deleting the five bundled YAML files from an
        installed copy produced a scan that ran, said `rulepack 0.0.0
        (e3b0c44298fc1c14)`, lost the entire capability and composite layer, and
        reported `scan complete`. The rulepack hash changed, which is a signal
        only if something compares it, and nothing did.

        That is the shape this tool exists to refuse in other people's
        pipelines: a control that reads as present while doing much less than it
        claims. An empty rule set is not a scan with fewer rules; it is a scan
        whose output no longer means what its reader thinks.
        """
        if loader is None:
            # The default load, once per process: compiling 1,390 rules' patterns is most of a
            # scan's fixed cost, and the packs are immutable once loaded. Keyed by directory, so
            # anything pointing the tool at another copy loads that one.
            return cls._builtin_once(str(cls.builtin_pack_dir()))
        return cls._load_builtin(loader, cls.builtin_pack_dir())

    @classmethod
    @functools.cache
    def _builtin_once(cls, directory: str) -> tuple[RulePack, ...]:
        return cls._load_builtin(cls(), Path(directory))

    @classmethod
    def _load_builtin(cls, ldr: RuleLoader, directory: Path) -> tuple[RulePack, ...]:
        if not directory.is_dir():
            raise RulePackError(
                f"the bundled rule packs are missing from {directory}",
                hint=(
                    "This installation is incomplete. Reinstall cordon-scanner; a scan "
                    "without them would report far less and look the same."
                ),
            )
        packs = ldr.load_dir(directory)
        total = sum(len(pack.rules) for pack in packs)
        if total < cls.MIN_BUILTIN_RULES:
            raise RulePackError(
                f"only {total} bundled rule(s) loaded from {directory}, expected at "
                f"least {cls.MIN_BUILTIN_RULES}",
                hint=(
                    "Rule packs are missing or truncated. Reinstall cordon-scanner "
                    "rather than scanning with a fraction of the rules."
                ),
            )
        return packs


@dataclass(frozen=True, slots=True)
class RuleTestFailure:
    rule_id: str
    kind: str
    sample: str
    detail: str


class RuleTester:
    """Executes the samples a rule declares about itself.

    Separate from the loader because loading answers "is this pack well
    formed?" and this answers "does it match anything?". A rule that parses,
    compiles, loads and matches nothing is the failure a detection tool cannot
    see from the inside: the scan runs, the pack is present, the output is
    empty, and everything looks healthy.

    This is what `cordon rules test` runs and what CI runs on every commit,
    which is what makes an inert rule impossible to ship unnoticed.
    """

    @staticmethod
    def run(pack: RulePack) -> tuple[RuleTestFailure, ...]:
        """Execute every rule's declared samples.

        This is what ``cordon rules test`` runs, and what the project's own CI runs
        on every commit. It is the mechanism that makes an inert rule impossible to
        ship unnoticed.

        Only directly-matchable kinds are executed here. Composite and graph rules
        are exercised by the corpus tests, because their inputs are other findings
        rather than text.
        """
        failures: list[RuleTestFailure] = []

        for compiled in pack.rules:
            rule = compiled.rule
            if compiled.match.kind not in {MatchKind.REGEX, MatchKind.LITERAL, MatchKind.AST}:
                continue

            for sample in rule.tests.positive:
                result = RuleTester._sample_matches(compiled, sample)
                if result is False:
                    failures.append(
                        RuleTestFailure(rule.id, "positive", sample, "expected a match, got none")
                    )
            for sample in rule.tests.negative:
                result = RuleTester._sample_matches(compiled, sample)
                if result is True:
                    failures.append(
                        RuleTestFailure(
                            rule.id, "negative", sample, "expected no match, but it matched"
                        )
                    )

        return tuple(failures)

    @staticmethod
    def _sample_matches(compiled: CompiledRule, sample: str) -> bool | None:
        r"""Decide a sample exactly the way the detector decides a file.

        Returns None for a sample that cannot be evaluated here -- an `ast` rule
        for a language whose provider is an uninstalled optional extra -- so the
        caller skips it rather than failing it. The provider-bearing extra is
        installed in the test environment, so a skipped sample there is a setup
        gap, not a rule that ships unchecked.

        The prefilter is applied here for the same reason it is applied there:
        without it, a rule whose prefilter is wrong passes all of its own
        positive samples while matching nothing in production. That happened.
        `secret\w{4,9}token` extracted the prefilter `4,9}token`, a literal that
        appears in no file the rule is meant to match, so the rule was skipped
        everywhere and its tests stayed green -- precisely the silent failure the
        sample runner exists to prevent.

        Running the same path turns that class of bug into a load-time failure
        naming the rule.
        """
        if compiled.match.kind is MatchKind.AST:
            # Parsed, not scanned. Running the sample through the same resolver
            # the detector uses is the only way a sample can demonstrate what
            # this kind claims -- that `f = os.system; f(x)` is the same call as
            # `os.system(x)`. A byte comparison here would pass on the first
            # spelling and prove nothing about the second.
            from cordon_scanner.detect.ast_providers import AstProviders

            language = compiled.rule.languages[0] if compiled.rule.languages else "python"
            provider = AstProviders.ast_provider_for(language)
            if provider is None:
                return None
            return bool(compiled.match.ast_query.matching(provider.resolve_calls(sample)))

        data = sample.encode("utf-8")

        if not compiled.match.admits(data):
            return False

        if compiled.match.regex is not None:
            regex = compiled.match.regex_for(data)
            return regex is not None and regex.search(data) is not None
        if compiled.match.literals:
            return any(lit in data for lit in compiled.match.literals)
        return False

    # ---------------------------------------------------------------------------
    # Registry
    # ---------------------------------------------------------------------------


class RuleSet:
    """The rules active for one scan, indexed for fast selection.

    Built once per Scanner rather than per scan, so pattern compilation is not
    repeated. The indexes exist because selecting rules by language and path for
    every file is otherwise a linear scan of the whole rule set per file.
    """

    @property
    def version(self) -> str:
        """A version for the whole active rule set.

        `packs[0].version` was recorded in every result, and with five packs at
        potentially different versions that is whichever pack sorted first --
        arbitrary, and wrong as soon as one pack moves. The set is named
        instead, and `content_hash` remains the exact identity.
        """
        versions = sorted({pack.version for pack in self.packs})
        if not versions:
            return "0.0.0"
        return versions[0] if len(versions) == 1 else "+".join(versions)

    def __init__(self, packs: Iterable[RulePack]) -> None:
        self.packs = tuple(packs)
        self.rules = tuple(r for pack in self.packs for r in pack.rules if r.rule.enabled)
        self._by_language: dict[str, list[CompiledRule]] = {}
        self._language_agnostic: list[CompiledRule] = []

        for compiled in self.rules:
            if compiled.rule.languages:
                for language in compiled.rule.languages:
                    self._by_language.setdefault(language, []).append(compiled)
            else:
                self._language_agnostic.append(compiled)

    def for_language(self, language: str | None) -> tuple[CompiledRule, ...]:
        """Rules applicable to a language, plus those that apply to everything.

        A rule with no declared language is not "unknown", it is deliberately
        universal: encoded payloads and bidirectional control characters mean the
        same thing in every language.
        """
        specific = self._by_language.get(language or "", [])
        return tuple(specific) + tuple(self._language_agnostic)

    def by_kind(self, kind: MatchKind) -> tuple[CompiledRule, ...]:
        return tuple(r for r in self.rules if r.match.kind is kind)

    def get(self, rule_id: str) -> CompiledRule | None:
        return next((r for r in self.rules if r.id == rule_id), None)

    @property
    def content_hash(self) -> str:
        """Hash of every loaded pack, recorded in each scan result.

        Makes a result self-describing: months later it is still possible to say
        exactly which rules produced it, which is what auditability requires and
        what makes the incremental cache safe to invalidate on a rule change.
        """
        digest = hashlib.sha256()
        for pack in sorted(self.packs, key=lambda p: p.id):
            digest.update(f"{pack.id}@{pack.version}:{pack.content_hash}".encode())
        return digest.hexdigest()[:16]

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self) -> Iterator[CompiledRule]:
        return iter(self.rules)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


__all__ = [
    "CompiledMatch",
    "CompiledRule",
    "PatternCompiler",
    "RuleLoader",
    "RulePack",
    "RuleSet",
    "RuleTestFailure",
    "RuleTester",
]
