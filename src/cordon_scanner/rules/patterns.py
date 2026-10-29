"""Rule patterns made safe and fast to run: the checks that refuse a pattern that could backtrack
without bound, and the literals every match must contain, which let a rule skip a file without
running its pattern."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.foundation.errors import UnsafePatternError

if TYPE_CHECKING:
    pass


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
        except Exception:  # pragma: no cover - parser internals changed  # noqa: BLE001
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
        shapes = UnsafeShapes(cls, rule_id)
        shapes.walk(parsed, inside_unbounded=False)
        wildcards = shapes.wildcards

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
        except Exception:  # any doubt means no prefilter, never a wrong one  # noqa: BLE001
            return ()
        ignorecase = sre.SRE_FLAG_IGNORECASE
        if not fold and tree.state.flags & ignorecase:
            return ()

        found = LiteralRequirement(sre, shortest=shortest, adjacent=adjacent, fold=fold).sequence(
            tree
        )
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


class LiteralRequirement:
    """The literals every match of a parsed pattern contains (`PatternCompiler.required_literals`),
    read construct by construct with the settings of one call."""

    def __init__(self, sre: Any, *, shortest: int, adjacent: bool, fold: bool) -> None:
        self.sre = sre
        self.shortest = shortest
        self.adjacent = adjacent
        self.fold = fold
        self.ignorecase = sre.SRE_FLAG_IGNORECASE

    def any_case(self, av: Any) -> bool:
        """Whether a group's own flags make its literals match in any case."""
        return not self.fold and bool(av[1] & self.ignorecase)

    def sequence(self, items: Any) -> set[bytes] | None:
        candidates = (
            self._adjacent_candidates(items) if self.adjacent else self._literal_candidates(items)
        )
        usable = [c for c in candidates if c and min(len(x) for x in c) >= self.shortest]
        if not usable:
            return None
        return max(usable, key=lambda c: (min(len(x) for x in c), -len(c)))

    def _adjacent_candidates(self, items: Any) -> list[set[bytes]]:
        """What each run of finite sets side by side requires, and what each other item does."""
        candidates: list[set[bytes]] = []
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
            if op is self.sre.AT:
                continue
            piece = self.finite(op, av)
            if piece is not None:
                extend(piece)
                continue
            if op in (
                self.sre.MAX_REPEAT,
                self.sre.MIN_REPEAT,
                getattr(self.sre, "POSSESSIVE_REPEAT", None),
            ):
                low, _, item = av
                inner = self.finite_items(item) if low >= 1 else None
                if inner is not None:
                    extend(inner)
                    close()
                    run_set = set(inner)
                    continue
            close()
            found = self.node(op, av)
            if found is not None:
                candidates.append(found)
        close()
        return candidates

    def _literal_candidates(self, items: Any) -> list[set[bytes]]:
        """What each run of literal bytes requires, and what each other item does."""
        candidates: list[set[bytes]] = []
        run = bytearray()
        for op, av in items:
            if op is self.sre.LITERAL:
                run.append(av)
                continue
            if run:
                candidates.append({bytes(run)})
                run = bytearray()
            found = self.node(op, av)
            if found is not None:
                candidates.append(found)
        if run:
            candidates.append({bytes(run)})
        return candidates

    def finite(self, op: Any, av: Any) -> set[bytes] | None:
        """The exact strings one item can match, when there are few; else None."""
        if op is self.sre.LITERAL:
            return {bytes([av])}
        if op is self.sre.IN:
            chars: set[int] = set()
            for kind, value in av:
                if kind is self.sre.LITERAL:
                    chars.add(value)
                elif kind is self.sre.RANGE and value[1] - value[0] < RequiredLiterals.CLASS_LIMIT:
                    chars.update(range(value[0], value[1] + 1))
                elif kind is self.sre.CATEGORY and value is self.sre.CATEGORY_SPACE:
                    chars.update(b" \t\n\r\x0b\x0c")
                else:
                    return None
            if not chars or len(chars) > RequiredLiterals.CLASS_LIMIT:
                return None
            return {bytes([c]) for c in chars}
        if op is self.sre.SUBPATTERN:
            return None if self.any_case(av) else self.finite_items(av[3])
        if op is self.sre.BRANCH:
            union: set[bytes] = set()
            for branch in av[1]:
                found = self.finite_items(branch)
                if found is None:
                    return None
                union |= found
            return union if len(union) <= RequiredLiterals.PRODUCT_LIMIT else None
        return None

    def finite_items(self, items: Any) -> set[bytes] | None:
        """The exact strings a sequence can match, when every item is finite and few."""
        result: set[bytes] = {b""}
        for op, av in items:
            if op is self.sre.AT:
                return None  # an assertion inside an alternative: keep it simple, no set
            piece = self.finite(op, av)
            if piece is None or len(result) * len(piece) > RequiredLiterals.PRODUCT_LIMIT:
                return None
            result = {a + b for a in result for b in piece}
        return result

    def node(self, op: Any, av: Any) -> set[bytes] | None:
        if op is self.sre.SUBPATTERN:
            return None if self.any_case(av) else self.sequence(av[3])
        if op is self.sre.ATOMIC_GROUP:
            return self.sequence(av)
        if op is self.sre.BRANCH:
            union: set[bytes] = set()
            for branch in av[1]:
                found = self.sequence(branch)
                if found is None:
                    return None
                union |= found
            return union
        if op in (
            self.sre.MAX_REPEAT,
            self.sre.MIN_REPEAT,
            getattr(self.sre, "POSSESSIVE_REPEAT", None),
        ):
            low, _, item = av
            return self.sequence(item) if low >= 1 else None
        return None


class UnsafeShapes:
    """One walk over a parsed pattern for the shapes that backtrack catastrophically
    (`PatternCompiler._reject_unsafe`): it raises at the first, and counts unbounded wildcards."""

    def __init__(self, limits: type[PatternCompiler], rule_id: str) -> None:
        self.limits = limits
        self.rule_id = rule_id
        self.wildcards = 0

    def walk(self, node: Any, *, inside_unbounded: bool, outer_bound: int = 1) -> None:
        for opcode, argument in node:
            name = str(opcode)

            if name == "GROUPREF" or name.startswith("GROUPREF"):
                raise UnsafePatternError(
                    f"rule {self.rule_id}: pattern uses a backreference",
                    hint=(
                        "Backreferences force a backtracking engine. Detection "
                        "rules do not need them; restructure the pattern."
                    ),
                )

            if name in {"MAX_REPEAT", "MIN_REPEAT"}:
                self._repeat(argument, inside_unbounded=inside_unbounded, outer_bound=outer_bound)
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
                        f"rule {self.rule_id}: pattern applies an unbounded quantifier to "
                        f"a group containing an alternation, which can backtrack "
                        f"catastrophically",
                        hint=("Rewrite so no unbounded quantifier encloses an alternation."),
                    )
                for branch in branches:
                    self.walk(
                        branch,
                        inside_unbounded=inside_unbounded,
                        outer_bound=outer_bound,
                    )
                continue

            if name == "SUBPATTERN":
                self.walk(
                    argument[-1],
                    inside_unbounded=inside_unbounded,
                    outer_bound=outer_bound,
                )
                continue

            if name in {"ASSERT", "ASSERT_NOT"}:
                # A lookahead is a group for backtracking purposes, and
                # `(?=(a+))+` was accepted by the textual check for exactly
                # this reason.
                self.walk(argument[1], inside_unbounded=inside_unbounded)
                continue

            if name == "ATOMIC_GROUP":
                self.walk(argument, inside_unbounded=False)
                continue

    def _repeat(self, argument: Any, *, inside_unbounded: bool, outer_bound: int) -> None:
        """A repeat: its bound against the nesting product, its wildcard count, and whether it repeats
        something that itself repeats without bound; then what it repeats."""
        _low, high, sub = argument
        truly_unbounded = high >= _MAXREPEAT
        # A large bounded repeat is unbounded for this purpose. The
        # engine's backtracking does not care that the ceiling is
        # written down, only how many ways the input can be split.
        unbounded = truly_unbounded or high > self.limits.LARGE_REPEAT

        bound = 1 if truly_unbounded else max(1, int(high))
        product = outer_bound * bound
        if outer_bound > 1 and product > self.limits.MAX_NESTED_REPEAT_PRODUCT:
            raise UnsafePatternError(
                f"rule {self.rule_id}: nested repeats multiply to {product}, "
                f"over the {self.limits.MAX_NESTED_REPEAT_PRODUCT} allowed",
                hint=(
                    "Bounded repeats nest just as badly as unbounded ones. "
                    "Flatten the pattern or lower the bounds."
                ),
            )

        if truly_unbounded and self.limits._is_wildcard(sub):
            # Only `.`-like repeats are counted. `\d+` and `\s+`
            # are unbounded too, but they are anchored to a narrow
            # character class and do not produce the polynomial
            # blowup this cap exists for. Counting them rejected
            # `\bnc\s+(?:-[a-z]+\s+){0,4}\S+\s+\d+`, a shipped
            # rule that is entirely safe.
            self.wildcards += 1
        if inside_unbounded and unbounded:
            # (a+)+ and every disguise of it, at any depth.
            raise UnsafePatternError(
                f"rule {self.rule_id}: pattern applies an unbounded quantifier to "
                f"something that itself repeats without bound, which can "
                f"backtrack catastrophically",
                hint=(
                    "Shapes like (a+)+ and ((a+))+ let a crafted input "
                    "consume unbounded CPU. Rewrite so no unbounded "
                    "quantifier encloses another."
                ),
            )
        self.walk(
            sub,
            inside_unbounded=inside_unbounded or unbounded,
            outer_bound=product,
        )
