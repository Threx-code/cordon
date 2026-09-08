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

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.core.config import RestrictedYamlParser
from cordon_scanner.core.errors import RulePackError, UnsafePatternError
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
        "all",
        "any",
        "unless",
        "capability",
        "threshold",
        "window",
        "query",
        "field",
        "value",
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


UNIMPLEMENTED_KINDS: frozenset[MatchKind] = frozenset(
    {MatchKind.AST, MatchKind.STRUCTURAL, MatchKind.GRAPH}
)
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
    def _split_top_level_alternation(pattern: bytes) -> list[bytes]:
        """Split a pattern on `|` that is not inside a group or character class."""
        branches: list[bytes] = []
        depth = 0
        in_class = False
        start = 0
        i = 0
        while i < len(pattern):
            ch = pattern[i : i + 1]
            if ch == b"\\":
                i += 2
                continue
            if in_class:
                if ch == b"]":
                    in_class = False
            elif ch == b"[":
                in_class = True
            elif ch == b"(":
                depth += 1
            elif ch == b")":
                depth = max(0, depth - 1)
            elif ch == b"|" and depth == 0:
                branches.append(pattern[start:i])
                start = i + 1
            i += 1
        branches.append(pattern[start:])
        return branches

    @staticmethod
    def _longest_literal_run(pattern: bytes) -> bytes:
        """Longest substring that every match of this pattern must contain.

        Conservative by design. It walks only the top level, stops at any construct
        that makes continuation unsafe, and returns empty whenever it is unsure. A
        wrong answer here is a missed match, which is the one error class this
        project treats as unacceptable, so uncertainty always resolves to "no
        prefilter" rather than to a guess.
        """
        literal = bytearray()
        best = bytearray()
        i = 0
        depth = 0
        n = len(pattern)

        def flush() -> None:
            nonlocal best
            if len(literal) > len(best):
                best = literal.copy()
            literal.clear()

        while i < n:
            ch = pattern[i : i + 1]

            if ch == b"\\":
                nxt = pattern[i + 1 : i + 2]
                # An escaped punctuation character is a literal; a class shorthand
                # such as \d or an anchor such as \b is not.
                if nxt and nxt not in b"dDwWsSbBAZzntrfvxu0123456789":
                    if depth == 0:
                        literal += nxt
                else:
                    flush()
                i += 2
                continue

            if ch in b"([":
                depth += 1
                flush()
                i += 1
                continue

            if ch in b")]":
                depth = max(0, depth - 1)
                i += 1
                continue

            if ch in b"*?":
                # The preceding character is optional, so it cannot be required.
                if literal:
                    literal.pop()
                flush()
                i += 1
                continue

            if ch == b"{":
                # Skip the whole `{m,n}` token. Flushing on `{` alone and then
                # continuing left `0`, `,`, `4` and `}` to be accumulated as
                # required literal bytes, so `secret\w{4,9}token` produced the
                # prefilter `4,9}token` -- a literal that appears in no file the
                # rule is meant to match. Every affected rule was skipped for
                # every file it should have caught, silently, and its own
                # positive samples still passed because the sample runner did
                # not apply the prefilter.
                close = pattern.find(b"}", i)
                if close == -1:
                    # A bare `{` is a literal brace in a regex, not a quantifier.
                    if depth == 0:
                        literal += ch
                    i += 1
                    continue
                body = pattern[i + 1 : close]
                if body and all(c in b"0123456789," for c in body):
                    # A genuine quantifier. The preceding character may repeat
                    # zero times, so it cannot be required either.
                    if body.startswith(b"0") and literal:
                        literal.pop()
                    flush()
                    i = close + 1
                    continue
                if depth == 0:
                    literal += ch
                i += 1
                continue

            if ch in b"+|.^$":
                flush()
                i += 1
                continue

            if depth == 0:
                literal += ch
            i += 1

        flush()
        return bytes(best)

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
        """
        branches = PatternCompiler._split_top_level_alternation(pattern)
        literals: list[bytes] = []
        for branch in branches:
            found = PatternCompiler._longest_literal_run(branch)
            # Below three bytes a prefilter matches almost everything and costs more
            # than it saves.
            if len(found) < 3:
                return ()
            literals.append(found)
        return tuple(sorted(set(literals)))

    # ---------------------------------------------------------------------------
    # Rule pack
    # ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CompiledMatch:
    """A rule's matching strategy, resolved at load time."""

    kind: MatchKind
    regex: re.Pattern[bytes] | None = None
    literals: tuple[bytes, ...] = ()
    capability: Capability | None = None
    scope: str = "file"
    all_of: tuple[Any, ...] = ()
    any_of: tuple[Any, ...] = ()
    unless: tuple[Any, ...] = ()
    threshold: float = 0.0
    window: int = 0
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    prefilter: tuple[bytes, ...] = ()
    """Literals for which at least one must be present for this rule to match.

    Computed once at load time (see :func:`_extract_prefilter`). Empty means no
    prefilter is possible and the rule is evaluated against every candidate
    file."""


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
            return CompiledMatch(kind=kind, regex=regex, prefilter=prefilter, raw=dict(raw))

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
            return CompiledMatch(
                kind=kind,
                scope=scope,
                all_of=tuple(raw.get("all") or ()),
                any_of=tuple(raw.get("any") or ()),
                unless=tuple(raw.get("unless") or ()),
                raw=dict(raw),
            )

        # `structural`, `ast` and `graph` are declared in `MatchKind` and
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

    @classmethod
    def load_builtin(cls, loader: RuleLoader | None = None) -> tuple[RulePack, ...]:
        """Load the packs bundled with the installed tool.

        Returns empty rather than raising when the directory is absent, because
        an installation without bundled packs is a broken installation and the
        caller reports that far more usefully than an import-time crash here.
        """
        ldr = loader or cls()
        directory = cls.builtin_pack_dir()
        if not directory.is_dir():
            return ()
        return ldr.load_dir(directory)


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
            if compiled.match.kind not in {MatchKind.REGEX, MatchKind.LITERAL}:
                continue

            for sample in rule.tests.positive:
                if not RuleTester._sample_matches(compiled, sample):
                    failures.append(
                        RuleTestFailure(rule.id, "positive", sample, "expected a match, got none")
                    )
            for sample in rule.tests.negative:
                if RuleTester._sample_matches(compiled, sample):
                    failures.append(
                        RuleTestFailure(
                            rule.id, "negative", sample, "expected no match, but it matched"
                        )
                    )

        return tuple(failures)

    @staticmethod
    def _sample_matches(compiled: CompiledRule, sample: str) -> bool:
        r"""Decide a sample exactly the way the detector decides a file.

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
        data = sample.encode("utf-8")

        prefilter = compiled.match.prefilter
        if prefilter and not any(literal in data for literal in prefilter):
            return False

        if compiled.match.regex is not None:
            return compiled.match.regex.search(data) is not None
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
