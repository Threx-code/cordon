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

from cordon.core.config import _load_yaml_subset
from cordon.core.errors import RulePackError, UnsafePatternError
from cordon.core.models import (
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

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping

RULE_ID = re.compile(r"^[A-Z][A-Z0-9]*(\.[A-Z0-9_]+)+$")
"""Rule identifiers are dotted, uppercase and hierarchical.

The shape is enforced because identifiers appear in suppressions, baselines,
SARIF output and policy files, all of which outlive the rule. A namespace makes
them greppable and lets a policy target a family.
"""

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")

_PACK_KEYS = frozenset({"id", "version", "license", "source", "requires_engine", "description"})
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
    {"kind", "pattern", "patterns", "literal", "literals", "scope", "all", "any",
     "unless", "capability", "threshold", "window", "query", "field", "value"}
)


# ---------------------------------------------------------------------------
# Pattern safety
# ---------------------------------------------------------------------------

_RISKY_GROUP = re.compile(
    r"""
    \(                        # a group
    (?P<body>
        (?:[^()\\]|\\.)*      # its contents, no nesting
    )
    \)                        # close
    \s*
    (?P<quant>[+*]|\{\d*,\}?)  # an unbounded quantifier applied to the group
    """,
    re.VERBOSE,
)
"""A group with an unbounded quantifier applied to it.

Whether that is dangerous depends on the group's contents, which
:func:`validate_pattern` inspects.
"""

_UNBOUNDED_INSIDE = re.compile(r"(?:[^\\]|^)[+*]|\{\d*,\}?")

_BACKREFERENCE = re.compile(r"\\[1-9]|\(\?P=")


def validate_pattern(pattern: str, *, rule_id: str) -> re.Pattern[bytes]:
    """Compile a rule pattern, refusing anything that could hang the scanner.

    Rejected constructs and why:

    * **Nested unbounded quantifiers** (``(a+)+``, ``(a*)*``, ``(a|aa)+``). These
      are the classic catastrophic-backtracking shapes. A single crafted file
      turns one of these into an unbounded CPU burn on every worker that touches
      it.
    * **Backreferences**. They force a backtracking engine and are never needed
      for the kind of matching a detection rule does.

    The per-file timeout in the worker is the backstop, not the primary control.
    Catching it here means the failure surfaces when the pack is authored, with
    the rule's name attached, instead of as a mysterious timeout in somebody
    else's pipeline six months later.
    """
    if _BACKREFERENCE.search(pattern):
        raise UnsafePatternError(
            f"rule {rule_id}: pattern uses a backreference",
            hint=(
                "Backreferences force a backtracking engine. Detection rules do not "
                "need them; restructure the pattern."
            ),
        )

    for group in _RISKY_GROUP.finditer(pattern):
        body = group.group("body")

        # A quantifier inside a quantified group is the classic (a+)+ shape:
        # the number of ways to split the input grows exponentially.
        nested = _UNBOUNDED_INSIDE.search(body) is not None

        # An alternation inside a quantified group is the (a|aa)+ shape. Whether
        # it actually backtracks depends on whether the branches can match the
        # same text, which is undecidable in general -- so this is refused
        # conservatively. Rejecting a safe pattern costs the author one rewrite;
        # accepting an unsafe one costs every user of the pack a hung scan.
        alternation = "|" in body

        if nested or alternation:
            shape = "a quantifier" if nested else "an alternation"
            raise UnsafePatternError(
                f"rule {rule_id}: pattern applies an unbounded quantifier to a group "
                f"containing {shape}, which can backtrack catastrophically",
                hint=(
                    "Shapes like (a+)+ and (a|aa)+ let a crafted input consume "
                    "unbounded CPU. Rewrite so no unbounded quantifier applies to a "
                    "group that itself repeats or alternates."
                ),
            )

    try:
        # Compiled against bytes: matching happens on raw file content so that
        # the ~99 percent of files with no match are never decoded at all.
        return re.compile(pattern.encode("utf-8"), re.MULTILINE)
    except re.error as exc:
        raise UnsafePatternError(f"rule {rule_id}: invalid pattern: {exc}") from exc


# ---------------------------------------------------------------------------
# Compiled rule
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

        if ch in b"+{|.^$":
            flush()
            i += 1
            continue

        if depth == 0:
            literal += ch
        i += 1

    flush()
    return bytes(best)


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
    branches = _split_top_level_alternation(pattern)
    literals: list[bytes] = []
    for branch in branches:
        found = _longest_literal_run(branch)
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
        data = _load_yaml_subset(text, source=source)
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

        return {k: str(v) for k, v in pack.items()}

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
        if self.strict_baseline and baseline_hits > 0 and confidence >= Confidence.HIGH:
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
            message=_clean(str(raw["message"])),
            remediation=_clean(str(raw.get("remediation", ""))),
            match_kind=compiled_match.kind,
            version=str(raw.get("version", "1.0.0")),
            rulepack=pack_id,
            languages=_str_tuple(raw.get("languages")),
            ecosystems=_str_tuple(raw.get("ecosystems")),
            paths_include=_str_tuple(paths.get("include")),
            paths_exclude=_str_tuple(paths.get("exclude")),
            evidence_policy=evidence_policy,
            capability=capability,
            provenance=provenance,
            tests=tests,
            references=_str_tuple(raw.get("references")),
            enabled=bool(raw.get("enabled", True)),
            baseline_hits=baseline_hits,
            raw=dict(raw),
        )

        return CompiledRule(rule=rule, match=compiled_match)

    def _compile_match(
        self, raw: Any, rule_id: str, where: str
    ) -> CompiledMatch:
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
            patterns = _str_tuple(raw.get("patterns")) or (
                (str(raw["pattern"]),) if raw.get("pattern") else ()
            )
            if not patterns:
                raise RulePackError(f"{where}: regex match requires `pattern` or `patterns`")
            # Multiple patterns become one alternation, compiled once. Matching
            # cost is then independent of how many alternatives a rule declares.
            combined = "|".join(f"(?:{p})" for p in patterns)
            regex = validate_pattern(combined, rule_id=rule_id)
            # Extract from the individual patterns rather than the combined one:
            # wrapping each in (?:...) puts every literal inside a group, where
            # the conservative walker will not read it.
            prefilter: tuple[bytes, ...] = ()
            per_pattern = [_extract_prefilter(p.encode("utf-8")) for p in patterns]
            if all(per_pattern):
                prefilter = tuple(sorted({lit for group in per_pattern for lit in group}))
            return CompiledMatch(
                kind=kind, regex=regex, prefilter=prefilter, raw=dict(raw)
            )

        if kind is MatchKind.LITERAL:
            literals = _str_tuple(raw.get("literals")) or (
                (str(raw["literal"]),) if raw.get("literal") else ()
            )
            if not literals:
                raise RulePackError(f"{where}: literal match requires `literal` or `literals`")
            encoded = tuple(s.encode("utf-8") for s in literals)
            return CompiledMatch(
                kind=kind, literals=encoded, prefilter=encoded, raw=dict(raw)
            )

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

        # structural, ast and graph kinds are resolved by their detectors, which
        # own the query language for their layer.
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
            note=_clean(str(raw.get("note", ""))),
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
            positive=_str_tuple(raw.get("positive")),
            negative=_str_tuple(raw.get("negative")),
        )


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleTestFailure:
    rule_id: str
    kind: str
    sample: str
    detail: str


def run_rule_tests(pack: RulePack) -> tuple[RuleTestFailure, ...]:
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
            if not _sample_matches(compiled, sample):
                failures.append(
                    RuleTestFailure(
                        rule.id, "positive", sample, "expected a match, got none"
                    )
                )
        for sample in rule.tests.negative:
            if _sample_matches(compiled, sample):
                failures.append(
                    RuleTestFailure(
                        rule.id, "negative", sample, "expected no match, but it matched"
                    )
                )

    return tuple(failures)


def _sample_matches(compiled: CompiledRule, sample: str) -> bool:
    data = sample.encode("utf-8")
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


def _str_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(v) for v in value)
    return ()


def _clean(text: str) -> str:
    """Collapse whitespace from folded YAML block scalars."""
    return " ".join(text.split())


def builtin_pack_dir() -> Path:
    return Path(__file__).parent / "builtin"


def load_builtin_rules(loader: RuleLoader | None = None) -> tuple[RulePack, ...]:
    ldr = loader or RuleLoader()
    directory = builtin_pack_dir()
    if not directory.is_dir():
        return ()
    return ldr.load_dir(directory)


__all__ = [
    "CompiledMatch",
    "CompiledRule",
    "RuleLoader",
    "RulePack",
    "RuleSet",
    "RuleTestFailure",
    "load_builtin_rules",
    "run_rule_tests",
    "validate_pattern",
]
