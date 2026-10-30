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
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.foundation.capabilities import Capability, MatchKind
from cordon_scanner.foundation.errors import RulePackError
from cordon_scanner.foundation.formats.restricted_yaml import RestrictedYamlParser
from cordon_scanner.foundation.models import Category, Confidence, RedactionMode, Severity
from cordon_scanner.foundation.once import OneOff
from cordon_scanner.foundation.paths import PackagePaths
from cordon_scanner.foundation.rule_model import Rule, RuleProvenance, RuleTests
from cordon_scanner.foundation.text.literals import LiteralGate
from cordon_scanner.rules.pack import CompiledMatch, CompiledRule, RulePack
from cordon_scanner.rules.patterns import PatternCompiler
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


UNIMPLEMENTED_KINDS: frozenset[MatchKind] = frozenset({MatchKind.STRUCTURAL, MatchKind.GRAPH})
"""Match kinds the vocabulary declares and no code implements.

Kept in `MatchKind` because they are the planned vocabulary and removing them
would make the roadmap unreadable, and refused at load because accepting one
produces a rule that cannot fire. Delete an entry here when its detector lands,
and the loader starts accepting it with no other change.
"""


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

        baseline_hits = self._check_samples_and_baseline(raw, tests, confidence, where=where)

        paths = raw.get("paths") or {}
        if not isinstance(paths, dict):
            raise RulePackError(f"{where}: `paths` must be a mapping with include/exclude")
        RuleLoader._validate_globs(paths, where=where)

        evidence_policy, capability = RuleLoader._policy_and_capability(raw, where=where)

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

    def _check_samples_and_baseline(
        self, raw: Mapping[str, Any], tests: RuleTests, confidence: Confidence, *, where: str
    ) -> int:
        """Refuse a text-matching rule without positive and negative samples, and a rule that
        surfaces findings at high confidence with benign-corpus hits; the recorded hits."""
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
        return baseline_hits

    @staticmethod
    def _policy_and_capability(
        raw: Mapping[str, Any], *, where: str
    ) -> tuple[RedactionMode, Capability | None]:
        """The rule's evidence policy and the capability it labels, or None."""
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
        return evidence_policy, capability

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
            return RuleLoader._compile_regex(raw, kind, rule_id, where)

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
    def _compile_regex(
        raw: dict[str, Any], kind: MatchKind, rule_id: str, where: str
    ) -> CompiledMatch:
        """A regex match: its patterns as one validated alternation, the exact-case prefilter, the
        folded one, and the literal gates `regex_for` tests per pattern."""
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

    @staticmethod
    def _compile_ast(raw: Mapping[str, Any], *, where: str) -> CompiledMatch:
        """Compile `kind: ast` into a query `detect/astquery.py` can run.

        Validated as strictly as every other kind, and for the reason the
        refusal this replaces gave: the cost of a rule that cannot fire is that
        it looks exactly like a rule that found nothing.
        """
        from cordon_scanner.analysis.shared.astquery import AstQuery

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
        from cordon_scanner.foundation.errors import ConfigError
        from cordon_scanner.foundation.files.globs import PathGlob

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
        return PackagePaths.root() / "rules" / "builtin"

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
            bundled = cls._builtin_once(str(cls.builtin_pack_dir()))
        else:
            bundled = cls._load_builtin(loader, cls.builtin_pack_dir())
        # Then the packs the signed feed delivered (`intel/malware/feed_rules.py`): they add rules,
        # never replace a bundled one, and a shadow pack loads only in the Cloud analyser fleet.
        from cordon_scanner.rules.feed_packs import FeedPacks

        ids = {compiled.rule.id for pack in bundled for compiled in pack.rules}
        return bundled + FeedPacks.packs(loader or cls(), ids)

    @classmethod
    def running_feed_packs(cls, *, shadow: bool | None = None) -> tuple[str, ...]:
        """`FeedPacks.loaded`, against the bundled rules of this install: what a default scan
        here runs."""
        from cordon_scanner.rules.feed_packs import FeedPacks

        bundled = cls._builtin_once(str(cls.builtin_pack_dir()))
        ids = {compiled.rule.id for pack in bundled for compiled in pack.rules}
        return FeedPacks.loaded(cls(), ids, shadow=shadow)

    @staticmethod
    @OneOff.cache
    def _builtin_once(directory: str) -> tuple[RulePack, ...]:

        return RuleLoader._load_builtin(RuleLoader(), Path(directory))

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
    "PatternCompiler",
    "RuleLoader",
    "RuleSet",
]
