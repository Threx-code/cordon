"""Match every file against a rule file the operator names (`--rule-file RULES`), with cordon-rule.

The same arrangement as the ClamAV hand-off: off unless asked for, the rules chosen by whoever runs
the scan and never by the repository being scanned, and a report that says whether they ran. A rule
file is where a security team keeps the signatures it trusts -- its own, its vendor's, a feed's --
and this applies them to a scan as they are written.

The rule language is Cordon's own code (`rule_engine.lang`, with `rule_engine.pattern` and `rule_engine.scan` for the
strings): no native library reads a scanned file. Rules that cannot be used -- a file that does not
compile, a module the engine does not implement -- are reported in an operational finding rather
than as nothing, because "no rule matched" and "no rule ran" must never look alike. Rules are
compiled once per scan; each file is matched with a timeout, so a pathological rule cannot hold a
scan. A rule's `severity` meta, when it names one, sets the finding's severity; otherwise a match is
HIGH and SUSPICIOUS, because a rule asserts a pattern, not a verdict -- unless its meta says
`category = "malicious"`.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    FileUnit,
    RepositoryUnit,
    ScanContext,
    Unit,
)
from cordon_scanner.detect.binary.rule_engine.anchoring.automaton import Automaton
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon_scanner.foundation.paths import PackagePaths

if TYPE_CHECKING:
    from cordon_scanner.detect.binary.rule_engine.tokens import Includes

MATCH_RULE: Final = "SUSPECT.RULEFILE.MATCH.001"
MALICIOUS_RULE: Final = "MALWARE.RULEFILE.MATCH.001"
STATUS_RULE: Final = "OPERATIONAL.RULEFILE.STATUS"
UNAVAILABLE_RULE: Final = "OPERATIONAL.RULEFILE.UNAVAILABLE"
SHAPE_RULE: Final = "OPERATIONAL.RULEFILE.SHAPE"
UNMATCHED_RULE: Final = "SUSPECT.RULEFILE.UNMATCHED.001"
REFERENCE: Final = "https://github.com/Threx-code/cordon/blob/main/tutorials/31-rule-files.md"
MATCH_TIMEOUT_SECONDS: Final = 10
#: The operator's own rule file, not the scanned data: large enough for YARA-Forge's full pack
#: (over 16 MiB), its compile still bounded by the time it takes, and kept by the pack cache.
MAX_RULES_BYTES: Final = 256 << 20
#: `--rule-file builtin`: the pack shipped with Cordon (`rules/rule_files/`), DataDog GuardDog's `threat-*`
#: source-code rules at a pinned commit, Apache-2.0, less any that fired on the benign corpus.
BUILTIN: Final = "builtin"
BUILTIN_PACK: Final = PackagePaths.root() / "rules" / "rule_files" / "cordon-builtin.yar"


class RuleFileEngine:
    """Compile once, match many, with cordon-rule."""

    def __init__(
        self,
        rules_path: str,
        module_data: tuple[tuple[str, str], ...] = (),
        *,
        use_cache: bool = True,
        workers: int = 1,
    ) -> None:
        from cordon_scanner.detect.binary.rule_engine.lang import Rules

        path = BUILTIN_PACK if rules_path == BUILTIN else Path(rules_path)
        if not path.is_file():
            raise OSError(f"no rule file at {rules_path}")
        if path.stat().st_size > MAX_RULES_BYTES:
            raise OSError(f"the rule file is over {MAX_RULES_BYTES} bytes")
        # Compiled from the operator's file. `include` is a file read, so only the operator's own
        # file on disk may use it, and only for files under that file's directory (a rule
        # collection's index includes its members), all within the size limit. The built-in
        # pack, and rule text from anywhere else, never reads another file.
        text = path.read_text(encoding="utf-8", errors="replace")
        # Compiled once per version of the rules (`rule_engine/pack_cache`): a collection read and
        # prepared on the first scan is loaded on the next, in every worker.
        from cordon_scanner.detect.binary.rule_engine.pack_cache import PackCache
        from cordon_scanner.foundation.paths import StatePaths

        self.rules = Rules.compile(
            text,
            includes=None if rules_path == BUILTIN else RuleFileEngine.includes(path),
            cache=PackCache(StatePaths.default_cache_dir() / "rule-packs") if use_cache else None,
        )
        self.version = "cordon-rule"
        # Data given to the scan for a module (`--rule-module-data cuckoo=report.json`): read
        # once, here; a module the rules import that takes data and was given none answers
        # without it, and the scan says so (`without`).
        from cordon_scanner.detect.binary.modules.builtin import Builtin

        takes = Builtin.with_data()
        self.given: dict[str, Any] = {}
        for name, data_path in module_data:
            if name not in takes:
                raise OSError(f"no module reads data given to the scan by the name {name!r}")
            self.given[name] = takes[name](Path(data_path).read_bytes())
        self.without = sorted((self.rules.imports & set(takes)) - set(self.given))
        # Matches kept by file content (`rule_engine/match_cache`): the same bytes in another
        # package, or the next scan, are not matched again. None when the rules cannot be kept.
        from cordon_scanner.detect.binary.rule_engine.match_cache import MatchCache

        self.matches = MatchCache(StatePaths.default_cache_dir() / "rule-matches")
        self.identity = (
            MatchCache.identity(RuleFileEngine.files(rules_path), module_data, self.rules.imports)
            if use_cache
            else None
        )
        self.notes: list[tuple[str, str]] = self.rules.notes
        from cordon_scanner.detect.binary.rule_layers import RuleLayers

        #: The rules that also read a file's decoded layers (`layers = "decoded"`); every other rule
        #: reads the raw bytes only.
        self.layered = frozenset(r.name for r in self.rules.rules if RuleLayers.wanted(r.meta))
        # A large file matched by several processes at once, each against a share of the rules
        # (`rule_pool`): the serial answer, from the scan's main process only.
        from cordon_scanner.detect.binary.rule_pool import RulePool

        self.pool = (
            RulePool(
                self.rules,
                (RuleFileEngine, RuleFileDetector.why, rules_path, module_data, use_cache),
                workers,
            )
            if RulePool.wanted(self.rules, workers)
            else None
        )
        from cordon_scanner.detect.binary.modules.scanner_facts.facts import ScanFacts

        #: The scanner-fact modules the rules import: when any, the files are matched in the
        #: engine's deferred pass, once those facts exist (`engine/pipeline/facts`).
        self.facts = self.rules.imports & ScanFacts.MODULES
        """What the compiler decided where a rule did not say (a field two engines declare with
        different types, read in the reference's shape): reported with the scan, never silent."""

    @staticmethod
    def includes(path: Path) -> Includes:
        """Where an operator's rule file at `path` may include from."""
        from cordon_scanner.detect.binary.rule_engine.tokens import Includes

        return Includes(path.parent, top=path, max_bytes=MAX_RULES_BYTES - path.stat().st_size)

    @staticmethod
    def files(rules_path: str) -> list[Path]:
        """The rule file and every file its includes read, for a scan's cache (the built-in
        pack includes nothing)."""
        if rules_path == BUILTIN:
            return [BUILTIN_PACK]
        path = Path(rules_path)
        read = RuleFileEngine.includes(path).closure(
            path.read_text(encoding="utf-8", errors="replace")
        )
        return [path, *read]

    def fact_modules(self, unit: FileUnit, ctx: ScanContext) -> dict[str, Any]:
        """The `package`, `js` and `python` modules the rules import, for this file of this scan
        (`modules.scanner_facts`): read from the facts the engine gathered after detection."""
        from cordon_scanner.detect.binary.modules.scanner_facts.js import Js
        from cordon_scanner.detect.binary.modules.scanner_facts.package import Package
        from cordon_scanner.detect.binary.modules.scanner_facts.python import Python

        facts = ctx.scan_facts or {}
        out: dict[str, Any] = {}
        if "package" in self.facts:
            out["package"] = Package.module(facts, unit.path, ctx)
        if "js" in self.facts:
            out["js"] = Js.module(unit.path, ctx, unit.content)
        if "python" in self.facts:
            out["python"] = Python.module(unit.path, ctx, unit.content)
        return out

    def match(self, data: bytes, facts: dict[str, Any] | None = None) -> list[Any]:
        """The rules' matches over `data`; `facts` gives the scanner-fact modules for the file
        (`fact_modules`), whose answers are never kept by content (`MatchCache.UNCACHEABLE`)."""
        if self.identity is not None:
            kept = self.matches.get(self.identity, data)
            if kept is not None:
                return kept
        from cordon_scanner.detect.binary.rule_pool import RulePool

        given = {**self.given, **facts} if facts else self.given
        found: list[Any] | None = None
        # the pool's workers hold their own module data, so a file with per-file facts (the
        # deferred pass) is matched here; those rules are never kept by content either
        if self.pool is not None and not facts and len(data) >= RulePool.LARGE:
            from concurrent.futures.process import BrokenProcessPool

            try:
                found = self.pool.match(data, MATCH_TIMEOUT_SECONDS)
            except (BrokenProcessPool, OSError):
                # the pool, not the file, failed (a worker could not start, or was killed): the
                # file is matched serially, and the scan carries on without the pool
                self.pool.close()
                self.pool = None
        if found is None:
            found = list(self.rules.match(data, timeout=MATCH_TIMEOUT_SECONDS, given=given))
        if self.identity is not None:
            self.matches.put(self.identity, data, found)
        return found

    @staticmethod
    def applies(match: Any, path: str) -> bool:
        """A rule's `path_include` meta (`*.py,*.js`), where it states one, limits which files its
        match counts for: a rule written for source code says nothing about a README."""
        meta = getattr(match, "meta", None)
        wanted = meta.get("path_include") if isinstance(meta, dict) else None
        if not isinstance(wanted, str) or not wanted.strip():
            return True
        import fnmatch

        base = path.rpartition("!")[2].rpartition("/")[2].lower()
        return any(
            fnmatch.fnmatchcase(base, glob.strip().lower())
            for glob in wanted.split(",")
            if glob.strip()
        )


class RuleFileDetector(BaseDetector):
    id = "rule-file"
    version = "0.1.0"
    operator_enabled = True
    """Runs only when the operator names a rules file; exercised against a fake engine in tests."""
    categories = frozenset({Category.MALICIOUS, Category.SUSPICIOUS, Category.OPERATIONAL})
    requires = DetectorRequirements(content=True, repository=True)

    def __init__(self) -> None:
        self._engine: RuleFileEngine | None = None
        self._failed: str | None = None

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(getattr(ctx.config, "rule_file", None))

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        def rule(
            rule_id: str,
            title: str,
            severity: Severity,
            category: Category,
            message: str,
            remediation: str,
        ) -> DeclaredRule:
            return DeclaredRule(
                id=rule_id,
                title=title,
                severity=severity,
                confidence=Confidence.HIGH
                if category is not Category.OPERATIONAL
                else Confidence.CONFIRMED,
                category=category,
                detector=RuleFileDetector.id,
                message=message,
                references=(REFERENCE,),
                remediation=remediation,
            )

        return (
            rule(MATCH_RULE, "An operator's rule matched this file", Severity.HIGH, Category.SUSPICIOUS,
                 "A rule from the rule file named with --rule-file matched this file.",
                 "Read the rule that matched and decide; the rule's author states what it detects."),
            rule(MALICIOUS_RULE, "An operator's rule identifies this file as malware", Severity.CRITICAL, Category.MALICIOUS,
                 "A rule whose metadata declares it a malware signature matched this file.",
                 "Remove the file and find out how it entered the repository."),
            rule(STATUS_RULE, "The rule file examined the scan's files", Severity.INFO, Category.OPERATIONAL,
                 "Every file in this scan was also matched against the named rule file.", "None needed."),
            rule(UNAVAILABLE_RULE, "A rule file was asked for and could not be used", Severity.INFO, Category.OPERATIONAL,
                 "The scan was asked to use a rule file and could not, so no file was matched against it.",
                 "Check the rules file compiles, and that it imports only modules Cordon's engine implements."),
            rule(UNMATCHED_RULE, "A file could not be matched against the rule file", Severity.HIGH,
                 Category.SUSPICIOUS,
                 "Matching this file against the rule file stopped before an answer: it ran past the time allowed, a pattern needed more threads than the engine runs, a string had more places to try than the engine holds for one file, or a module could not read the file. A file can be built to do any of these on purpose, so it is not passed as clean.",
                 "Inspect the file: a large run of one repeated byte, a format the rule's strings occur in everywhere, or a malformed header is what stops a match."),
            rule(SHAPE_RULE, "A rule reads a field two engines declare differently, and did not say which", Severity.INFO,
                 Category.OPERATIONAL,
                 "A field with two shapes (one per rule engine) was read in the reference engine's shape because nothing in the rule decided.",
                 "Compare the field with a value of the shape you mean (an integer or a text, a 40-digit hex string or raw bytes), or read a name only one engine has."),
        )  # fmt: skip

    def _ensure(self, ctx: ScanContext) -> RuleFileEngine | None:
        if self._engine is None and self._failed is None:
            try:
                self._engine = RuleFileEngine(
                    str(ctx.config.rule_file),
                    tuple(ctx.config.rule_module_data),
                    use_cache=ctx.config.use_cache,
                    workers=getattr(getattr(ctx.config, "limits", None), "max_workers", 0)
                    or os.cpu_count()
                    or 1,
                )
            except Exception as exc:  # noqa: BLE001
                self._failed = (
                    f"the rules could not be loaded: {type(exc).__name__}: {str(exc)[:200]}"
                )
        return self._engine

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        engine = self._ensure(ctx)
        if isinstance(unit, RepositoryUnit):
            if engine is None:
                return [
                    self._operational(
                        UNAVAILABLE_RULE,
                        f"A rule file was requested and could not be used: {self._failed}.",
                        ctx,
                    )
                ]
            without = "".join(
                f" The rules import {name}, which reads data given to the scan, and none was "
                f"given (--rule-module-data {name}=FILE): its functions answered without it."
                for name in engine.without
            )
            return [
                self._operational(
                    STATUS_RULE,
                    f"Files were also matched against the rule file ({engine.version}), with the "
                    f"{Automaton.status()}.{without}",
                    ctx,
                ),
                *(
                    self._operational(SHAPE_RULE, f"Rule {name}: {note}.", ctx)
                    for name, note in engine.notes
                ),
            ]
        if not isinstance(unit, FileUnit) or engine is None:
            return ()
        if engine.facts and ctx.scan_facts is None:
            return ()  # matched in the deferred pass, with the scanner's facts (`defers`)
        facts = engine.fact_modules(unit, ctx) if engine.facts else None
        try:
            matches = engine.match(unit.content.raw, facts)
        except Exception as exc:  # noqa: BLE001
            refused = [
                self._operational(
                    UNAVAILABLE_RULE,
                    f"The rule file could not be matched against {unit.content.path}: {type(exc).__name__}.",
                    ctx,
                )
            ]
            # every failure here comes from the file being matched (the rule file compiled when the
            # engine was built): one an attacker can cause, so it fails the gate, never passes clean
            refused.append(self._unmatched(unit, exc, ctx))
            return refused
        found = [
            self._finding(unit, match, ctx)
            for match in matches
            if RuleFileEngine.applies(match, unit.content.path)
        ]
        if engine.layered and "#" not in unit.path:
            found += self._layered(engine, unit, {str(m.rule) for m in matches}, ctx, facts)
        return found

    def defers(self, ctx: ScanContext) -> bool:
        """Whether this scan's files are matched after detection, in the engine's deferred pass:
        the rules import a module reading the scanner's facts (`modules.scanner_facts`), which
        exist only once every detector has run. A rule set importing none of them is matched
        during detection, as before."""
        engine = self._ensure(ctx) if self.applicable(ctx) else None
        return bool(engine is not None and engine.facts)

    def _layered(
        self,
        engine: RuleFileEngine,
        unit: FileUnit,
        matched: set[str],
        ctx: ScanContext,
        facts: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """The rules that ask for decoded layers, over each layer under the file's bytes
        (`rule_layers`), each match naming its layer. A rule that matched the raw bytes is not
        reported again for a layer; a layer that cannot be matched fails as the raw file does."""
        from cordon_scanner.detect.binary.rule_layers import RuleLayers

        out: list[Finding] = []
        for layer in RuleLayers.of(unit.content.raw):
            try:
                matches = engine.match(layer.data, facts)
            except Exception as exc:  # noqa: BLE001
                out.append(
                    self._operational(
                        UNAVAILABLE_RULE,
                        f"The rule file could not be matched against {unit.content.path}'s layer "
                        f"decoded from {layer.how}: {type(exc).__name__}.",
                        ctx,
                    )
                )
                out.append(self._unmatched(unit, exc, ctx))  # as the raw file: never passed clean
                continue
            for match in matches:
                name = str(match.rule)
                if (
                    name in engine.layered
                    and name not in matched
                    and RuleFileEngine.applies(match, unit.content.path)
                ):
                    matched.add(name)
                    out.append(self._finding(unit, match, ctx, layer=(layer.how, layer.depth)))
        return out

    @staticmethod
    def _meta(match: Any) -> dict[str, Any]:
        meta = getattr(match, "meta", None)
        return meta if isinstance(meta, dict) else {}

    def _finding(
        self, unit: FileUnit, match: Any, ctx: ScanContext, layer: tuple[str, int] | None = None
    ) -> Finding:
        name = str(getattr(match, "rule", "unnamed"))[:128]
        meta = self._meta(match)
        malicious = str(meta.get("category", "")).lower() == "malicious"
        rule_id = MALICIOUS_RULE if malicious else MATCH_RULE
        severity = Severity.CRITICAL if malicious else Severity.HIGH
        named = str(meta.get("severity", "")).lower()
        if named and not malicious:
            with contextlib.suppress(ValueError):
                severity = Severity.parse(named)
        category = Category.MALICIOUS if malicious else Category.SUSPICIOUS
        return Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=Confidence.HIGH,
            message=(
                f"The rule {name} matched this file."
                if layer is None
                else f"The rule {name} matched this file's layer decoded from {layer[0]} "
                f"(layer {layer[1]})."
            )
            + (f" {str(meta['description'])[:300]}" if meta.get("description") else ""),
            location=Location(path=unit.content.path, project=unit.project),
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(f"{name}:".encode() + unit.content.raw[:65536]),
                redaction=RedactionMode.HASH_ONLY,
                metadata=(("rule", name),)
                + (() if layer is None else (("layer", layer[0]), ("depth", str(layer[1])))),
            ),
            remediation=next(r.remediation for r in self.declared_rules() if r.id == rule_id),
            explanation=Explanation(summary=f"rule {name} matched", matched_rule=rule_id),
            risk=ctx.scorer.score(severity, Confidence.HIGH),
            detector=self.id,
            references=(REFERENCE,),
        )

    @staticmethod
    def why(exc: BaseException) -> str:
        """What stopped the match, from the error and the errors it was raised from."""
        reasons: list[str] = []
        seen: BaseException | None = exc
        for _ in range(8):
            if seen is None:
                break
            text = str(seen) or type(seen).__name__
            if text not in reasons:
                reasons.append(text)
            seen = seen.__cause__
        return "; ".join(reasons)

    def _unmatched(self, unit: Any, exc: BaseException, ctx: ScanContext) -> Finding:
        """The failed match as a finding that fails the gate: a file that stops a match is not passed."""
        message = f"{unit.content.path} could not be matched against the rule file ({RuleFileDetector.why(exc)})."
        return Finding(
            rule_id=UNMATCHED_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(path=str(unit.content.path)),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(f"{UNMATCHED_RULE}:{message}".encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation=next(
                r.remediation for r in self.declared_rules() if r.id == UNMATCHED_RULE
            ),
            explanation=Explanation(summary=message, matched_rule=UNMATCHED_RULE),
            risk=ctx.scorer.score(Severity.HIGH, Confidence.CONFIRMED),
            detector=self.id,
            references=(REFERENCE,),
            degrades_coverage=True,
        )

    def _operational(self, rule_id: str, message: str, ctx: ScanContext) -> Finding:
        return Finding(
            rule_id=rule_id,
            category=Category.OPERATIONAL,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(path="."),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(f"{rule_id}:{message}".encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation=next(r.remediation for r in self.declared_rules() if r.id == rule_id),
            explanation=Explanation(summary=message, matched_rule=rule_id),
            risk=ctx.scorer.score(Severity.INFO, Confidence.CONFIRMED),
            detector=self.id,
            references=(REFERENCE,),
            degrades_coverage=rule_id == UNAVAILABLE_RULE,
        )


__all__ = ["RuleFileDetector", "RuleFileEngine"]
