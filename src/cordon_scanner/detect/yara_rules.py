"""Hand every file to YARA, with rules the operator names (`--yara RULES`).

The same arrangement as the ClamAV hand-off: off unless asked for, the rules chosen by whoever runs
the scan and never by the repository being scanned, and a report that says whether it ran. YARA is
where a security team keeps the signatures it trusts -- its own, its vendor's, a feed's -- and this
lets a scan apply them without the team rewriting them as Cordon rules.

`yara-python` is optional and is not a dependency of the package (C1): with it absent, a scan that
asked for YARA says so in an operational finding rather than reporting nothing, because "no rule
matched" and "no rule ran" must never look alike. Rules are compiled once per scan; each file is
matched with a timeout, so a pathological rule cannot hold a scan. A rule's `severity` meta, when
it names one, sets the finding's severity; otherwise a match is HIGH and SUSPICIOUS, because a
YARA rule asserts a pattern, not a verdict -- unless its meta says `category = "malicious"`.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final

from cordon_scanner.core.models import (
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
from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    FileUnit,
    RepositoryUnit,
    ScanContext,
    Unit,
)
from cordon_scanner.detect.catalogue import DeclaredRule

MATCH_RULE: Final = "SUSPECT.YARA.MATCH.001"
MALICIOUS_RULE: Final = "MALWARE.YARA.MATCH.001"
STATUS_RULE: Final = "OPERATIONAL.YARA.STATUS"
UNAVAILABLE_RULE: Final = "OPERATIONAL.YARA.UNAVAILABLE"
REFERENCE: Final = "https://yara.readthedocs.io/en/stable/writingrules.html"
MATCH_TIMEOUT_SECONDS: Final = 10
MAX_RULES_BYTES: Final = 16 << 20


class YaraEngine:
    """Compile once, match many. Imported lazily: the module is optional."""

    def __init__(self, rules_path: str) -> None:
        import yara  # type: ignore[import-not-found]

        path = Path(rules_path)
        if not path.is_file():
            raise OSError(f"no YARA rules file at {rules_path}")
        if path.stat().st_size > MAX_RULES_BYTES:
            raise OSError(f"the YARA rules file is over {MAX_RULES_BYTES} bytes")
        # Compiled from the operator's file. `includes=False`: an include directive would let one
        # rules file pull in others from wherever it names, which is not what was asked for.
        self.rules = yara.compile(filepath=str(path), includes=False)
        self.version = getattr(yara, "__version__", "unknown")
        self.yara = yara

    def match(self, data: bytes) -> list[Any]:
        return list(self.rules.match(data=data, timeout=MATCH_TIMEOUT_SECONDS))


class YaraDetector(BaseDetector):
    id = "yara"
    version = "0.1.0"
    operator_enabled = True
    """Runs only when the operator names a rules file; exercised against a fake engine in tests."""
    categories = frozenset({Category.MALICIOUS, Category.SUSPICIOUS, Category.OPERATIONAL})
    requires = DetectorRequirements(content=True, repository=True)

    def __init__(self) -> None:
        self._engine: YaraEngine | None = None
        self._failed: str | None = None

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(getattr(ctx.config, "yara", None))

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
                detector=YaraDetector.id,
                message=message,
                references=(REFERENCE,),
                remediation=remediation,
            )

        return (
            rule(MATCH_RULE, "An operator's YARA rule matched this file", Severity.HIGH, Category.SUSPICIOUS,
                 "A rule from the YARA rules file named with --yara matched this file.",
                 "Read the rule that matched and decide; the rule's author states what it detects."),
            rule(MALICIOUS_RULE, "An operator's YARA rule identifies this file as malware", Severity.CRITICAL, Category.MALICIOUS,
                 "A YARA rule whose metadata declares it a malware signature matched this file.",
                 "Remove the file and find out how it entered the repository."),
            rule(STATUS_RULE, "YARA examined the scan's files", Severity.INFO, Category.OPERATIONAL,
                 "Every file in this scan was also matched against the named YARA rules.", "None needed."),
            rule(UNAVAILABLE_RULE, "YARA was asked for and could not be used", Severity.INFO, Category.OPERATIONAL,
                 "The scan was asked to use YARA and could not, so no file was matched against the rules.",
                 "Install yara-python and check the rules file compiles: yara-python must be importable."),
        )  # fmt: skip

    def _ensure(self, ctx: ScanContext) -> YaraEngine | None:
        if self._engine is None and self._failed is None:
            try:
                self._engine = YaraEngine(str(ctx.config.yara))
            except ImportError:
                self._failed = "the yara-python module is not installed"
            except Exception as exc:
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
                        f"YARA was requested and could not be used: {self._failed}.",
                        ctx,
                    )
                ]
            return [
                self._operational(
                    STATUS_RULE,
                    f"Files were also matched against YARA rules (yara-python {engine.version}).",
                    ctx,
                )
            ]
        if not isinstance(unit, FileUnit) or engine is None:
            return ()
        try:
            matches = engine.match(unit.content.raw)
        except Exception as exc:
            return [
                self._operational(
                    UNAVAILABLE_RULE,
                    f"YARA could not match {unit.content.path}: {type(exc).__name__}.",
                    ctx,
                )
            ]
        return [self._finding(unit, match, ctx) for match in matches]

    @staticmethod
    def _meta(match: Any) -> dict[str, Any]:
        meta = getattr(match, "meta", None)
        return meta if isinstance(meta, dict) else {}

    def _finding(self, unit: FileUnit, match: Any, ctx: ScanContext) -> Finding:
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
            message=f"The YARA rule {name} matched this file."
            + (f" {str(meta['description'])[:300]}" if meta.get("description") else ""),
            location=Location(path=unit.content.path, project=unit.project),
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(f"{name}:".encode() + unit.content.raw[:65536]),
                redaction=RedactionMode.HASH_ONLY,
                metadata=(("yara_rule", name),),
            ),
            remediation=next(r.remediation for r in self.declared_rules() if r.id == rule_id),
            explanation=Explanation(summary=f"YARA rule {name} matched", matched_rule=rule_id),
            risk=ctx.scorer.score(severity, Confidence.HIGH),
            detector=self.id,
            references=(REFERENCE,),
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


__all__ = ["YaraDetector", "YaraEngine"]
