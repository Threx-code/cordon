"""Scan orchestration.

The engine is the application core. It knows the *shape* of a scan -- which
phases run, in what order, with what feeding what -- and nothing about how any
individual step is implemented. It holds references to protocols, never to
concrete detectors, ecosystems or reporters.

That separation is what makes the rest of the architecture work. A new detector
is registered, not wired in. A new output format never touches this file. And
because detectors are pure functions over immutable units, moving execution from
a loop to a process pool to a distributed queue is a deployment decision rather
than a rewrite.

Phases:

    Source -> Inventory -> Plan -> Execute -> Correlate -> Judge

Each has one input type and one output type, so a phase can be replaced,
parallelised or cached without disturbing its neighbours.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from cordon.core.config import Config
from cordon.core.content import FileContent, Skipped
from cordon.core.errors import DetectorError
from cordon.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Hook,
    LanguageStat,
    Location,
    RedactionMode,
    Repository,
    RiskScore,
    ScanResult,
    ScanStats,
    Severity,
)
from cordon.core.policy import SuppressionMatcher, filter_for_reporting
from cordon.core.scoring import RiskScorer
from cordon.core.walker import Walker
from cordon.detect.base import FileUnit, ScanContext
from cordon.langs.registry import identify_language
from cordon.rules.loader import RuleSet, load_builtin_rules
from cordon.version import SCHEMA_VERSION, __version__

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from cordon.detect.base import Detector

NO_RISK = RiskScore(value=0, base=0, confidence_multiplier=1.0)


@dataclass
class _Accumulator:
    """Mutable state for one scan.

    Deliberately local to a single run. The engine itself holds no per-scan
    state, which is what makes one Scanner instance reusable and safe to share.
    """

    findings: list[Finding] = field(default_factory=list)
    complete: bool = True
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    rules_evaluated: int = 0


class Engine:
    """Runs the phases. Holds no per-scan state."""

    def __init__(
        self,
        config: Config,
        *,
        rules: RuleSet | None = None,
        detectors: Sequence[Detector] | None = None,
    ) -> None:
        self.config = config
        self.rules = rules if rules is not None else RuleSet(load_builtin_rules())
        self.detectors = tuple(detectors) if detectors is not None else self._default_detectors()
        self.scorer = RiskScorer()

    @staticmethod
    def _default_detectors() -> tuple[Detector, ...]:
        from cordon.core.registry import default_detectors

        return default_detectors()

    # -- Entry point -----------------------------------------------------

    def scan(self, target: str | Path) -> ScanResult:
        """Scan a target and return a complete, sorted result."""
        started = time.monotonic()
        acc = _Accumulator()

        root = Path(target).resolve()
        inventory = self.inventory(root, acc)
        ctx = self._context(inventory)

        deadline = started + self.config.limits.total_timeout

        for unit in self._units(root, inventory, acc, deadline):
            for detector in self.detectors:
                if not self._detector_enabled(detector, ctx):
                    continue
                acc.findings.extend(self._run(detector, unit, ctx, acc))

        # A suppression that expired is reported, not merely inactive: the
        # finding it was hiding reappears at the same moment somebody is told
        # why, rather than as an unexplained new failure weeks later.
        matcher = SuppressionMatcher(self.config)
        acc.findings.extend(matcher.expiry_findings())
        findings = matcher.apply(acc.findings)

        result = ScanResult(
            findings=findings,
            repository=inventory,
            stats=ScanStats(
                files_scanned=acc.files_scanned,
                files_skipped=acc.files_skipped,
                bytes_scanned=acc.bytes_scanned,
                rules_evaluated=len(self.rules),
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            complete=acc.complete,
            schema_version=SCHEMA_VERSION,
            engine_version=__version__,
            rulepack_version=self.rules.packs[0].version if self.rules.packs else "0.0.0",
            rulepack_hash=self.rules.content_hash,
            config_hash=self.config.fingerprint(),
        )

        return filter_for_reporting(result, self.config).sorted()

    # -- Phase 0: inventory ----------------------------------------------

    def inventory(self, root: Path, acc: _Accumulator | None = None) -> Repository:
        """Determine what the target is.

        Consumed by every detector's applicability check, which is what makes
        detector selection automatic rather than configured. A user should not
        have to declare that their repository contains Terraform; the tool should
        observe it.
        """
        walker = self._walker()
        languages: dict[str, tuple[int, int]] = {}
        evidence: dict[str, set[str]] = {}
        hooks: list[Hook] = []
        total_bytes = 0
        file_count = 0

        for entry in walker.walk(root):
            if entry.is_symlink:
                continue
            file_count += 1
            total_bytes += entry.size

            language = identify_language(entry.rel_path)
            if language:
                files, size = languages.get(language, (0, 0))
                languages[language] = (files + 1, size + entry.size)
                evidence.setdefault(language, set()).add(
                    f"*{Path(entry.rel_path).suffix}" if Path(entry.rel_path).suffix else entry.rel_path
                )

            hooks.extend(self._hooks_for(entry.rel_path))

        stats = tuple(
            LanguageStat(
                language=language,
                files=files,
                bytes=size,
                share=(size / total_bytes) if total_bytes else 0.0,
                evidence=tuple(sorted(evidence.get(language, ()))),
            )
            # Sorted by size then name: byte-weighted ranking reflects what the
            # repository actually is better than file count, which over-weights
            # many small config files. The name breaks ties so the order is
            # deterministic.
            for language, (files, size) in sorted(
                languages.items(), key=lambda kv: (-kv[1][1], kv[0])
            )
        )

        if acc is not None and walker.stats.limit_hit:
            acc.complete = False

        return Repository(
            root=str(root),
            languages=stats,
            hooks=tuple(hooks),
            file_count=file_count,
            total_bytes=total_bytes,
        )

    @staticmethod
    def _hooks_for(rel_path: str) -> Iterator[Hook]:
        """Identify paths that execute during install, build or version control.

        First-class because execution context is the largest single multiplier in
        the risk model. Detecting these before scanning is what lets the same
        capability pair be quiet in application code and decisive here.

        This is the filename-level pass. Manifest lifecycle scripts are found by
        the manifest detector, which can parse them properly.
        """
        name = rel_path.rpartition("/")[2]
        if name in {"setup.py", "conanfile.py", "build.rs", "binding.gyp"}:
            yield Hook(kind="build", path=rel_path, name=name)
        elif rel_path.startswith(".githooks/") or "/.git/hooks/" in f"/{rel_path}":
            yield Hook(kind="githook", path=rel_path, name=name)
        elif rel_path.startswith(".github/workflows/"):
            yield Hook(kind="ci", path=rel_path, name=name)

    # -- Phase 1: planning and unit production ---------------------------

    def _walker(self) -> Walker:
        return Walker(
            exclude=self.config.exclude,
            include=self.config.include,
            limits=self.config.limits,
        )

    def _context(self, inventory: Repository) -> ScanContext:
        return ScanContext(
            config=self.config,
            rules=self.rules,
            repository=inventory,
            install_hook_paths=frozenset(h.path for h in inventory.hooks),
            scorer=self.scorer,
            offline=self.config.offline,
        )

    def _units(
        self,
        root: Path,
        inventory: Repository,
        acc: _Accumulator,
        deadline: float,
    ) -> Iterator[FileUnit]:
        """Produce one unit per scannable file.

        A generator rather than a list, so memory stays bounded on a repository
        of unknown size. That is a security property as much as an efficiency
        one: the input is attacker-controlled and its size is not known in
        advance.
        """
        walker = self._walker()

        for entry in walker.walk(root):
            if time.monotonic() > deadline:
                # A partial result a human can act on beats a stack trace, and
                # marking it partial is what stops it being read as a pass.
                acc.complete = False
                acc.findings.append(
                    _operational(
                        path=str(root),
                        rule_id="OPERATIONAL.SCAN.TIMEOUT",
                        message=(
                            f"The scan exceeded its {self.config.limits.total_timeout:.0f}s "
                            f"budget and stopped early. Results are partial."
                        ),
                        remediation=(
                            "Raise limits.total_timeout, narrow the scan with --include, "
                            "or scan projects individually."
                        ),
                    )
                )
                return

            if entry.is_symlink:
                acc.files_skipped += 1
                acc.findings.append(
                    _operational(
                        path=entry.rel_path,
                        rule_id="OPERATIONAL.FILE.SYMLINK",
                        message="Symbolic link was recorded but not followed.",
                        remediation="No action needed. Links are never dereferenced.",
                        severity=Severity.INFO,
                    )
                )
                continue

            loaded = FileContent.load(entry.real_path, entry.rel_path, self.config.limits)
            if isinstance(loaded, Skipped):
                acc.files_skipped += 1
                acc.complete = False
                acc.findings.append(
                    _operational(
                        path=entry.rel_path,
                        rule_id="OPERATIONAL.FILE.UNREADABLE",
                        message=f"File could not be read ({loaded.reason}); it was not scanned.",
                        remediation="Check permissions, or exclude the path deliberately.",
                    )
                )
                continue

            acc.files_scanned += 1
            acc.bytes_scanned += len(loaded.raw)

            yield FileUnit(content=loaded, language=identify_language(entry.rel_path))

        if walker.stats.limit_hit:
            acc.complete = False
            acc.findings.append(
                _operational(
                    path=str(root),
                    rule_id="OPERATIONAL.SCAN.LIMIT",
                    message=f"Traversal stopped early: {walker.stats.limit_hit}",
                    remediation="Raise the relevant limit or narrow the scan.",
                )
            )

        # An exclusion matching nothing is either a mistake or a hole held open
        # for a file that does not exist yet. Both are worth surfacing: commit a
        # file at that path and it would be skipped by the very check meant to
        # examine it.
        for pattern in walker.stats.unmatched_patterns:
            acc.findings.append(
                _operational(
                    path=pattern,
                    rule_id="POLICY.EXCLUDE.UNMATCHED",
                    category=Category.POLICY,
                    severity=Severity.LOW,
                    message=(
                        f"Exclusion pattern {pattern!r} matched nothing. An exclusion "
                        f"for a path that does not exist silently skips any file later "
                        f"committed there."
                    ),
                    remediation="Remove the pattern, or correct it to match its intended path.",
                )
            )

    # -- Phase 2: execution ----------------------------------------------

    def _detector_enabled(self, detector: Detector, ctx: ScanContext) -> bool:
        if not self.config.detector_enabled(detector.id):
            return False
        if detector.requires.network and ctx.offline:
            return False
        return detector.applicable(ctx)

    def _run(
        self, detector: Detector, unit: FileUnit, ctx: ScanContext, acc: _Accumulator
    ) -> list[Finding]:
        """Run one detector over one unit, containing its failures.

        A detector that raises must not abort the scan, because one broken
        detector silently reducing coverage across every file is far worse than
        one loud finding saying it broke. The scan continues and reports itself
        as incomplete.
        """
        try:
            produced = list(detector.inspect(unit, ctx))
        except Exception as exc:
            acc.complete = False
            return [
                _operational(
                    path=unit.path,
                    rule_id="OPERATIONAL.DETECTOR.FAILED",
                    message=(
                        f"Detector {detector.id!r} failed on this file, so its checks "
                        f"did not run: {type(exc).__name__}: {exc}"
                    ),
                    remediation="Report this with the file that triggered it.",
                    severity=Severity.MEDIUM,
                )
            ]

        # The engine asserts that findings are located within the unit they came
        # from. A detector that reports about a file it was not given is a bug,
        # and silently accepting it would make findings untraceable.
        for finding in produced:
            if (
                finding.category is not Category.OPERATIONAL
                and finding.location.path != unit.path
            ):
                raise DetectorError(
                    f"detector {detector.id!r} produced a finding for "
                    f"{finding.location.path!r} while inspecting {unit.path!r}"
                )
        return produced


def _operational(
    *,
    path: str,
    rule_id: str,
    message: str,
    remediation: str,
    category: Category = Category.OPERATIONAL,
    severity: Severity = Severity.INFO,
) -> Finding:
    """Build a finding about the scan itself.

    Every degradation produces one of these. A file that was not examined is
    indistinguishable in the output from one that was examined and found clean,
    so coverage loss must always be stated rather than inferred.
    """
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        message=message,
        location=Location(path=path),
        evidence=Evidence(
            kind=EvidenceKind.METADATA,
            match_hash=Evidence.hash_bytes(f"{rule_id}:{path}".encode()),
            redaction=RedactionMode.NONE,
        ),
        remediation=remediation,
        explanation=Explanation(
            summary="Reported so that reduced coverage is never silent.",
            matched_rule=rule_id,
        ),
        risk=NO_RISK,
        detector="engine",
    )


__all__ = ["Engine"]
