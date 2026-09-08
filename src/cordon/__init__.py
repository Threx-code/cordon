"""Cordon: a language-agnostic software supply-chain security scanner.

This module is the entire public API. Everything not listed in ``__all__`` is
internal and may change in any release.

The surface is deliberately small. A security tool that other systems embed
needs a contract narrow enough to keep stable, because every exported name is
one that cannot be changed without breaking somebody's pipeline.

    from cordon import Scanner, Config

    scanner = Scanner(Config.from_file("cordon.yaml"))
    result = scanner.scan("./repository")

    for finding in result.findings:
        print(finding.rule_id, finding.severity, finding.location)

Guarantees:

* Everything returned is immutable. A caller cannot mutate a result and
  re-serialise it as though a scan produced it.
* A ``Scanner`` is reusable. Rules are compiled once at construction, not per
  scan, which matters for a long-lived process embedding it.
* Output is deterministic. Identical inputs produce identical findings in a
  stable order.
* Nothing here executes code from the target, and nothing reaches the network
  unless the configuration explicitly permits it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon.core.config import Config, OrgConstraints, Policy, resolve
from cordon.core.errors import (
    ConfigError,
    CordonError,
    DetectorError,
    ExitCode,
    LimitExceeded,
    PolicyViolationError,
    RulePackError,
    SourceError,
    UnsafePatternError,
)
from cordon.core.limits import Limits
from cordon.core.models import (
    Capability,
    Category,
    Confidence,
    Dependency,
    Evidence,
    Finding,
    Hook,
    Location,
    Project,
    RedactionMode,
    Repository,
    RiskScore,
    Rule,
    ScanResult,
    ScanStats,
    Scope,
    Severity,
    Suppression,
)
from cordon.core.policy import Baseline, PolicyGate, Verdict
from cordon.version import RULEPACK_VERSION, SCHEMA_VERSION, __version__

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from pathlib import Path

    from cordon.detect.base import Detector


class Scanner:
    """The entry point.

    Construct once and reuse. Rule compilation and plugin discovery happen here,
    not per scan, so a server embedding Cordon pays that cost at startup rather
    than on every request.
    """

    def __init__(
        self,
        config: Config | None = None,
        *,
        detectors: Sequence[Detector] | None = None,
    ) -> None:
        from cordon.core.engine import Engine
        from cordon.core.registry import Registry
        from cordon.rules.loader import RuleSet, load_builtin_rules

        self.config = config or Config.default()

        packs = list(load_builtin_rules())
        if self.config.extra_rule_paths:
            from cordon.rules.loader import RuleLoader

            loader = RuleLoader()
            packs.extend(loader.load_file(p) for p in self.config.extra_rule_paths)

        self.rules = RuleSet(packs)

        if detectors is None:
            registry = Registry(allow_third_party=self.config.allow_plugins)
            detectors = registry.detectors()

        self._engine = Engine(self.config, rules=self.rules, detectors=detectors)

    def scan(self, target: str | Path) -> ScanResult:
        """Scan a directory, file or archive."""
        return self._engine.scan(target)

    def inventory(self, target: str | Path) -> Repository:
        """Determine what a target is, without scanning its contents."""
        from pathlib import Path as _Path

        return self._engine.inventory(_Path(target).resolve())

    def stream(self, target: str | Path) -> Iterator[Finding]:
        """Yield findings as they are produced.

        For callers that cannot hold a full result in memory. Ordering is
        production order rather than the sorted order ``scan`` guarantees,
        because sorting requires having seen everything.
        """
        yield from self._engine.scan(target).findings


__all__ = [
    "RULEPACK_VERSION",
    "SCHEMA_VERSION",
    "Baseline",
    "Capability",
    "Category",
    "Confidence",
    "Config",
    "ConfigError",
    "CordonError",
    "Dependency",
    "DetectorError",
    "Evidence",
    "ExitCode",
    "Finding",
    "Hook",
    "LimitExceeded",
    "Limits",
    "Location",
    "OrgConstraints",
    "Policy",
    "PolicyGate",
    "PolicyViolationError",
    "Project",
    "RedactionMode",
    "Repository",
    "RiskScore",
    "Rule",
    "RulePackError",
    "ScanResult",
    "ScanStats",
    "Scanner",
    "Scope",
    "Severity",
    "SourceError",
    "Suppression",
    "UnsafePatternError",
    "Verdict",
    "__version__",
    "resolve",
]
