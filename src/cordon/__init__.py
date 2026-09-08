"""Cordon: a language-agnostic software supply-chain security scanner.

This module is the entire public API. Everything not listed in ``__all__`` is
internal and may change in any release.

The surface is deliberately small. A security tool that other systems embed
needs a contract narrow enough to keep stable, because every exported name is
one that cannot be changed without breaking somebody's pipeline.

    from cordon import Scanner

    scanner = Scanner.for_target("./repository")
    result = scanner.scan("./repository")

    for finding in result.findings:
        print(finding.rule_id, finding.severity, finding.location)

``for_target`` is the supported constructor, and this example used to read
``Scanner(Config.from_file("cordon.yaml"))`` instead. That is a bypass:
``Config.from_file`` performs no clamping at all -- not the organisation
ceiling, not the withholding of powers from a configuration that came from
inside the scan target -- so every platform embedding Cordon followed the
documented example and silently ran with no ceiling. Passing a ``Config``
directly is still supported for callers that build one deliberately; it is
simply not the way to load one from disk.

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

from cordon.core.config import Config, ConfigResolver, OrgConstraints, Policy
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
    from collections.abc import Sequence
    from pathlib import Path

    from cordon.detect.base import Detector
    from cordon.sources.base import FileSource


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
        source: FileSource | None = None,
    ) -> None:
        from cordon.core.engine import Engine
        from cordon.core.registry import Registry
        from cordon.rules.loader import RuleLoader, RuleSet

        self.config = config or Config.default()

        packs = list(RuleLoader.load_builtin())
        if self.config.extra_rule_paths:
            from cordon.rules.loader import RuleLoader

            loader = RuleLoader()
            packs.extend(loader.load_file(p) for p in self.config.extra_rule_paths)

        self.rules = RuleSet(packs)

        if detectors is None:
            registry = Registry(allow_third_party=self.config.allow_plugins)
            detectors = registry.detectors()

        self._engine = Engine(self.config, rules=self.rules, detectors=detectors, source=source)

    @classmethod
    def for_target(
        cls,
        target: str | Path,
        *,
        config_path: str | Path | None = None,
        policy_path: str | Path | None = None,
        detectors: Sequence[Detector] | None = None,
        source: FileSource | None = None,
        **overrides: object,
    ) -> Scanner:
        """Build a Scanner with the configuration a scan of `target` implies.

        The supported way to construct one. Routes through
        :meth:`ConfigResolver.resolve`, which is the only place the four
        configuration layers are assembled and the only place the organisation
        ceiling is applied -- including the withholding of powers from a
        configuration file that came from inside the scan target, since that
        file is part of the untrusted input.

        ``Scanner(config)`` remains available for a caller assembling a Config
        deliberately. It does not clamp, because it cannot know where the
        Config came from.
        """
        from pathlib import Path as _Path

        root = _Path(target)
        config = ConfigResolver.resolve(
            root=root if root.is_dir() else root.parent,
            config_path=config_path,
            policy_path=policy_path,
            **overrides,
        )
        return cls(config, detectors=detectors, source=source)

    def scan(self, target: str | Path) -> ScanResult:
        """Scan a directory, file or archive."""
        return self._engine.scan(target)

    def inventory(self, target: str | Path) -> Repository:
        """Determine what a target is, without scanning its contents."""
        from pathlib import Path as _Path

        return self._engine.inventory(_Path(target).resolve())

    # `stream()` used to live here. It was documented "for callers that cannot
    # hold a full result in memory" and implemented as
    # `yield from self._engine.scan(target).findings` -- it ran the entire scan
    # to completion and held everything, giving no streaming benefit whatever to
    # a caller who chose it precisely for that reason.
    #
    # Removed rather than kept with a corrected docstring. The engine cannot
    # stream today: manifest hooks are discovered during the collection pass and
    # change the context every later finding is scored against, so detection
    # cannot begin until that pass completes. A method that cannot do what its
    # name says is worse than an absent one, because a caller reads the name.
    # `limits.max_memory_bytes` is what bounds a scan in the meantime.


__all__ = [
    "RULEPACK_VERSION",
    "SCHEMA_VERSION",
    "Baseline",
    "Capability",
    "Category",
    "Confidence",
    "Config",
    "ConfigError",
    "ConfigResolver",
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
