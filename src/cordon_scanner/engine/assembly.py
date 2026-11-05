"""Putting a scan together: its rules, its detectors and the engine that runs them, in one place.

The public `Scanner` and the engine's own callers (an incoming commit judged against an empty
root) build a scan the same way: the built-in rule packs and any the configuration adds, each
added pack's own samples run first, and the detectors the registry finds unless the caller hands
its own. Here, rather than in `Scanner`, so nothing inside the engine reaches up to the package's
front door to get a scan built.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.detect.base import Detector
    from cordon_scanner.engine.engine import Engine
    from cordon_scanner.engine.progress import Progress
    from cordon_scanner.foundation.config.settings import Config
    from cordon_scanner.sources.base import FileSource


class ScanAssembly:
    """Builds the engine a configuration asks for."""

    @staticmethod
    def engine(
        config: Config,
        *,
        detectors: Sequence[Detector] | None = None,
        source: FileSource | None = None,
        progress: Progress | None = None,
    ) -> Engine:
        from cordon_scanner.engine.engine import Engine
        from cordon_scanner.engine.registry import Registry
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        packs = list(RuleLoader.load_builtin())
        if config.extra_rule_paths:
            from cordon_scanner.foundation.errors import RulePackError
            from cordon_scanner.rules.tester import RuleTester

            loader = RuleLoader()
            for path in config.extra_rule_paths:
                pack = loader.load_file(path)
                # The samples run here too, not only under `cordon-scanner rules test`: a pack whose own
                # samples fail would load and report nothing while the scan looks healthy.
                failures = RuleTester.run(pack)
                if failures:
                    first = failures[0]
                    raise RulePackError(
                        f"{path}: {first.rule_id} fails its own {first.kind} sample: {first.detail}",
                        hint="Run `cordon-scanner rules test` on the pack to see every failing sample.",
                    )
                packs.append(pack)

        shadowed: list[tuple[str, str, str]] = []
        if detectors is None:
            registry = Registry(allow_third_party=config.allow_plugins)
            detectors = registry.detectors()
            # Carried into the engine so a package that tried to take a
            # built-in's name is reported. Skipping it silently would trade a
            # denial of service for a quiet one.
            shadowed = registry.shadowed

        return Engine(
            config,
            rules=RuleSet(packs),
            detectors=detectors,
            source=source,
            progress=progress,
            shadowed=shadowed,
        )


__all__ = ["ScanAssembly"]
