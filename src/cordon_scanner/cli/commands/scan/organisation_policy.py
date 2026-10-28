"""`scan --cloud-policy`: the organisation's signed policy bundle from Cordon Cloud, its approved
suppressions, and the gate mode that decides whether a failing verdict fails the build."""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING, Any

from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from cordon_scanner.foundation.results import ScanResult


class OrganisationPolicy:
    @staticmethod
    def exit_code(verdict: Any, bundle: Any, result: ScanResult, *, quiet: bool) -> int:
        """The exit code the pipeline sees: the verdict's, unless the organisation's bundle puts
        this repository's gate in `observe` or `warn`, where a failing verdict is reported and
        recorded but does not fail the build. Without a bundle the verdict stands unchanged."""
        code = int(verdict.exit_code)
        if bundle is None or code == int(ExitCode.CLEAN):
            return code
        from cordon_scanner.foundation.targets import TargetName

        key = TargetName.of(result)
        mode = bundle.gate_mode(key)
        if mode not in ("observe", "warn"):
            return code
        if not quiet:
            print(
                f"{PROGRAM}: {key} is in {mode} mode: the verdict is recorded, the build is not failed",
                file=sys.stderr,
            )
        return int(ExitCode.CLEAN)

    @staticmethod
    def fetch(args: argparse.Namespace) -> tuple[Any, str | None]:
        """Fetch and verify the organisation's bundle; no bundle, no scan."""
        from cordon_scanner.cloud import CloudError, auth, policy
        from cordon_scanner.intel.malware.feed import FeedClient

        try:
            credentials = auth.CloudAuth.current(args.cloud_url)
            bundle = policy.CloudPolicy.fetch(
                credentials, offline=bool(args.offline) or FeedClient.offline_requested()
            )
        except CloudError as exc:
            raise ConfigError(
                f"the organisation policy could not be applied: {exc}",
                hint=f"Run `{PROGRAM} login`, or connect once so a current bundle is cached.",
            ) from exc
        if args.verbose:
            print(
                f"{PROGRAM}: organisation policy v{bundle.version} ({bundle.source}, "
                f"key {bundle.key_id}, {len(bundle.suppressions)} approved suppression(s))",
                file=sys.stderr,
            )
        path = policy.CloudPolicy.materialise(bundle)
        return bundle, str(path) if path is not None else None

    @staticmethod
    def add_suppressions(config: Any, suppressions: tuple[Any, ...]) -> Any:
        """Add the organisation's approved suppressions, held to the same rules as any other."""
        from cordon_scanner.foundation.config.parser import ConfigParser

        problems = [
            f"{s.rule} at {s.path}: {problem}"
            for s in suppressions
            if (problem := ConfigParser._suppression_violation(s, config.constraints))
        ]
        if problems:
            raise ConfigError(
                "suppressions in the organisation's policy bundle are not acceptable:\n  - "
                + "\n  - ".join(problems)
            )
        return config.with_overrides(suppressions=(*config.suppressions, *suppressions))


__all__ = ["OrganisationPolicy"]
