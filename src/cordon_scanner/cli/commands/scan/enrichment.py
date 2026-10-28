"""What `scan` adds to a finished result when a flag asks for it: checks that run after the engine,
over the packages the scan holds."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.foundation.errors import ConfigError
from cordon_scanner.foundation.models import Severity

if TYPE_CHECKING:
    from cordon_scanner.foundation.models import Finding
    from cordon_scanner.foundation.results import ScanResult


class ScanEnrichment:
    @staticmethod
    def add_model_findings(
        args: argparse.Namespace, target: Path, result: ScanResult, config: Any
    ) -> ScanResult:
        """`--model`: Cordon's own model scores the packages the scan holds (`model/client.py`).

        A model that could not be asked is said, and the scan is incomplete: a check the operator
        asked for and did not get is coverage lost, never a clean result."""
        from dataclasses import replace as _replace

        from cordon_scanner.decide.policy import SuppressionMatcher
        from cordon_scanner.detect.agents.model import MALICIOUS_PACKAGE, UNAVAILABLE
        from cordon_scanner.foundation.results import OperationalFinding
        from cordon_scanner.intel.malware.feed import FeedClient
        from cordon_scanner.model.client import ModelClient, ModelError, ModelTargets

        spec = getattr(args, "model", None)
        if not spec:
            return result
        forbidden = not config.constraints.allow_network
        if args.offline or FeedClient.offline_requested() or forbidden:
            raise ConfigError(
                "--model asks a model server, and this scan may not use the network",
                hint="Drop --offline (or CORDON_OFFLINE), or run without --model.",
            )
        added: list[Finding] = []
        complete = result.complete
        try:
            units, capped = ModelTargets.collect(target)
            if units:
                client = ModelClient.for_target(spec, getattr(args, "cloud_url", None))
                for verdict in client.score(units):
                    if not verdict.malicious:
                        continue
                    by = " and ".join(
                        {"package": "the package as a whole", "file": "its worst file"}[r]
                        for r in verdict.reasons
                    )
                    file_score = (
                        "" if verdict.file_score is None else f", file {verdict.file_score:.3f}"
                    )
                    added.append(
                        OperationalFinding.package_check(
                            path=verdict.location,
                            rule_id=MALICIOUS_PACKAGE,
                            message=(
                                f"Cordon's model scores this package malicious, by {by or 'its score'} "
                                f"(package {verdict.package_score:.3f}{file_score})."
                            ),
                            severity=Severity.HIGH,
                            remediation="Do not install or run it until it has been reviewed.",
                        )
                    )
            if capped:
                complete = False
                added.append(
                    OperationalFinding.build(
                        path=".",
                        rule_id=UNAVAILABLE,
                        message="More packages were found than one scan sends to the model (2,000); the rest were not scored.",
                        remediation="Scan the dependency tree in parts.",
                    )
                )
        except ModelError as exc:
            complete = False
            added.append(
                OperationalFinding.build(
                    path=".",
                    rule_id=UNAVAILABLE,
                    message=f"Cordon's model was not asked: {exc}",
                    remediation="Check the --model address, the sign-in or CORDON_MODEL_TOKEN, and that the server is up.",
                )
            )
        if not added and complete == result.complete:
            return result
        kept = list(SuppressionMatcher(config).apply(added))
        return _replace(
            result,
            complete=complete,
            findings=tuple(sorted((*result.findings, *kept), key=lambda f: -f.severity.value)),
        )


__all__ = ["ScanEnrichment"]
