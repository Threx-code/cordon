"""What `scan` adds to a finished result when a flag asks for it: checks that run after the engine,
over the packages the scan holds."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.foundation.errors import ConfigError, CordonError
from cordon_scanner.foundation.models import Severity
from cordon_scanner.version import PROGRAM

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
        from cordon_scanner.engine.pipeline.operational import OperationalFinding
        from cordon_scanner.engine.pipeline.releases import ReleaseChecks
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
                        ReleaseChecks.package_check(
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

    @staticmethod
    def add_release_diff(
        args: argparse.Namespace, target: Path, result: Any, config: Any, selected: Any
    ) -> Any:
        """The scan result, plus what this release adds over the one before it.

        `--compare-with` names the earlier artefact. Without it, `--online` and a published npm or
        PyPI artefact fetch the previous release from the registry. A comparison that cannot be
        made is said, never silently skipped.
        """
        from dataclasses import replace as _replace

        from cordon_scanner import Scanner
        from cordon_scanner.detect.supply import release_diff
        from cordon_scanner.sources import previous as previous_release

        compare_with = getattr(args, "compare_with", None)
        if not compare_with and not (args.online and target.is_file()):
            return result
        with previous_release.PreviousRelease.workspace() as work:
            publisher_change = ""
            try:
                if compare_with:
                    earlier = Path(compare_with)
                    if not earlier.exists():
                        raise CordonError(f"--compare-with: {earlier} does not exist")
                    label = earlier.name
                else:
                    named = getattr(args, "package_identity", None)
                    identity = (
                        previous_release.Identity(*named)
                        if named and named[0] not in ("npm", "pypi") and named[2]
                        else previous_release.PreviousRelease.identify(target)
                    )
                    if identity is None:
                        return result
                    found = previous_release.PreviousRelease.fetch_previous(identity, work)
                    if found is None:
                        if not args.quiet:
                            print(
                                f"no earlier release of {identity.name} to compare with",
                                file=sys.stderr,
                            )
                        return result
                    earlier, label, publisher_change = (
                        found.path,
                        found.label,
                        found.publisher_change,
                    )
            except (OSError, ValueError, KeyError) as exc:
                print(f"{PROGRAM}: release comparison skipped: {exc}", file=sys.stderr)
                return result
            old = Scanner(config, detectors=selected).scan(earlier)
        changes = release_diff.ReleaseDiff.compare(
            release_diff.Profile.of(result), release_diff.Profile.of(old), previous=label
        )
        if publisher_change:
            changes.append(
                release_diff.Change(
                    release_diff.RELEASE_NEW_PUBLISHER,
                    Severity.MEDIUM,
                    "package.json",
                    publisher_change
                    + " A new publishing account on an established package is how most "
                    "maintainer-takeover compromises first show.",
                )
            )
        if not args.quiet:
            print(
                f"compared with {label}: "
                + (
                    ", ".join(sorted({c.rule_id.split(".")[2].lower() for c in changes}))
                    if changes
                    else "no new install hooks, capabilities, obfuscation or binaries"
                ),
                file=sys.stderr,
            )
        if not changes:
            return result
        added = release_diff.ReleaseDiff.as_findings(changes, result)
        return _replace(
            result,
            findings=tuple(sorted((*result.findings, *added), key=lambda f: -f.severity.value)),
        )

    @staticmethod
    def add_manifest_confusion(
        args: argparse.Namespace, target: Path, result: ScanResult, config: Any
    ) -> ScanResult:
        """`--online` and a published npm tarball: does the registry describe this tarball?"""
        from dataclasses import replace as _replace

        from cordon_scanner.decide.policy import SuppressionMatcher
        from cordon_scanner.detect.supply.manifest_confusion import ManifestConfusion
        from cordon_scanner.intel.malware.feed import FeedClient

        offline = not args.online or args.offline or FeedClient.offline_requested()
        if offline or not target.is_file():
            return result
        added = list(SuppressionMatcher(config).apply(ManifestConfusion.check(target)))
        if not added:
            return result
        return _replace(
            result,
            findings=tuple(sorted((*result.findings, *added), key=lambda f: -f.severity.value)),
        )

    @staticmethod
    def add_secret_history(
        args: argparse.Namespace, target: Path, result: ScanResult, config: Any
    ) -> ScanResult:
        """`--history` and `--verify-secrets`: findings from git history and from the issuers."""
        from dataclasses import replace as _replace

        if not getattr(args, "history", False) and not getattr(args, "verify_secrets", False):
            return result
        from cordon_scanner.decide.policy import SuppressionMatcher
        from cordon_scanner.detect.secrets.secret_history import (
            HistorySecretScan,
            SecretLiveness,
            SecretValues,
        )
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        root = target if target.is_dir() else target.parent
        added: list[Finding] = []
        history_blobs: dict[tuple[str, str], bytes] = {}
        if getattr(args, "history", False):
            scan = HistorySecretScan(root, config, RuleSet(RuleLoader.load_builtin()))
            added.extend(scan.run())
            history_blobs = scan.blob_contents
        if getattr(args, "verify_secrets", False):
            values = SecretValues(root, history_blobs)
            added.extend(SecretLiveness().verify([*result.findings, *added], values))
            history_blobs.clear()
        if not added:
            return result
        added = list(SuppressionMatcher(config).apply(added))
        findings = tuple(sorted((*result.findings, *added), key=lambda f: -f.severity.value))
        complete = result.complete and not any(f.degrades_coverage for f in added)
        return _replace(result, findings=findings, complete=complete)


__all__ = ["ScanEnrichment"]
