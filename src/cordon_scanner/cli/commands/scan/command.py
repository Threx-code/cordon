"""`scan`: a directory, file, archive, container image or package URL, run in phases -- the
target, the configuration the flags and the organisation's policy make, the detectors, the scan and
what is added to it, then the baseline and VEX, and last the verdict, the reports and the exit code."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.cli.commands.scan.enrichment import ScanEnrichment
from cordon_scanner.cli.commands.scan.git_modes import GitModes
from cordon_scanner.cli.commands.scan.options import ScanOptions
from cordon_scanner.cli.commands.scan.organisation_policy import OrganisationPolicy
from cordon_scanner.cli.commands.scan.output import ScanOutput
from cordon_scanner.cli.commands.scan.suppression import ScanSuppression
from cordon_scanner.cli.dependency_payload import DependencyPayload
from cordon_scanner.cli.progress import TerminalProgress, TerminalText
from cordon_scanner.engine.audit import AuditLog
from cordon_scanner.foundation.errors import ConfigError, CordonError, ExitCode
from cordon_scanner.foundation.models import Confidence, Severity
from cordon_scanner.foundation.renames import Renamed
from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from cordon_scanner.engine.progress import Progress
    from cordon_scanner.foundation.results import ScanResult
    from cordon_scanner.sources.base import FileSource


class ScanCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction, epilog: str) -> None:  # type: ignore[type-arg]
        ScanOptions.add_parser(sub, epilog)

    @classmethod
    def _scan_package(cls, args: argparse.Namespace) -> int:
        """`scan pkg:<type>/<name>@<version>`: fetch the published archive, verify it, scan it."""
        from cordon_scanner.foundation.errors import SourceError
        from cordon_scanner.intel.malware.feed import FeedClient
        from cordon_scanner.sources.package import PackageTarget, PackageTargetError

        try:
            package = PackageTarget.parse(str(args.target))
        except PackageTargetError as exc:
            raise ConfigError(
                str(exc), hint="Example: cordon-scanner scan pkg:npm/left-pad@1.3.0 --online"
            ) from exc
        if not args.online or args.offline or FeedClient.offline_requested():
            raise ConfigError(
                f"scanning {package.label} asks its registry for the archive, and this scan is offline",
                hint="Pass --online to fetch it. Nothing about your code is sent; only the package name and version.",
            )
        try:
            with package.fetched() as archive:
                print(
                    f"Fetched {package.label} as {archive.name}; digest verified against the registry.",
                    file=sys.stderr,
                )
                # The purl names the package exactly, so the release comparison need not re-identify
                # it from the archive -- which it can only do for npm and PyPI.
                identity = (package.ecosystem, package.name, package.version or "")
                return cls.run(
                    argparse.Namespace(
                        **{**vars(args), "target": str(archive), "package_identity": identity}
                    )
                )
        except PackageTargetError as exc:
            raise SourceError(
                str(exc), hint="Check the name and version exist on the public registry."
            ) from exc

    @classmethod
    def run(cls, args: argparse.Namespace) -> int:
        from cordon_scanner.sources.package import PackageTarget

        if PackageTarget.is_package_url(str(args.target)):
            return cls._scan_package(args)
        target = cls._target(args)
        config, cloud_bundle = cls._configure(args, target, cls._overrides(args))
        selected = cls._detectors(args, config)
        notify = cls._notify(args, config)

        source = GitModes.source(args, target)

        # Checked before the scan, not after it. An audit log that turns out to
        # be unwritable once the work is done leaves an operator with a scan
        # they cannot attest to; failing here makes it a corrected command line.
        audit = AuditLog.prepare(args.audit_log) if args.audit_log else None

        # stderr, never stdout: a report is written to stdout when --output is
        # not given, and a progress line there corrupts the JSON or SARIF a
        # pipeline is parsing.
        progress: Progress | None = None
        if TerminalText.should_show(sys.stderr, args.progress, quiet=args.quiet):
            progress = TerminalProgress(sys.stderr, color=ScanOutput.use_color(args.no_color))

        result = cls._scan(args, target, config, selected, source, progress)
        result = ScanSuppression.apply_baseline(args, result)
        result = ScanSuppression.apply_vex(args, result)
        return cls._finish(args, target, result, config, audit, notify, cloud_bundle)

    @staticmethod
    def _target(args: argparse.Namespace) -> Path:
        """The path the scan reads, once the flags that need the network or a directory agree."""
        if getattr(args, "verify_secrets", False) and (not args.online or args.offline):
            raise ConfigError(
                "--verify-secrets sends each found credential to its own issuer, and this scan is offline",
                hint="Add --online. Values go only to the issuer that minted them, never to Cordon.",
            )

        target = Path("/" if getattr(args, "host", False) and args.target == "." else args.target)
        if not target.exists():
            raise CordonError(
                f"target does not exist: {target}",
                hint="Pass a directory, file, archive path, or a package URL such as pkg:npm/name@1.0.0.",
            )
        if getattr(args, "host", False) and not target.is_dir():
            raise ConfigError(f"--host reads a filesystem root, and {target} is not a directory")
        return target

    @staticmethod
    def _overrides(args: argparse.Namespace) -> dict[str, Any]:
        """The configuration the flags set, before any file or policy is read."""
        from cordon_scanner.foundation.models import RedactionMode

        # A mistyped flag value is the user's mistake, not ours, and the difference
        # is visible in the exit code: 3 says "fix your invocation", 2 says "this is
        # a bug in cordon". Letting a bare ValueError escape reported the second for
        # a `--severity extreme` typo, which is both the wrong code and an
        # accusation against the wrong party.
        overrides: dict[str, Any] = {}
        try:
            if args.severity:
                overrides["severity_threshold"] = Severity.parse(args.severity)
            if args.confidence:
                overrides["confidence_threshold"] = Confidence.parse(args.confidence)
            if args.evidence:
                overrides["evidence"] = RedactionMode(args.evidence)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        if args.exclude:
            overrides["exclude"] = tuple(args.exclude)
        if args.include:
            overrides["include"] = tuple(args.include)
        if args.rules:
            overrides["extra_rule_paths"] = tuple(args.rules)
        # The command line is the operator, so this is the one layer allowed to
        # ask for the network. `--offline` is the default and is accepted as an
        # explicit statement of it; `--online` is what the coverage matrix has
        # always told users to pass. Neither overrides an organisation policy:
        # `stricter_of` takes `self.offline or org.offline`.
        if args.online:
            overrides["offline"] = False
        elif args.offline:
            overrides["offline"] = True
        # `--offline` and CORDON_OFFLINE mean no network at all, the air-gapped mode: the intel
        # feed is not fetched either. Without them the scan still never sends anything about
        # the code; it only pulls the public, signed feed.
        from cordon_scanner.intel.malware.feed import FeedClient

        if args.offline or FeedClient.offline_requested():
            overrides["intel_feed"] = False
        if getattr(args, "reachability", False):
            overrides["reachability"] = True
        if getattr(args, "no_expand", False):
            overrides["expand_archives"] = False
        if getattr(args, "clamav", None):
            overrides["clamav"] = args.clamav
        if getattr(args, "keyrings", None):
            overrides["keyrings"] = tuple(args.keyrings)
        if rule_file := Renamed.rule_file(args, PROGRAM):
            overrides["rule_file"] = rule_file
        if getattr(args, "registry_tokens", None):
            from cordon_scanner.intel.registries.private_registries import PrivateRegistries

            try:
                overrides["private_registries"] = tuple(
                    tuple(r) for r in PrivateRegistries.parse(args.registry_tokens)
                )
            except ValueError as exc:
                raise ConfigError(str(exc)) from exc
        if getattr(args, "judge", None):
            overrides["judge"] = args.judge
            overrides["judge_blocks"] = bool(getattr(args, "judge_blocks", False))
            overrides["judge_max_calls"] = max(1, int(getattr(args, "judge_max_calls", 200)))
        return overrides

    @staticmethod
    def _configure(
        args: argparse.Namespace, target: Path, overrides: dict[str, Any]
    ) -> tuple[Any, Any]:
        """The configuration the scan runs with, and the organisation's bundle when one applies."""
        from cordon_scanner.foundation.config.resolver import ConfigResolver

        cloud_bundle = None
        policy_path = args.policy
        if getattr(args, "cloud_policy", False):
            if args.policy:
                raise ConfigError(
                    "--cloud-policy and --policy both name the organisation policy",
                    hint="Use one: the cloud bundle is the organisation policy when --cloud-policy is set.",
                )
            cloud_bundle, policy_path = OrganisationPolicy.fetch(args)

        config = ConfigResolver.resolve(
            root=target if target.is_dir() else target.parent,
            config_path=args.config,
            policy_path=policy_path,
            allow_network=args.allow_network,
            **overrides,
        )
        if cloud_bundle is not None and cloud_bundle.suppressions:
            config = OrganisationPolicy.add_suppressions(config, cloud_bundle.suppressions)

        if args.no_detector:
            detectors = dict(config.detectors)
            for name in args.no_detector:
                detectors[name] = False
            config = config.with_overrides(detectors=detectors)

        if args.timeout is not None:
            config = config.with_overrides(limits=config.limits.merged(total_timeout=args.timeout))
        if args.no_cache:
            config = config.with_overrides(use_cache=False)
        if args.cache_dir:
            config = config.with_overrides(cache_dir=args.cache_dir)
        if args.jobs is not None:
            config = config.with_overrides(limits=config.limits.merged(max_workers=args.jobs))

        if args.fail_on or args.fail_on_incomplete or getattr(args, "hardening", False):
            from dataclasses import replace as _replace

            policy = config.policy
            if getattr(args, "hardening", False):
                policy = _replace(policy, hardening=True)
            if args.fail_on:
                try:
                    policy = _replace(policy, fail_on_severity=Severity.parse(args.fail_on))
                except ValueError as exc:
                    raise ConfigError(f"--fail-on: {exc}") from exc
            if args.fail_on_incomplete:
                policy = _replace(policy, fail_on_incomplete=True)
            config = config.with_overrides(policy=policy)

        # Re-check the organisation ceiling against the configuration the scan
        # will actually run with. Every override above edits a Config that
        # `resolve()` already validated, so without this the ceiling applies to
        # an intermediate value and not to the real one -- which is how
        # `--no-detector capability` turned a failing build into a passing one
        # against a policy requiring that detector.
        config.recheck_constraints()
        return config, cloud_bundle

    @staticmethod
    def _detectors(args: argparse.Namespace, config: Any) -> Any:
        """The detectors `--detector` and `--advisories` choose, or None for every registered one."""
        from cordon_scanner.engine.registry import Registry

        selected = None
        if args.detector:
            selected = Registry(allow_third_party=config.allow_plugins).detectors(
                only=args.detector
            )

        if args.advisories:
            # Replaces the bundled database rather than adding to it. An
            # organisation that supplies its own is stating what it considers
            # authoritative, and silently merging a shipped list into it would
            # produce findings it did not choose to act on.
            from cordon_scanner.detect.supply.advisories.detector import AdvisoryDetector
            from cordon_scanner.intel.advisories.advisories import AdvisoryDatabase

            database = AdvisoryDatabase.from_file(args.advisories)
            base = selected or Registry(allow_third_party=config.allow_plugins).detectors()
            selected = tuple([d for d in base if d.id != "advisory"] + [AdvisoryDetector(database)])
        return selected

    @staticmethod
    def _notify(args: argparse.Namespace, config: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """The channels to post to and the occasions to post on: the command line's, else the
        configuration's (`notify.channels`, `notify.on`), else no channel and the default occasions.
        Validated before the scan, like the audit log below: an unknown channel is a corrected
        command line, not a message that silently never arrives."""
        from cordon_scanner.notify.notifier import Notifier

        channels_text = getattr(args, "notify", None) or ",".join(config.notify_channels)
        triggers_text = getattr(args, "notify_on", None) or ",".join(config.notify_on)
        try:
            channels = Notifier.parse_channels(channels_text) if channels_text else ()
            triggers = (
                Notifier.parse_triggers(triggers_text)
                if triggers_text
                else Notifier.DEFAULT_TRIGGERS
            )
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        return channels, tuple(triggers)

    @staticmethod
    def _scan(
        args: argparse.Namespace,
        target: Path,
        config: Any,
        selected: Any,
        source: FileSource | None,
        progress: Progress | None,
    ) -> ScanResult:
        """The engine's result, and what the flags add to it once it is finished."""
        from cordon_scanner import Scanner

        if getattr(args, "host", False):
            result = Scanner(config, detectors=selected, progress=progress).scan_host(
                target, args.home
            )
        else:
            result = Scanner(config, detectors=selected, source=source, progress=progress).scan(
                target
            )
            result = ScanEnrichment.add_release_diff(args, target, result, config, selected)
            result = DependencyPayload.applied(args, target, result, config, selected)
            result = ScanEnrichment.add_manifest_confusion(args, target, result, config)
            result = ScanEnrichment.add_secret_history(args, target, result, config)
            result = ScanEnrichment.add_model_findings(args, target, result, config)
        return result

    @staticmethod
    def _finish(
        args: argparse.Namespace,
        target: Path,
        result: ScanResult,
        config: Any,
        audit: AuditLog | None,
        notify: tuple[tuple[str, ...], tuple[str, ...]],
        cloud_bundle: Any,
    ) -> int:
        """The verdict, the reports, the audit record, the notifications and the upload, and the
        exit code the pipeline sees."""
        from cordon_scanner.decide.policy import PolicyGate
        from cordon_scanner.report.base import ReportOptions

        formats = args.format or ["text"]
        # The verdict first: it is a pure function of the result, and the text view prints what
        # fails the gate in full and the rest as one line (`ReportOptions.blocking`).
        verdict = PolicyGate.evaluate(result, config.policy)
        opts = ReportOptions(
            color=ScanOutput.use_color(args.no_color),
            verbose=args.verbose,
            blocking=frozenset(f.fingerprint for f in verdict.triggering),
            quiet=args.quiet,
        )
        ScanOutput.emit(result, formats, args.output, opts, quiet=args.quiet)

        if audit is not None:
            # After the verdict, so the recorded exit code is the one the
            # pipeline actually saw. A write failure here is loud rather than
            # swallowed: a scan nobody can attest to should not look like a
            # scan nobody audited.
            try:
                audit.record(
                    result,
                    exit_code=int(verdict.exit_code),
                    target_kind="archive" if target.is_file() else "directory",
                    policy=args.policy or os.environ.get("CORDON_POLICY") or "",
                )
            except OSError as exc:
                print(f"{PROGRAM}: audit log could not be written: {exc}", file=sys.stderr)
                return int(ExitCode.SCANNER_ERROR)

        if not args.quiet and verdict.exit_code is not ExitCode.CLEAN:
            print(f"\nFAILED: {verdict.reason}", file=sys.stderr)
        channels, triggers = notify
        if channels:
            from cordon_scanner.notify.notifier import Notifier

            # `failed` is the gate's findings exit and `incomplete` its incomplete exit, so the
            # default occasions are exactly when a scan posted before `--notify-on` existed.
            gate = "passed" if verdict.exit_code is ExitCode.CLEAN else "failed"
            complete = verdict.exit_code is not ExitCode.INCOMPLETE
            failed = verdict.exit_code is ExitCode.FINDINGS
            if Notifier.fires(triggers, gate="failed" if failed else "passed", complete=complete):
                deliveries = ScanOutput.notify(
                    channels, result, verdict, gate=gate, verbose=args.verbose
                )
                if audit is not None:
                    try:
                        audit.record_deliveries(deliveries)
                    except OSError as exc:
                        print(f"{PROGRAM}: audit log could not be written: {exc}", file=sys.stderr)
                        return int(ExitCode.SCANNER_ERROR)
        if getattr(args, "upload", False):
            # The upload carries the verdict as it is; Cordon applies the repository's mode too.
            ScanOutput.upload(args, result, verdict, target)
        return OrganisationPolicy.exit_code(verdict, cloud_bundle, result, quiet=args.quiet)


__all__ = ["ScanCommand"]
