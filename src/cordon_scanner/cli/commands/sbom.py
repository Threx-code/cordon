"""`sbom generate`: a CycloneDX or SPDX bill of materials from the resolved dependency graph."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from cordon_scanner.foundation.errors import ConfigError, CordonError, ExitCode
from cordon_scanner.version import PROGRAM, __version__


class SbomCommand:
    NO_DECLARED_VERSION = "0.0.0"
    """Stands for "this target declares no version of its own".

    Also the value emitted when nothing better is found, so a document always
    carries a version string -- both specifications want one.
    """

    @classmethod
    def add_parser(cls, sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        sbom = sub.add_parser(
            "sbom", help="generate or inspect a bill of materials for a scan target"
        ).add_subparsers(dest="sbom_command")
        sbom_generate = sbom.add_parser(
            "generate", help="write a CycloneDX or SPDX document from the resolved graph"
        )
        sbom_generate.add_argument("target", nargs="?", default=".")
        sbom_generate.add_argument("--format", choices=("cyclonedx", "spdx"), default="cyclonedx")
        sbom_generate.add_argument("--output", "-o", metavar="PATH", default=None)
        sbom_generate.add_argument(
            "--exclude",
            action="append",
            default=[],
            metavar="GLOB",
            help="skip matching paths, as `scan --exclude` does (repeatable)",
        )
        sbom_generate.add_argument(
            "--ai",
            action="store_true",
            help=(
                "write the AI bill of materials instead (CycloneDX 1.6): agent instruction, skill "
                "and prompt files, agent settings, MCP servers, models and AI SDKs"
            ),
        )
        sbom_generate.add_argument(
            "--vulnerabilities",
            action="store_true",
            help=(
                "embed the advisory matches (CycloneDX `vulnerabilities`), marking those on "
                "CISA KEV or ENISA EUVD as exploited: the per-release record the EU Cyber "
                "Resilience Act asks a manufacturer to keep"
            ),
        )
        sbom_generate.add_argument(
            "--name",
            metavar="NAME",
            default=None,
            help="root component name (default: directory name)",
        )
        sbom_generate.add_argument(
            "--component-version",
            metavar="VERSION",
            default=cls.NO_DECLARED_VERSION,
            help=(
                "root component version (default: whatever the target's own manifest "
                "declares, or 0.0.0 when it declares none)"
            ),
        )

    @classmethod
    def run(cls, args: argparse.Namespace) -> int:
        """Generate a bill of materials from the resolved dependency graph.

        The counterpart to `SUSPECT.SBOM.DRIFT.001` (`detect/sbom.py`), which
        only ever compares an existing document against this same graph.
        Resolves the graph the same way a scan does -- reading lockfiles and
        manifests, never invoking a package manager (`docs/01-ARCHITECTURE.md`
        C4) -- but with no detectors registered, so nothing is matched against
        a rule and this is materially faster than a full scan.
        """
        action = getattr(args, "sbom_command", None)
        if action is None:
            print(f"{PROGRAM}: sbom needs generate", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)

        if action != "generate":
            raise ConfigError(f"unknown sbom action: {action}")

        from cordon_scanner import Scanner

        target = Path(args.target)
        if not target.exists():
            raise CordonError(
                f"target does not exist: {target}",
                hint="Pass a directory, file or archive path.",
            )

        if getattr(args, "ai", False) and (args.format != "cyclonedx" or not target.is_dir()):
            raise ConfigError(
                "--ai writes CycloneDX for a directory",
                hint="Pass a repository directory and --format cyclonedx (the default).",
            )
        detectors: tuple[Any, ...] = ()
        if getattr(args, "vulnerabilities", False):
            if args.format != "cyclonedx":
                raise ConfigError(
                    "--vulnerabilities needs --format cyclonedx",
                    hint="SPDX 2.3 has no field for vulnerability status; use a VEX document beside it.",
                )
            from cordon_scanner.detect.supply.advisory import AdvisoryDetector

            detectors = (AdvisoryDetector(),)
        from cordon_scanner.foundation.config import Config

        config = Config.default()
        if getattr(args, "exclude", None):
            config = config.with_overrides(exclude=tuple(args.exclude))
        result = Scanner(config, detectors=detectors).scan(target)
        cls._write(args, cls._document(args, target, result, embed=bool(detectors)))

        if not result.complete:
            print(
                f"{PROGRAM}: the scan that produced this graph was incomplete; "
                f"the bill of materials may be missing components",
                file=sys.stderr,
            )
            return int(ExitCode.INCOMPLETE)
        return int(ExitCode.CLEAN)

    @classmethod
    def _document(
        cls, args: argparse.Namespace, target: Path, result: Any, *, embed: bool
    ) -> dict[str, Any]:
        """The document for the format asked for, its root named as the target names itself."""
        from cordon_scanner.report import sbom as sbom_report

        # The scan has already parsed the target's own manifests, so the
        # directory name is a fallback rather than the answer. A project whose
        # package.json says `{"name": "g", "version": "1.0.0"}` was described in
        # its own SBOM as `scan@0.0.0`, taken from whatever the directory
        # happened to be called.
        declared_name, declared_version = cls._root_component(result, target)
        root_name = args.name or declared_name or target.resolve().name or "target"
        root_version = (
            args.component_version
            if args.component_version != cls.NO_DECLARED_VERSION
            else (declared_version or cls.NO_DECLARED_VERSION)
        )

        if getattr(args, "ai", False):
            from cordon_scanner.report import aibom

            document = aibom.AiBom.cyclonedx_document(
                target,
                result.dependencies,
                root_name=root_name,
                root_version=root_version,
                tool_version=__version__,
            )
        elif args.format == "cyclonedx":
            document = sbom_report.SbomDocument.cyclonedx_document(
                result.dependencies,
                root_name=root_name,
                root_version=root_version,
                tool_version=__version__,
            )
            if embed:
                cls._embed_vulnerabilities(document, result)
        else:
            document = sbom_report.SbomDocument.spdx_document(
                result.dependencies,
                root_name=root_name,
                root_version=root_version,
                tool_version=__version__,
            )
        return document

    @staticmethod
    def _write(args: argparse.Namespace, document: dict[str, Any]) -> None:
        """To `--output`, saying how many components it holds, or else to stdout."""
        import json

        payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
        if args.output:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(payload, encoding="utf-8")
            if "packages" in document:
                # SPDX lists the root among its packages, as the one the document DESCRIBES;
                # CycloneDX keeps it apart. Counted the same way, so the two formats agree.
                described = {
                    r.get("relatedSpdxElement")
                    for r in document.get("relationships", ())
                    if r.get("relationshipType") == "DESCRIBES"
                }
                written = sum(1 for p in document["packages"] if p.get("SPDXID") not in described)
            else:
                written = len(document.get("components", ())) + len(document.get("services", ()))
            print(f"wrote {destination} ({written} component(s), {args.format})")
        else:
            sys.stdout.write(payload)

    @staticmethod
    def _root_component(result: object, target: Path) -> tuple[str | None, str | None]:
        """The name and version the target declares for itself, if it does.

        The shallowest manifest wins, and ties break on path, so a monorepo
        with several manifests names the same one on every run -- an SBOM that
        described a different component depending on directory iteration order
        would not be reproducible.

        A manifest that carries no name contributes nothing: the caller falls
        back to the directory, which is a guess clearly labelled as one.
        """
        from cordon_scanner.ecosystems.registry import EcosystemRegistry
        from cordon_scanner.foundation.content import FileContent
        from cordon_scanner.foundation.limits import Limits

        repository = getattr(result, "repository", None)
        projects = sorted(
            getattr(repository, "projects", ()) or (),
            key=lambda p: (p.path.count("/"), p.path),
        )
        for project in projects:
            ecosystem = EcosystemRegistry.get(project.ecosystem)
            if ecosystem is None:
                continue
            for manifest_path in project.manifests:
                loaded = FileContent.load(target / manifest_path, manifest_path, Limits())
                if not isinstance(loaded, FileContent):
                    continue
                try:
                    manifest = ecosystem.parse_manifest(loaded)
                except Exception:  # noqa: BLE001, S112
                    continue
                if manifest.parse_error or not manifest.name:
                    continue
                return (manifest.name, manifest.version)
        return (None, None)

    @staticmethod
    def _embed_vulnerabilities(document: dict[str, Any], result: Any) -> None:
        """Add the advisory matches to a CycloneDX document, and say when one is exploited."""
        from cordon_scanner.report.vex import EXPLOITED_RULE, VULNERABILITY_RULES, VexReporter

        findings = [
            f for f in result.findings if f.rule_id in VULNERABILITY_RULES and not f.is_suppressed
        ]
        document["vulnerabilities"] = [VexReporter._statement(f) for f in findings]
        exploited = [f for f in findings if f.rule_id == EXPLOITED_RULE]
        document["metadata"]["properties"] = [
            {"name": "cordon:vulnerabilities", "value": str(len(findings))},
            {"name": "cordon:exploited", "value": str(len(exploited))},
        ]
        if exploited:
            print(
                f"{PROGRAM}: {len(exploited)} component vulnerabilit"
                f"{'y is' if len(exploited) == 1 else 'ies are'} exploited in the wild (CISA KEV / "
                f"ENISA EUVD). Under the EU Cyber Resilience Act, an actively exploited "
                f"vulnerability in a product you ship is reportable within 24 hours.",
                file=sys.stderr,
            )


__all__ = ["SbomCommand"]
