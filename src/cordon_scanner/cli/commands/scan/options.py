"""`scan`'s options, one method per argument group, in the order its help lists them."""

from __future__ import annotations

import argparse
import os

from cordon_scanner.cli.dependency_payload import DependencyPayload
from cordon_scanner.version import PROGRAM


class ScanOptions:
    @classmethod
    def add_parser(cls, sub: argparse._SubParsersAction, epilog: str) -> None:  # type: ignore[type-arg]
        scan = sub.add_parser(
            "scan",
            help="scan a directory, file or archive",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=epilog,
        )
        scan.add_argument(
            "target",
            nargs="?",
            default=".",
            help=(
                "path to scan (default: .), or a package URL such as pkg:npm/name@1.0.0 "
                "(npm, pypi, cargo, gem, nuget, golang, hex, pub, maven), or a container image as "
                "pkg:docker/nginx@1.27, pulled from its registry; needs --online"
            ),
        )

        cls._add_host(scan)
        cls._add_secrets(scan)
        cls._add_selection(scan)
        cls._add_rules(scan)
        cls._add_policy(scan)
        execution = scan.add_argument_group("execution")
        cls._add_execution(execution)
        cls._add_assessment(execution)
        cls._add_lookups(execution)
        cls._add_reporting(execution)

    @staticmethod
    def _add_host(scan: argparse.ArgumentParser) -> None:
        """`--host` and `--home`: a machine's own installs rather than a repository."""
        host_group = scan.add_argument_group("host")
        host_group.add_argument(
            "--host",
            action="store_true",
            help=(
                "read TARGET as the root of an installed system (default /): its OS packages and the "
                "language packages installed outside any project, matched for known vulnerabilities "
                "and malicious releases (OS packages with --online). Files are not content-scanned"
            ),
        )
        host_group.add_argument(
            "--home",
            metavar="DIR",
            default=None,
            help="with --host, also read this user's own installs (pipx, ~/.local, ~/go/bin, cargo install)",
        )

    @staticmethod
    def _add_secrets(scan: argparse.ArgumentParser) -> None:
        """`--history` and `--verify-secrets`."""
        secrets_group = scan.add_argument_group("secrets")
        secrets_group.add_argument(
            "--history",
            action="store_true",
            help="also read every blob in git history that is no longer in the tree, for secrets",
        )
        secrets_group.add_argument(
            "--verify-secrets",
            action="store_true",
            help="ask each found credential's own issuer whether it still works (needs --online)",
        )

    @staticmethod
    def _add_selection(scan: argparse.ArgumentParser) -> None:
        """Which files are read: includes, excludes and the git modes."""
        selection = scan.add_argument_group("selection")
        selection.add_argument(
            "--include",
            action="append",
            metavar="GLOB",
            help="restrict to matching paths (repeatable)",
        )
        selection.add_argument(
            "--exclude", action="append", metavar="GLOB", help="skip matching paths (repeatable)"
        )

        git_mode = selection.add_mutually_exclusive_group()
        git_mode.add_argument(
            "--staged",
            action="store_true",
            help="scan the content staged in git, not the working tree (for pre-commit hooks)",
        )
        git_mode.add_argument(
            "--tracked",
            action="store_true",
            help="scan only files git tracks, skipping build output and ignored paths",
        )
        git_mode.add_argument(
            "--git-diff",
            metavar="REF",
            help="scan only files that differ from REF",
        )

    @staticmethod
    def _add_rules(scan: argparse.ArgumentParser) -> None:
        """Which detectors run, and the rules and advisories they use."""
        rules = scan.add_argument_group("detectors and rules")
        rules.add_argument(
            "--detector",
            action="append",
            metavar="ID",
            help="run only these detectors (repeatable)",
        )
        rules.add_argument(
            "--no-detector",
            action="append",
            metavar="ID",
            help="disable a detector (organisation policy may forbid this)",
        )
        rules.add_argument(
            "--rules", action="append", metavar="PATH", help="additional rule pack (repeatable)"
        )
        rules.add_argument(
            "--advisories",
            metavar="PATH",
            help=(
                "advisory database to use instead of the bundled one, as JSON. "
                "How an air-gapped site stays current without network access."
            ),
        )

    @staticmethod
    def _add_policy(scan: argparse.ArgumentParser) -> None:
        """Thresholds, the failure policy, configuration and the report formats."""
        policy = scan.add_argument_group("policy and output")
        policy.add_argument(
            "--severity", metavar="LEVEL", help="report at or above: info|low|medium|high|critical"
        )
        policy.add_argument(
            "--confidence", metavar="LEVEL", help="report at or above: low|medium|high|confirmed"
        )
        policy.add_argument(
            "--fail-on", metavar="LEVEL", help="fail the build at or above this severity"
        )
        policy.add_argument(
            "--fail-on-incomplete", action="store_true", help="treat a degraded scan as a failure"
        )
        policy.add_argument(
            "--hardening",
            action="store_true",
            help=(
                "report pipeline, container and infrastructure hardening findings at their own "
                "severity instead of recording them at LOW"
            ),
        )
        policy.add_argument(
            "--baseline",
            metavar="PATH",
            help="treat findings recorded in this file as already-known",
        )
        policy.add_argument(
            "--vex",
            metavar="PATH",
            action="append",
            default=None,
            help=(
                "an OpenVEX or CycloneDX VEX document (repeatable): a vulnerability a statement "
                "rules out (not_affected, fixed) is marked suppressed with its justification"
            ),
        )
        policy.add_argument("--config", metavar="PATH", help="repository configuration file")
        policy.add_argument("--policy", metavar="PATH", help="organisation policy file")
        policy.add_argument(
            "--format",
            "-f",
            action="append",
            metavar="FMT[:PATH]",
            help=(
                "text|json|sarif|junit|markdown|github. Repeatable. "
                "Append :PATH to write that format to a file, "
                "for example --format sarif:cordon.sarif"
            ),
        )
        policy.add_argument(
            "--output",
            "-o",
            metavar="PATH",
            help="write to a file (only valid with a single --format)",
        )
        policy.add_argument(
            "--evidence",
            metavar="MODE",
            choices=["none", "masked", "hash_only"],
            help=(
                "none|masked|hash_only (default: masked). The stricter of this "
                "and each rule's own policy wins, so `none` only takes effect "
                "for rules that permit it -- no shipped rule does."
            ),
        )

    @staticmethod
    def _add_execution(execution: argparse._ArgumentGroup) -> None:
        """Time and cache limits, the network mode, the release comparison and the
        dependency payload."""
        execution.add_argument(
            "--timeout", type=float, metavar="SECONDS", help="total wall-clock budget"
        )
        execution.add_argument(
            "--no-cache", action="store_true", help="ignore and do not write the incremental cache"
        )
        execution.add_argument(
            "--cache-dir", metavar="PATH", help="where to keep the incremental cache"
        )
        execution.add_argument(
            "--jobs",
            "-j",
            type=int,
            metavar="N",
            help="worker processes (0 or unset means automatic)",
        )
        execution.add_argument(
            "--offline",
            action="store_true",
            default=None,
            help=(
                "forbid all network access, including the signed intel feed (air-gapped "
                "use; CORDON_OFFLINE=1 does the same). The intel's age is still reported"
            ),
        )
        execution.add_argument(
            "--online",
            action="store_true",
            help=(
                "permit the detectors that query a package registry (npm and pypi "
                "only; other ecosystems are reported as unasked). Off by default; "
                "an organisation policy forbidding network access still wins, and a "
                "config found inside the scan target can never set it"
            ),
        )
        execution.add_argument(
            "--compare-with",
            metavar="PATH",
            help=(
                "an earlier release of the same package; report what this one adds -- a new "
                "install hook, new network or execution capability, new obfuscation or binaries. "
                "With --online and a published npm or PyPI artefact, the previous release is "
                "fetched from the registry instead"
            ),
        )
        DependencyPayload.add_argument(execution)
        execution.add_argument(
            "--allow-network",
            action="store_true",
            help=(
                "permit the one network operation there is: fetching a --policy "
                "URL, which must carry a #sha256= digest. Never used for scanning"
            ),
        )

    @staticmethod
    def _add_assessment(execution: argparse._ArgumentGroup) -> None:
        """Reachability, notifications, Cordon's own model and the second-opinion judge."""
        execution.add_argument(
            "--reachability",
            action="store_true",
            help=(
                "annotate vulnerability findings with import reachability: a vuln "
                "in a transitive dependency no first-party code imports is lowered "
                "and tagged (never dropped). Reads every source file to collect imports"
            ),
        )
        execution.add_argument(
            "--notify",
            metavar="CHANNELS",
            help=(
                "when the gate fails, post one message to each channel: webhook, slack, "
                "teams (comma-separated). URLs come only from CORDON_NOTIFY_WEBHOOK, "
                "CORDON_NOTIFY_SLACK and CORDON_NOTIFY_TEAMS; the webhook is signed with "
                "CORDON_NOTIFY_WEBHOOK_SECRET. A failed delivery never changes the exit code"
            ),
        )
        execution.add_argument(
            "--model",
            metavar="SERVER",
            default=None,
            help=(
                "also have Cordon's own detection model score the packages this scan holds (a scanned "
                "package archive, archives in the tree, installed node_modules and site-packages): "
                "cordon-cloud (`cordon-scanner login`), or the https:// address of a cordon-model-server "
                "with its token in CORDON_MODEL_TOKEN. Sends features -- counts and hashed identifiers "
                "-- never source"
            ),
        )
        execution.add_argument(
            "--judge",
            metavar="MODEL",
            default=os.environ.get("CORDON_JUDGE") or None,
            help=(
                "also have a language model judge agent-facing text (instruction files, skills, "
                "MCP tool descriptions, hook commands): cordon-cloud (recommended; "
                f"`{PROGRAM} login`), anthropic[:<model>], openai:<model>, or ollama:<model> to keep "
                "everything on this machine. Off by default; only agent-facing text is sent, and "
                "the report says whether it ran (env: CORDON_JUDGE)"
            ),
        )
        execution.add_argument(
            "--judge-blocks",
            action="store_true",
            help="report a malicious verdict from --judge at HIGH, inside the default gate (default: it warns)",
        )
        execution.add_argument(
            "--judge-max-calls",
            type=int,
            default=200,
            metavar="N",
            help="the most model calls --judge may make in one scan (default 200)",
        )

    @staticmethod
    def _add_lookups(execution: argparse._ArgumentGroup) -> None:
        """Private registries, signing keyrings, extra rule files and ClamAV."""
        execution.add_argument(
            "--registry-token",
            dest="registry_tokens",
            action="append",
            metavar="URL=VARIABLE",
            default=[os.environ["CORDON_REGISTRY_TOKENS"]]
            if os.environ.get("CORDON_REGISTRY_TOKENS")
            else [],
            help=(
                "with --online, ask a private registry about what was resolved from it, presenting "
                "the token held in the environment variable named (repeatable; never the token "
                "itself). Never set from a repository's configuration (env: CORDON_REGISTRY_TOKENS)"
            ),
        )
        execution.add_argument(
            "--keyring",
            dest="keyrings",
            action="append",
            metavar="FILE",
            default=[
                p for p in os.environ.get("CORDON_KEYRINGS", "").split(os.pathsep) if p.strip()
            ],
            help=(
                "with --online, verify a Helm chart's provenance file and an Ansible collection's "
                "signatures against the OpenPGP keys in FILE, as `helm verify --keyring` and "
                "`ansible-galaxy collection verify --keyring` do: armored, binary or a GnuPG keybox "
                "(repeatable). Never set from a repository's own "
                "configuration (env: CORDON_KEYRINGS, separated by the path separator)"
            ),
        )
        execution.add_argument(
            "--rule-file",
            metavar="RULES",
            default=os.environ.get("CORDON_RULE_FILE") or None,
            help="also match every file against a cordon-rule rule file (`builtin` for the pack "
            "shipped with Cordon). Off by default; never set from a repository's own "
            "configuration (env: CORDON_RULE_FILE)",
        )
        execution.add_argument("--yara", dest="rule_file_old", help=argparse.SUPPRESS)
        execution.add_argument(
            "--clamav",
            metavar="SOCKET",
            default=os.environ.get("CORDON_CLAMAV") or None,
            help=(
                "also hand each file to a local ClamAV daemon: a Unix socket path, or "
                "tcp://127.0.0.1:3310. Off by default; the report says whether it ran. "
                "Never set from a repository's own configuration (env: CORDON_CLAMAV)"
            ),
        )

    @staticmethod
    def _add_reporting(execution: argparse._ArgumentGroup) -> None:
        """The upload and the organisation policy from Cordon Cloud, archive expansion, and
        what the terminal shows."""
        execution.add_argument(
            "--upload",
            action="store_true",
            help=(
                "send the results to Cordon Cloud after the scan (K2: an in-toto statement "
                "over the JSON results, signed keylessly with the CI identity when sigstore is "
                f"installed). Needs `{PROGRAM} login` or a CI OIDC token. A failed upload is "
                "reported and never changes the exit code"
            ),
        )
        execution.add_argument(
            "--cloud-policy",
            action="store_true",
            help=(
                "apply the organisation policy and approved suppressions from Cordon Cloud, "
                "verified against the policy key pinned at sign-in. Replaces --policy. If no "
                "current, verified bundle is available the scan does not run (exit 3)"
            ),
        )
        execution.add_argument(
            "--cloud-url",
            metavar="URL",
            default=None,
            help="Cordon Cloud API base (default: CORDON_CLOUD_URL, else https://api.cordon.dev)",
        )
        execution.add_argument(
            "--no-expand",
            action="store_true",
            help=(
                "do not open archives found inside a directory scan. Faster, and the "
                "scan is then marked incomplete if any archive went unopened"
            ),
        )
        execution.add_argument("--quiet", "-q", action="store_true", help="findings only")
        execution.add_argument("--verbose", "-v", action="store_true", help="more detail")
        execution.add_argument("--no-color", action="store_true", help="disable colour")
        execution.add_argument(
            "--audit-log",
            metavar="PATH",
            help=(
                "append one JSON line per scan recording what ran and what was "
                "suppressed; never file content"
            ),
        )
        execution.add_argument(
            "--progress",
            choices=("auto", "always", "never"),
            default="auto",
            help=(
                "show a live progress line on stderr; auto means only when "
                "stderr is an interactive terminal"
            ),
        )


__all__ = ["ScanOptions"]
