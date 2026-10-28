"""`config validate`, `config fetch-policy`, `config policy-drift` and `config explain`: checking a
configuration, and the organisation policy that bounds it."""

from __future__ import annotations

import argparse
from pathlib import Path

from cordon_scanner.foundation.errors import ConfigError, ExitCode


class ConfigCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        config_cmd = sub.add_parser("config", help="check configuration")
        config_sub = config_cmd.add_subparsers(dest="config_command", metavar="<action>")
        validate = config_sub.add_parser("validate", help="validate a configuration file")
        fetch_policy = config_sub.add_parser(
            "fetch-policy",
            help="fetch a digest-pinned organisation policy once, so scans read it offline",
        )
        fetch_policy.add_argument("url", help="https://host/policy.yaml#sha256=<64 hex>")
        drift = config_sub.add_parser(
            "policy-drift",
            help="check a vendored policy copy against the published one (exit 1 when they differ)",
        )
        drift.add_argument("vendored", help="the copy in this repository")
        drift.add_argument(
            "--published",
            required=True,
            help="the published policy: a path, or its URL with #sha256=<hex> (compared by digest, nothing fetched)",
        )
        validate.add_argument("path", nargs="?", default=None)
        validate.add_argument("--policy", metavar="PATH")
        explain = config_sub.add_parser("explain", help="show effective settings and their origin")
        explain.add_argument("path", nargs="?", default=None)
        explain.add_argument("--policy", metavar="PATH")

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        from cordon_scanner.foundation.config import Config
        from cordon_scanner.foundation.config_resolver import ConfigResolver

        action = args.config_command or "validate"

        if action == "validate":
            config = Config.from_file(args.path) if args.path else Config.discover(".")
            if args.policy:
                from cordon_scanner.foundation.config_resolver import ConfigResolver

                org, constraints = ConfigResolver.load_org_policy(args.policy)
                config.clamped_by(org, constraints)
            print("configuration is valid")
            return int(ExitCode.CLEAN)

        if action == "fetch-policy":
            from cordon_scanner.engine.cache import ScanCache
            from cordon_scanner.foundation.distribution import PolicyDistribution

            if not PolicyDistribution.is_remote(args.url):
                raise ConfigError(
                    "fetch-policy takes the policy's https URL with its #sha256= digest"
                )
            # The one network request this command exists for, to the URL the operator named, and
            # its content is fixed by the digest. Scans then read the cached copy with the network
            # off -- which is what a policy saying `allow_network: false` asks of them.
            cached = PolicyDistribution.resolve(
                args.url, allow_network=True, cache_dir=ScanCache.default_cache_dir()
            )
            ConfigResolver.load_org_policy(cached)
            print(f"verified and cached: {cached}")
            print(f"scan with --policy '{args.url}'; no network is needed from now on")
            return int(ExitCode.CLEAN)

        if action == "policy-drift":
            from cordon_scanner.foundation.distribution import PolicyDistribution

            vendored = Path(args.vendored)
            if not vendored.is_file():
                raise ConfigError(f"no policy at {vendored}")
            actual = PolicyDistribution.digest_of(vendored)
            expected = PolicyDistribution.published_digest(args.published)
            if actual == expected:
                print(f"{vendored} matches the published policy (sha256 {actual})")
                return int(ExitCode.CLEAN)
            print(
                f"{vendored} has drifted from the published policy: sha256 {actual}, published {expected}. "
                "A drifted copy is a ceiling nobody set; replace it, or point --policy at the published one."
            )
            return int(ExitCode.FINDINGS)

        if action == "explain":
            config = ConfigResolver.resolve(
                root=".", config_path=args.path, policy_path=args.policy
            )
            print("effective configuration\n")
            print(f"  severity_threshold    {config.severity_threshold}")
            print(f"  confidence_threshold  {config.confidence_threshold}")
            print(f"  evidence              {config.evidence}")
            print(f"  offline               {config.offline}")
            print(f"  fail_on               {config.policy.fail_on_severity}")
            print(
                f"  fail_on_categories    "
                f"{', '.join(sorted(str(c) for c in config.policy.fail_on_categories))}"
            )
            print(
                f"  suppressions          {len(config.suppressions)} "
                f"({len(config.active_suppressions())} active)"
            )
            print(f"  config hash           {config.fingerprint()}")
            if config.provenance:
                print("\norigins")
                for entry in config.explain():
                    print(f"  {entry}")
            return int(ExitCode.CLEAN)

        raise ConfigError(f"unknown config action: {action}")


__all__ = ["ConfigCommand"]
