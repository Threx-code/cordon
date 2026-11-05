"""`runner`: take scan jobs from Cordon Cloud and run them inside the operator's own network,
connecting outbound only."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.version import PROGRAM


class RunnerCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        runner = sub.add_parser(
            "runner",
            help="run scan jobs from Cordon Cloud inside your own network (outbound only)",
        )
        runner.add_argument("--url", default=None, help="Cordon Cloud API base")
        runner.add_argument(
            "--allow-host",
            action="append",
            default=[],
            metavar="HOST",
            help="a host the runner may clone or download from (repeat); jobs naming any other are refused",
        )
        runner.add_argument(
            "--label", action="append", default=[], help="a label jobs can target (repeat)"
        )
        runner.add_argument(
            "--git-credential",
            action="append",
            default=[],
            metavar="HOST=ENV",
            help=(
                "clone private repositories on HOST with the credential in environment variable "
                "ENV: a token, or user:token (repeat). For GitLab and Bitbucket, which cannot "
                "mint a token per clone"
            ),
        )
        runner.add_argument(
            "--id", default=None, help="this runner's name (default: the host name)"
        )
        runner.add_argument(
            "--work-dir", default=None, help="where job workspaces are created and removed"
        )
        runner.add_argument("--once", action="store_true", help="take at most one job, then exit")
        runner.add_argument(
            "--allow-online",
            action="store_true",
            help="let jobs ask for registry lookups (off: the cloud cannot turn on network use here)",
        )
        runner.add_argument(
            "--make-fixes",
            action="store_true",
            help=(
                "also take fix jobs: move one npm or PyPI dependency to a safe version in its lockfile "
                "and push a branch (no package manager or package code is run). Off by default"
            ),
        )

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        import socket

        from cordon_scanner.cloud import CloudEndpoint, CloudError, runner

        token = os.environ.get("CORDON_RUNNER_TOKEN", "")
        if not token:
            raise ConfigError(
                "CORDON_RUNNER_TOKEN is not set",
                hint="Create a runner token in the dashboard and pass it in the environment, never as a flag.",
            )
        if not args.allow_host:
            raise ConfigError(
                "a runner needs at least one --allow-host",
                hint="Name the hosts it may clone from, for example --allow-host github.com.",
            )
        try:
            url = CloudEndpoint.base_url(args.url)
        except CloudError as exc:
            raise ConfigError(str(exc)) from exc
        credentials = []
        for spec in args.git_credential:
            host, _, variable = spec.partition("=")
            if host.lower() not in {h.lower() for h in args.allow_host}:
                raise ConfigError(
                    f"--git-credential names {host!r}, which is not an --allow-host",
                    hint="A credential is only ever sent to a host the runner may clone from.",
                )
            value = os.environ.get(variable, "") if variable else ""
            if not value:
                raise ConfigError(
                    f"--git-credential {spec}: the environment variable {variable or '(none)'} is empty",
                    hint="Pass the credential in the environment, never as a flag.",
                )
            credentials.append(runner.CloudRunner.git_credential(host, value))
        config = runner.RunnerConfig(
            url=url,
            token=token,
            runner_id=args.id or socket.gethostname(),
            allowed_hosts=frozenset(h.lower() for h in args.allow_host),
            labels=tuple(args.label),
            work_dir=Path(args.work_dir) if args.work_dir else Path(tempfile.gettempdir()),
            git_credentials=tuple(credentials),
            make_fixes=bool(getattr(args, "make_fixes", False)),
            allow_online=bool(getattr(args, "allow_online", False)),
        )
        print(f"{PROGRAM}: runner {config.runner_id} polling {url}", file=sys.stderr)
        runner.CloudRunner.serve(
            config,
            once=args.once,
            log=lambda line: print(f"{PROGRAM}: {line}", file=sys.stderr),
        )
        return int(ExitCode.CLEAN)


__all__ = ["RunnerCommand"]
