"""The entry point, and the flag that has to be typed.

`cordon-sandbox` runs untrusted code. That is its purpose and it is also the
single most dangerous thing in this repository, so the interface is built to
make the decision explicit and hard to make by accident:

* Nothing runs without `--sandbox`. The flag carries no information the command
  does not already imply -- naming the subcommand and the package would be
  enough for an argument parser. It exists to be typed deliberately, and to make
  a copied command line obviously the thing it is.
* Nothing runs without isolation. A missing container runtime is an error with
  no override, because the alternative is somebody believing they are protected
  while a package installs on their laptop.
* Nothing here is reachable from `cordon-scanner`. The scanner's promise is that
  it never executes what it scans, and a promise with an entry point into
  execution is not one.

Exit codes match the scanner's, so a pipeline can treat the two the same way:
0 nothing observed, 1 something was, 2 the component failed, 3 bad invocation.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from cordon_sandbox.fetch import fetch
from cordon_sandbox.isolation import IsolationError, available_backend
from cordon_sandbox.observe import Run, observe

CLEAN = 0
OBSERVED = 1
FAILED = 2
BAD_INVOCATION = 3

REFUSAL = (
    "cordon-sandbox installs and runs the package you name. Pass --sandbox to "
    "say you meant that. It is not a switch that changes behaviour; it is there "
    "so that running untrusted code is never something you did by accident."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cordon-sandbox",
        description=(
            "Install a package under isolation and report what it did. "
            "This EXECUTES the package. The scanner does not; this is the "
            "separate component that does, and only when asked."
        ),
    )
    parser.add_argument(
        "ecosystem", choices=("npm", "pypi"), help="which registry the package is from"
    )
    parser.add_argument("package", help="package name, optionally with a version specifier")
    parser.add_argument(
        "--sandbox",
        action="store_true",
        help="required. Confirms you intend to execute this package.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the observation record as JSON instead of prose",
    )
    return parser


def render(run: Run) -> str:
    lines = [
        f"ran: {run.command}",
        f"image: {run.image}",
        f"runtime: {run.backend.command} {run.backend.version}",
        "",
        "isolation in effect:",
        *[f"  - {claim}" for claim in run.guarantees],
        "",
    ]

    if not run.observations:
        traced = (
            "This run recorded filesystem effects, exit status, output and the "
            "install's execve and connect calls. What it does not see is "
            "behaviour that needs neither: a package that read a file and held "
            "it, or one that waited out the analysis window."
            if run.traced
            else "This run recorded filesystem effects, exit status and output "
            "and produced no syscall trace, so a package that ran something or "
            "tried to reach somewhere would look exactly like this."
        )
        lines += [
            "observed: nothing worth reporting.",
            "",
            "That is not a clean bill of health. " + traced,
        ]
    else:
        lines.append("observed:")
        lines += [f"  [{o.kind}] {o.detail}" for o in run.observations]

    if run.output_tail.strip():
        lines += ["", "last output from the install:", run.output_tail.rstrip()]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.sandbox:
        print(REFUSAL, file=sys.stderr)
        return BAD_INVOCATION

    try:
        # Isolation is established before anything is downloaded, so a missing
        # runtime is discovered before the network is touched at all.
        backend = available_backend()
        artefact = fetch(args.ecosystem, args.package)
        run = observe(backend, args.ecosystem, artefact)
    except IsolationError as exc:
        print(str(exc), file=sys.stderr)
        return FAILED

    if args.json:
        import json

        print(
            json.dumps(
                {
                    "command": run.command,
                    "image": run.image,
                    "runtime": f"{run.backend.command} {run.backend.version}",
                    "isolation": list(run.guarantees),
                    "exit_status": run.exit_status,
                    "timed_out": run.timed_out,
                    "syscalls_traced": run.traced,
                    "observations": [
                        {"kind": o.kind, "detail": o.detail} for o in run.observations
                    ],
                },
                indent=2,
            )
        )
    else:
        print(render(run))

    return OBSERVED if run.observations else CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
