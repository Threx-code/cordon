"""An identity token from a CI provider's own agent program, for the CIs that hand one out that way.

Buildkite and CircleCI give a job its OIDC token through their agent's command line
(`buildkite-agent oidc request-token`, `circleci run oidc get`) rather than an environment
variable or an endpoint. `keyless.OidcToken` names the command; this runs it: the program found on
`PATH`, fixed arguments, no shell, a time limit, and the output accepted only when it has a JSON
Web Token's three parts. Nothing it runs comes from the network.

Kept apart from `keyless`, which talks to the network, so that each file does one of the two.
"""

from __future__ import annotations

import shutil
import subprocess


class CiAgentToken:
    """`request(argv)`: the token the CI's agent prints, or None."""

    @staticmethod
    def request(argv: list[str]) -> str | None:
        path = shutil.which(argv[0])
        if path is None:
            return None
        try:
            done = subprocess.run(  # noqa: S603 - fixed arguments, no shell
                [path, *argv[1:]], capture_output=True, text=True, timeout=60, check=False
            )
        except (OSError, subprocess.SubprocessError):
            return None
        token = done.stdout.strip()
        return token if done.returncode == 0 and token.count(".") == 2 else None


__all__ = ["CiAgentToken"]
