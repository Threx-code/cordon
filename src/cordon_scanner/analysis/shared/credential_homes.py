"""Where a credential belongs: the service that issued it and the only one it authenticates to.

A credential has a HOME (`CREDENTIAL_HOMES`): a GitHub client sends `GITHUB_TOKEN` to
`api.github.com`, a publisher sends `NPM_TOKEN` to the registry. A generic `MY_SERVICE_API_KEY` has
none we can know. Some hosts exist to hold other services' credentials (`CREDENTIAL_CUSTODIANS`: a
CI provider's variables API, a secrets manager), and sending one there is their purpose. An AWS
secret access key or session token has no home at all: AWS clients sign with it and never send it.

These are facts about credentials and hosts, read by the Python and JavaScript analysis and by the
named-credential flows in `detect/code/secretflow.py`, which judge them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

#: Hosts whose purpose is holding other services' credentials: CI variables and secret stores. A
#: tool that registers a deployment credential with one of them sends the raw value, legitimately.
CREDENTIAL_CUSTODIANS: Final = (
    "app.terraform.io",
    "api.github.com",
    "gitlab.com",
    "circleci.com",
    "api.travis-ci.com",
    "api.travis-ci.org",
    "vault.",
    "doppler.com",
    "1password.com",
    "api.vercel.com",
    "api.netlify.com",
    "api.heroku.com",
    "api.render.com",
    "api.fly.io",
    "backboard.railway.app",
    "infisical.com",
    "akeyless.io",
    "bitwarden.com",
    "buildkite.com",
    "dev.azure.com",
    "bitbucket.org",
)


@dataclass(frozen=True)
class Home:
    """Where one family of credentials belongs: host suffixes, or words a self-hosted copy of the
    service carries in its name (`github.mycorp.com`, `npm.internal.example`)."""

    service: str
    suffixes: tuple[str, ...] = ()
    words: tuple[str, ...] = ()
    homeless: bool = False
    """Never sent by a legitimate client, to anyone (AWS signs with its secret key)."""


#: Credential names, matched against the whole environment variable name, and their homes.
CREDENTIAL_HOMES: Final[tuple[tuple[re.Pattern[str], Home], ...]] = (
    (
        re.compile(r"^AWS_(?:SECRET_ACCESS_KEY|SESSION_TOKEN)$"),
        Home("AWS", homeless=True),
    ),
    (
        re.compile(
            r"^(?:GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|GH_PAT|GITHUB_API_TOKEN|GITHUB_ACCESS_TOKEN)$"
        ),
        Home(
            "GitHub",
            (
                "github.com",
                "githubusercontent.com",
                "ghcr.io",
                "githubapp.com",
                "ghe.com",
            ),
            ("github", "ghe"),
        ),
    ),
    (
        re.compile(
            r"^(?:NPM_TOKEN|NODE_AUTH_TOKEN|NPM_AUTH_TOKEN|NPM_CONFIG__AUTH|NPM_CONFIG_TOKEN)$"
        ),
        Home(
            "npm",
            ("npmjs.org", "npmjs.com", "npm.pkg.github.com", "yarnpkg.com"),
            ("npm", "registry", "artifactory", "jfrog", "nexus", "verdaccio", "pkg", "repo"),
        ),
    ),
    (
        re.compile(
            r"^(?:PYPI_TOKEN|PYPI_API_TOKEN|PYPI_PASSWORD|TWINE_PASSWORD|TEST_PYPI_API_TOKEN)$"
        ),
        Home(
            "PyPI",
            ("pypi.org", "pythonhosted.org"),
            ("pypi", "artifactory", "jfrog", "nexus", "devpi", "pkg", "repo"),
        ),
    ),
    (
        re.compile(
            r"^(?:CI_JOB_TOKEN|GITLAB_TOKEN|GITLAB_PRIVATE_TOKEN|GITLAB_API_TOKEN|CI_REGISTRY_PASSWORD)$"
        ),
        Home("GitLab", ("gitlab.com", "gitlab.io"), ("gitlab",)),
    ),
    (
        re.compile(r"^(?:SLACK_BOT_TOKEN|SLACK_TOKEN|SLACK_USER_TOKEN|SLACK_APP_TOKEN)$"),
        Home("Slack", ("slack.com",), ()),
    ),
    (
        re.compile(r"^(?:DOCKER_PASSWORD|DOCKERHUB_TOKEN|DOCKER_HUB_TOKEN|DOCKERHUB_PASSWORD)$"),
        Home("Docker Hub", ("docker.io", "docker.com"), ("docker", "registry", "harbor")),
    ),
    (
        re.compile(r"^(?:STRIPE_SECRET_KEY|STRIPE_API_KEY)$"),
        Home("Stripe", ("stripe.com",), ()),
    ),
    (
        re.compile(r"^(?:CLOUDFLARE_API_TOKEN|CLOUDFLARE_API_KEY|CF_API_TOKEN)$"),
        Home("Cloudflare", ("cloudflare.com",), ()),
    ),
    (
        re.compile(r"^(?:DIGITALOCEAN_TOKEN|DIGITALOCEAN_ACCESS_TOKEN|DO_API_TOKEN)$"),
        Home("DigitalOcean", ("digitalocean.com",), ()),
    ),
    (
        re.compile(r"^(?:HEROKU_API_KEY)$"),
        Home("Heroku", ("heroku.com",), ()),
    ),
    (
        re.compile(r"^(?:DISCORD_TOKEN|DISCORD_BOT_TOKEN)$"),
        Home("Discord", ("discord.com", "discordapp.com", "discord.gg"), ()),
    ),
    (
        re.compile(r"^(?:CARGO_REGISTRY_TOKEN)$"),
        Home("crates.io", ("crates.io",), ("cargo", "crates", "registry", "artifactory", "jfrog")),
    ),
    (
        re.compile(r"^(?:GEM_HOST_API_KEY|RUBYGEMS_API_KEY)$"),
        Home("RubyGems", ("rubygems.org",), ("gem", "artifactory", "jfrog", "nexus")),
    ),
    (
        re.compile(r"^(?:NUGET_API_KEY|NUGET_AUTH_TOKEN)$"),
        Home("NuGet", ("nuget.org",), ("nuget", "artifactory", "jfrog", "nexus", "pkgs.dev.azure")),
    ),
)

_HOST: Final = re.compile(r"^[a-z][a-z0-9+.-]*://(?:[^@/\s]*@)?(\[[0-9a-f:.]+\]|[^/:?#\s]+)", re.I)


class SecretFlow:
    """Where a credential belongs, and whether a host is outside it."""

    @staticmethod
    def home_of(name: str) -> Home | None:
        for pattern, home in CREDENTIAL_HOMES:
            if pattern.match(name):
                return home
        return None

    @staticmethod
    def host_of(url: str) -> str | None:
        found = _HOST.match(url.strip())
        return found.group(1).lower().strip("[]") if found else None

    @staticmethod
    def misdirected(name: str, host: str | None) -> bool:
        """Whether sending the credential `name` to `host` is outside its home.

        An unknown host is never misdirected: a URL a user configures names nothing.
        """
        home = SecretFlow.home_of(name)
        if home is None or not host:
            return False
        if host in ("localhost", "127.0.0.1", "::1") or host.endswith((".local", ".internal")):
            return False
        if any(
            host == c or host.endswith("." + c) or host.startswith(c) for c in CREDENTIAL_CUSTODIANS
        ):
            return False
        if home.homeless:
            return True
        if any(host == s or host.endswith("." + s) for s in home.suffixes):
            return False
        labels = re.split(r"[.-]", host)
        return not any(word in labels or host.startswith(word) for word in home.words)


__all__ = ["CREDENTIAL_CUSTODIANS", "CREDENTIAL_HOMES", "Home", "SecretFlow"]
