"""A named credential sent somewhere it does not belong.

`SUSPECT.EXFIL.ENVIRONMENT.001` catches the whole environment in a request, and the install-hook
composites catch a credential read beside any egress in a script that runs at install. What neither
sees is the careful version: one named credential, read at import or at call time, put in a request
to a host that is not the credential's own service.

Reading one named setting and calling its service is what every API client does -- a GitHub client
sends `GITHUB_TOKEN` to `api.github.com`, a publisher sends `NPM_TOKEN` to the registry -- so the
claim here is narrow and checkable:

* the credential has a HOME: the service that issued it and the only one it authenticates to
  (`CREDENTIAL_HOMES`); a generic `MY_SERVICE_API_KEY` has none we can know, and is not judged;
* the destination is a host written in the file -- a literal, or a name bound to one -- not a
  variable a user configures, which says nothing about where the request goes;
* the host is not the credential's home, nor a service whose purpose is to hold other services'
  credentials (a CI provider's variables API, a secrets manager).

An AWS secret access key or session token has no home at all: AWS clients sign requests with it
and never send it, so the raw value in any request to a host outside that short list is the claim.
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


class JavaScriptFlow:
    """A named credential from `process.env` reaching a request to a host outside its home.

    No parser: JavaScript has none here without a dependency. Statement-level instead -- the names
    bound to `process.env.X` (directly or destructured), the names bound to URL literals, and every
    request call whose argument list mentions one of each. A name rebound in between, or a value
    passed through a function, is not followed; the claim stays narrow rather than guessed.
    """

    _ENV_READ = re.compile(
        r"""process\.env(?:\.([A-Z][A-Z0-9_]*)|\[\s*["'`]([A-Z][A-Z0-9_]*)["'`]\s*\])"""
    )
    _BIND = re.compile(r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)""")
    _DESTRUCTURE = re.compile(r"""(?:const|let|var)\s*\{([^}]*)\}\s*=\s*process\.env\b""")
    _CALL = re.compile(
        r"""(?<![\w$.])(?:fetch|axios(?:\.(?:get|post|put|patch|request))?|got(?:\.(?:get|post|put))?"""
        r"""|(?:https?|http2)\.(?:get|request)|request(?:\.(?:get|post))?|superagent\.(?:get|post)"""
        r"""|needle(?:\.(?:get|post))?|ky(?:\.(?:get|post))?|\$\.(?:get|post|ajax)|XMLHttpRequest)\s*\("""
    )
    _URL = re.compile(r"""["'`]((?:https?|wss?)://[^"'`\s]+)""")
    MAX_ARGUMENTS: Final = 4000

    @staticmethod
    def _arguments(text: str, open_paren: int) -> str:
        depth, index = 0, open_paren
        end = min(len(text), open_paren + JavaScriptFlow.MAX_ARGUMENTS)
        while index < end:
            character = text[index]
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    return text[open_paren + 1 : index]
            index += 1
        return text[open_paren + 1 : end]

    @staticmethod
    def findings(text: str) -> list[tuple[int, str, str]]:
        """`(offset of the request call, credential name, host)` for each misdirected send."""
        credentials: dict[str, str] = {}  # bound name -> credential name
        hosts: dict[str, str] = {}  # bound name -> host of the URL literal it holds
        for match in JavaScriptFlow._DESTRUCTURE.finditer(text):
            for part in match.group(1).split(","):
                key, _, alias = part.partition(":")
                key, alias = key.strip(), (alias.strip() or key.strip())
                if SecretFlow.home_of(key):
                    credentials[alias] = key
        for match in JavaScriptFlow._BIND.finditer(text):
            name, value = match.group(1), match.group(2)
            read = JavaScriptFlow._ENV_READ.search(value)
            if read:
                key = read.group(1) or read.group(2)
                if SecretFlow.home_of(key):
                    credentials[name] = key
            url = JavaScriptFlow._URL.search(value)
            if url:
                host = SecretFlow.host_of(url.group(1))
                if host:
                    hosts[name] = host
        found: list[tuple[int, str, str]] = []
        for call in JavaScriptFlow._CALL.finditer(text):
            arguments = JavaScriptFlow._arguments(text, call.end() - 1)
            named: set[str] = set()
            for read in JavaScriptFlow._ENV_READ.finditer(arguments):
                key = read.group(1) or read.group(2)
                if SecretFlow.home_of(key):
                    named.add(key)
            words = set(re.findall(r"[A-Za-z_$][\w$]*", arguments))
            named.update(credentials[w] for w in words & set(credentials))
            if not named:
                continue
            destinations = {
                h
                for h in (SecretFlow.host_of(u) for u in JavaScriptFlow._URL.findall(arguments))
                if h
            }
            destinations.update(hosts[w] for w in words & set(hosts))
            for key in sorted(named):
                for host in sorted(destinations):
                    if SecretFlow.misdirected(key, host):
                        found.append((call.start(), key, host))
                        break
        return found


__all__ = ["CREDENTIAL_CUSTODIANS", "CREDENTIAL_HOMES", "Home", "JavaScriptFlow", "SecretFlow"]
