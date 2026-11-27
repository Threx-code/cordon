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
        # The contents of a credential store on disk (`SecretFlow.store_of`): no client sends the
        # file itself anywhere (group A (a): http_query 0.0.1 posted ~/.aws/credentials).
        re.compile(r"^CREDENTIAL_FILE(?::\w+)?$"),
        Home("a credential store", homeless=True),
    ),
    (
        # A wallet's private key or seed: a wallet signs with it locally and never sends it
        # (group A (a): web3_py_checksum 1.1 put `account.key.hex()` in a Telegram URL).
        re.compile(r"^(?:WALLET_PRIVATE_KEY|WALLET_MNEMONIC|PRIVATE_KEY|MNEMONIC|SEED_PHRASE)$"),
        Home("a wallet", homeless=True),
    ),
    (
        re.compile(
            r"^(?:GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|GH_PAT|GITHUB_API_TOKEN|GITHUB_ACCESS_TOKEN|HOMEBREW_GITHUB_API_TOKEN)$"
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
        Home(
            "Docker Hub",
            ("docker.io", "docker.com"),
            ("docker", "registry", "harbor"),
        ),
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
        Home(
            "crates.io",
            ("crates.io",),
            ("cargo", "crates", "registry", "artifactory", "jfrog"),
        ),
    ),
    (
        re.compile(r"^(?:GEM_HOST_API_KEY|RUBYGEMS_API_KEY)$"),
        Home(
            "RubyGems",
            ("rubygems.org",),
            ("gem", "artifactory", "jfrog", "nexus"),
        ),
    ),
    (
        re.compile(r"^(?:NUGET_API_KEY|NUGET_AUTH_TOKEN)$"),
        Home(
            "NuGet",
            ("nuget.org",),
            ("nuget", "artifactory", "jfrog", "nexus", "pkgs.dev.azure"),
        ),
    ),
    # The registries below were added so that every ecosystem has its publisher's credential here, or a
    # reason it has none (`NO_CREDENTIAL`). Each name is the one the registry's own tool documents.
    (
        # https://hexdocs.pm/hex/Mix.Tasks.Hex.Config.html
        re.compile(r"^HEX_API_KEY$"),
        Home("Hex", ("hex.pm", "hexdocs.pm"), ("hex", "hexpm", "artifactory")),
    ),
    (
        # https://getcomposer.org/doc/03-cli.md#composer-auth (one JSON of tokens for every host it names)
        re.compile(r"^COMPOSER_AUTH$"),
        Home(
            "Composer",
            ("packagist.org", "packagist.com", "github.com", "gitlab.com", "bitbucket.org"),
            ("packagist", "satis", "artifactory", "jfrog", "nexus"),
        ),
    ),
    (
        # https://docs.conan.io/2/reference/environment.html
        re.compile(r"^CONAN_PASSWORD(?:_\w+)?$"),
        Home(
            "Conan",
            ("conan.io", "jfrog.io"),
            ("conan", "artifactory", "jfrog"),
        ),
    ),
    (
        # https://developer.hashicorp.com/terraform/cli/config/config-file#environment-variable-credentials
        re.compile(r"^TF_TOKEN_\w+$"),
        Home(
            "Terraform registry",
            ("terraform.io", "hashicorp.com"),
            ("terraform", "tfe", "registry"),
        ),
    ),
    (
        # https://docs.ansible.com/ansible/latest/reference_appendices/config.html
        re.compile(r"^ANSIBLE_GALAXY_TOKEN$"),
        Home(
            "Ansible Galaxy",
            ("ansible.com", "redhat.com"),
            ("galaxy", "automation", "hub", "pulp"),
        ),
    ),
    (
        # https://docs.cachix.org/getting-started
        re.compile(r"^CACHIX_AUTH_TOKEN$"),
        Home("Cachix", ("cachix.org",), ("cachix", "nix", "attic")),
    ),
    (
        # https://raw.githubusercontent.com/microsoft/vscode-vsce/main/README.md
        re.compile(r"^VSCE_PAT$"),
        Home(
            "Visual Studio Marketplace",
            ("visualstudio.com", "dev.azure.com"),
            (),
        ),
    ),
    (
        # https://raw.githubusercontent.com/eclipse/openvsx/master/cli/README.md
        re.compile(r"^OVSX_PAT$"),
        Home("Open VSX", ("open-vsx.org", "eclipse.org"), ("openvsx", "vsx")),
    ),
    (
        # https://docs.gradle.org/current/userguide/publishing_gradle_plugins.html
        re.compile(r"^GRADLE_PUBLISH_(?:KEY|SECRET)$"),
        Home(
            "Gradle Plugin Portal",
            ("gradle.org",),
            ("gradle", "artifactory", "nexus"),
        ),
    ),
    (
        # https://raw.githubusercontent.com/Anaconda-Platform/anaconda-client/master/binstar_client/utils/config.py
        re.compile(r"^ANACONDA_API_TOKEN$"),
        Home(
            "Anaconda.org",
            ("anaconda.org", "anaconda.com"),
            ("anaconda", "conda", "artifactory"),
        ),
    ),
    (
        # https://raw.githubusercontent.com/CocoaPods/cocoapods-trunk/master/lib/pod/command/trunk.rb
        re.compile(r"^COCOAPODS_TRUNK_TOKEN$"),
        Home("CocoaPods Trunk", ("cocoapods.org",), ()),
    ),
    (
        # https://docs.brew.sh/Manpage (the GitHub Packages registry Homebrew pulls bottles from)
        re.compile(r"^HOMEBREW_DOCKER_REGISTRY_(?:BASIC_AUTH_)?TOKEN$"),
        Home(
            "GitHub Packages",
            ("ghcr.io", "github.com"),
            ("github", "ghe"),
        ),
    ),
)


@dataclass(frozen=True)
class Credential:
    """What an ecosystem's publisher authenticates with: the services (`Home.service`) whose credentials it uses, or
    why it has none to name (the fact about how it is published, with the page that says so)."""

    services: tuple[str, ...]
    reason: str = ""


#: Every ecosystem, by id: its credentials in `CREDENTIAL_HOMES`, or why it has none.
ECOSYSTEM_CREDENTIALS: Final[dict[str, Credential]] = {
    "actions": Credential(("GitHub",)),
    "ansible": Credential(("Ansible Galaxy",)),
    "bazel": Credential(
        (),
        "a Bazel module is published by a pull request to the Bazel Central Registry on GitHub, so its credential is the GitHub one (https://github.com/bazelbuild/bazel-central-registry)",
    ),
    "cargo": Credential(("crates.io",)),
    "cocoapods": Credential(("CocoaPods Trunk",)),
    "composer": Credential(("Composer",)),
    "conan": Credential(("Conan",)),
    "conda": Credential(("Anaconda.org",)),
    "cran": Credential(
        (),
        "a CRAN package is submitted through a web form with an e-mail confirmation, so it has no token (https://cran.r-project.org/web/packages/policies.html)",
    ),
    "gomod": Credential(
        (),
        "a Go module is published by pushing a git tag; the proxy fetches it, so there is no registry credential (https://go.dev/ref/mod#vcs)",
    ),
    "gradle": Credential(("Gradle Plugin Portal",)),
    "hackage": Credential(
        (),
        "cabal reads the Hackage token from `--token` or its config file, not from a variable (cabal-install Upload.hs: https://github.com/haskell/cabal)",
    ),
    "helm": Credential(
        (),
        "helm takes registry credentials from `helm registry login` flags and its registry config file; the login command documents no variable (https://helm.sh/docs/helm/helm_registry_login/)",
    ),
    "hex": Credential(("Hex",)),
    "homebrew": Credential(("GitHub", "GitHub Packages")),
    "image": Credential(("Docker Hub",)),
    "julia": Credential(
        (),
        "a Julia package is registered by a pull request to the General registry on GitHub, so its credential is the GitHub one (https://github.com/JuliaRegistries/General)",
    ),
    "maven": Credential(
        (),
        "Maven names a server's credentials by the `id` the user gives it in settings.xml, so no variable name is fixed (https://maven.apache.org/settings.html#servers)",
    ),
    "nix": Credential(("Cachix",)),
    "npm": Credential(("npm",)),
    "nuget": Credential(("NuGet",)),
    "opam": Credential(
        (),
        "an opam package is published by a pull request to opam-repository on GitHub, so its credential is the GitHub one (https://github.com/ocaml/opam-repository)",
    ),
    "pub": Credential(
        (),
        "pub reads a token from whichever variable the user names with `dart pub token add --env-var`, so no name is fixed (https://dart.dev/tools/pub/cmd/pub-token)",
    ),
    "pypi": Credential(("PyPI",)),
    "rubygems": Credential(("RubyGems",)),
    "swift": Credential(
        (),
        "SwiftPM keeps a registry login in the keychain or .netrc, and publishes by git tag, so no variable is documented (https://docs.swift.org/swiftpm/documentation/packagemanagerdocs/)",
    ),
    "terraform": Credential(("Terraform registry",)),
    "vcpkg": Credential(
        (),
        "a vcpkg port is published by a pull request to microsoft/vcpkg on GitHub, so its credential is the GitHub one (https://github.com/microsoft/vcpkg)",
    ),
    "vscode": Credential(("Visual Studio Marketplace", "Open VSX")),
}

_HOST: Final = re.compile(r"^[a-z][a-z0-9+.-]*://(?:[^@/\s]*@)?(\[[0-9a-f:.]+\]|[^/:?#\s]+)", re.I)


class SecretFlow:
    """Where a credential belongs, and whether a host is outside it."""

    #: Where services keep credentials on disk, by store: the same stores `CredentialSweep` counts.
    STORES: Final[dict[str, re.Pattern[str]]] = {
        name: re.compile(pattern)
        for name, pattern in {
            "ssh": r"\.ssh/(?:id_(?:rsa|ed25519|ecdsa|dsa)|identity)\b",
            "aws": r"\.aws/credentials\b",
            "npmrc": r"(?<![\w.])\.npmrc\b",
            "netrc": r"(?<![\w.])\.netrc\b",
            "kube": r"\.kube/config\b",
            "docker": r"\.docker/config\.json\b",
            "gh": r"\.config/gh/hosts\.ya?ml\b",
            "git": r"(?<![\w.])\.git-credentials\b",
            "pypirc": r"(?<![\w.])\.pypirc\b",
            "gcloud": r"\.config/gcloud/(?:credentials\.db|application_default_credentials\.json)",
            "azure": r"\.azure/(?:accessTokens|msal_token_cache)",
        }.items()
    }
    #: Stores whose credentials authenticate to one fixed service: sent anywhere else, or to a host
    #: the file does not write down, they left their home. `ssh` has no host: its keys sign locally.
    #: The other stores name their own hosts (a registry, a netrc machine): only a send to a hidden
    #: or chat/tunnel/raw-IP destination is outside them (`SecretSources._store_outside`).
    FIXED_HOMES: Final[dict[str, tuple[str, ...]]] = {
        "ssh": (),
        "aws": ("amazonaws.com", "aws.amazon.com", "amazonaws.com.cn"),
        "gcloud": ("googleapis.com", "google.com"),
        "azure": ("microsoftonline.com", "azure.com", "windows.net", "microsoft.com"),
    }

    @staticmethod
    def store_of(path_parts: list[str]) -> str | None:
        """The credential store a path names, written whole or in parts
        (`os.path.join(home, ".aws", "credentials")`), or None."""
        joined = "/".join(p.strip("/") for p in path_parts if p)
        for name, pattern in SecretFlow.STORES.items():
            if pattern.search(joined) or any(pattern.search(p) for p in path_parts):
                return name
        return None

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


__all__ = [
    "CREDENTIAL_CUSTODIANS",
    "CREDENTIAL_HOMES",
    "ECOSYSTEM_CREDENTIALS",
    "Credential",
    "Home",
    "SecretFlow",
]
