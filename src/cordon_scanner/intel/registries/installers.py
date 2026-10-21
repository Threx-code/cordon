"""Official one-line installers of widely used developer tools.

`curl https://astral.sh/uv/install.sh | sh` is how uv is installed: the vendor's own host, serving
the vendor's own script. A fetch-and-run naming one of these is setup, reported below the gate; the
same line naming any other host keeps its full weight. Matched on the host and path of the URL
actually fetched, never on a substring elsewhere on the line.
"""

from __future__ import annotations

import re
from typing import Final

_URL: Final = re.compile(r"(?i)https?://([a-z0-9.-]{1,253})(/[^\s|\"'`)]{0,200})?")

KNOWN_INSTALLERS: Final = (
    ("astral.sh", ""),
    ("sh.rustup.rs", ""),
    ("bun.sh", ""),
    ("deno.land", ""),
    ("get.docker.com", ""),
    ("get.pnpm.io", ""),
    ("install.python-poetry.org", ""),
    ("pyenv.run", ""),
    ("ollama.com", "/install.sh"),
    ("starship.rs", "/install.sh"),
    ("sdk.cloud.google.com", ""),
    ("cli.github.com", ""),
    ("gh.io", "/copilot-install"),
    ("raw.githubusercontent.com", "/homebrew/install/"),
    ("raw.githubusercontent.com", "/nvm-sh/nvm/"),
    # Coding agents, model runtimes and cloud CLIs, each from its vendor's documented URL.
    ("claude.ai", "/install.sh"),
    ("cursor.com", "/install"),
    ("lmstudio.ai", "/install.sh"),
    ("opencode.ai", "/install"),
    ("aka.ms", "/install-azd.sh"),
    ("aka.ms", "/installazurecli"),
    ("fly.io", "/install.sh"),
    ("get.helm.sh", ""),
    ("raw.githubusercontent.com", "/helm/helm/"),
    ("sh.vector.dev", ""),
    ("tailscale.com", "/install.sh"),
    ("get.k3s.io", ""),
    ("mise.run", ""),
    ("mise.jdx.dev", "/install.sh"),
    ("install.determinate.systems", ""),
    ("nixos.org", "/nix/install"),
    ("get.sdkman.io", ""),
    ("volta.sh", ""),
    ("fnm.vercel.app", "/install"),
    ("cli.doppler.com", "/install.sh"),
    ("supabase.com", "/install"),
    ("get.jetify.com", ""),
    ("pixi.sh", "/install.sh"),
    ("micro.mamba.pm", "/install.sh"),
    ("foundry.paradigm.xyz", ""),
    ("raw.githubusercontent.com", "/ohmyzsh/ohmyzsh/"),
    # Release binaries of a tool listed above by its install.sh host, owner and repository exact:
    # astral-sh/uv ships `uv-<target>` archives, which editor extensions fetch instead of piping
    # install.sh (review 98 #28). Never a whole host or a wildcard owner.
    ("github.com", "/astral-sh/uv/releases/download/"),
    ("github.com", "/astral-sh/uv/releases/latest/download/"),
)
"""(host, path prefix) pairs. A host matches itself and its subdomains."""


class OfficialInstallers:
    """Official one-line installers of widely used developer tools."""

    @staticmethod
    def is_official_installer(text: str) -> bool:
        """Whether the first URL in this text is a listed official installer."""
        found = _URL.search(text)
        if found is None:
            return False
        host, path = found.group(1).lower(), (found.group(2) or "").lower()
        return any(
            (host == known or host.endswith("." + known)) and path.startswith(prefix)
            for known, prefix in KNOWN_INSTALLERS
        )

    @staticmethod
    def pinned_download(url: str) -> bool:
        """Whether `url`, a whole URL, is a download from a listed installer's own path: https, the
        host exactly (no user or port in front of it), a listed entry that names a path and not a
        bare host -- `deno.land` also serves anyone's modules under `/x/` -- and nothing that can
        climb out of that path (`.`/`..` segments, a backslash, a percent-escape)."""
        if not url.startswith("https://"):
            return False
        rest = url[len("https://") :]
        host, slash, path = rest.partition("/")
        host = host.lower()
        if not slash or not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
            return False
        path = "/" + path.split("?", 1)[0].split("#", 1)[0]
        if "\\" in path or "%" in path or any(seg in (".", "..") for seg in path.split("/")):
            return False
        return any(
            prefix and (host == known or host.endswith("." + known)) and path.startswith(prefix)
            for known, prefix in KNOWN_INSTALLERS
        )


__all__ = ["KNOWN_INSTALLERS", "OfficialInstallers"]
