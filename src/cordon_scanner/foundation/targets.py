"""What a scan's target is called when Cordon names it outside the scan: in a notification, an
upload to Cordon Cloud, an organisation's gate bundle or an AI-BOM.

One name everywhere, so the bundle that sets a repository's gate mode, the dashboard that lists its
uploads and the message that says its gate failed all refer to the same thing. The name never
carries credentials: a remote such as `https://user:token@host/owner/repo.git` is named
`host/owner/repo`.
"""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.foundation.results import ScanResult


class TargetName:
    """A scan's target as a name."""

    @staticmethod
    def of(result: ScanResult) -> str:
        """The repository's remote without credentials, or the target's last path segment."""
        repository = result.repository
        remote = (repository.remote if repository else None) or ""
        if remote:
            parsed = urllib.parse.urlsplit(remote)
            if parsed.scheme in ("http", "https", "ssh") and parsed.hostname:
                return f"{parsed.hostname}{parsed.path}".removesuffix(".git")
            if "@" in remote and ":" in remote:  # git@host:owner/repo.git
                return remote.split("@", 1)[1].replace(":", "/", 1).removesuffix(".git")
        root = ((repository.root if repository else None) or "").rstrip("/\\")
        return root.replace("\\", "/").rsplit("/", 1)[-1] or "scan"


__all__ = ["TargetName"]
