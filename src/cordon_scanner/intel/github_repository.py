"""A GitHub repository's current name, as GitHub itself resolves the one a manifest declares.

A package declares the repository it came from when it is published, and repositories are
renamed: filelock still declares `tox-dev/py-filelock`, which GitHub renamed to `tox-dev/filelock`,
the name its build certificates carry. GitHub keeps the old name as a redirect to the same
repository:

    GET https://api.github.com/repos/tox-dev/py-filelock
      -> 301 https://api.github.com/repositories/17098256
      -> 200 {"id": 17098256, "full_name": "tox-dev/filelock", ...}

Only the API host is asked, over HTTPS; a redirect is followed only within it. `GITHUB_TOKEN`,
when set, is sent to GitHub's own API alone (the unauthenticated limit is 60 requests an hour).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Final

API: Final = "https://api.github.com"
TIMEOUT: Final = 15.0
MAX_BYTES: Final = 1 << 20


class _ApiRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https" or target.hostname != "api.github.com":
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class GitHubRepository:
    @staticmethod
    def current(owner: str, name: str) -> tuple[str, str] | None:
        """`(owner, name)` as GitHub names the repository now, or None where it cannot say."""
        quoted = "/".join(urllib.parse.quote(part, safe="-._") for part in (owner, name))
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "cordon-scanner"}
        token = os.environ.get("GITHUB_TOKEN", "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(f"{API}/repos/{quoted}", headers=headers)  # noqa: S310 - fixed https host
        try:
            with urllib.request.build_opener(_ApiRedirects).open(request, timeout=TIMEOUT) as r:
                document = json.loads(r.read(MAX_BYTES))
        except (urllib.error.URLError, OSError, ValueError):
            return None
        full_name = document.get("full_name") if isinstance(document, dict) else None
        if not isinstance(full_name, str) or full_name.count("/") != 1:
            return None
        current_owner, _, current_name = full_name.partition("/")
        return current_owner, current_name


__all__ = ["GitHubRepository"]
