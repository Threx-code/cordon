"""Hackage's `01-index.tar`, kept in the scanner's cache directory (that one file, nothing else) and brought up to date by fetching only
what was appended: an HTTP Range from the cached length, less the tar's closing zero blocks. After every update the whole file is hashed
(locally; the network is not read again) and must be the length and SHA-256 the signed snapshot states, else the file is deleted and the
install refused. The release SHA-256s are then read out of it: `<name>/<version>/package.json` holds a signed `targets` entry with the
tarball's SHA-256 and MD5."""

from __future__ import annotations

import hashlib
import http.client
import json
import mmap
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.foundation.network.failures import NetworkFailure
from cordon_scanner.foundation.network.redirects import NoRedirects
from cordon_scanner.sources.install.plan import InstallRefused
from cordon_scanner.version import USER_AGENT

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from cordon_scanner.sources.install.managers.hackage_trust import IndexFacts

    #: Fetches the bytes of the index from `start` to its end, as a series of chunks.
    Ranged = Callable[[int], Iterable[bytes]]


class HackageIndex:
    URL: ClassVar[str] = "https://hackage.haskell.org/01-index.tar"
    FILE: ClassVar[str] = "hackage-01-index.tar"
    #: A tar ends in two zero blocks; Hackage appends over them, so they are fetched again.
    CLOSING: ClassVar[int] = 1024
    BLOCK: ClassVar[int] = 512
    CHUNK: ClassVar[int] = 1 << 20
    NAME: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"([A-Za-z0-9][A-Za-z0-9-]*)/([0-9][0-9.]*)/package\.json"
    )

    @classmethod
    def ranged(cls, start: int, end: int) -> Iterable[bytes]:
        """`01-index.tar` bytes `start` to `end` (exclusive) from hackage.haskell.org: https, no redirect, a 206 for exactly that range."""
        parsed = urllib.parse.urlsplit(cls.URL)
        request = urllib.request.Request(  # noqa: S310 - the one https URL above
            cls.URL,
            headers={"User-Agent": USER_AGENT, "Range": f"bytes={start}-{end - 1}"},
            method="GET",
        )
        try:
            with urllib.request.build_opener(NoRedirects).open(request, timeout=60) as response:
                stated = str(response.headers.get("Content-Range", ""))
                if response.status != 206 or not stated.startswith(f"bytes {start}-{end - 1}/"):
                    raise InstallRefused(
                        f"{parsed.netloc} did not serve the byte range of the index asked for ({response.status}, {stated[:60]!r})"
                    )
                got = 0
                while chunk := response.read(cls.CHUNK):
                    got += len(chunk)
                    if got > end - start:
                        raise InstallRefused("the index range was longer than the one asked for")
                    yield chunk
        except urllib.error.HTTPError as exc:
            NetworkFailure.release(exc)
            raise InstallRefused(
                f"HTTP {exc.code} from {parsed.netloc} fetching the index"
            ) from exc
        except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            raise InstallRefused(f"{NetworkFailure.reason(exc)} fetching the index") from exc

    @classmethod
    def sha256(cls, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(cls.CHUNK):
                digest.update(chunk)
        return digest.hexdigest()

    @classmethod
    def current(cls, cache: Path, facts: IndexFacts, fetch: Ranged | None = None) -> Path:
        """The cached index, brought to the length and SHA-256 `facts` states."""
        cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = cache / cls.FILE
        size = path.stat().st_size if path.is_file() and not path.is_symlink() else 0
        tries = [max(size - cls.CLOSING, 0), 0] if 0 < size <= facts.length else [0]
        for start in tries:
            if start == facts.length:
                if cls.sha256(path) == facts.sha256:
                    return path
                continue
            source = fetch(start) if fetch is not None else cls.ranged(start, facts.length)
            with path.open("r+b" if path.exists() else "wb") as handle:
                handle.truncate(start)
                handle.seek(start)
                for chunk in source:
                    handle.write(chunk)
                handle.truncate(facts.length)
            if path.stat().st_size == facts.length and cls.sha256(path) == facts.sha256:
                path.chmod(0o600)
                return path
        path.unlink(missing_ok=True)
        raise InstallRefused(
            "the Hackage index is not the file the signed snapshot describes (its length and SHA-256 differ); nothing was installed"
        )

    @classmethod
    def targets(
        cls, path: Path, wanted: set[tuple[str, str]]
    ) -> dict[tuple[str, str], dict[str, str]]:
        """For each wanted (name, version), the `hashes` of its tarball from the last `package.json` the index holds for it."""
        found: dict[tuple[str, str], dict[str, str]] = {}
        with (
            path.open("rb") as handle,
            mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data,
        ):
            at = 0
            end = len(data)
            while at + cls.BLOCK <= end:
                header = data[at : at + cls.BLOCK]
                if header[0] == 0:
                    at += cls.BLOCK
                    continue
                name = header[:100].split(b"\0", 1)[0]
                try:
                    size = int(header[124:136].split(b"\0", 1)[0].strip() or b"0", 8)
                except ValueError as exc:
                    raise InstallRefused(
                        "the Hackage index holds an entry Cordon cannot read"
                    ) from exc
                body = at + cls.BLOCK
                matched = cls.NAME.fullmatch(name)
                if matched and size <= 1 << 16:
                    key = (matched.group(1).decode(), matched.group(2).decode())
                    if key in wanted:
                        entry = cls.hashes(bytes(data[body : body + size]), key)
                        if entry:
                            found[key] = entry
                at = body + (size + cls.BLOCK - 1) // cls.BLOCK * cls.BLOCK
        return found

    @staticmethod
    def hashes(text: bytes, key: tuple[str, str]) -> dict[str, str]:
        try:
            targets = json.loads(text)["signed"]["targets"]
        except (ValueError, KeyError, TypeError):
            return {}
        wanted = f"<repo>/package/{key[0]}-{key[1]}.tar.gz"
        entry = targets.get(wanted) if isinstance(targets, dict) else None
        digests = entry.get("hashes") if isinstance(entry, dict) else None
        if not isinstance(digests, dict):
            return {}
        return {str(k): str(v) for k, v in digests.items() if isinstance(v, str)}


__all__ = ["HackageIndex"]
