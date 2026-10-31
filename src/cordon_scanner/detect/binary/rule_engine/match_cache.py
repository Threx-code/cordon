"""cordon-rule's match cache: a file's matches against one compiled rule set, kept by the file's
content, so the same bytes are matched once across every package and every scan.

A rule's answer is a function of the file's bytes, the rules (with every file their includes read),
the engine, and the data given to modules (a Cuckoo report, vt metadata), and nothing else: not the
file's path, its package or the scan. So the same vendored library, licence file or minified bundle
in a thousand packages is matched once. The scan cache (`engine/cache.py`) cannot do this: it keys a
file's findings by its context too, because a code finding depends on where code runs. Rule matches
do not, and the path filter a rule applies (`RuleFileEngine.applies`) runs after the cache.

Never cached: rules that import `time` (an answer may change between scans) or `console` (its
messages are part of every scan's output), and a match that did not finish. An entry is used only
when it is this user's, writable by no one else, and its HMAC-SHA256 under a per-user key, made as the
pack cache makes its own, verifies, since a forged entry that hides a match is a missed detection. Entries are JSON, never
pickle, so reading one runs nothing. A refused or unreadable entry is a miss, counted in `refused`.
Entries live two levels deep by their key's first byte, so a directory holds at most about
1/256 of them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.detect.binary.rule_engine.pack_cache import PackCache

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.binary.rule_engine.lang import Match


class MatchCache:
    """Kept matches under one directory, by rule-set identity and file content."""

    FORMAT: ClassVar[int] = 1
    UNCACHEABLE: ClassVar[frozenset[str]] = frozenset({"time", "console"})

    def __init__(self, root: Path) -> None:
        self.root = root
        self.signer = PackCache(root)  # the same per-user key mechanism, in this directory
        self.refused = 0
        self.hits = 0

    @staticmethod
    def identity(
        files: Iterable[Path], module_data: Iterable[tuple[str, str]], imports: frozenset[str]
    ) -> str | None:
        """What a rule set's answers depend on, as one digest; None when they cannot be kept."""
        if imports & MatchCache.UNCACHEABLE:
            return None
        digest = hashlib.sha256(f"{MatchCache.FORMAT}\0{PackCache.engine_digest()}\0".encode())
        for path in files:
            digest.update(str(path).encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
        for name, data_path in sorted(module_data):
            digest.update(
                name.encode() + b"\0" + hashlib.sha256(Path(data_path).read_bytes()).digest()
            )
        digest.update(",".join(sorted(imports)).encode())
        return digest.hexdigest()

    def _path(self, identity: str, data: bytes) -> Path:
        key = hashlib.sha256(identity.encode() + b"\0" + hashlib.sha256(data).digest()).hexdigest()
        return self.root / key[:2] / key

    def get(self, identity: str, data: bytes) -> list[Match] | None:
        path = self._path(identity, data)
        try:
            st = path.stat()
            if st.st_uid != os.getuid() or st.st_mode & 0o022:
                self.refused += 1
                return None
            mac_line, _, signed = path.read_bytes().partition(b"\n")
            expected = self.signer.sign(signed)
            if expected is None or not hmac.compare_digest(
                mac_line.decode("ascii", "replace"), expected
            ):
                self.refused += 1
                return None
            entry = json.loads(signed)
            if entry.get("format") != MatchCache.FORMAT or entry.get("identity") != identity:
                return None
            matches = [MatchCache._match(m) for m in entry["matches"]]
        except FileNotFoundError:
            return None
        except (OSError, ValueError, KeyError, TypeError):
            self.refused += 1
            return None
        self.hits += 1
        return matches

    def put(self, identity: str, data: bytes, matches: list[Match]) -> None:
        """Keep `matches` for this content; a failure keeps nothing."""
        path = self._path(identity, data)
        try:
            signed = json.dumps(
                {
                    "format": MatchCache.FORMAT,
                    "identity": identity,
                    "matches": [MatchCache._plain(m) for m in matches],
                },
                sort_keys=True,
            ).encode()
            mac = self.signer.sign(signed)
            if mac is None:
                return
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".match-")
            with os.fdopen(fd, "wb") as handle:
                handle.write(mac.encode() + b"\n" + signed)
            Path(tmp).chmod(0o600)
            Path(tmp).replace(path)
        except (OSError, TypeError, ValueError):
            return

    @staticmethod
    def _plain(match: Match) -> dict[str, Any]:
        return {
            "rule": match.rule,
            "tags": list(match.tags),
            "meta": [[k, MatchCache._value(v)] for k, v in match.meta.items()],
            "strings": [
                [offset, name, base64.b64encode(data).decode()]
                for offset, name, data in match.strings
            ],
        }

    @staticmethod
    def _value(v: Any) -> list[Any]:
        """A meta value with its type, so a bytes value comes back as bytes and a bool as a bool."""
        if isinstance(v, bytes):
            return ["b", base64.b64encode(v).decode()]
        return ["v", v]

    @staticmethod
    def _match(plain: dict[str, Any]) -> Match:
        from cordon_scanner.detect.binary.rule_engine.lang import Match

        meta = {k: base64.b64decode(v) if kind == "b" else v for k, (kind, v) in plain["meta"]}
        strings = [(int(o), str(n), base64.b64decode(d)) for o, n, d in plain["strings"]]
        return Match(rule=plain["rule"], tags=list(plain["tags"]), meta=meta, strings=strings)


__all__ = ["MatchCache"]
