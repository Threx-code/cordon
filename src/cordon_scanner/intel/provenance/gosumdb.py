"""A Go module version's record in the Go checksum database, verified as a client of a transparency log verifies it.

`go.sum` lines are the module's `h1:` hashes. The checksum database (sum.golang.org) is an append-only Merkle tree of
records `<module> <version> h1:...`; a lookup answers with the record, and a tree head the database signed:

    <record id>
    <module> <version> h1:...
    <module> <version>/go.mod h1:...
    <blank line>
    go.sum database tree
    <size>
    <root, base64>
    <blank line>
    — sum.golang.org <base64: 4-byte key hint, Ed25519 signature>

Verified here from first principles, against the database's own public key pinned in this file:

1. the signature over the tree head, with the key the database is known by;
2. the record's leaf is in that tree: its hash, folded with an audit path built from the database's tiles
   (`/tile/8/<level>/<index>`, 256 hashes each), reaches the signed root;
3. the record's `h1:` is the one `go.sum` pins (`invalid` when it is another: the module was changed after it was logged,
   or the lock names a hash the log never held).

A module the database has no record of (a private module, or `GONOSUMDB`) is `absent`; a database that cannot be reached
is `unverifiable`. Network use is the scan's `--online` only, over HTTPS to sum.golang.org."""

from __future__ import annotations

import base64
import hashlib
import http.client
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import ClassVar, Final

from cordon_scanner.foundation.network.downloads import Download
from cordon_scanner.foundation.network.failures import NetworkFailure
from cordon_scanner.foundation.network.redirects import NoRedirects
from cordon_scanner.intel.provenance._ed25519 import Ed25519
from cordon_scanner.intel.provenance.bazel_provenance import ModuleCheck
from cordon_scanner.intel.provenance.transparency import Merkle

HOST: Final = "https://sum.golang.org"
NAME: Final = "sum.golang.org"
#: The database's public key, as `go` itself pins it (`knownGOSUMDB` in cmd/go/internal/modfetch/key.go of the Go source,
#: `sum.golang.org+033de0ae+<key>`, read 2026-11-26): a type byte 0x01 then the Ed25519 key.
KEY: Final = "Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"
HEIGHT: Final = 8
TILE: Final = 1 << HEIGHT
MAX_TILE_BYTES: Final = TILE * 32 + 64
MAX_LOOKUP_BYTES: Final = 1 << 16
TIMEOUT: Final = 15.0
MAX_TILES: Final = 80


class SumdbError(Exception):
    """The database's answer is not what a verifier accepts."""


class SumdbKey:
    @classmethod
    def raw(cls) -> bytes:
        decoded = base64.b64decode(KEY)
        return decoded[1:]

    @classmethod
    def hint(cls) -> bytes:
        """The 4 bytes a signature line begins with: the note hash of the key's name, type and key."""
        return hashlib.sha256(NAME.encode() + b"\n" + base64.b64decode(KEY)).digest()[:4]


class SumdbNote:
    """The signed tree head at the end of a lookup answer."""

    def __init__(self, size: int, root: bytes) -> None:
        self.size, self.root = size, root

    @classmethod
    def parse(cls, text: str) -> SumdbNote:
        body, separator, signatures = text.partition("\n\n")
        if not separator:
            raise SumdbError("a tree head with no signature")
        lines = body.split("\n")
        if len(lines) != 3 or lines[0] != "go.sum database tree" or not lines[1].isdigit():
            raise SumdbError("a tree head that is not the database's")
        root = base64.b64decode(lines[2], validate=True)
        if len(root) != 32:
            raise SumdbError("a tree root of the wrong length")
        signed = (body + "\n").encode()
        prefix = chr(0x2014) + " " + NAME + " "
        for line in signatures.split("\n"):
            if not line.startswith(prefix):
                continue
            raw = base64.b64decode(line[len(prefix) :], validate=True)
            if raw[:4] == SumdbKey.hint() and Ed25519.verify(SumdbKey.raw(), signed, raw[4:]):
                return cls(int(lines[1]), root)
        raise SumdbError("no signature of the checksum database's key over the tree head")


class SumdbTiles:
    """The database's hash tiles, read as the tree's stored hashes: a hash at `(level, index)` is the root of the 2**level
    leaves from `index << level`."""

    def __init__(self, size: int, read: Callable[[str], bytes]) -> None:
        self.size, self.read = size, read
        self._tiles: dict[str, bytes] = {}

    @staticmethod
    def number(n: int) -> str:
        """A tile number in the database's path form: groups of three digits, each but the last prefixed `x`."""
        groups = []
        while True:
            groups.append(f"{n % 1000:03d}")
            n //= 1000
            if n == 0:
                break
        groups.reverse()
        return "/".join([f"x{g}" for g in groups[:-1]] + [groups[-1]])

    def tile(self, level: int, n: int, width: int) -> bytes:
        path = f"tile/{HEIGHT}/{level}/{self.number(n)}" + ("" if width == TILE else f".p/{width}")
        if path not in self._tiles:
            if len(self._tiles) >= MAX_TILES:
                raise SumdbError("a proof that needs more tiles than any real one")
            data = self.read(path)
            if len(data) != width * 32:
                raise SumdbError("a tile of the wrong length")
            self._tiles[path] = data
        return self._tiles[path]

    def stored(self, level: int, index: int) -> bytes:
        tile_level, rise = divmod(level, HEIGHT)
        at_level = self.size >> (HEIGHT * tile_level)
        first = index << rise
        n = first // TILE
        width = min(TILE, at_level - TILE * n)
        if width <= 0 or first - TILE * n + (1 << rise) > width:
            raise SumdbError("a hash the tree does not hold")
        data = self.tile(tile_level, n, width)
        start = first - TILE * n
        hashes = [data[(start + i) * 32 : (start + i + 1) * 32] for i in range(1 << rise)]
        while len(hashes) > 1:
            hashes = [Merkle.node(hashes[i], hashes[i + 1]) for i in range(0, len(hashes), 2)]
        return hashes[0]

    def subtree(self, start: int, end: int) -> bytes:
        """The Merkle tree hash of the leaves `[start, end)` (RFC 9162 2.1.1)."""
        count = end - start
        if count & (count - 1) == 0 and start % count == 0:
            level = count.bit_length() - 1
            return self.stored(level, start >> level)
        split = 1 << ((count - 1).bit_length() - 1)
        return Merkle.node(self.subtree(start, start + split), self.subtree(start + split, end))

    def path(self, index: int) -> list[bytes]:
        """The audit path of leaf `index` in the tree of `size` leaves (RFC 9162 2.1.3.1), deepest sibling first."""
        out: list[bytes] = []
        start, end = 0, self.size
        siblings: list[tuple[int, int]] = []
        while end - start > 1:
            split = 1 << ((end - start - 1).bit_length() - 1)
            if index - start < split:
                siblings.append((start + split, end))
                end = start + split
            else:
                siblings.append((start, start + split))
                start += split
        for first, last in reversed(siblings):
            out.append(self.subtree(first, last))
        return out


class GoSumdb:
    #: Module version asked for as the database writes it.
    _KEY: ClassVar[str] = KEY

    @staticmethod
    def escaped(text: str) -> str:
        """The proxy's case encoding: each upper-case letter is `!` and its lower-case form."""
        return "".join(f"!{c.lower()}" if c.isupper() else c for c in text)

    @staticmethod
    def get(url: str, limit: int) -> bytes | None:
        """The body, or None where the database has no such file (404, 410)."""
        if urllib.parse.urlsplit(url).scheme != "https":
            raise ValueError("not https")
        request = urllib.request.Request(url, headers={"User-Agent": "cordon-scanner"})  # noqa: S310 - https only
        try:
            with urllib.request.build_opener(NoRedirects).open(
                request, timeout=TIMEOUT
            ) as response:
                body: bytes = Download.read(response, limit + 1)
        except urllib.error.HTTPError as exc:
            NetworkFailure.release(exc)
            if exc.code in (404, 410):
                return None
            raise
        if len(body) > limit:
            raise ValueError("response too large")
        return body

    @classmethod
    def lookup_url(cls, module: str, version: str) -> str:
        return f"{HOST}/lookup/{urllib.parse.quote(cls.escaped(module), safe='/!')}@{urllib.parse.quote(cls.escaped(version), safe='!')}"

    @classmethod
    def check(cls, name: str, version: str, integrity: str | None) -> ModuleCheck:
        """The module's record in the checksum database: in the signed tree, and the `h1:` the lock pins when it pins one."""
        canonical = version if version.startswith("v") else f"v{version}"
        try:
            answer = cls.get(cls.lookup_url(name, canonical), MAX_LOOKUP_BYTES)
            return (
                cls.verify(name, canonical, integrity, answer, lambda path: cls._tile(path))
                if answer is not None
                else ModuleCheck(
                    "absent", f"the checksum database has no record of {name}@{canonical}"
                )
            )
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            return ModuleCheck(
                "unverifiable",
                f"the checksum database could not be asked: {NetworkFailure.reason(exc)}",
            )

    @classmethod
    def _tile(cls, path: str) -> bytes:
        body = cls.get(f"{HOST}/{path}", MAX_TILE_BYTES)
        if body is None:
            raise SumdbError("the database holds no such tile")
        return body

    @classmethod
    def verify(
        cls,
        name: str,
        version: str,
        integrity: str | None,
        answer: bytes,
        read: Callable[[str], bytes],
    ) -> ModuleCheck:
        """The lookup answer and the tiles checked as the docstring says; no network of its own (`read` serves the tiles)."""
        try:
            text = answer.decode("utf-8")
            record_part, separator, note_text = text.partition("\n\n")
            if not separator:
                raise SumdbError("an answer with no tree head")
            identity, _, lines = record_part.partition("\n")
            if not identity.isdigit() or not lines:
                raise SumdbError("an answer with no record")
            note = SumdbNote.parse(note_text)
            record = (lines + "\n").encode()
            index = int(identity)
            if index >= note.size:
                raise SumdbError("a record the signed tree does not hold")
            tiles = SumdbTiles(note.size, read)
            leaf = Merkle.leaf(record)
            root = Merkle.root_from_proof(index, note.size, leaf, tiles.path(index))
            if root != note.root:
                raise SumdbError("the record's audit path does not reach the signed root")
        except (SumdbError, ValueError, UnicodeDecodeError) as exc:
            return ModuleCheck("invalid", f"the checksum database's answer did not verify: {exc}")
        recorded = cls.recorded(lines, name, version)
        if recorded is None:
            return ModuleCheck("invalid", f"the record does not name {name}@{version}")
        if integrity and integrity.startswith("h1:") and integrity != recorded:
            return ModuleCheck(
                "invalid", f"go.sum pins {integrity}, the checksum database recorded {recorded}"
            )
        return ModuleCheck("verified", f"recorded in the checksum database as {recorded}")

    @staticmethod
    def recorded(lines: str, name: str, version: str) -> str | None:
        prefix = f"{name} {version} "
        for line in lines.splitlines():
            if line.startswith(prefix):
                value = line[len(prefix) :].strip()
                return value if value.startswith("h1:") and " " not in value else None
        return None
