"""One commit's tree from a git server, by git's own protocol: what a release archive is proved
against (`intel/upstream_advisories.ContentProof`).

Git names every file by its content (a blob id: SHA-1 over `blob <size>\\0<bytes>`), so a release
archive's files can be compared with a tag's tree by id alone, on any server that speaks git's
smart HTTP -- GitHub, GitLab, savannah, sourceware -- with no archive endpoint and no API:

    POST <repo>/git-upload-pack   (protocol v2)  command=fetch, want <tag>, deepen 1,
                                                 filter blob:none where the server offers it
    -> a packfile: the tag, its commit and the commit's trees (and blobs, without the filter)

The packfile is read here: object headers, zlib streams, and offset and reference deltas. Only
trees are walked; blobs, when sent, are not read beyond their ids. Bounded in size and depth.
"""

from __future__ import annotations

import hashlib
import re
import struct
import urllib.request
import zlib
from typing import Any, Final

MAX_PACK_BYTES: Final = 512 << 20
MAX_DEPTH: Final = 64
AGENT: Final = "git/2.45.0 (cordon-scanner)"

_TYPES: Final = {1: b"commit", 2: b"tree", 3: b"blob", 4: b"tag"}


class GitFetchError(RuntimeError):
    """The server did not give the commit's tree."""


class GitFetch:
    @staticmethod
    def _pkt(line: str) -> bytes:
        data = line.encode()
        return f"{len(data) + 4:04x}".encode() + data

    @staticmethod
    def _request(url: str, body: bytes | None) -> tuple[bytes, str]:
        headers = {"User-Agent": AGENT, "Git-Protocol": "version=2"}
        if body is not None:
            headers["Content-Type"] = "application/x-git-upload-pack-request"
            headers["Accept"] = "application/x-git-upload-pack-result"
        request = urllib.request.Request(url, data=body, headers=headers)  # noqa: S310 - https
        with urllib.request.urlopen(request, timeout=300) as response:  # noqa: S310
            data: bytes = response.read(MAX_PACK_BYTES + 1)
            final = str(response.geturl())
        if len(data) > MAX_PACK_BYTES:
            raise GitFetchError("response too large")
        if not final.startswith("https://"):
            raise GitFetchError("redirected off https")
        return data, final

    @staticmethod
    def _lines(data: bytes) -> list[bytes | None]:
        """pkt-lines; None for a flush, delim or response-end packet."""
        out: list[bytes | None] = []
        index = 0
        while index + 4 <= len(data):
            length = int(data[index : index + 4], 16)
            if length < 4:
                out.append(None)
                index += 4
                continue
            out.append(data[index + 4 : index + length])
            index += length
        return out

    @staticmethod
    def tree(repository: str, want: str) -> dict[str, str]:
        """`path -> blob id` of every file in the tree of `want` (a commit, or a tag object, which
        is peeled), from `repository` over https."""
        return GitPack.files(GitFetch.objects(repository, want, blobs=False), want)

    @staticmethod
    def blob(repository: str, want: str) -> bytes:
        """One file's bytes by its blob id (a vcpkg port's portfile, by the id its tree names)."""
        kind, content = GitFetch.objects(repository, want, blobs=True).get(want, (b"", b""))
        if kind != b"blob":
            raise GitFetchError("the server did not send the blob")
        return content

    @staticmethod
    def objects(repository: str, want: str, *, blobs: bool) -> dict[str, tuple[bytes, bytes]]:
        """Every object the server sends for `want`, without file contents unless `blobs`."""
        base = repository if repository.endswith(".git") else f"{repository}.git"
        if not base.startswith("https://") or not re.fullmatch(r"[0-9a-f]{40}", want):
            raise GitFetchError("not an https repository and object id")
        answer, final = GitFetch._request(f"{base}/info/refs?service=git-upload-pack", None)
        # Where the ref request ended up (savannah redirects to https.git.savannah.gnu.org): the
        # fetch, a POST, goes there, since a redirect is not followed for one.
        base = final.split("/info/refs", 1)[0]
        advertised = b"".join(line or b"" for line in GitFetch._lines(answer))
        if b"version 2" in advertised:
            fetch_line = re.search(rb"fetch=([^\n]*)", advertised)
            features = (fetch_line.group(1) if fetch_line else b"").split()
            body = b"".join(
                [
                    GitFetch._pkt("command=fetch\n"),
                    GitFetch._pkt(f"agent={AGENT}\n"),
                    b"0001",
                    GitFetch._pkt("no-progress\n"),
                    GitFetch._pkt(f"want {want}\n"),
                    *([GitFetch._pkt("deepen 1\n")] if b"shallow" in features else []),
                    *(
                        [GitFetch._pkt("filter blob:none\n")]
                        if b"filter" in features and not blobs
                        else []
                    ),
                    GitFetch._pkt("done\n"),
                    b"0000",
                ]
            )
            markers: tuple[bytes, ...] = (b"packfile",)
        else:
            # Protocol v0 (sourceware's server): the capabilities follow the first ref, and a
            # want must be an advertised ref's tip -- which a tag's is.
            capabilities = advertised.split(b"\0", 1)[1] if b"\0" in advertised else b""
            offered = [
                c
                for c in (b"side-band-64k", b"no-progress", b"shallow", b"filter")
                if re.search(rb"(?:^|\s)" + c + rb"(?:\s|$)", capabilities)
            ]
            if b"side-band-64k" not in offered:
                raise GitFetchError("the server offers no side band to read a pack from")
            body = b"".join(
                [
                    GitFetch._pkt(f"want {want} {' '.join(c.decode() for c in offered)}\n"),
                    *([GitFetch._pkt("deepen 1\n")] if b"shallow" in offered else []),
                    *(
                        [GitFetch._pkt("filter blob:none\n")]
                        if b"filter" in offered and not blobs
                        else []
                    ),
                    b"0000",
                    GitFetch._pkt("done\n"),
                ]
            )
            markers = (b"NAK", b"ACK " + want.encode())
        pack = bytearray()
        in_pack = False
        for line in GitFetch._lines(GitFetch._request(f"{base}/git-upload-pack", body)[0]):
            if line is None:
                continue
            if not in_pack:
                in_pack = line.rstrip(b"\n") in markers
                if line.startswith(b"ERR "):
                    raise GitFetchError(line[4:].decode("utf-8", "replace").strip())
                continue
            band = line[:1]
            if band == b"\x01":
                pack += line[1:]
            elif band == b"\x03":
                raise GitFetchError(line[1:].decode("utf-8", "replace").strip())
        return GitPack.read(bytes(pack))


class GitPack:
    @staticmethod
    def _apply(base: bytes, delta: bytes) -> bytes:
        index = 0

        def varint() -> int:
            nonlocal index
            value = shift = 0
            while True:
                byte = delta[index]
                index += 1
                value |= (byte & 0x7F) << shift
                shift += 7
                if not byte & 0x80:
                    return value

        varint()  # the base's size
        size = varint()
        out = bytearray()
        while index < len(delta):
            op = delta[index]
            index += 1
            if op & 0x80:
                offset = length = 0
                for bit in range(4):
                    if op & (1 << bit):
                        offset |= delta[index] << (8 * bit)
                        index += 1
                for bit in range(3):
                    if op & (1 << (4 + bit)):
                        length |= delta[index] << (8 * bit)
                        index += 1
                out += base[offset : offset + (length or 0x10000)]
            elif op:
                out += delta[index : index + op]
                index += op
            else:
                raise GitFetchError("a delta instruction of zero")
        if len(out) != size:
            raise GitFetchError("a delta that does not produce its size")
        return bytes(out)

    @staticmethod
    def read(pack: bytes) -> dict[str, tuple[bytes, bytes]]:
        """`id -> (type, content)` of every object in a packfile, deltas resolved."""
        if pack[:4] != b"PACK":
            raise GitFetchError("no packfile in the answer")
        (count,) = struct.unpack(">I", pack[8:12])
        index = 12
        by_offset: dict[int, tuple[bytes, bytes]] = {}
        pending: list[tuple[int, int, Any, bytes]] = []
        objects: dict[str, tuple[bytes, bytes]] = {}
        for _ in range(count):
            start = index
            byte = pack[index]
            index += 1
            kind = (byte >> 4) & 7
            while byte & 0x80:
                byte = pack[index]
                index += 1
            base_ref: Any = None
            if kind == 6:  # an offset delta
                byte = pack[index]
                index += 1
                offset = byte & 0x7F
                while byte & 0x80:
                    byte = pack[index]
                    index += 1
                    offset = ((offset + 1) << 7) | (byte & 0x7F)
                base_ref = start - offset
            elif kind == 7:  # a reference delta
                base_ref = pack[index : index + 20].hex()
                index += 20
            stream = zlib.decompressobj()
            content = stream.decompress(pack[index:], MAX_PACK_BYTES)
            index = len(pack) - len(stream.unused_data)
            if kind in _TYPES:
                by_offset[start] = (_TYPES[kind], content)
                identifier = hashlib.sha1(  # noqa: S324 - git's object id, not a security hash
                    _TYPES[kind] + b" " + str(len(content)).encode() + b"\0" + content
                ).hexdigest()
                objects[identifier] = by_offset[start]
            else:
                pending.append((start, kind, base_ref, content))
        for _ in range(MAX_DEPTH):
            unresolved = []
            for start, kind, base_ref, delta in pending:
                base = by_offset.get(base_ref) if kind == 6 else objects.get(base_ref)
                if base is None:
                    unresolved.append((start, kind, base_ref, delta))
                    continue
                kind_name, content = base[0], GitPack._apply(base[1], delta)
                by_offset[start] = (kind_name, content)
                identifier = hashlib.sha1(  # noqa: S324
                    kind_name + b" " + str(len(content)).encode() + b"\0" + content
                ).hexdigest()
                objects[identifier] = (kind_name, content)
            if not unresolved:
                break
            if len(unresolved) == len(pending):
                raise GitFetchError("a delta whose base is not in the pack")
            pending = unresolved
        return objects

    @staticmethod
    def files(objects: dict[str, tuple[bytes, bytes]], want: str) -> dict[str, str]:
        """`path -> blob id` under the commit `want` names (peeling a tag)."""
        identifier = want
        for _ in range(8):
            kind, content = objects.get(identifier, (b"", b""))
            if kind == b"tag":
                found = re.match(rb"object ([0-9a-f]{40})", content)
                identifier = found.group(1).decode() if found else ""
            elif kind == b"commit":
                found = re.match(rb"tree ([0-9a-f]{40})", content)
                identifier = found.group(1).decode() if found else ""
            elif kind == b"tree":
                break
            else:
                raise GitFetchError("the commit's tree is not in the pack")
        out: dict[str, str] = {}

        def walk(tree: str, prefix: str, depth: int) -> None:
            if depth > MAX_DEPTH:
                raise GitFetchError("a tree nested too deep")
            kind, content = objects.get(tree, (b"", b""))
            if kind != b"tree":
                raise GitFetchError("a tree missing from the pack")
            index = 0
            while index < len(content):
                space = content.index(b" ", index)
                null = content.index(b"\0", space)
                mode = content[index:space]
                name = content[space + 1 : null].decode("utf-8", "surrogateescape")
                child = content[null + 1 : null + 21].hex()
                index = null + 21
                if mode == b"40000":
                    walk(child, f"{prefix}{name}/", depth + 1)
                elif mode in (b"100644", b"100755"):
                    out[f"{prefix}{name}"] = child
                # A symlink (120000) or submodule (160000) is not a file of the release.

        walk(identifier, "", 0)
        return out

    @staticmethod
    def blob_id(data: bytes) -> str:
        return hashlib.sha1(  # noqa: S324 - git's object id
            b"blob " + str(len(data)).encode() + b"\0" + data
        ).hexdigest()


__all__ = ["GitFetch", "GitFetchError", "GitPack"]
