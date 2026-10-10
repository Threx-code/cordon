"""git's own protocol, read here (`intel/gitfetch`), and the content proof built on it.

The packfile below is written by hand to git's pack format -- a blob, a blob stored as an offset
delta, a blob stored as a reference delta, trees and a commit -- so that delta resolution and the
tree walk are checked against bytes whose ids are known.
"""

from __future__ import annotations

import hashlib
import struct
import zlib

import pytest

from cordon_scanner.intel.gitfetch import GitFetchError, GitPack


class Pack:
    """A packfile, built object by object."""

    @staticmethod
    def oid(kind: bytes, content: bytes) -> str:
        return hashlib.sha1(kind + b" %d\0" % len(content) + content).hexdigest()  # noqa: S324

    @staticmethod
    def header(kind: int, size: int) -> bytes:
        out = bytearray([(kind << 4) | (size & 0x0F)])
        size >>= 4
        while size:
            out[-1] |= 0x80
            out.append(size & 0x7F)
            size >>= 7
        return bytes(out)

    @staticmethod
    def varint(value: int) -> bytes:
        out = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            out.append(byte | (0x80 if value else 0))
            if not value:
                return bytes(out)

    @staticmethod
    def delta(base: bytes, suffix: bytes) -> bytes:
        """A delta that copies all of `base`, then inserts `suffix`."""
        copy = bytes([0x80 | 0x10, len(base)])  # offset 0, one size byte
        return (
            Pack.varint(len(base))
            + Pack.varint(len(base) + len(suffix))
            + copy
            + bytes([len(suffix)])
            + suffix
        )

    @staticmethod
    def offset(distance: int) -> bytes:
        out = [distance & 0x7F]
        distance >>= 7
        while distance:
            distance -= 1
            out.insert(0, 0x80 | (distance & 0x7F))
            distance >>= 7
        return bytes(out)

    @staticmethod
    def tree(entries: list[tuple[bytes, bytes, str]]) -> bytes:
        return b"".join(
            mode + b" " + name + b"\0" + bytes.fromhex(oid) for mode, name, oid in entries
        )

    @staticmethod
    def build() -> tuple[bytes, str, dict[str, str]]:
        a = b"hello\n"
        b = a + b"world\n"
        c = a + b"again\n"
        id_a, id_b, id_c = (Pack.oid(b"blob", x) for x in (a, b, c))
        sub = Pack.tree([(b"100644", b"b.txt", id_b), (b"100644", b"c.txt", id_c)])
        id_sub = Pack.oid(b"tree", sub)
        root = Pack.tree([(b"100644", b"a.txt", id_a), (b"40000", b"dir", id_sub)])
        id_root = Pack.oid(b"tree", root)
        commit = f"tree {id_root}\nauthor a <a> 0 +0000\ncommitter a <a> 0 +0000\n\nm\n".encode()
        id_commit = Pack.oid(b"commit", commit)

        body = bytearray()
        offsets: list[int] = []

        def add(raw: bytes) -> None:
            offsets.append(12 + len(body))
            body.extend(raw)

        add(Pack.header(3, len(a)) + zlib.compress(a))
        delta_b = Pack.delta(a, b"world\n")
        here = 12 + len(body)
        add(Pack.header(6, len(delta_b)) + Pack.offset(here - offsets[0]) + zlib.compress(delta_b))
        delta_c = Pack.delta(a, b"again\n")
        add(Pack.header(7, len(delta_c)) + bytes.fromhex(id_a) + zlib.compress(delta_c))
        for kind, raw in ((2, sub), (2, root), (1, commit)):
            add(Pack.header(kind, len(raw)) + zlib.compress(raw))
        pack = b"PACK" + struct.pack(">II", 2, 6) + bytes(body)
        return pack, id_commit, {"a.txt": id_a, "dir/b.txt": id_b, "dir/c.txt": id_c}


class TestThePack:
    def test_deltas_resolve_and_the_tree_is_walked(self) -> None:
        pack, commit, expected = Pack.build()
        objects = GitPack.read(pack)
        assert GitPack.files(objects, commit) == expected

    def test_a_blob_id_is_gits(self) -> None:
        assert (
            GitPack.blob_id(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        )  # git's empty blob
        assert GitPack.blob_id(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"

    def test_a_delta_whose_base_is_absent_is_an_error(self) -> None:
        delta = Pack.delta(b"x", b"y")
        body = Pack.header(7, len(delta)) + b"\x11" * 20 + zlib.compress(delta)
        with pytest.raises(GitFetchError):
            GitPack.read(b"PACK" + struct.pack(">II", 2, 1) + body)

    def test_not_a_pack_is_an_error(self) -> None:
        with pytest.raises(GitFetchError):
            GitPack.read(b"<html>")
