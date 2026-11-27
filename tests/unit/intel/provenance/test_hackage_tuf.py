"""Hackage's signed metadata and index (`releases/hackage_tuf`, `hackage_index`, `tuf`).

`hackage/{root,timestamp,snapshot}.json` are the real documents Hackage served on 2026-11-26 (valid to 2026-11-29); the whole real
chain, down to a real release in the real 1 GB index, was run once by hand against them (`Chart-cairo 1.0`). Here the index is
small and built, with keys made for the test, so that each way a tail, a cache or a signature can be wrong can be made."""

from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import io
import json
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer
from cordon_scanner.intel.provenance.releases.hackage_index import (
    IndexCache,
    IndexProblem,
    TarIndex,
)
from cordon_scanner.intel.provenance.releases.hackage_tuf import HackageTuf
from cordon_scanner.intel.provenance.releases.tuf import CanonicalJson, Tuf, TufError
from cordon_scanner.intel.provenance.sigstore_bundle import TrustRoot
from support import ROOT

REAL = ROOT / "tests" / "unit" / "intel" / "provenance" / "hackage"
CAPTURED = dt.datetime(2026, 11, 26, 6, 0, tzinfo=dt.UTC)


class Real:
    @staticmethod
    def source() -> Any:
        class Source:
            def document(self, name: str) -> bytes:
                return (REAL / name).read_bytes()

            def index_range(self, start: int, length: int, sink: Callable[[bytes], None]) -> None:
                raise OSError("not served")

        return Source()


class TestTheCanonicalForm:
    def test_keys_are_sorted_and_nothing_is_spaced(self) -> None:
        assert (
            CanonicalJson.dumps({"b": [1, None, True], "a": {"y": "x", "x": False}})
            == b'{"a":{"x":false,"y":"x"},"b":[1,null,true]}'
        )

    def test_only_quote_backslash_and_controls_are_escaped(self) -> None:
        assert CanonicalJson.dumps('a"b\\c\n/é') == '"a\\"b\\\\c\\u000a/é"'.encode()

    def test_a_float_is_not_carried(self) -> None:
        with pytest.raises(TufError):
            CanonicalJson.dumps(1.5)


class TestTheRealMetadata:
    def test_the_pinned_root_is_the_one_the_key_holders_publish(self) -> None:
        raw = (TrustRoot.DATA / "hackage-root.json").read_bytes()
        # The same bytes at hackage.haskell.org/root.json and at haskell-infra/hackage-root-keys, 2026-11-26.
        assert (
            hashlib.sha256(raw).hexdigest()
            == "f62e46cb51d4a499a8336894d7a46071b7e528135ad71614c7102c1de0aeeabc"
        )

    def test_the_chain_gives_the_indexs_length_and_hash(self) -> None:
        meta = HackageTuf.index_meta(Real.source(), CAPTURED)
        assert meta == {
            "length": 1057653248,
            "sha256": "5e65cdc47dc93948339f4c91c61bada96dda31893b0eeef28be79d0a0c4efb56",
        }

    def test_after_the_expiry_nothing_verifies(self) -> None:
        with pytest.raises(TufError, match="timestamp has expired"):
            HackageTuf.index_meta(Real.source(), dt.datetime(2026, 12, 5, tzinfo=dt.UTC))

    @pytest.mark.parametrize("document", ["timestamp.json", "snapshot.json"])
    def test_a_changed_signature_byte_is_refused(self, document: str) -> None:
        raw = json.loads((REAL / document).read_text(encoding="utf-8"))
        sig = bytearray(base64.b64decode(raw["signatures"][0]["sig"]))
        sig[3] ^= 1
        raw["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
        source = Real.source()
        original = source.document
        source.document = lambda name: (
            json.dumps(raw).encode() if name == document else original(name)
        )
        with pytest.raises(TufError):
            HackageTuf.index_meta(source, CAPTURED)

    def test_a_snapshot_that_is_not_the_one_the_timestamp_names_is_refused(self) -> None:
        source = Real.source()
        original = source.document
        source.document = lambda name: (
            original(name) + b" " if name == "snapshot.json" else original(name)
        )
        with pytest.raises(TufError, match="not the one the timestamp names"):
            HackageTuf.index_meta(source, CAPTURED)

    def test_a_changed_signed_part_fails_the_signature(self) -> None:
        raw = (REAL / "timestamp.json").read_text(encoding="utf-8").replace("112676", "112677")
        source = Real.source()
        original = source.document
        source.document = lambda name: raw.encode() if name == "timestamp.json" else original(name)
        with pytest.raises(TufError, match="not signed by enough"):
            HackageTuf.index_meta(source, CAPTURED)


class World:
    """A repository of our own: keys made here, a root that the code is told to pin, an index we can grow and break."""

    KEYS: ClassVar[dict[str, Ed25519Signer]] = {}

    @classmethod
    def signer(cls, name: str) -> Ed25519Signer:
        if name not in cls.KEYS:
            cls.KEYS[name] = Ed25519Signer(hashlib.sha256(name.encode()).digest())
        return cls.KEYS[name]

    @classmethod
    def key(cls, name: str) -> tuple[str, dict[str, Any]]:
        body = {
            "keytype": "ed25519",
            "keyval": {"public": base64.b64encode(cls.signer(name).public).decode()},
        }
        return hashlib.sha256(CanonicalJson.dumps(body)).hexdigest(), body

    @classmethod
    def sign(cls, signed: dict[str, Any], names: list[str]) -> dict[str, Any]:
        message = CanonicalJson.dumps(signed)
        return {
            "signed": signed,
            "signatures": [
                {
                    "keyid": cls.key(n)[0],
                    "method": "ed25519",
                    "sig": base64.b64encode(cls.signer(n).sign(message)).decode(),
                }
                for n in names
            ],
        }

    @classmethod
    def root(
        cls,
        version: int,
        roots: list[str],
        signers: list[str],
        expires: str = "2030-01-01T00:00:00Z",
    ) -> bytes:
        names = [*roots, "timestamp", "snapshot"]
        signed = {
            "_type": "Root",
            "expires": expires,
            "keys": dict(cls.key(n) for n in names),
            "roles": {
                "root": {"keyids": [cls.key(n)[0] for n in roots], "threshold": 2},
                "timestamp": {"keyids": [cls.key("timestamp")[0]], "threshold": 1},
                "snapshot": {"keyids": [cls.key("snapshot")[0]], "threshold": 1},
                "targets": {"keyids": [], "threshold": 1},
            },
            "version": version,
        }
        return json.dumps(cls.sign(signed, signers)).encode()

    @staticmethod
    def package(name: str, version: str, archive: bytes) -> bytes:
        target = {
            f"<repo>/package/{name}-{version}.tar.gz": {
                "hashes": {"sha256": hashlib.sha256(archive).hexdigest()},
                "length": len(archive),
            }
        }
        return json.dumps(
            {
                "signatures": [],
                "signed": {"_type": "Targets", "expires": None, "targets": target, "version": 0},
            }
        ).encode()

    @staticmethod
    def entries(*more: tuple[str, str, bytes]) -> dict[str, bytes]:
        out = {
            "a/1.0/a.cabal": b"name: a\n",
            "a/1.0/package.json": World.package("a", "1.0", ARCHIVE),
        }
        for name, version, archive in more:
            out[f"{name}/{version}/package.json"] = World.package(name, version, archive)
        return out

    @staticmethod
    def tar(entries: dict[str, bytes]) -> bytes:
        """A tar as Hackage's index is: 512-byte blocks, no record padding, the 1024-byte zero trailer at the end."""
        out = b""
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            out += info.tobuf(tarfile.USTAR_FORMAT) + data + b"\0" * (-len(data) % 512)
        return out + b"\0" * 1024

    def __init__(self, entries: dict[str, bytes], root_signers: list[str] | None = None) -> None:
        self.roots = ["r1", "r2", "r3"]
        self.root_raw = self.root(1, self.roots, root_signers or ["r1", "r2"])
        self.expires = "2030-01-01T00:00:00Z"
        self.index = self.tar(entries)
        self.calls: list[tuple[int, int]] = []
        self.break_tail: Callable[[bytes], bytes] | None = None

    def snapshot(self, index: bytes | None = None) -> bytes:
        data = self.index if index is None else index
        signed = {
            "_type": "Snapshot",
            "expires": self.expires,
            "meta": {
                "<repo>/01-index.tar": {
                    "hashes": {"sha256": hashlib.sha256(data).hexdigest()},
                    "length": len(data),
                },
                "<repo>/root.json": {
                    "hashes": {"sha256": hashlib.sha256(self.root_raw).hexdigest()},
                    "length": len(self.root_raw),
                },
            },
            "version": 1,
        }
        return json.dumps(self.sign(signed, ["snapshot"])).encode()

    def timestamp(self, snapshot: bytes) -> bytes:
        signed = {
            "_type": "Timestamp",
            "expires": self.expires,
            "meta": {
                "<repo>/snapshot.json": {
                    "hashes": {"sha256": hashlib.sha256(snapshot).hexdigest()},
                    "length": len(snapshot),
                }
            },
            "version": 1,
        }
        return json.dumps(self.sign(signed, ["timestamp"])).encode()

    def document(self, name: str) -> bytes:
        if name == "root.json":
            return self.root_raw
        if name == "snapshot.json":
            return self.snapshot()
        return self.timestamp(self.snapshot())

    def index_range(self, start: int, length: int, sink: Callable[[bytes], None]) -> None:
        self.calls.append((start, length))
        piece = self.index[start:length]
        if self.break_tail is not None and start > 0:
            piece = self.break_tail(piece)
        for at in range(0, len(piece), 700):
            sink(piece[at : at + 700])

    def pin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(HackageTuf, "_pinned", self.root_raw)


ARCHIVE = b"the source archive of the release"
NOW = dt.datetime(2026, 11, 26, tzinfo=dt.UTC)


class TestAReleaseAgainstTheIndex:
    def verify(
        self,
        world: World,
        tmp_path: Path,
        archive: bytes = ARCHIVE,
        name: str = "a",
        version: str = "1.0",
    ) -> Any:
        return HackageTuf.verify(
            archive, name, version, world, IndexCache(tmp_path / "hackage"), NOW
        )  # type: ignore[arg-type]

    def test_the_archive_the_index_lists_is_verified(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        world = World(World.entries())
        world.pin(monkeypatch)
        found = self.verify(world, tmp_path)
        assert found.outcome == "verified", found.detail
        assert world.calls == [(0, len(world.index))]

    def test_another_archive_is_invalid(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        world = World(World.entries())
        world.pin(monkeypatch)
        found = self.verify(world, tmp_path, ARCHIVE + b"!")
        assert found.outcome == "invalid" and "not the archive" in found.detail

    def test_a_release_the_index_does_not_list_is_absent(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        world = World(World.entries())
        world.pin(monkeypatch)
        assert self.verify(world, tmp_path, version="2.0").outcome == "absent"

    def test_the_later_entry_of_a_name_is_the_one(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        world = World({})
        first = World.package("a", "1.0", b"old")
        second = World.package("a", "1.0", ARCHIVE)
        world.index = World.tar({"a/1.0/package.json": first})[:-1024] + World.tar(
            {"a/1.0/package.json": second}
        )
        world.pin(monkeypatch)
        assert self.verify(world, tmp_path).outcome == "verified"


class TestTheCachedIndex:
    def grown(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[World, bytes, Path]:
        """A cache holding the index as it was; the repository now has more."""
        world = World(World.entries())
        world.pin(monkeypatch)
        old = world.index
        cache = tmp_path / "hackage"
        cache.mkdir()
        (cache / "01-index.tar").write_bytes(old)
        world.index = World.tar(World.entries(("b", "2.0", b"another archive")))
        return world, old, cache / "01-index.tar"

    def run(
        self,
        world: World,
        tmp_path: Path,
        name: str = "b",
        version: str = "2.0",
        archive: bytes = b"another archive",
    ) -> Any:
        return HackageTuf.verify(
            archive, name, version, world, IndexCache(tmp_path / "hackage"), NOW
        )  # type: ignore[arg-type]

    def test_a_refresh_asks_only_for_the_tail_and_overwrites_the_trailer(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        world, old, path = self.grown(monkeypatch, tmp_path)
        found = self.run(world, tmp_path)
        assert found.outcome == "verified", found.detail
        assert world.calls == [(len(old) - 1024, len(world.index))]
        assert path.read_bytes() == world.index

    def test_a_cache_that_is_current_is_not_asked_again(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        world, _, _ = self.grown(monkeypatch, tmp_path)
        self.run(world, tmp_path)
        world.calls.clear()
        assert self.run(world, tmp_path).outcome == "verified" and world.calls == []

    def test_a_tail_that_does_not_make_the_snapshots_hash_is_refused_and_the_cache_restored(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        world, old, path = self.grown(monkeypatch, tmp_path)
        real = world.index
        world.break_tail = lambda piece: piece[:-1] + bytes([piece[-1] ^ 1])
        # The full read is broken too, so nothing can make the hash.
        broken = world.index_range
        world.index_range = (
            lambda start, length, sink: (  # type: ignore[method-assign]
                broken(start, length, lambda piece: sink(piece[:-1] + bytes([piece[-1] ^ 1])))
                if start == 0
                else broken(start, length, sink)
            )
        )
        found = self.run(world, tmp_path)
        assert found.outcome == "unverifiable" and "snapshot's hash" in found.detail
        assert path.read_bytes() == old and not (path.parent / "01-index.tar.part").exists()
        assert real != old

    def test_a_truncated_tail_is_refused_and_the_cache_restored(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        world, old, path = self.grown(monkeypatch, tmp_path)
        serve = world.index_range

        def short(start: int, length: int, sink: Callable[[bytes], None]) -> None:
            serve(start, length - 100, sink)

        world.index_range = short  # type: ignore[method-assign]
        found = self.run(world, tmp_path)
        assert found.outcome == "unverifiable" and "short" in found.detail
        assert path.read_bytes() == old

    def test_a_cache_with_a_bad_prefix_is_replaced_whole(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        world, old, path = self.grown(monkeypatch, tmp_path)
        path.write_bytes(bytes([old[0] ^ 1]) + old[1:])
        found = self.run(world, tmp_path)
        assert found.outcome == "verified", found.detail
        assert world.calls == [(len(old) - 1024, len(world.index)), (0, len(world.index))]
        assert path.read_bytes() == world.index

    def test_a_cache_longer_than_the_snapshot_is_started_again(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        world, _, path = self.grown(monkeypatch, tmp_path)
        path.write_bytes(world.index + b"\0" * 2048)
        assert self.run(world, tmp_path).outcome == "verified"
        assert path.read_bytes() == world.index

    def test_a_repository_that_sends_more_than_the_snapshot_states_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        world, old, path = self.grown(monkeypatch, tmp_path)
        serve = world.index_range
        world.index_range = lambda start, length, sink: (
            serve(start, length, sink) or sink(b"x" * 10)
        )  # type: ignore[method-assign]
        assert self.run(world, tmp_path).outcome == "unverifiable"
        assert path.read_bytes() == old

    def test_a_size_past_the_bound_is_not_accepted(self, tmp_path: Path) -> None:
        with pytest.raises(IndexProblem, match="size"):
            IndexCache(tmp_path).ensure(object(), IndexCache.MAX_BYTES + 1, "0" * 64)  # type: ignore[arg-type]


class TestTheTarWalk:
    def test_names_over_a_hundred_characters_are_read_from_their_long_name_record(
        self, tmp_path: Path
    ) -> None:
        name = "p" * 60
        version = "1." + "0" * 60
        data = World.package(name, version, b"x")
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
            info = tarfile.TarInfo(f"{name}/{version}/package.json")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        path = tmp_path / "i.tar"
        path.write_bytes(buffer.getvalue())
        assert TarIndex.read(path, f"{name}/{version}/package.json") == data

    def test_a_header_with_an_unreadable_size_is_refused(self, tmp_path: Path) -> None:
        raw = bytearray(World.tar({"a/1/package.json": b"{}"}))
        raw[124:136] = b"not-octal!!\0"
        path = tmp_path / "i.tar"
        path.write_bytes(bytes(raw))
        with pytest.raises(IndexProblem):
            TarIndex.entries(path)


class TestRootSuccession:
    def rotated(
        self, monkeypatch: pytest.MonkeyPatch, version: int, signers: list[str], roots: list[str]
    ) -> Any:
        world = World(World.entries())
        world.pin(monkeypatch)
        world.root_raw = World.root(version, roots, signers)
        return world

    def test_a_successor_signed_by_the_old_and_the_new_keys_is_followed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        world = self.rotated(monkeypatch, 2, ["r1", "r2", "r4"], ["r1", "r4", "r5"])
        monkeypatch.setattr(HackageTuf, "_pinned", World.root(1, ["r1", "r2", "r3"], ["r1", "r2"]))
        root, _ = HackageTuf.root(world, NOW)
        assert root["signed"]["version"] == 2

    def test_a_successor_signed_only_by_its_own_keys_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        world = self.rotated(monkeypatch, 2, ["r4", "r5"], ["r4", "r5"])
        monkeypatch.setattr(HackageTuf, "_pinned", World.root(1, ["r1", "r2", "r3"], ["r1", "r2"]))
        with pytest.raises(TufError, match="neither the pinned one"):
            HackageTuf.root(world, NOW)

    def test_an_older_root_signed_by_the_old_keys_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        world = self.rotated(monkeypatch, 1, ["r1", "r3"], ["r1", "r2", "r3"])
        world.root_raw = World.root(0, ["r1", "r2", "r3"], ["r1", "r2"])
        monkeypatch.setattr(HackageTuf, "_pinned", World.root(1, ["r1", "r2", "r3"], ["r1", "r2"]))
        with pytest.raises(TufError, match="neither the pinned one"):
            HackageTuf.root(world, NOW)

    def test_a_pinned_root_that_its_own_keys_did_not_sign_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        world = World(World.entries())
        monkeypatch.setattr(HackageTuf, "_pinned", World.root(1, ["r1", "r2", "r3"], ["r1"]))
        with pytest.raises(TufError, match="pinned root is not signed"):
            HackageTuf.root(world, NOW)

    def test_an_expired_root_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        world = World(World.entries())
        raw = World.root(1, ["r1", "r2", "r3"], ["r1", "r2"], expires="2026-01-01T00:00:00Z")
        monkeypatch.setattr(HackageTuf, "_pinned", raw)
        world.root_raw = raw
        with pytest.raises(TufError, match="root has expired"):
            HackageTuf.root(world, NOW)


class TestTheThreshold:
    def test_the_same_key_twice_counts_once(self) -> None:
        signed = {"x": 1}
        document = World.sign(signed, ["r1"])
        document["signatures"] *= 2
        keys = {World.key("r1")[0]: World.signer("r1").public}
        assert not Tuf.signed_by(document, [World.key("r1")[0]], 2, keys)
        assert Tuf.signed_by(document, [World.key("r1")[0]], 1, keys)

    def test_a_key_the_root_does_not_name_for_the_role_does_not_count(self) -> None:
        document = World.sign({"x": 1}, ["r1"])
        keys = {World.key("r1")[0]: World.signer("r1").public}
        assert not Tuf.signed_by(document, [World.key("r2")[0]], 1, keys)

    def test_a_key_whose_id_is_not_its_digest_is_refused(self) -> None:
        signed = json.loads(World.root(1, ["r1", "r2", "r3"], ["r1", "r2"]))["signed"]
        forged = copy.deepcopy(signed)
        some = next(iter(forged["keys"]))
        forged["keys"][some]["keyval"]["public"] = base64.b64encode(
            World.signer("other").public
        ).decode()
        with pytest.raises(TufError, match="not its digest"):
            Tuf.keys(forged)

    def test_a_duplicate_key_in_the_metadata_is_refused(self) -> None:
        with pytest.raises(TufError, match="duplicate"):
            Tuf.parse(b'{"signed":{"a":1,"a":2},"signatures":[]}')

    @pytest.mark.parametrize("raw", [b"", b"[]", b'{"signed":1,"signatures":[]}', b"\xff"])
    def test_something_that_is_not_metadata_is_refused(self, raw: bytes) -> None:
        with pytest.raises(TufError):
            Tuf.parse(raw)
