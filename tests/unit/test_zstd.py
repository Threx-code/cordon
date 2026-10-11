"""The core's zstd decoder (`intel/zstd`), against frames the reference zstd library wrote.

The fixtures under `tests/unit/data/zstd/` were written by `zstandard` (the reference C library)
from the inputs `Inputs` regenerates here, at each level and option named in the file name; the
decoder must give back exactly those inputs. `conda-info.tar.zst` is the `info-*.tar.zst` member
of a real conda-forge package, its decompressed SHA-256 recorded from the reference library."""

from __future__ import annotations

import contextlib
import hashlib
import io
import tarfile
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.intel.zstd import XXH64, Zstd, ZstdError

FIXTURES = Path(__file__).resolve().parent / "data" / "zstd"


class Inputs:
    WORDS = (
        b"package source version build requirements host run test about license home summary "
        b"description url sha256 number script python numpy setuptools pip wheel conda forge "
        b"recipe feedstock maintainers extra channel noarch platform linux osx win"
    ).split()

    @staticmethod
    def stream(seed: bytes, size: int) -> bytes:
        """Bytes no compressor can shrink: SHA-256 in counter mode."""
        out = bytearray()
        counter = 0
        while len(out) < size:
            out += hashlib.sha256(seed + counter.to_bytes(8, "little")).digest()
            counter += 1
        return bytes(out[:size])

    @staticmethod
    def text(size: int) -> bytes:
        """Recipe-like text: words picked by a fixed generator, so matches and literals mix."""
        noise = Inputs.stream(b"text", size)
        out = bytearray()
        i = 0
        while len(out) < size:
            out += Inputs.WORDS[noise[i % len(noise)] % len(Inputs.WORDS)]
            out += b"\n" if noise[(i + 1) % len(noise)] < 24 else b" "
            i += 2
        return bytes(out[:size])

    @staticmethod
    def all() -> dict[str, bytes]:
        text = Inputs.text(300_000)
        noise = Inputs.stream(b"noise", 20_000)
        return {
            "empty": b"",
            "byte": b"x",
            "text": text,
            "noise": noise,
            "same": b"\x07" * 400_000,
            "mixed": text[:50_000] + noise + text[:50_000] + b"\0" * 70_000 + text[-30_000:],
        }


CASES = [
    ("empty", "3"),
    ("byte", "3"),
    ("text", "1"),
    ("text", "19"),
    ("text", "3-checksum"),
    ("noise", "3"),
    ("same", "3"),
    ("same", "19-checksum"),
    ("mixed", "1"),
    ("mixed", "19-checksum"),
    ("mixed", "3-nosize"),
]


class TestAgainstTheReferenceLibrary:
    @pytest.mark.parametrize(("name", "how"), CASES)
    def test_the_input_comes_back(self, name: str, how: str) -> None:
        compressed = (FIXTURES / f"{name}-{how}.zst").read_bytes()
        assert Zstd.decompress(compressed, 1 << 24) == Inputs.all()[name]

    def test_frames_and_a_skippable_frame_one_after_another(self) -> None:
        inputs = Inputs.all()
        compressed = (FIXTURES / "frames.zst").read_bytes()
        assert Zstd.decompress(compressed, 1 << 24) == inputs["text"][:60_000] + inputs["mixed"]

    def test_a_real_conda_info_member(self) -> None:
        compressed = (FIXTURES / "conda-info.tar.zst").read_bytes()
        expected = (FIXTURES / "conda-info.sha256").read_text().split()[0]
        data = Zstd.decompress(compressed, 1 << 26)
        assert hashlib.sha256(data).hexdigest() == expected
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            assert "info/index.json" in archive.getnames()


class TestRefusals:
    def test_a_wrong_checksum(self) -> None:
        compressed = bytearray((FIXTURES / "text-3-checksum.zst").read_bytes())
        compressed[-1] ^= 1
        with pytest.raises(ZstdError, match="checksum"):
            Zstd.decompress(bytes(compressed), 1 << 24)

    def test_the_limit(self) -> None:
        compressed = (FIXTURES / "same-3.zst").read_bytes()
        with pytest.raises(ZstdError, match="limit"):
            Zstd.decompress(compressed, 1000)

    def test_not_zstd(self) -> None:
        with pytest.raises(ZstdError):
            Zstd.decompress(b"PK\x03\x04 not zstd", 1 << 20)

    def test_a_cut_frame(self) -> None:
        compressed = (FIXTURES / "text-19.zst").read_bytes()
        with pytest.raises(ZstdError):
            Zstd.decompress(compressed[: len(compressed) // 2], 1 << 24)


class TestTheStream:
    def test_a_reader_stops_early(self) -> None:
        compressed = (FIXTURES / "text-19.zst").read_bytes()
        reader = Zstd.Reader(compressed, 1 << 24)
        assert reader.read(10) == Inputs.all()["text"][:10]

    def test_the_conda_reader_uses_it(self, monkeypatch) -> None:
        import builtins

        from cordon_scanner.intel.upstream_advisories import CondaPackage

        real = builtins.__import__

        def without_zstd(name: str, *args: Any, **kwargs: Any) -> Any:
            if name in ("compression", "zstandard"):
                raise ImportError(name)
            return real(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", without_zstd)
        compressed = (FIXTURES / "conda-info.tar.zst").read_bytes()
        with tarfile.open(fileobj=CondaPackage._zstd_stream(compressed), mode="r|") as archive:
            recipe = CondaPackage._from_tar(archive)
        assert recipe is not None and "source" in recipe


class TestXXH64:
    @pytest.mark.parametrize(
        ("data", "digest"),
        [
            # The reference vectors of xxHash's own sanity test (seed 0).
            (b"", 0xEF46DB3751D8E999),
            (b"a", 0xD24EC4F1A98C6E5B),
            (b"abc", 0x44BC2CF5AD770999),
        ],
    )
    def test_reference_vectors(self, data: bytes, digest: int) -> None:
        assert XXH64.digest(data) == digest

    def test_past_the_32_byte_stripes(self) -> None:
        # Recorded from the reference `xxhash` library.
        inputs = Inputs.all()
        assert XXH64.digest(inputs["text"][:1000]) == 0xC68CFF02E61B9EC9
        assert XXH64.digest(inputs["noise"][:37]) == 0x927A3C5BC3DE6A3D


class TestDamage:
    @pytest.mark.parametrize(
        ("name", "positions"), [("conda-info.tar", 400), ("mixed-3-nosize", 160), ("frames", 160)]
    )
    def test_a_damaged_byte_is_a_zstd_error_or_a_checked_result(
        self, name: str, positions: int
    ) -> None:
        original = (FIXTURES / f"{name}.zst").read_bytes()
        step = max(1, len(original) // positions)
        for at in [*range(min(64, len(original))), *range(64, len(original), step)]:
            for flip in (0x01, 0x80, 0xFF):
                damaged = bytearray(original)
                damaged[at] ^= flip
                with contextlib.suppress(ZstdError):
                    Zstd.decompress(bytes(damaged), 1 << 24)
