"""What a package's compiled programs carry, as features the package verdict can read.

Family G of the detection model (`reviews/self-improving/06-DETECTION-MODEL.md`). A platform
binary is most of what a malicious launcher package ships, and its source is nowhere in the
package: the scanner's code rules have nothing to read, and the import-table rules
(`BinaryImports`) name four combinations. These features describe every executable the package
ships -- what it is, what it was built with, and which behaviours its symbols and strings name --
and leave the judgement to the model, which weighs them against the legitimate platform binaries
of the npm work set (esbuild, swc, sharp and their kind).

Keys (`exe_*`, counts across the package's executables, each capped):

- `exe_elf`, `exe_pe`, `exe_macho`, `exe_wasm`: how many of each format;
- `exe_lang_<go|rust|dotnet|pyinstaller|nexe|pkg>`: what built them, by the builder's own marks;
- `exe_group_<behaviour>`: how many distinct names of that behaviour the strings carry -- process
  launch, network, keystroke capture, clipboard, screen capture, credential stores, wallets,
  persistence, debugger checks, process injection, host discovery, chat-service drop points;
- `exe_shape_<url|ip|onion|b64|psenc>`: how many strings have that shape;
- `exe_packed`: a packer's own signature; `exe_high_entropy`: the share of 4 KB blocks (every
  sixteenth one) above 7.2 bits a byte, in tenths;
- `exe_log_size`: the largest executable's size, as the number of its decimal digits;
- `exe_tok_<h>`: the words its strings are made of -- symbol and API names, format strings,
  messages -- hashed, each counted once per executable, the top `TOKENS` across the package.
  Every address, IP, onion name, blob and host name is blanked first, so a word of one is never
  a key: what is learned is what the program names, not where it sends.

A string's value is never a feature: a group counts names on a fixed list, a shape counts strings
of that shape. Read in windows of `WINDOW` bytes with `OVERLAP` carried across each cut, so an
executable of any size held in a window source costs one pass and bounded memory.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.foundation.formats.scanned_json import ScannedJson
from cordon_scanner.foundation.once import OneOff
from cordon_scanner.foundation.paths import PackagePaths

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from pathlib import Path


class BinaryFeatures:
    """`of(executables)`: the `exe_*` facts of a package's compiled programs."""

    WINDOW: ClassVar[int] = 4 * 1024 * 1024
    OVERLAP: ClassVar[int] = 512
    BLOCK: ClassVar[int] = 4096
    CAP: ClassVar[int] = 50

    FORMATS: ClassVar[tuple[tuple[bytes, str], ...]] = (
        (b"\x7fELF", "elf"),
        (b"MZ", "pe"),
        (b"\xcf\xfa\xed\xfe", "macho"),
        (b"\xce\xfa\xed\xfe", "macho"),
        (b"\xca\xfe\xba\xbe", "macho"),
        (b"\x00asm", "wasm"),
    )

    LANGUAGES: ClassVar[dict[str, re.Pattern[bytes]]] = {
        "go": re.compile(rb"Go build ID: |\bruntime\.goexit\b|\bgo1\.\d{1,2}(?:\.\d{1,2})?$", re.M),
        "rust": re.compile(rb"/rustc/[0-9a-f]{40}|\brust_panic\b|RUST_BACKTRACE"),
        "dotnet": re.compile(rb"_CorExeMain|_CorDllMain|mscoree\.dll"),
        "pyinstaller": re.compile(rb"PYZ-00\.pyz|_MEIPASS|pyi-runtime-tmpdir"),
        "nexe": re.compile(rb"<nexe~~sentinel>"),
        "pkg": re.compile(rb"PAYLOAD_POSITION|pkg/prelude/bootstrap\.js"),
    }

    #: Names of a behaviour, as the platform and the common languages' libraries spell them, kept as
    #: package data, one file per group (`detect/data/exe-strings-<group>.json`): data, not code --
    #: one file listing debugger checks beside network and credential names is exactly the
    #: co-occurrence the anti-analysis rules exist to report.
    DATA: ClassVar[Path] = PackagePaths.data("detect")

    @staticmethod
    @OneOff.cache
    def groups() -> dict[str, tuple[bytes, ...]]:
        out: dict[str, tuple[bytes, ...]] = {}
        for path in sorted(BinaryFeatures.DATA.glob("exe-strings-*.json")):
            names = ScannedJson.loads(path.read_text(encoding="utf-8"))
            out[path.stem.removeprefix("exe-strings-")] = tuple(str(n).encode() for n in names)
        return out

    SHAPES: ClassVar[dict[str, re.Pattern[bytes]]] = {
        "url": re.compile(rb"https?://[A-Za-z0-9.-]{3,253}"),
        "ip": re.compile(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
        "onion": re.compile(rb"[a-z2-7]{16,56}\.onion"),
        "b64": re.compile(rb"[A-Za-z0-9+/]{120,}={0,2}"),
        "psenc": re.compile(rb"(?i)powershell[^\n]{0,40}-e(?:nc|ncodedcommand)?\s"),
    }
    #: Read in the first window, where the headers and section names are.
    PACKERS: ClassVar[re.Pattern[bytes]] = re.compile(rb"UPX!|UPX0\x00|\.MPRESS1|\.themida|\.vmp0")
    _ASCII: ClassVar[re.Pattern[bytes]] = re.compile(rb"[\x20-\x7e]{5,}")
    TOKENS: ClassVar[int] = 1500
    HASH_MOD: ClassVar[int] = 1 << 18
    _WORD: ClassVar[re.Pattern[bytes]] = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{3,39}")
    _RUN: ClassVar[re.Pattern[bytes]] = re.compile(rb"[^\s\x00]{4,2048}")
    #: What is never a word -- where a program sends -- by the top-level domains a host name ends
    #: in, the shape of an IP and of an encoded blob.
    _TLDS: ClassVar[frozenset[bytes]] = frozenset(
        b"com net org io ru xyz top cn info onion app dev me cc su tk pw biz site online link club "
        b"live co uk de fr jp kr br in us eu ws to gg sh".split()
    )
    _IP: ClassVar[re.Pattern[bytes]] = re.compile(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
    _BLOB: ClassVar[re.Pattern[bytes]] = re.compile(rb"[A-Za-z0-9+/]{40}")
    #: Written to start on a printable byte, not on a group: four times faster on a 4 MB window.
    _WIDE: ClassVar[re.Pattern[bytes]] = re.compile(rb"[\x20-\x7e]\x00(?:[\x20-\x7e]\x00){4,}")

    @staticmethod
    def format_of(head: bytes) -> str | None:
        return next(
            (name for magic, name in BinaryFeatures.FORMATS if head.startswith(magic)), None
        )

    @staticmethod
    def of(executables: Iterable[tuple[int, Callable[[int, int], bytes]]]) -> dict[str, float]:
        """`executables`: each one's size and a reader of (offset, length) -> bytes."""
        out: Counter[str] = Counter()
        words: Counter[bytes] = Counter()
        largest = 0
        for size, read in executables:
            kind = BinaryFeatures.format_of(read(0, 4))
            if kind is None:
                continue
            out[f"exe_{kind}"] += 1
            largest = max(largest, size)
            words.update(BinaryFeatures._one(size, read, out))
        if largest:
            out["exe_log_size"] = len(str(largest))
        for word, n in sorted(words.items(), key=lambda kv: (-kv[1], kv[0]))[
            : BinaryFeatures.TOKENS
        ]:
            out[f"exe_tok_{BinaryFeatures.hashed(word)}"] += n
        return {k: float(min(v, BinaryFeatures.CAP)) for k, v in out.items()}

    @staticmethod
    def hashed(word: bytes) -> int:
        digest = hashlib.blake2b(word, digest_size=4).digest()
        return int.from_bytes(digest, "big") % BinaryFeatures.HASH_MOD

    @staticmethod
    def _one(size: int, read: Callable[[int, int], bytes], out: Counter[str]) -> set[bytes]:
        """Adds one executable's facts to `out`; returns the distinct words its strings hold."""
        names: dict[str, set[bytes]] = {g: set() for g in BinaryFeatures.groups()}
        words: set[bytes] = set()
        langs: set[str] = set()
        shapes: Counter[str] = Counter()
        packed = False
        blocks = high = 0
        carry = b""
        offset = 0
        while offset < size:
            chunk = read(offset, BinaryFeatures.WINDOW)
            if not chunk:
                break
            # Every check reads the printable strings, ASCII and UTF-16, not the raw bytes: a
            # fortieth of the window on a real platform binary. Names are looked for across the
            # cut (`carry`); shapes are counted in the new bytes only, so none is counted twice.
            new = BinaryFeatures.strings(chunk)
            # A name across the cut is whole in the strings of the bytes around it.
            strings = new + b"\n" + BinaryFeatures.strings(carry + chunk[: BinaryFeatures.OVERLAP])
            for group, spellings in BinaryFeatures.groups().items():
                names[group].update(s for s in spellings if s in strings)
            langs.update(n for n, p in BinaryFeatures.LANGUAGES.items() if p.search(strings))
            if offset == 0:
                packed = BinaryFeatures.PACKERS.search(chunk) is not None
            for shape, pattern in BinaryFeatures.SHAPES.items():
                shapes[shape] += len(pattern.findall(new))
            words.update(BinaryFeatures.words(new))
            # Every sixteenth block: the share is what is wanted, and a byte histogram per 4 KB
            # is the one cost here that grows with the file.
            for start in range(0, len(chunk) - BinaryFeatures.BLOCK + 1, 16 * BinaryFeatures.BLOCK):
                blocks += 1
                high += BinaryFeatures.entropy(chunk[start : start + BinaryFeatures.BLOCK]) > 7.2
            carry = chunk[-BinaryFeatures.OVERLAP :]
            offset += len(chunk)
        for group, found in names.items():
            if found:
                out[f"exe_group_{group}"] += len(found)
        for lang in langs:
            out[f"exe_lang_{lang}"] += 1
        for shape, n in shapes.items():
            if n:
                out[f"exe_shape_{shape}"] += n
        if packed:
            out["exe_packed"] += 1
        if blocks:
            out["exe_high_entropy"] = max(out["exe_high_entropy"], round(10 * high / blocks))
        return words

    @staticmethod
    def words(strings: bytes) -> set[bytes]:
        """The words of `strings`, each distinct run of non-space bytes asked once: a run that is
        an address, an IP, a blob or a host name gives none. Plain byte tests, not a pattern per
        run: a 133 MB program has two hundred thousand distinct runs."""
        kept: list[bytes] = []
        for run in set(BinaryFeatures._RUN.findall(strings)):
            if b"://" in run:
                continue
            if b"." in run and (
                b"/" in run
                or run.rsplit(b".", 1)[-1].lower().rstrip(b"\"');,)]") in BinaryFeatures._TLDS
                or (run.count(b".") >= 3 and BinaryFeatures._IP.search(run) is not None)
            ):
                continue
            if len(run) >= 40 and BinaryFeatures._BLOB.search(run) is not None:
                continue
            kept.append(run)
        return set(BinaryFeatures._WORD.findall(b" ".join(kept)))

    @staticmethod
    def strings(data: bytes) -> bytes:
        """The printable runs of `data`, ASCII then UTF-16 with its zero bytes dropped, one a line."""
        ascii_runs = b"\n".join(BinaryFeatures._ASCII.findall(data))
        wide_runs = b"\n".join(BinaryFeatures._WIDE.findall(data)).replace(b"\x00", b"")
        return ascii_runs + b"\n" + wide_runs

    @staticmethod
    def entropy(block: bytes) -> float:
        counts = Counter(block)
        n = len(block)
        return -sum(c / n * math.log2(c / n) for c in counts.values())


__all__ = ["BinaryFeatures"]
