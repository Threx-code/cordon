"""What a pickle would import if it were loaded, read without loading it.

Unpickling calls whatever callable the stream names, which is why a model file (`.pkl`, `.pt`,
`.pth`, `.bin`, `.joblib`, `.ckpt`) can run `os.system` the moment someone loads it. The names are
in the opcode stream: `GLOBAL` carries `module\\nname`, and `STACK_GLOBAL` takes the two strings
most recently pushed or fetched from the memo. `pickletools.genops` walks the opcodes without
executing any of them, and this tracks enough of the stack to name every import.

PyTorch's `.pt`, `.pth` and zip-format `.bin` are ZIP archives holding `<name>/data.pkl`; those are
opened with `zipfile`, or, when only the start of a large file was read, found by their local
header.
"""

from __future__ import annotations

import array
import io
import pickletools
import struct
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Final

from cordon_scanner.analysis.formats import FormatBounds, FormatError

MAX_MEMO_BYTES: Final = 64 * 1024 * 1024
"""The most the walk's memo holds: 8 bytes an entry, the byte offset of the memoised string's
opcode (-1 for any other value), so an import through a `GET` is read back from the pickle's own
bytes, exactly, whatever the string -- `__import__("evil-mod")` imports evil-mod.py, so no shape
rule can say which strings name a module. A pickle is read to its end whatever its size (review 98,
D: a 6.2 MB dictionary cache of 3.2 million opcodes was refused at a 2,000,000-opcode cap, and the
scan with it incomplete); its 938,293 memo entries cost 7.5 MB here, not the 99 MB of the strings.
Past this bound, nothing more is memoised and the read is reported as partial, never silently cut."""
MAX_PICKLES: Final = 16
"""`.pt` archives can hold several pickles; more than this is refused rather than walked."""

PICKLE_SUFFIXES: Final = (
    ".pkl",
    ".pickle",
    ".pt",
    ".pth",
    ".bin",
    ".joblib",
    ".ckpt",
    ".sav",
    ".dill",
)
ALWAYS_PICKLE: Final = (".pkl", ".pickle", ".joblib", ".dill", ".sav")
"""Suffixes that mean pickle whatever the first bytes are -- protocol 0, the text form the classic
`cos\nsystem` payload uses, has no magic. `.bin`, `.pt` and `.ckpt` name many other formats and
are read only when their bytes are a pickle or a PyTorch zip."""

DANGEROUS: Final = {
    "os": None,
    "posix": None,
    "nt": None,
    "subprocess": None,
    "socket": None,
    "pty": None,
    "shutil": None,
    "runpy": None,
    "webbrowser": None,
    "ctypes": None,
    "importlib": None,
    "marshal": None,
    "code": None,
    "codeop": None,
    "commands": None,
    "platform": None,
    "requests": None,
    "httplib": None,
    "http.client": None,
    "urllib": None,
    "urllib.request": None,
    "urllib2": None,
    "telnetlib": None,
    "ftplib": None,
    "smtplib": None,
    "asyncio": None,
    "multiprocessing": None,
    "sys": None,
    "pathlib": frozenset(
        {
            # The file-mutating methods only: a load that writes, deletes, moves, re-permissions or
            # links a path has run a payload. Storing a path (`pathlib.Path`, the class) does not,
            # so the class itself is left out (PickleBall `ours/write_file.pkl` is Path.write_text).
            "Path.write_text",
            "Path.write_bytes",
            "Path.rename",
            "Path.replace",
            "Path.unlink",
            "Path.rmdir",
            "Path.chmod",
            "Path.symlink_to",
            "Path.hardlink_to",
        }
    ),
    "pickle": frozenset({"loads", "load", "Unpickler"}),
    "_pickle": frozenset({"loads", "load", "Unpickler"}),
    "dill": None,
    "builtins": frozenset(
        {
            "eval",
            "exec",
            "compile",
            "open",
            "__import__",
            "getattr",
            "setattr",
            "input",
            "breakpoint",
            "globals",
            "vars",
        }
    ),
    "__builtin__": frozenset(
        {
            "eval",
            "exec",
            "compile",
            "open",
            "__import__",
            "getattr",
            "setattr",
            "input",
            "execfile",
            "file",
        }
    ),
    "operator": frozenset({"attrgetter", "methodcaller"}),
    "functools": frozenset({"partial"}),
    "types": frozenset({"FunctionType", "CodeType", "LambdaType"}),
}
"""Modules whose callables run commands, reach the network, touch files or evaluate code.
`None` means every name in the module; a set names the dangerous members only."""

#: Command/code-execution modules that stay dangerous when reached through an attribute chain. A
#: pickle GETs `os` off `torch.serialization` (which does `import os`) and calls `system` on it; the
#: dotted name is then `torch.serialization.os.system`, not `os.system`, so the direct match misses
#: it (census B: PickleBall `ours/call_system.pkl`). Only the unambiguous command/code modules are
#: here -- a benign module whose last component is literally `os`/`subprocess`/`runpy` is not a real
#: shape, while `code`/`commands`/`socket` as a trailing component plausibly are, so they are left out.
SUFFIX_MODULES: Final = frozenset({"os", "posix", "nt", "subprocess", "runpy"})

#: Callables dangerous by name wherever they are imported from. A re-export of `execfile` under
#: `_pydev_bundle._pydev_execfile` runs a file all the same (census B: `pytorch_reduce_execfile.pt`).
DANGEROUS_CALLABLES: Final = frozenset({"execfile"})

#: Dangerous-but-dual-use: object-reconstruction primitives that benign model files legitimately
#: use -- getattr/setattr to rebuild attributes, functools.partial, operator/types helpers, and
#: dill's own `_dill` module (how every dill-serialised object rebuilds itself). On their own these
#: are reported as an unexplained import (SUSPECT.MODEL.PICKLE_IMPORT), not a load-and-run block;
#: paired with a DANGEROUS_ALWAYS import in the same pickle they keep the critical PICKLE_EXEC
#: (census B: the 14 benign ML-weight false positives were dill._dill._*, __builtin__.getattr,
#: functools.partial, builtins.setattr -- none alongside an os/exec import).
DANGEROUS_DUAL: Final = frozenset(
    {
        "builtins.getattr",
        "builtins.setattr",
        "builtins.globals",
        "builtins.vars",
        "__builtin__.getattr",
        "__builtin__.setattr",
        "operator.attrgetter",
        "operator.methodcaller",
        "functools.partial",
        "types.FunctionType",
        "types.CodeType",
        "types.LambdaType",
    }
)
DANGEROUS_DUAL_PREFIXES: Final = ("dill._dill.",)

SAFE_PREFIXES: Final = (
    "torch.",
    "numpy.",
    "collections.",
    "sklearn.",
    "scipy.",
    "pandas.",
    "xgboost.",
    "lightgbm.",
    "tensorflow.",
    "keras.",
    "transformers.",
    "tokenizers.",
    # The rest of the data and model stack a shipped model or cache names (review 98: joblib's
    # numpy wrapper, CatBoost and scikit-learn models, Sphinx's build environment, paths).
    "joblib.numpy_pickle.",
    "catboost.",
    "sentence_transformers.",
    "gensim.",
    "spacy.",
    "statsmodels.",
    "networkx.",
    "docutils.nodes.",
    "sphinx.addnodes.",
    "sphinx.environment.",
    "pathlib.PosixPath",
    "pathlib.WindowsPath",
    "pathlib.PurePosixPath",
    "pathlib.PureWindowsPath",
    "uuid.UUID",
    "datetime.",
    "decimal.",
    "fractions.",
    "copyreg._reconstructor",
    "_codecs.encode",
    "builtins.set",
    "builtins.frozenset",
    "builtins.slice",
    "builtins.bytearray",
    "builtins.complex",
    "builtins.range",
    "__builtin__.set",
    "__builtin__.slice",
    "__builtin__.frozenset",
)
"""Imports ordinary model files make. Anything neither dangerous nor listed here is reported as
unrecognised rather than trusted."""


@dataclass(frozen=True)
class PickleImport:
    module: str
    name: str
    offset: int
    member: str = ""
    """The archive member the pickle was read from, for a PyTorch zip."""

    @property
    def dotted(self) -> str:
        return f"{self.module}.{self.name}"

    @property
    def dangerous(self) -> bool:
        if self.name in DANGEROUS_CALLABLES:
            return True
        for module, names in DANGEROUS.items():
            if self.module == module or self.module.startswith(module + "."):
                return names is None or self.name in names
        # A command/code module reached through an attribute chain, named in the module or the
        # qualified name: `torch` GET `serialization.os.system` is os.system off torch's `os`. Any
        # command/code module that appears as a component with a callable after it is dangerous.
        return any(part in SUFFIX_MODULES for part in self.dotted.split(".")[:-1])

    @property
    def dual(self) -> bool:
        """A dangerous import that is also an ordinary object-reconstruction primitive."""
        return self.dotted in DANGEROUS_DUAL or self.dotted.startswith(DANGEROUS_DUAL_PREFIXES)

    @property
    def always(self) -> bool:
        """Dangerous and not merely a reconstruction primitive: loading runs it (os, exec, a loader)."""
        return self.dangerous and not self.dual

    @property
    def recognised(self) -> bool:
        return self.dotted.startswith(SAFE_PREFIXES) or self.dotted in SAFE_PREFIXES


@dataclass
class PickleReport:
    imports: list[PickleImport] = field(default_factory=list)
    partial: bool = False
    refusal: str | None = None
    """Why the read is partial, where the reader itself stopped keeping what it read: the memo
    past `MAX_MEMO_BYTES`. Reported as the file read in part."""
    memo_bytes: int = 0
    """What the memo holds, in bytes: 8 an entry."""
    """Only part of the stream could be read (the file was read in part, or ended early)."""
    pickles: int = 0


class PickleReader:
    """The imports a pickle would perform when loaded, without loading it."""

    @staticmethod
    def looks_like_pickle(raw: bytes) -> bool:
        """A pickle stream (protocol 2 to 5, or 0/1 opening with a GLOBAL), or a zip that holds one the
        way PyTorch saves it."""
        if len(raw) >= 2 and raw[0] == 0x80 and 2 <= raw[1] <= 5:
            return True
        if raw[:1] == b"c" and b"\n" in raw[:256]:
            return True
        if raw[:4] == b"PK\x03\x04":
            return b"data.pkl" in raw[:4096] or b"/data.pkl" in raw[-65536:]
        return False

    @staticmethod
    @FormatBounds.bounded
    def read(raw: bytes, *, truncated: bool = False) -> PickleReport:
        """Every import a pickle, or a PyTorch zip of pickles, would perform on load."""
        report = PickleReport(partial=truncated)
        if raw[:4] == b"PK\x03\x04":
            for member, data, cut in PickleReader._zip_pickles(raw, truncated=truncated):
                report.partial |= cut
                PickleReader._walk_streams(data, report, member)
        else:
            PickleReader._walk_streams(raw, report, "")
        if report.pickles == 0 and not report.imports and not report.partial:
            raise FormatError("not a readable pickle")
        return report

    @staticmethod
    def read_members(
        members: Iterable[tuple[str, bytes]], *, truncated: bool = False
    ) -> PickleReport:
        """A report over pickle members already extracted from an archive (by name and bytes), for
        a zip too large to hold that was read through its index on disk (`detect/binary/formats`).
        Each member is walked as its own stream set; nothing here raises on an empty set."""
        report = PickleReport(partial=truncated)
        for name, data in members:
            PickleReader._walk_streams(data, report, name)
        return report

    @staticmethod
    def _walk_streams(data: bytes, report: PickleReport, member: str) -> None:
        """A file can hold several pickle streams end to end: a benign decoy that STOPs early, then
        the real payload appended after it (PickleBall `coldwaterq_inject_calc.pt`, whose first
        stream is a lone integer). Walk each from where the last one stopped; a run of bytes that is
        not a pickle ends the file. `genops` leaves the position just past the STOP it read, so the
        next walk resumes at the following stream."""
        stream = io.BytesIO(data)
        total = len(data)
        while stream.tell() < total and report.pickles < MAX_PICKLES:
            start = stream.tell()
            count, clean = PickleReader._walk(stream, report, member)
            if count == 0 or stream.tell() <= start:
                # Nothing here was a pickle opcode: trailing data, not another stream.
                break
            report.pickles += 1
            if not clean:
                # The stream ran out or hit a byte that is not an opcode; stop before trailing data.
                break

    @staticmethod
    def _walk(stream: io.BytesIO, report: PickleReport, member: str) -> tuple[int, bool]:
        """Follow the stack from each opcode's declared effect, so `STACK_GLOBAL` names exactly the
        two values it would consume -- a decoy string pushed and popped in between changes nothing.

        Reads one stream from the current position to its STOP. Returns the opcode count and whether
        it ended cleanly at a STOP; a count of zero means the position did not begin a pickle."""
        stack: list[object] = []  # a string as the offset of its opcode (int); else None or _MARK
        memo = array.array("q")
        memo_count = 0
        count = 0
        again: io.BytesIO | None = None  # a second view of the bytes, to read a string back
        try:
            for opcode, argument, position in pickletools.genops(stream):
                count += 1
                name = opcode.name
                if name in ("GLOBAL", "INST"):
                    module, _, attribute = str(argument).partition(" ")
                    report.imports.append(PickleImport(module, attribute, position or 0, member))
                elif name == "STACK_GLOBAL":
                    if again is None:
                        again = io.BytesIO(stream.getbuffer())
                    module_value, name_value = (
                        (
                            PickleReader._string_at(again, stack[-2]),
                            PickleReader._string_at(again, stack[-1]),
                        )
                        if len(stack) >= 2
                        else (None, None)
                    )
                    if isinstance(module_value, str) and isinstance(name_value, str):
                        report.imports.append(
                            PickleImport(module_value, name_value, position or 0, member)
                        )
                    else:
                        report.imports.append(
                            PickleImport("<unresolved>", "<unresolved>", position or 0, member)
                        )
                if name == "MEMOIZE":
                    PickleReader._memoise(memo, memo_count, stack, report)
                    memo_count += 1
                    continue
                if name in ("PUT", "BINPUT", "LONG_BINPUT"):
                    PickleReader._memoise(memo, int(str(argument)), stack, report)
                    continue
                before = opcode.stack_before
                if pickletools.markobject in before:
                    while stack and stack.pop() is not _MARK:
                        pass
                    del stack[len(stack) - before.index(pickletools.markobject) :]
                elif before:
                    del stack[max(len(stack) - len(before), 0) :]
                if name in _STRING_OPS:
                    stack.append(position)  # the string, as where to read it back from
                elif name in ("GET", "BINGET", "LONG_BINGET"):
                    key = int(str(argument))
                    found = memo[key] if 0 <= key < len(memo) else -1
                    stack.append(found if found >= 0 else None)
                else:
                    stack.extend(
                        _MARK if item is pickletools.markobject else None
                        for item in opcode.stack_after
                    )
        except FormatError:
            raise
        except (ValueError, EOFError, struct.error, UnicodeDecodeError, IndexError):
            # A stream that ends early is expected when only the start of a file was read; anything
            # found before the break is still reported. `count == 0` means the position was not a
            # pickle at all (`read` turns an empty, un-truncated result into an unreadable finding).
            if count > 0:
                report.partial = True
            return count, False
        return count, True

    @staticmethod
    def _memoise(
        memo: array.array[int], key: int, stack: list[object], report: PickleReport
    ) -> None:
        """Record what a later `GET` of `key` gives: the offset of the string on top of the stack,
        or -1 for any other value (a `GET` of it gives None, what the value gave). The memo is an
        array of offsets, 8 bytes an entry, so it holds the pickle's data at no cost but the
        count; past `MAX_MEMO_BYTES` nothing more is kept and the read is reported as partial."""
        top = stack[-1] if stack else None
        offset = top if isinstance(top, int) else -1
        if key >= len(memo):
            if (key + 1) * memo.itemsize > MAX_MEMO_BYTES:
                report.partial = True
                report.refusal = report.refusal or (
                    f"its memo exceeds {MAX_MEMO_BYTES} bytes: imports through the memo past "
                    "that point are unresolved"
                )
                return
            memo.extend([-1] * (key + 1 - len(memo)))
            report.memo_bytes = len(memo) * memo.itemsize
        memo[key] = offset

    @staticmethod
    def _string_at(again: io.BytesIO, value: object) -> str | None:
        """The string a stack entry stands for, read back from its opcode; None for any other."""
        if not isinstance(value, int):
            return None
        again.seek(value)
        try:
            opcode, argument, _position = next(pickletools.genops(again))
        except (ValueError, EOFError, StopIteration):
            return None
        if opcode.name not in _STRING_OPS:
            return None
        return argument.decode("latin-1") if isinstance(argument, bytes) else str(argument)

    @staticmethod
    def _zip_pickles(raw: bytes, *, truncated: bool) -> list[tuple[str, bytes, bool]]:
        found: list[tuple[str, bytes, bool]] = []
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for info in archive.infolist():
                    if info.filename.endswith(".pkl"):
                        if len(found) >= MAX_PICKLES:
                            raise FormatError(f"the archive holds more than {MAX_PICKLES} pickles")
                        with archive.open(info) as handle:
                            found.append((info.filename, handle.read(64 << 20), False))
            return found
        except zipfile.BadZipFile:
            pass
        # Read in part: the central directory at the end is missing, so walk the local headers.
        offset = 0
        while len(found) < MAX_PICKLES:
            offset = raw.find(b"PK\x03\x04", offset)
            if offset < 0 or offset + 30 > len(raw):
                break
            method, csize, _usize, name_len, extra_len = struct.unpack_from(
                "<8xH8xIIHH", raw, offset
            )
            name = raw[offset + 30 : offset + 30 + name_len].decode("utf-8", errors="replace")
            start = offset + 30 + name_len + extra_len
            if name.endswith(".pkl") and method == 0:
                data = raw[start : start + csize] if csize else raw[start:]
                found.append((name, data, len(data) < csize or truncated))
            offset = start + max(csize, 1)
        if not found:
            raise FormatError("no pickle was found in the archive")
        return found


_STRING_OPS: Final = frozenset(
    {
        "SHORT_BINUNICODE",
        "BINUNICODE",
        "UNICODE",
        "BINUNICODE8",
        "SHORT_BINSTRING",
        "BINSTRING",
        "STRING",
    }
)
_MARK: Final = object()


__all__ = ["DANGEROUS", "PICKLE_SUFFIXES", "PickleImport", "PickleReader", "PickleReport"]
