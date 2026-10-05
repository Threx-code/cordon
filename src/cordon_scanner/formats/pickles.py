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

import io
import pickletools
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Final

from cordon_scanner.formats import FormatBounds, FormatError

MAX_OPCODES: Final = 2_000_000
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
        for module, names in DANGEROUS.items():
            if self.module == module or self.module.startswith(module + "."):
                return names is None or self.name in names
        return False

    @property
    def recognised(self) -> bool:
        return self.dotted.startswith(SAFE_PREFIXES) or self.dotted in SAFE_PREFIXES


@dataclass
class PickleReport:
    imports: list[PickleImport] = field(default_factory=list)
    partial: bool = False
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
                report.pickles += 1
                report.partial |= cut
                PickleReader._walk(data, report, member)
        else:
            report.pickles = 1
            PickleReader._walk(raw, report, "")
        return report

    @staticmethod
    def _walk(data: bytes, report: PickleReport, member: str) -> None:
        """Follow the stack from each opcode's declared effect, so `STACK_GLOBAL` names exactly the
        two values it would consume -- a decoy string pushed and popped in between changes nothing."""
        stack: list[object] = []
        memo: dict[int, object] = {}
        count = 0
        try:
            for opcode, argument, position in pickletools.genops(io.BytesIO(data)):
                count += 1
                if count > MAX_OPCODES:
                    raise FormatError(f"the pickle has more than {MAX_OPCODES} opcodes")
                name = opcode.name
                if name in ("GLOBAL", "INST"):
                    module, _, attribute = str(argument).partition(" ")
                    report.imports.append(PickleImport(module, attribute, position or 0, member))
                elif name == "STACK_GLOBAL":
                    module_value, name_value = (
                        (stack[-2], stack[-1]) if len(stack) >= 2 else (None, None)
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
                    memo[len(memo)] = stack[-1] if stack else None
                    continue
                if name in ("PUT", "BINPUT", "LONG_BINPUT"):
                    memo[int(str(argument))] = stack[-1] if stack else None
                    continue
                before = opcode.stack_before
                if pickletools.markobject in before:
                    while stack and stack.pop() is not _MARK:
                        pass
                    del stack[len(stack) - before.index(pickletools.markobject) :]
                elif before:
                    del stack[max(len(stack) - len(before), 0) :]
                if name in _STRING_OPS:
                    stack.append(
                        argument.decode("latin-1") if isinstance(argument, bytes) else str(argument)
                    )
                elif name in ("GET", "BINGET", "LONG_BINGET"):
                    stack.append(memo.get(int(str(argument))))
                else:
                    stack.extend(
                        _MARK if item is pickletools.markobject else None
                        for item in opcode.stack_after
                    )
        except FormatError:
            raise
        except (ValueError, EOFError, struct.error, UnicodeDecodeError, IndexError) as exc:
            # A stream that ends early is expected when only the start of a file was read; anything
            # found before the break is still reported. With nothing found, it was not a pickle.
            if not report.partial and not report.imports:
                raise FormatError(f"not a readable pickle ({type(exc).__name__})") from exc
            report.partial = True

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
