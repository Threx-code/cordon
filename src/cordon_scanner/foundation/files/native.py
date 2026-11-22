"""Whether a file is a native executable or library: the files a release can ship that no source rule reads."""

from __future__ import annotations

from typing import Final

_MAGIC: Final = (
    b"\x7fELF",  # ELF: Linux and BSD executables, shared objects, `.node` addons
    b"\xfe\xed\xfa\xce",  # Mach-O, 32-bit, either byte order
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",  # Mach-O, 64-bit, either byte order
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",  # a Mach-O universal binary, or a Java class file: both are executable code
    b"\x00asm",  # WebAssembly
)
_PORTABLE_EXECUTABLE_EXTENSIONS: Final = frozenset(
    {".exe", ".dll", ".sys", ".scr", ".ocx", ".pyd", ".node", ".efi"}
)


class NativeFile:
    @staticmethod
    def is_native(path: str, head: bytes) -> bool:
        """Whether a file with this name and these first bytes is an ELF, Mach-O, WebAssembly or Java class file, or a
        Windows executable (`MZ` and a name that says so; a bare `MZ` is a text file often enough to mean nothing)."""
        if head.startswith(_MAGIC):
            return True
        name = path.rsplit("!", 1)[-1].rsplit("/", 1)[-1].lower()
        dot = name.rfind(".")
        return head[:2] == b"MZ" and dot > 0 and name[dot:] in _PORTABLE_EXECUTABLE_EXTENSIONS
