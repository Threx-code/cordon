"""File formats recognised by the bytes they start with: each format's magic, where it sits, whether
the format runs, the extensions it is normally stored under and what kind of thing it is -- so a
file's format can be named whatever it is called, and a name that disagrees with its bytes noticed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


MAX_FAT_ARCHITECTURES = 20
"""How many slices a universal binary may declare and still be one.

`0xCAFEBABE` is both a Java class file's magic and a Mach-O universal binary's.
The four bytes after it are a count of architectures in one and a class-file
version in the other, and the two ranges do not overlap: a fat binary holds a
handful of slices, and a class file's version has been at least 45 since Java
1.1. Twenty is comfortably above any real slice count and far below any version
field."""


class MachO:
    """Mach-O headers that share a magic number with other formats."""

    @staticmethod
    def _is_fat_macho(head: bytes) -> bool:
        """Whether `0xCAFEBABE` here begins a universal binary rather than a class.

        Without this, `fat.dylib` was identified as a Java class and reported as a
        file whose contents contradict its name -- on the strength of four bytes
        that two formats happen to share.
        """
        if len(head) < 8:
            return False
        return int.from_bytes(head[4:8], "big") <= MAX_FAT_ARCHITECTURES


@dataclass(frozen=True, slots=True)
class Format:
    """A file format, recognised by the bytes it starts with."""

    name: str
    magic: tuple[bytes, ...]
    executable: bool = False
    extensions: tuple[str, ...] = ()
    """Extensions this format is normally stored under. Used only to notice
    disagreement; an empty tuple means the format is not tied to a name."""

    offset: int = 0
    """Where the magic sits, for a format that puts a length before its signature.

    Zero for everything whose bytes start with its own magic, which is nearly all of
    them. See `ISO-BMFF image`, whose signature follows a box length."""

    kind: str = "data"
    """What the format IS, as distinct from what it is called.

    Only `INTERCHANGEABLE_KINDS` acts on this. Everything else keeps comparing
    formats, because within the executable kinds the distinction is the whole
    point: a shell script named `.so` and a Java class named `.dylib` are both
    worth reporting, and both share a kind with the format they displace."""


FORMATS: tuple[Format, ...] = (
    Format(
        "ELF executable",
        (b"\x7fELF",),
        executable=True,
        # `.dll` is here because .NET names a native interop library `.dll` on
        # every platform it targets: `duplicati` ships
        # `ReleaseBuilder/Resources/linux-arm-binary/SQLite.Interop.dll`, which is an
        # ELF, and the finding read "an executable rather than an executable" -- the
        # message saying in its own words that nothing was disguised.
        #
        # `.o` was here and is gone. An object file is whatever the toolchain emits:
        # ELF, Mach-O, COFF, WebAssembly, or a Windows resource object --
        # `bazel/src/main/cpp/resources.o` is the last of those and `dotnet/runtime`
        # and `clay` ship wasm ones. A `.o` is linked rather than executed, so the
        # substitution this rule exists to notice cannot be made with one, and
        # enumerating every format a compiler may write is a list that is always
        # one toolchain out of date.
        extensions=(".so", ".elf", ".dll"),
        kind="executable",
    ),
    Format(
        "PE executable",
        (b"MZ",),
        executable=True,
        # `.sys` was here and is gone. It means a PE driver on modern Windows and
        # something else everywhere the name came from first: `rufus` ships FreeDOS's
        # `KERNEL.SYS` and four keyboard drivers as DOS boot images, syslinux's
        # `ldlinux_v6.sys` opens with its own text header, and `cosmopolitan` keeps
        # terminfo entries at `usr/share/terminfo/a/ansi.sys`. Nine findings across
        # the corpus, every one a file correctly named for what it is.
        extensions=(".exe", ".dll"),
        kind="executable",
    ),
    Format(
        "Mach-O executable",
        (
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
            b"\xce\xfa\xed\xfe",
            # Universal ("fat") binaries, in all four spellings. The first is
            # byte-for-byte a Java class file's magic; `identify` tells them
            # apart by what follows. See `_is_fat_macho`.
            b"\xca\xfe\xba\xbe",
            b"\xca\xfe\xba\xbf",
            b"\xbe\xba\xfe\xca",
            b"\xbf\xba\xfe\xca",
        ),
        executable=True,
        # `.so` is here as well as under ELF. A shared object is ELF on Linux
        # and Mach-O on macOS, and every compiled Python extension on a Mac is
        # a Mach-O `.so`: `_socket.cpython-312-darwin.so`, `_ssl...so`, and so
        # on. Listing it only under ELF meant scanning any macOS virtualenv
        # reported every one of them as a file whose contents contradict its
        # name -- two hundred and forty-five high-severity findings in one
        # `site-packages`, and the first thing a Mac user would have seen.
        # `.bundle` was here and is gone, for the reason `.o` and `.sys` above are: the
        # extension has more than one settled meaning. A Ruby or Python native extension
        # on macOS is a Mach-O `.bundle`, and `gtk-mac-bundler` reads an XML document with
        # the same extension -- `nmap` keeps one at
        # `zenmap/install_scripts/macosx/zenmap.bundle`, which opens `<?xml version="1.0"`.
        # A `.bundle` is `dlopen`ed rather than executed, so the substitution this rule
        # exists to notice cannot be made with one.
        extensions=(".dylib", ".so", ".dll"),
        kind="executable",
    ),
    Format(
        "Java class",
        (b"\xca\xfe\xba\xbe",),
        executable=True,
        extensions=(".class",),
        kind="executable",
    ),
    Format(
        "WebAssembly",
        (b"\x00asm",),
        executable=True,
        extensions=(".wasm",),
        kind="executable",
    ),
    # No extensions, deliberately. A shebang identifies a script when it is
    # present, but no source extension *promises* one: most Python files have
    # no shebang, and listing `.py` here made every one of them disagree with
    # its own name. Only formats whose files must begin with their magic take
    # part in the mismatch check.
    Format("shell script", (b"#!",), executable=True, kind="executable"),
    Format(
        "ZIP archive",
        # `PK\x03\x04` is a local file header, which an archive with no members does
        # not have. An EMPTY zip is its end-of-central-directory record alone --
        # `bazel/src/tools/singlejar/data/empty.zip` is exactly that, and so is
        # `ContextMenuManager`'s `ShellNew/0.zip`, the template Windows copies when
        # you ask for a new compressed folder. `PK\x07\x08` opens a spanned archive.
        (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
        extensions=(".zip", ".jar", ".whl", ".egg", ".apk"),
        kind="archive",
    ),
    Format("gzip archive", (b"\x1f\x8b",), extensions=(".gz", ".tgz"), kind="archive"),
    Format(
        "PNG image",
        (
            b"\x89PNG\r\n\x1a\n",
            # The same file after a text-mode round trip. `0x89` is not valid UTF-8,
            # so a tool that decoded the bytes as text and re-encoded them replaced it
            # with U+FFFD: `radare2/shlr/www/t/rlogo.png` begins with the three bytes
            # of the replacement character and then `PNG\r\n\x1a\n`. The file is a
            # damaged PNG, which is a mistake in the repository rather than a format
            # wearing another format's name, and the rule is about disguise.
            b"\xef\xbf\xbdPNG\r\n\x1a\n",
        ),
        extensions=(".png",),
        kind="image",
    ),
    Format("JPEG image", (b"\xff\xd8\xff",), extensions=(".jpg", ".jpeg"), kind="image"),
    Format("GIF image", (b"GIF8",), extensions=(".gif",), kind="image"),
    Format("PDF document", (b"%PDF-",), extensions=(".pdf",), kind="document"),
    # The rest of the image formats, added for the kind test rather than for their own
    # sake. Jest's `website/static/img/favicon.png` is a Photoshop document, which was
    # reported as "named .png but its contents are not png image" -- true, and the
    # reason it says "not" rather than naming PSD is that PSD was not in this table.
    # An image saved in the wrong format is a naming error whichever direction it goes,
    # and the check can only say so about formats it can recognise.
    Format("Photoshop document", (b"8BPS",), extensions=(".psd", ".psb"), kind="image"),
    Format("BMP image", (b"BM",), extensions=(".bmp",), kind="image"),
    Format(
        "TIFF image",
        (b"II*\x00", b"MM\x00*"),
        extensions=(".tif", ".tiff"),
        kind="image",
    ),
    Format("ICO image", (b"\x00\x00\x01\x00",), extensions=(".ico",), kind="image"),
    # The modern formats, which are the commonest wrong extension there is: a build
    # step or a designer converts an asset and keeps the old name. `odysseus`'s
    # `static/icons/sglang-logo.png` and `miru-app`'s `assets/icon/anilist.jpg` are
    # both WebP, and neither was recognised at all -- so the check could not say they
    # were images saved under the wrong name, only that they were "not PNG".
    #
    # WebP, AVIF and HEIC all sit inside a container whose magic is at an offset, so
    # each is matched on the container signature that precedes it. RIFF and ISO-BMFF
    # both carry a length field between the signature and the brand, which is why the
    # brand cannot be part of a prefix match.
    Format("WebP image", (b"RIFF",), extensions=(".webp",), kind="image"),
    Format(
        "ISO-BMFF image",
        # `ftyp` at offset four, with the four bytes before it a big-endian box length.
        # Those three lengths were written out as prefixes and the length is whatever
        # the brand list needs: `dioxus` and `glide` both ship AVIFs whose first box is
        # 0x2c bytes long, and neither was recognised. An offset is the honest way to
        # say "these four bytes, after a length I am not going to predict".
        (b"ftyp",),
        offset=4,
        extensions=(".avif", ".heic", ".heif"),
        kind="image",
    ),
    # SVG is deliberately absent. Every other entry here is a format whose files MUST
    # begin with fixed bytes, which is what makes an extension a promise worth
    # checking; an SVG is XML and may open with a comment, a doctype, a BOM or
    # whitespace. Adding it made `.svg` a promise and produced two findings on
    # Grafana's own icons within one run -- the same mistake the shebang entry above
    # already records for source extensions.
)


__all__ = ["FORMATS", "MAX_FAT_ARCHITECTURES", "Format", "MachO"]
