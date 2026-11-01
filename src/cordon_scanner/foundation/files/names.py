"""A file or member name as text: valid UTF-8 always, the same name for every name that is text
already, and two names never made one (item 34).

A name is bytes the scanned package chose. An archive reader or `os.scandir` hands a byte that is
not UTF-8 on as a lone surrogate (`surrogateescape`), and every `.encode()` of a path after that
raised: one such byte in a tar member's name ended the scan with no report (Finding.fingerprint).
So a name is made text where it enters, once, and nothing past that point meets a surrogate.

```
  b"run\\xa7.py"  -> "run\\udca7.py" (surrogateescape)  -> "run\\\\xa7.py"   the byte, shown
  "README.md"                                           -> "README.md"     untouched
```

Injective, because several stages key by path (the graph's files, detection's units, the cache):
two names made one would let one member's content stand for the other's. An archive member's name
is normalised first (`ArchiveReader.safe_member_name` turns `\\` into `/`), so no member name holds a
backslash and `\\xNN` cannot be a real one. A walked file's name can hold a backslash on POSIX, so
there the backslash is escaped too (`backslash=True`).
"""

from __future__ import annotations


class Names:
    @staticmethod
    def text(name: str, *, backslash: bool = False) -> str:
        """`name` with each byte that is not UTF-8 as `\\xNN`, any other lone surrogate as
        `\\uNNNN` (and, with `backslash`, each `\\` as `\\x5c`); a name that holds none is returned
        as it is."""
        if name.isascii() and not (backslash and "\\" in name):
            return name
        out = []
        for char in name:
            point = ord(char)
            if 0xDC80 <= point <= 0xDCFF:
                out.append(f"\\x{point - 0xDC00:02x}")
            elif 0xD800 <= point <= 0xDFFF:
                out.append(f"\\u{point:04x}")
            elif backslash and char == "\\":
                out.append("\\x5c")
            else:
                out.append(char)
        return "".join(out)


__all__ = ["Names"]
