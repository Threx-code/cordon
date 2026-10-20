"""What a compiled Java class calls and the string constants it carries, read from its constant pool.

Maven, Gradle and JCenter artifacts ship compiled classes. The malicious ones measured in review 98
(com.github.codingandcoding's maven-compiler-plugin, mail-watcher-plugin) published a clean
`-sources.jar` beside a jar whose bytecode was not built from it: the Java rules read the sources,
found the upstream project, and saw nothing. A class file keeps a readable record of what the rules
need -- every method it calls, by owner and name, and every string constant -- in its constant pool
(JVM specification, chapter 4.4).

```
  class file ──► magic 0xCAFEBABE, version ──► constant pool
                                                ├── Utf8          names and text
                                                ├── Class         -> Utf8 owner
                                                ├── Methodref     -> Class + NameAndType
                                                └── String        -> Utf8 constant
                                │
                                ▼
  calls:      groovy/lang/GroovyShell.evaluate   java/net/URL.openConnection
  constants:  "https://..."   "/tmp/x.groovy"   "addURL"
```

Read only; nothing is loaded or run. Bounded: at most 65,535 entries as the format allows, and any
inconsistency returns None rather than a guess.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

MAX_LITERAL: Final = 2_000

# Constant-pool tags (JVMS 4.4) and the bytes each entry's body takes after its tag.
_UTF8, _CLASS, _STRING = 1, 7, 8
_FIELDREF, _METHODREF, _INTERFACE_METHODREF, _NAME_AND_TYPE = 9, 10, 11, 12
_FIXED: Final = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2}
_FIXED.update({17: 4, 18: 4, 19: 2, 20: 2})


@dataclass(frozen=True, slots=True)
class ClassRefs:
    calls: frozenset[str]
    """`owner/Name.member` for every field and method the class references."""
    strings: tuple[str, ...]
    """Its string constants, in pool order."""


class JvmClass:
    @staticmethod
    def is_class(data: bytes) -> bool:
        """A class file, not the fat Mach-O that shares its magic: a class's major version is 45
        or more, where a fat binary has its (small) architecture count there."""
        return (
            len(data) >= 10
            and data[:4] == b"\xca\xfe\xba\xbe"
            and 45 <= struct.unpack_from(">H", data, 6)[0] <= 120
        )

    @classmethod
    def references(cls, data: bytes) -> ClassRefs | None:
        if not cls.is_class(data):
            return None
        try:
            count = struct.unpack_from(">H", data, 8)[0]
            offset, index = 10, 1
            utf8: dict[int, str] = {}
            classes: dict[int, int] = {}
            strings: list[int] = []
            refs: list[tuple[int, int]] = []
            name_types: dict[int, int] = {}
            while index < count:
                tag = data[offset]
                if tag == _UTF8:
                    length = struct.unpack_from(">H", data, offset + 1)[0]
                    body = data[offset + 3 : offset + 3 + length]
                    if len(body) != length:
                        return None
                    utf8[index] = body.decode("utf-8", "replace")
                    offset += 3 + length
                elif tag in _FIXED:
                    if tag == _CLASS:
                        classes[index] = struct.unpack_from(">H", data, offset + 1)[0]
                    elif tag == _STRING:
                        strings.append(struct.unpack_from(">H", data, offset + 1)[0])
                    elif tag in (_FIELDREF, _METHODREF, _INTERFACE_METHODREF):
                        refs.append(struct.unpack_from(">HH", data, offset + 1))
                    elif tag == _NAME_AND_TYPE:
                        name_types[index] = struct.unpack_from(">H", data, offset + 1)[0]
                    offset += 1 + _FIXED[tag]
                    if tag in (5, 6):
                        # A long or a double takes two slots (JVMS 4.4.5).
                        index += 1
                else:
                    return None
                index += 1
        except (struct.error, IndexError):
            return None
        calls = frozenset(
            f"{utf8.get(classes.get(owner, 0), '')}.{utf8.get(name_types.get(nt, 0), '')}"
            for owner, nt in refs
        )
        return ClassRefs(
            calls=calls,
            strings=tuple(utf8.get(i, "")[:MAX_LITERAL] for i in strings if utf8.get(i)),
        )


__all__ = ["ClassRefs", "JvmClass"]
