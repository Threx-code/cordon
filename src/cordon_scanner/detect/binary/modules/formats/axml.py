"""Android's compiled resource formats: the binary XML of AndroidManifest.xml and the resource table.

An APK's manifest is not text: aapt compiles it to a chunked binary form (ResXMLTree), with every name
and string in a string pool, and attributes that may be named by their resource ID instead of their
text. Malware strips or scrambles the attribute names (the platform reads the IDs, so the app still
installs), so an Android attribute is identified by its resource ID first and by its name only where
the file carries no ID, as the platform and Google's aapt2 do. `@string/...` references are resolved
through resources.arsc to the default configuration's value, else the first configuration that has
one, the way `aapt2 dump badging` reports an application label.

Every structure is read through the Cursor, bounds-checked; a chunk that does not fit ends the walk with
what was read before it. Nothing here allocates more than the file holds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.layout import ABSENT, Cursor


class Pool:
    """A ResStringPool: strings by index, UTF-8 or UTF-16, decoded once when first read."""

    __slots__ = ("count", "cur", "memo", "offsets_at", "strings_at", "utf8")

    UTF8_FLAG: ClassVar[int] = 0x100

    def __init__(self, cur: Cursor, at: int) -> None:
        u = cur.uint
        header = u(at + 2, 2, "little")
        self.cur = cur
        self.memo: dict[int, str | None] = {}
        self.count = int(u(at + 8, 4, "little") or 0)
        self.utf8 = bool((u(at + 16, 4, "little") or 0) & self.UTF8_FLAG)
        self.strings_at = at + int(u(at + 20, 4, "little") or 0)
        self.offsets_at = at + int(header or 0)

    def get(self, index: int) -> str | None:
        if not 0 <= index < self.count:
            return None
        if index in self.memo:
            return self.memo[index]
        rel = self.cur.uint(self.offsets_at + 4 * index, 4, "little")
        value = None if rel is ABSENT else self._read(self.strings_at + int(rel))
        self.memo[index] = value
        return value

    def _read(self, at: int) -> str | None:
        if self.utf8:
            # The UTF-16 length, then the UTF-8 byte length, each one byte or two (high bit set).
            skip = self._length(at, 1)
            if skip is None:
                return None
            length = self._length(skip[1], 1)
            if length is None:
                return None
            start, end = length[1], length[1] + length[0]
            return None if end > self.cur.n else self.cur.data[start:end].decode("utf-8", "replace")
        length = self._length(at, 2)
        if length is None:
            return None
        start, end = length[1], length[1] + 2 * length[0]
        return None if end > self.cur.n else self.cur.data[start:end].decode("utf-16-le", "replace")

    def _length(self, at: int, width: int) -> tuple[int, int] | None:
        """A string pool length of `width`-byte units: one unit, or two when the first's high bit is
        set. Returns the length and where the bytes after it start."""
        first = self.cur.uint(at, width, "little")
        if first is ABSENT:
            return None
        high = 1 << (8 * width - 1)
        if not int(first) & high:
            return int(first), at + width
        second = self.cur.uint(at + width, width, "little")
        if second is ABSENT:
            return None
        return ((int(first) & (high - 1)) << (8 * width)) | int(second), at + 2 * width


@dataclass
class Element:
    """One element of the binary XML: its name, its attributes by Android resource ID and by name, and
    its children."""

    name: str
    by_id: dict[int, Any] = field(default_factory=dict)
    by_name: dict[str, Any] = field(default_factory=dict)
    children: list[Element] = field(default_factory=list)

    def attr(self, resource_id: int, name: str) -> Any:
        """The attribute an Android resource ID names, else the one its text names."""
        if resource_id in self.by_id:
            return self.by_id[resource_id]
        return self.by_name.get(name)

    def all(self, name: str) -> list[Element]:
        return [c for c in self.children if c.name == name]


class Reference:
    """An attribute whose value is a resource (`@string/app_name`): its ID, resolved on request."""

    __slots__ = ("id",)

    def __init__(self, resource_id: int) -> None:
        self.id = resource_id


class BinaryXml:
    """A ResXMLTree read into elements."""

    XML, POOL, RESOURCE_MAP = 0x0003, 0x0001, 0x0180
    START, END = 0x0102, 0x0103
    STRING, REFERENCE, INT_DEC, INT_HEX, BOOLEAN = 0x03, 0x01, 0x10, 0x11, 0x12
    MAX_DEPTH: ClassVar[int] = 256

    @staticmethod
    def root(file: bytes) -> Element | None:
        """The document element of a compiled XML file, or None when the bytes are not one."""
        cur = Cursor(file)
        u = cur.uint
        if u(0, 2, "little") != BinaryXml.XML:
            return None
        at = int(u(2, 2, "little") or 8)
        pool: Pool | None = None
        ids: list[int] = []
        stack: list[Element] = [Element("")]
        while at + 8 <= cur.n:
            kind, size = u(at, 2, "little"), int(u(at + 4, 4, "little") or 0)
            if size < 8 or at + size > cur.n:
                break
            if kind == BinaryXml.POOL and pool is None:
                pool = Pool(cur, at)
            elif kind == BinaryXml.RESOURCE_MAP:
                header = int(u(at + 2, 2, "little") or 8)
                ids = [int(u(p, 4, "little") or 0) for p in range(at + header, at + size - 3, 4)]
            elif kind == BinaryXml.START and pool is not None:
                element = BinaryXml._element(cur, at, pool, ids)
                if element is not None and len(stack) < BinaryXml.MAX_DEPTH:
                    stack[-1].children.append(element)
                    stack.append(element)
            elif kind == BinaryXml.END and len(stack) > 1:
                stack.pop()
            at += size
        top = stack[0].children
        return top[0] if top else None

    @staticmethod
    def _value(pool: Pool, raw: Any, kind: Any, data: Any) -> Any:
        """An attribute's value: its string, a resource reference, or its number."""
        if kind == BinaryXml.REFERENCE and data is not ABSENT:
            return Reference(int(data))
        if kind == BinaryXml.STRING:
            index = data if raw in (ABSENT, 0xFFFFFFFF) else raw
            return None if index is ABSENT else pool.get(int(index))
        if raw not in (ABSENT, 0xFFFFFFFF):
            return pool.get(int(raw))
        return None if data is ABSENT else int(data)

    @staticmethod
    def _element(cur: Cursor, at: int, pool: Pool, ids: list[int]) -> Element | None:
        u = cur.uint
        header = int(u(at + 2, 2, "little") or 16)
        ext = at + header
        name = pool.get(int(u(ext + 4, 4, "little") or 0xFFFFFFFF))
        start, size, count = (int(u(ext + o, 2, "little") or 0) for o in (8, 10, 12))
        if name is None:
            return None
        element = Element(name)
        for i in range(count):
            a = ext + start + i * (size or 20)
            name_index = u(a + 4, 4, "little")
            if name_index is ABSENT:
                break
            raw, kind, data = u(a + 8, 4, "little"), u(a + 15, 1), u(a + 16, 4, "little")
            element_value = BinaryXml._value(pool, raw, kind, data)
            index = int(name_index)
            if 0 <= index < len(ids) and ids[index] >> 24 == 0x01:
                element.by_id[ids[index]] = element_value
            text = pool.get(index)
            if text is not None:
                element.by_name[text] = element_value
        return element


class ResourceTable:
    """resources.arsc, read for one thing: a resource ID's string value, default configuration first."""

    TABLE, POOL, PACKAGE, TYPE = 0x0002, 0x0001, 0x0200, 0x0201
    NO_ENTRY: ClassVar[int] = 0xFFFFFFFF

    __slots__ = ("cur", "packages", "strings")

    def __init__(self, file: bytes) -> None:
        self.cur = Cursor(file)
        self.strings: Pool | None = None
        self.packages: dict[int, list[int]] = {}  # package id -> its type chunks' offsets
        u = self.cur.uint
        if u(0, 2, "little") != self.TABLE:
            return
        at = int(u(2, 2, "little") or 12)
        while at + 8 <= self.cur.n:
            kind, size = u(at, 2, "little"), int(u(at + 4, 4, "little") or 0)
            if size < 8 or at + size > self.cur.n:
                break
            if kind == self.POOL and self.strings is None:
                self.strings = Pool(self.cur, at)
            elif kind == self.PACKAGE:
                self._package(at, size)
            at += size

    def _package(self, at: int, size: int) -> None:
        u = self.cur.uint
        pid = int(u(at + 8, 4, "little") or 0)
        header = int(u(at + 2, 2, "little") or 0)
        chunk, end = at + header, at + size
        types = self.packages.setdefault(pid, [])
        while chunk + 8 <= end:
            kind, csize = u(chunk, 2, "little"), int(u(chunk + 4, 4, "little") or 0)
            if csize < 8 or chunk + csize > end:
                break
            if kind == self.TYPE:
                types.append(chunk)
            chunk += csize

    def string(self, resource_id: int) -> str | None:
        """The string a resource ID names: the default configuration's value, else the first that has
        one; following one reference to another string resource."""
        for _ in range(4):  # @string/a may itself be @string/b; a loop is cut, not followed forever
            found = self._value(resource_id)
            if found is None:
                return None
            kind, data = found
            if kind == BinaryXml.STRING:
                return self.strings.get(data) if self.strings is not None else None
            if kind != BinaryXml.REFERENCE:
                return None
            resource_id = data
        return None

    def _value(self, resource_id: int) -> tuple[int, int] | None:
        u = self.cur.uint
        pid, tid, eid = resource_id >> 24, (resource_id >> 16) & 0xFF, resource_id & 0xFFFF
        first: tuple[int, int] | None = None
        for chunk in self.packages.get(pid, ()):
            if u(chunk + 8, 1) != tid:
                continue
            header = int(u(chunk + 2, 2, "little") or 0)
            count = int(u(chunk + 12, 4, "little") or 0)
            entries_at = chunk + int(u(chunk + 16, 4, "little") or 0)
            if eid >= count:
                continue
            offset = u(chunk + header + 4 * eid, 4, "little")
            if offset in (ABSENT, self.NO_ENTRY):
                continue
            entry = entries_at + int(offset)
            flags = u(entry + 2, 2, "little")
            if (
                flags is ABSENT or int(flags) & 0x0001
            ):  # a complex (bag) entry holds no single string
                continue
            entry_size = int(u(entry, 2, "little") or 8)
            kind, data = u(entry + entry_size + 3, 1), u(entry + entry_size + 4, 4, "little")
            if kind is ABSENT or data is ABSENT:
                continue
            value = (int(kind), int(data))
            if self._default(chunk):
                return value
            first = first or value
        return first

    def _default(self, chunk: int) -> bool:
        """Whether a type chunk's configuration is the default one (every qualifier unset)."""
        u = self.cur.uint
        config_at = chunk + 20
        size = int(u(config_at, 4, "little") or 0)
        body = self.cur.data[config_at + 4 : config_at + max(size, 4)]
        return not any(body)


__all__ = ["BinaryXml", "Element", "Reference", "ResourceTable"]
