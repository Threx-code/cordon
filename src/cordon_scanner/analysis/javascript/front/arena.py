"""The syntax tree as an arena: a few native columns, one record a node, in pre-order.

A tree of 1.85 million `Node` objects cost 635 MB on a 10 MB bundle, 420 with compact nodes:
Python objects, headers and all. Here a node is a record across parallel `array.array` columns,
10 bytes in all, and the file's identifiers, literals and operators are spans into the source
text, sliced when read. The same bundle's tree is about 20 MB (review 98, D4).

```
  column   type        what
  kind     u8          the node type, an index into `kinds` (about 85 of them)
  start    u32         source offset
  length   u16         span length; 0xFFFF means "look it up" in `long_length`
  size     u16         records in the subtree, the node's own included; 0xFFFF: `big_size`
  flags    u8          bits 0-3: which optional children are present; bits 4-7: the kind's booleans

  pre-order: a node's first child is i + 1; its next sibling is i + size[i]. A named field is a
  position among the children, fixed per kind by the order the grammar gives fields in; an absent
  optional child costs nothing (its presence bit is 0); a list field that comes last is the
  remaining children, and a kind whose list is not last carries a child count in `counts`.
```

Reading: the cursor functions take and return indices, with no object per node, for the walks
that cover the tree (`resolve`). `Handle` wraps an index with `Node`'s read API (`type`, `start`,
`end`, `node["field"]`, `fields`) for code that reads a node here and there; two handles to one
node compare equal and hash alike, and `key` is the index, so a map keyed by a node is keyed by
its index, never by `id()` of a short-lived handle.

Writing: `Arena.from_tree` converts a parsed `Node` tree after the parse (the tree is then
released); the parser's own emission, a function body at a time as each closes, is the next step.
"""

from __future__ import annotations

import array
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from cordon_scanner.analysis.javascript.front.syntax import Node

ESCAPE = 0xFFFF
"""A u16 column's value for "look it up in the escape dict"."""
MAX_FIELDS = 8
"""A kind's fields, at most: one flags bit each. For a child field the bit says it is present; for
a boolean, that it is true. A field's bit is its index in the kind's name tuple, which only ever
appends, so no bit changes meaning however late a field's category is learned."""


class Shape:
    """What the grammar gives a kind: its field names in order, and each field's category --
    a child (a node), a list of nodes, a boolean, a code (an operator, a declaration's `kind`) or
    text (a name, a literal's value). A field first seen as None is pending: None says nothing
    about the category, and the first Property of a bundle carried kind=None, which would have
    made `kind` an "optional child" and dropped every later "init". A child field that is ever
    None is optional, with a presence bit."""

    __slots__ = ("_category", "booleans", "children", "codes", "lists", "names", "optional", "text")

    def __init__(self, names: tuple[str, ...]) -> None:
        if len(names) > MAX_FIELDS:
            raise ValueError(f"a kind with more than {MAX_FIELDS} fields: past the flags byte")
        self.names = names
        self._category: dict[str, str] = dict.fromkeys(names, "pending")
        self.optional: set[str] = set()
        self.lists: set[str] = set()
        self.children: list[str] = []
        self.booleans: list[str] = []
        self.codes: list[str] = []
        self.text: list[str] = []

    def add(self, name: str) -> None:
        """A field the first node of the kind did not carry (the grammar builds some kinds at more
        than one site, with different fields): pending, after the names so far."""
        if name not in self._category:
            if len(self.names) >= MAX_FIELDS:
                raise ValueError(f"a kind with more than {MAX_FIELDS} fields: past the flags byte")
            self.names = (*self.names, name)
            self._category[name] = "pending"

    def classify(self, name: str, category: str) -> None:
        """`name` is a `category` field ("child", "list", "bool", "code", "text"); the ordered
        lists are rebuilt in the grammar's field order."""
        self.add(name)
        if self._category[name] == category:
            return
        self._category[name] = category
        if category == "list":
            self.lists.add(name)
        self.children = [n for n in self.names if self._category[n] in ("child", "list")]
        self.booleans = [n for n in self.names if self._category[n] == "bool"]
        self.codes = [n for n in self.names if self._category[n] == "code"]
        self.text = [n for n in self.names if self._category[n] == "text"]

    def category(self, name: str) -> str:
        return self._category.get(name, "pending")

    @property
    def needs_count(self) -> bool:
        """A kind with two list fields records the first list's length in `counts`; one list,
        wherever it sits, is the children left over once the single children are counted."""
        return sum(1 for n in self.children if n in self.lists) >= 2


class Registry:
    """What every fragment of one parse shares: the kinds by number, each kind's shape, and each
    code field's values. One per parse, made by the parser's token stream; never a module's."""

    __slots__ = ("code_values", "kind_ids", "kinds", "shapes")

    def __init__(self) -> None:
        self.kinds: list[str] = []
        self.kind_ids: dict[str, int] = {}
        self.shapes: list[Shape] = []
        self.code_values: dict[int, list[str]] = {}


class Arena:
    """The columns of one tree, with the kinds, shapes and escapes that read them."""

    CODE_FIELDS: ClassVar[frozenset[str]] = frozenset({"operator", "kind", "meta", "property"})
    """Scalar fields whose values are a small set: kept as one-byte codes, by kind."""

    STUB: ClassVar[str] = "ArenaFragment"
    """The type of a node that stands for a subtree already written: its `fragment` field is the
    Arena of that subtree, spliced in where the stub sits."""

    def __init__(self, text: str, registry: Registry | None = None) -> None:
        self.text = text
        self.registry = registry if registry is not None else Registry()
        self.kind = array.array("B")
        self.start = array.array("I")
        self.length = array.array("H")
        self.size = array.array("H")
        self.flags = array.array("B")
        self.long_length: dict[int, int] = {}
        self.big_size: dict[int, int] = {}
        self.counts: dict[int, int] = {}
        """node -> the first list field's length, for a kind with two list fields."""
        self.codes: dict[int, int] = {}
        """node -> code: the index of its operator or kind value in `code_values[kind]`."""
        self.cooked: dict[tuple[int, str], str] = {}
        """(node, field) -> cooked text, where a literal's or template element's value is not
        its span."""

    @property
    def kinds(self) -> list[str]:
        return self.registry.kinds

    @property
    def kind_ids(self) -> dict[str, int]:
        return self.registry.kind_ids

    @property
    def shapes(self) -> list[Shape]:
        return self.registry.shapes

    @property
    def code_values(self) -> dict[int, list[str]]:
        return self.registry.code_values

    # -- building ----------------------------------------------------------------------------------

    @classmethod
    def from_tree(cls, root: Node, text: str, registry: Registry | None = None) -> Arena:
        """The arena of a parsed tree, written in pre-order by an explicit stack. A stub met on
        the way (a subtree the parser already wrote as a fragment) is spliced in whole."""
        arena = cls(text, registry)
        stack: list[tuple[Node, int]] = [(root, -1)]
        while stack:
            node, entered = stack.pop()
            if entered >= 0:
                arena._close(entered)
                continue
            if node.type == Arena.STUB:
                arena._splice(node["fragment"])
                continue
            index = len(arena.kind)
            children = arena._open(node, index)
            stack.append((node, index))
            stack.extend((child, -1) for child in reversed(children))
        return arena

    def _splice(self, fragment: Arena) -> None:
        """A fragment's records after this arena's, its index-keyed tables moved by the offset.
        Both read one registry, so kinds, shapes and codes mean the same on either side."""
        if fragment.registry is not self.registry:
            raise ValueError("a fragment of another parse cannot be spliced")
        offset = len(self.kind)
        self.kind.extend(fragment.kind)
        self.start.extend(fragment.start)
        self.length.extend(fragment.length)
        self.size.extend(fragment.size)
        self.flags.extend(fragment.flags)
        self.long_length.update({i + offset: v for i, v in fragment.long_length.items()})
        self.big_size.update({i + offset: v for i, v in fragment.big_size.items()})
        self.counts.update({i + offset: v for i, v in fragment.counts.items()})
        self.codes.update({i + offset: v for i, v in fragment.codes.items()})
        self.cooked.update({(i + offset, name): v for (i, name), v in fragment.cooked.items()})

    def _open(self, node: Node, index: int) -> list[Node]:
        """One record for `node`; its children, in field order, for the stack."""
        from cordon_scanner.analysis.javascript.front.syntax import Node as NodeClass

        fields = node.fields
        kind_id = self.kind_ids.get(node.type)
        if kind_id is None:
            kind_id = self._declare(node.type, fields)
        shape = self.shapes[kind_id]
        for name, value in fields.items():
            shape.add(name)
            if shape.category(name) == "pending" and value is not None:
                self._classify(shape, name, value)
        for name in shape.children:
            if fields.get(name) is None:
                shape.optional.add(name)  # a child field this node lacks: optional, with a bit
        self.kind.append(kind_id)
        self.start.append(node.start)
        length = node.end - node.start
        if length >= ESCAPE:
            self.long_length[index] = length
            length = ESCAPE
        self.length.append(length)
        self.size.append(0)
        flags = 0
        children: list[Node] = []
        # Fields in the shape's order, not the node's own: two construction sites of one kind
        # may name their fields in different orders, and a child's position must not depend on
        # which site built the node.
        for name in shape.names:
            value = fields.get(name)
            if isinstance(value, NodeClass):
                children.append(value)
                flags |= 1 << self._slot(shape, name)
            elif isinstance(value, list):
                children.extend(v for v in value if isinstance(v, NodeClass))
                flags |= 1 << self._slot(shape, name)
            elif value is None:
                pass  # an absent optional child (or a pending field): nothing to store
            elif isinstance(value, bool):
                if value:
                    flags |= 1 << self._slot(shape, name)
            elif name in shape.codes:
                values = self.code_values.setdefault(kind_id, [])
                text = str(value)
                if text not in values:
                    values.append(text)
                self.codes[index] = values.index(text)
            elif name in shape.text:
                # Stored only where the reader's own span rule would not give it back.
                text = str(value)
                if text != Arena.from_span(self.text[node.start : node.end], name):
                    self.cooked[index, name] = text
        self.flags.append(flags)
        if shape.needs_count:
            first = next(n for n in shape.children if n in shape.lists)
            self.counts[index] = sum(1 for v in fields[first] if isinstance(v, NodeClass))
        return children

    def _close(self, index: int) -> None:
        size = len(self.kind) - index
        if size >= ESCAPE:
            self.big_size[index] = size
            size = ESCAPE
        self.size[index] = size

    def _declare(self, kind: str, fields: dict[str, Any]) -> int:
        """A kind seen for the first time: its shape, each field classified from this node's
        value where there is one (a None stays pending until a value is seen)."""
        kind_id = len(self.kinds)
        self.kinds.append(kind)
        self.kind_ids[kind] = kind_id
        shape = Shape(tuple(fields))
        self.shapes.append(shape)
        if kind_id > 0xFF:
            raise ValueError("more than 256 node kinds: past the kind byte")
        for name, value in fields.items():
            if value is not None:
                self._classify(shape, name, value)
        return kind_id

    @staticmethod
    def _classify(shape: Shape, name: str, value: Any) -> None:
        """A field's category from its value's type: a list, a boolean, a string (a code where
        the field is one of `CODE_FIELDS`, else text), or a node."""
        category = {"list": "list", "bool": "bool", "str": "text"}.get(
            type(value).__name__, "child"
        )
        if category == "text" and name in Arena.CODE_FIELDS:
            category = "code"
        shape.classify(name, category)

    # -- the cursor API: indices in, indices out -------------------------------------------------

    def kind_of(self, i: int) -> str:
        return self.kinds[self.kind[i]]

    def end_of(self, i: int) -> int:
        n = self.length[i]
        return self.start[i] + (self.long_length[i] if n == ESCAPE else n)

    def size_of(self, i: int) -> int:
        n = self.size[i]
        return self.big_size[i] if n == ESCAPE else n

    def children_of(self, i: int) -> Iterator[int]:
        end = i + self.size_of(i)
        child = i + 1
        while child < end:
            yield child
            child += self.size_of(child)

    def span_text(self, i: int) -> str:
        return self.text[self.start[i] : self.end_of(i)]

    def field(self, i: int, name: str) -> Any:
        """The named field of node `i`: a child index, a list of child indices, a scalar, or None."""
        kind_id = self.kind[i]
        shape = self.shapes[kind_id]
        if name in shape.booleans:
            return bool(self.flags[i] & (1 << self._slot(shape, name)))
        if name in shape.codes:
            code = self.codes.get(i)
            return None if code is None else self.code_values[kind_id][code]
        if name in shape.text:
            cooked = self.cooked.get((i, name))
            return cooked if cooked is not None else Arena.from_span(self.span_text(i), name)
        if name not in shape.children:
            return None
        present = [n for n in shape.children if self._present(i, shape, n)]
        if name not in present:
            return None
        children = list(self.children_of(i))
        lists = [n for n in present if n in shape.lists]
        single = len(present) - len(lists)
        position = 0
        for field_name in present:
            if field_name in shape.lists:
                if len(lists) == 1:
                    length = len(children) - single
                elif field_name == lists[0]:
                    length = self.counts.get(i, 0)
                else:
                    length = len(children) - single - self.counts.get(i, 0)
                if field_name == name:
                    return children[position : position + length]
                position += length
            else:
                if field_name == name:
                    return children[position] if position < len(children) else None
                position += 1
        return None

    def _present(self, i: int, shape: Shape, name: str) -> bool:
        return bool(self.flags[i] & (1 << self._slot(shape, name)))

    @staticmethod
    def _slot(shape: Shape, name: str) -> int:
        """A field's flags bit: its index in the kind's name tuple."""
        return shape.names.index(name)

    @staticmethod
    def from_span(span: str, name: str) -> str:
        """A text field as its span gives it: the span itself (`raw`, a name), or the span without
        its quotes (a plain literal's `value`). What this cannot give back -- an escaped literal, a
        template element's cooked text -- the writer stores in `cooked`, by the same rule."""
        if name == "raw":
            return span
        quoted = len(span) >= 2 and span[0] in "'\"" and span[-1] == span[0]
        return span[1:-1] if quoted else span

    def key(self, i: int) -> int:
        return i


class Handle:
    """One node read from an arena: `Node`'s read API over an index. Equal and hashed by index."""

    __slots__ = ("arena", "index")

    def __init__(self, arena: Arena, index: int) -> None:
        self.arena, self.index = arena, index

    @property
    def type(self) -> str:
        return self.arena.kind_of(self.index)

    @property
    def start(self) -> int:
        return self.arena.start[self.index]

    @property
    def end(self) -> int:
        return self.arena.end_of(self.index)

    @property
    def key(self) -> int:
        return self.index

    def __getitem__(self, name: str) -> Any:
        value = self.arena.field(self.index, name)
        if isinstance(value, int) and not isinstance(value, bool):
            return Handle(self.arena, value)
        if isinstance(value, list):
            return [Handle(self.arena, v) for v in value]
        return value

    def children(self) -> list[Handle]:
        """The node's children, in order (what `Syntax.children` gave for a `Node`)."""
        return [Handle(self.arena, c) for c in self.arena.children_of(self.index)]

    @property
    def fields(self) -> dict[str, Any]:
        shape = self.arena.shapes[self.arena.kind[self.index]]
        return {name: self[name] for name in shape.names}

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Handle) and other.index == self.index and other.arena is self.arena

    def __hash__(self) -> int:
        return self.index

    def __repr__(self) -> str:
        return f"Handle({self.type}, {self.start}-{self.end})"


__all__ = ["Arena", "Handle", "Registry", "Shape"]
