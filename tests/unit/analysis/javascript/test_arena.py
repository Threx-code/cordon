"""The arena holds a parsed JavaScript tree in columns (review 98, D4): what a `Handle` reads
from it is what the `Node` it was written from held, field for field; the parser that writes
function bodies into fragments as they close gives the same columns as one write of the whole
tree; and index keys stand for node identity."""

from __future__ import annotations

from typing import Any

import pytest

from cordon_scanner.analysis.javascript.front.arena import Arena, Handle, Registry
from cordon_scanner.analysis.javascript.front.parser import Parser
from cordon_scanner.analysis.javascript.front.syntax import Node, Syntax

SOURCE = """
import fs from "fs";
const name = `hello ${who}`;
export function greet(who, ...rest) {
  if (!who) { return null; }
  const inner = (x) => x * 2;
  return { who, rest, [inner(1)]: true, "quoted": 1 };
}
class Box extends Base {
  static #count = 0;
  get value() { return this.#count; }
}
label: for (let i = 0; i < 3; i++) { continue label; }
greet?.("a") ?? fs.readFileSync(name, { encoding: "utf8" });
"""


class Lockstep:
    """The tree and the arena walked side by side, every node and every field compared."""

    @staticmethod
    def same(node: Node, handle: Handle) -> bool:
        return node.type == handle.type and (node.start, node.end) == (handle.start, handle.end)

    @classmethod
    def differences(cls, root: Node, arena: Arena) -> list[str]:
        out: list[str] = []
        stack: list[tuple[Node, int]] = [(root, 0)]
        while stack:
            node, index = stack.pop()
            handle = Handle(arena, index)
            if not cls.same(node, handle):
                out.append(f"{index}: {node.type} vs {handle.type}")
                continue
            for name, value in node.fields.items():
                out.extend(cls.field_differences(handle, name, value))
            kids = list(Syntax.children(node))
            indices = list(arena.children_of(index))
            if len(kids) != len(indices):
                out.append(f"{index}: {len(kids)} children vs {len(indices)}")
                continue
            stack.extend(zip(reversed(kids), reversed(indices), strict=True))
        return out

    @classmethod
    def field_differences(cls, handle: Handle, name: str, value: Any) -> list[str]:
        got = handle[name]
        where = f"{handle.index} {handle.type}.{name}"
        if isinstance(value, Node):
            return [] if isinstance(got, Handle) and cls.same(value, got) else [f"{where}: child"]
        if isinstance(value, list):
            items = [v for v in value if isinstance(v, Node)]
            ok = (
                isinstance(got, list)
                and len(got) == len(items)
                and all(cls.same(a, b) for a, b in zip(items, got, strict=True))
            )
            return [] if ok else [f"{where}: list"]
        if value is None or isinstance(value, bool):
            return [] if got is value else [f"{where}: {value!r} vs {got!r}"]
        return [] if str(value) == got else [f"{where}: scalar"]

    @staticmethod
    def kind_names(arena: Arena) -> list[str]:
        return [arena.kinds[k] for k in arena.kind]

    @staticmethod
    def code_names(arena: Arena) -> dict[int, str]:
        return {i: arena.code_values[arena.kind[i]][c] for i, c in arena.codes.items()}

    @staticmethod
    def columns(arena: Arena) -> tuple[bytes, ...]:
        return tuple(
            bytes(column)
            for column in (arena.kind, arena.start, arena.length, arena.size, arena.flags)
        )


class TestAHandleReadsWhatTheNodeHeld:
    def test_every_node_and_field_of_a_mixed_program(self) -> None:
        tree = Parser(SOURCE, typescript=False, jsx=True).program()
        arena = Arena.from_tree(tree, SOURCE)
        assert Lockstep.differences(tree, arena) == []
        assert len(arena.kind) > 50

    def test_a_typescript_program_too(self) -> None:
        source = "type T<U> = U[]; const x = <T<number>>y; enum E { A = 1 }\n"
        tree = Parser(source, typescript=True, jsx=False).program()
        assert Lockstep.differences(tree, Arena.from_tree(tree, source)) == []


class TestFragmentsSpliceToOneTree:
    def test_the_emitting_parse_gives_the_same_columns(self) -> None:
        plain = Arena.from_tree(Parser(SOURCE, typescript=False, jsx=True).program(), SOURCE)
        emitting = Parser(SOURCE, typescript=False, jsx=True, arena=True)
        program = emitting.program()
        assert emitting.registry is not None
        # Function bodies and top-level statements were released as stubs.
        assert any(child.type == Arena.STUB for child in program["body"])
        spliced = Arena.from_tree(program, SOURCE, emitting.registry)
        # Kinds and codes are numbered in order of first sight, which the fragments change;
        # what they name does not, nor do the other columns.
        assert (
            Lockstep.differences(Parser(SOURCE, typescript=False, jsx=True).program(), spliced)
            == []
        )
        assert Lockstep.columns(spliced)[1:] == Lockstep.columns(plain)[1:]
        assert Lockstep.kind_names(spliced) == Lockstep.kind_names(plain)
        assert Lockstep.code_names(spliced) == Lockstep.code_names(plain)
        assert spliced.cooked == plain.cooked
        assert spliced.long_length == plain.long_length
        assert spliced.big_size == plain.big_size
        assert spliced.counts == plain.counts
        assert sorted(spliced.kinds) == sorted(plain.kinds)

    def test_a_fragment_of_another_parse_is_refused(self) -> None:
        other = Parser("f(1)", typescript=False, jsx=True, arena=True)
        fragment = Arena.from_tree(other.program(), "f(1)", other.registry)
        stub = Node(Arena.STUB, 0, 4, fragment=fragment)
        program = Node("Program", 0, 4, body=[stub])
        with pytest.raises(ValueError, match="another parse"):
            Arena.from_tree(program, "f(1)", Registry())


class TestIndexKeysStandForIdentity:
    def test_handles_compare_and_hash_by_index(self) -> None:
        arena = Arena.from_tree(Parser("a; b;", typescript=False, jsx=True).program(), "a; b;")
        root = Handle(arena, 0)
        first, second = root.children()
        assert first != second
        assert first == Handle(arena, first.index)
        assert {first, Handle(arena, first.index)} == {first}
        assert first.key != second.key and root.key == 0

    def test_a_kind_past_the_byte_is_refused(self) -> None:
        # The program's kind and 255 more fill the kind byte; the 257th distinct kind is refused.
        fits = Node("Program", 0, 0, body=[Node(f"Kind{n}", 0, 0) for n in range(255)])
        assert len(Arena.from_tree(fits, "").kinds) == 256
        more = Node("Program", 0, 0, body=[Node(f"Kind{n}", 0, 0) for n in range(256)])
        with pytest.raises(ValueError, match="256"):
            Arena.from_tree(more, "")
