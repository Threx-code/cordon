"""SUSPECT.OBFUSCATION.PACKED.001's JSFuck signature (note 70 P1): TypeScript's array type indexed
by a member name is not JSFuck, wherever the file is; an array literal indexed so still is. Inert
fixtures: fragments that run nothing."""

from __future__ import annotations

import pytest

from cordon_scanner.detect.code.obfuscation.packing import PackingFindings
from cordon_scanner.foundation.content import FileContent

RULE = "SUSPECT.OBFUSCATION.PACKED.001"


class PackerKit:
    @staticmethod
    def packed(path: str, text: str) -> bool:
        content = FileContent.from_bytes(path, text.encode())
        return any(h.rule_id == RULE for h in PackingFindings.packers(content, "typescript"))


class TestTheJsfuckSignature:
    @pytest.mark.parametrize(
        "text",
        [
            'type A = Parameters<Step<any>[]["filter"]>[0];\n',
            'type B = Item[]["constructor"];\n',
            'type C = (Foo | Bar)[]["filter"];\n',
        ],
    )
    def test_an_array_type_indexed_by_name_is_not_jsfuck(self, text: str) -> None:
        assert not PackerKit.packed("types.d.ts", text)

    @pytest.mark.parametrize(
        "text",
        [
            'x = []["filter"]["constructor"]("return 1")();\n',
            '([]["filter"]["constructor"])("return 1")();\n',
            'y = 1 + []["constructor"];\n',
        ],
    )
    def test_an_array_literal_indexed_so_still_is(self, text: str) -> None:
        assert PackerKit.packed("index.js", text)

    def test_the_suffix_excuses_nothing(self) -> None:
        # Node's require loads a `.d.ts` as code: the same literal there is still reported.
        assert PackerKit.packed("types.d.ts", 'x = []["filter"]["constructor"]("return 1")();\n')
