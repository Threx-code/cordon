"""Golden vectors of the tree digest (`ArtifactDigests.of_tree`), shared byte for byte with the backend's capture of a skill folder.

`tree_digest_vectors.json` holds invented folders (path, mode, the bytes in hex) and the digest each must have. The test checks them against the
implementation and against a second, independent writing of the definition kept here: the lines `<path>\\0<mode>\\0<hex sha256 of the bytes>\\n` sorted by
the UTF-8 bytes of the path, hashed once, prefixed `sha256:`. The backend keeps the same file; it only adds to it.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from support import ROOT

VECTORS: list[dict[str, Any]] = json.loads(
    (ROOT / "tests" / "unit" / "contracts" / "tree_digest_vectors.json").read_text(encoding="utf-8")
)["vectors"]


class Independent:
    @staticmethod
    def digest(entries: list[tuple[str, str, bytes]]) -> str:
        lines = sorted(
            (
                (path.encode("utf-8"), f"{path}\0{mode}\0{hashlib.sha256(raw).hexdigest()}\n")
                for path, mode, raw in entries
            )
        )
        return (
            "sha256:"
            + hashlib.sha256("".join(line for _, line in lines).encode("utf-8")).hexdigest()
        )

    @staticmethod
    def entries(vector: dict[str, Any]) -> list[tuple[str, str, bytes]]:
        return [
            (item["path"], item["mode"], bytes.fromhex(item["bytes_hex"]))
            for item in vector["entries"]
        ]


class TestTheVectors:
    @pytest.mark.parametrize("vector", VECTORS, ids=[v["case"] for v in VECTORS])
    def test_the_implementation_gives_the_recorded_digest(self, vector: dict[str, Any]) -> None:
        assert ArtifactDigests.of_tree(Independent.entries(vector)) == vector["digest"]

    @pytest.mark.parametrize("vector", VECTORS, ids=[v["case"] for v in VECTORS])
    def test_an_independent_writing_of_the_definition_gives_it_too(
        self, vector: dict[str, Any]
    ) -> None:
        assert Independent.digest(Independent.entries(vector)) == vector["digest"]

    def test_the_order_of_the_entries_changes_nothing(self) -> None:
        by_case = {v["case"]: v["digest"] for v in VECTORS}
        assert by_case["two files, one order"] == by_case["two files, the other order"]

    def test_a_mode_or_a_content_change_moves_the_digest(self) -> None:
        by_case = {v["case"]: v["digest"] for v in VECTORS}
        base = by_case["two files, one order"]
        assert by_case["the mode changes"] != base and by_case["the content changes"] != base

    def test_no_files_is_the_digest_of_nothing(self) -> None:
        assert {v["case"]: v["digest"] for v in VECTORS}["no files"] == "sha256:" + hashlib.sha256(
            b""
        ).hexdigest()

    def test_the_byte_order_case_is_code_point_order_and_differs_from_utf_16_order(self) -> None:
        paths = [
            item["path"]
            for v in VECTORS
            if v["case"].startswith("UTF-8 byte order")
            for item in v["entries"]
        ]
        assert sorted(paths, key=lambda p: p.encode("utf-8")) == sorted(paths)
        assert sorted(paths, key=lambda p: p.encode("utf-16-be")) != sorted(paths)
