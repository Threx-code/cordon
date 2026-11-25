"""Golden vectors of the model tree digest (`ArtifactDigests.of_model`), shared byte for byte with the backend.

`model_digest_vectors.json` holds invented models (path to the `sha256:` digest of each file) and the digest each must have, checked against the
implementation and against a second, independent writing of the definition: the lines `<path>\\0<file digest>\\n` sorted by the UTF-8 bytes of the path,
hashed once, prefixed `sha256:`. The backend keeps the same file and only adds cases.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from support import ROOT

VECTORS: list[dict[str, Any]] = json.loads(
    (ROOT / "tests" / "unit" / "contracts" / "model_digest_vectors.json").read_text(
        encoding="utf-8"
    )
)["vectors"]


class Independent:
    @staticmethod
    def digest(files: dict[str, str]) -> str:
        listing = "".join(
            f"{path}\0{files[path]}\n" for path in sorted(files, key=lambda p: p.encode("utf-8"))
        )
        return "sha256:" + hashlib.sha256(listing.encode("utf-8")).hexdigest()


class TestTheVectors:
    @pytest.mark.parametrize("vector", VECTORS, ids=[v["case"] for v in VECTORS])
    def test_the_implementation_gives_the_recorded_digest(self, vector: dict[str, Any]) -> None:
        assert ArtifactDigests.of_model(vector["files"]) == vector["digest"]

    @pytest.mark.parametrize("vector", VECTORS, ids=[v["case"] for v in VECTORS])
    def test_an_independent_writing_of_the_definition_gives_it_too(
        self, vector: dict[str, Any]
    ) -> None:
        assert Independent.digest(vector["files"]) == vector["digest"]

    def test_the_order_of_the_files_changes_nothing_and_a_change_moves_the_digest(self) -> None:
        by_case = {v["case"]: v["digest"] for v in VECTORS}
        assert by_case["two files, one order"] == by_case["two files, the other order"]
        assert (
            by_case["a file changes"]
            != by_case["two files, one order"]
            != by_case["a path changes"]
        )

    def test_no_files_is_the_digest_of_nothing(self) -> None:
        assert {v["case"]: v["digest"] for v in VECTORS}["no files"] == "sha256:" + hashlib.sha256(
            b""
        ).hexdigest()

    def test_a_file_digest_that_is_not_one_is_refused(self) -> None:
        with pytest.raises(ValueError):
            ArtifactDigests.of_model({"w.bin": "not a digest"})
