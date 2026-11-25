"""`ArtifactDigests.of_tool_list` against the vectors the backend computes too.

A remote MCP server's artifact is the digest of its canonicalised tools list. The scanner computes
it (the device signer states it in a signed inventory) and the platform computes it (the registry
stores it when an approval is made, and compares it at each session start). If the two ever
disagree nothing will match, so both sides compute the SAME file of vectors and must agree on every
one. This file is the reference: its digests were made by this function.

`tool_list_digests.golden.json` is copied byte for byte into the backend repository
(`src/catalogue/tests/helpers/`). `PINNED` is its sha256 and is written in both repositories'
tests, so changing the file on one side without the other fails here or there. To add a vector:
append it, regenerate its digest with this function, copy the file to the backend and update
`PINNED` in both tests.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from support import ROOT

GOLDEN = ROOT / "tests" / "unit" / "contracts" / "tool_list_digests.golden.json"
PINNED = "d58aee173adf27c7e7e6f8e41dab7649aa013efd72cebcc4c38aaea8297419d0"
VECTORS = json.loads(GOLDEN.read_text(encoding="utf-8"))["vectors"]
BY_NAME = {vector["name"]: vector for vector in VECTORS}
DIGESTS = [vector for vector in VECTORS if "digest" in vector]
REFUSALS = [vector for vector in VECTORS if "error" in vector]
NO_DESCRIPTION = "a tool with no description and no schema"
IN_SCHEMA = "decomposed text inside the schema, in a key and in a value"
AGREEING = [
    ("one tool", "the same tool with its schema keys in another order"),
    ("two tools", "the same two tools in the other order"),
    (NO_DESCRIPTION, "a tool with an empty description and an empty schema"),
    (NO_DESCRIPTION, "fields that are not name, description or schema are not part of the digest"),
    ("composed text", "the same text decomposed is the same digest"),
    (IN_SCHEMA, "composed text inside the schema"),
]
DIFFERENT = [
    ("an empty list", "one tool"),
    ("one tool", "two tools"),
    ("numbers, booleans and null in a schema", "a list inside a schema keeps its order"),
]


class TestTheSharedVectors:
    def test_the_file_is_the_one_both_repositories_pin(self) -> None:
        assert hashlib.sha256(GOLDEN.read_bytes()).hexdigest() == PINNED

    def test_there_are_vectors_for_every_kind_of_case(self) -> None:
        assert len(VECTORS) == len(BY_NAME) >= 19
        assert len(REFUSALS) == 3

    @pytest.mark.parametrize("vector", DIGESTS, ids=[vector["name"] for vector in DIGESTS])
    def test_every_digest_is_what_the_function_makes(self, vector) -> None:
        assert ArtifactDigests.of_tool_list(vector["tools"]) == vector["digest"]
        assert ArtifactDigests.is_digest(vector["digest"])

    @pytest.mark.parametrize("vector", REFUSALS, ids=[vector["name"] for vector in REFUSALS])
    def test_every_refusal_is_refused_with_its_message(self, vector) -> None:
        with pytest.raises(ValueError, match=vector["error"]):
            ArtifactDigests.of_tool_list(vector["tools"])

    @pytest.mark.parametrize("pair", AGREEING, ids=[second for _, second in AGREEING])
    def test_what_must_be_one_digest_is_one_digest(self, pair) -> None:
        first, second = pair
        assert BY_NAME[first]["digest"] == BY_NAME[second]["digest"]

    @pytest.mark.parametrize("pair", DIFFERENT, ids=[second for _, second in DIFFERENT])
    def test_what_differs_has_a_different_digest(self, pair) -> None:
        first, second = pair
        assert BY_NAME[first]["digest"] != BY_NAME[second]["digest"]
