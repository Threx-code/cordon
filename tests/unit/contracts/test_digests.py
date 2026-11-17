"""`ArtifactDigests`: the digest an artifact is identified by (design spec 3.2)."""

from __future__ import annotations

import hashlib
from typing import ClassVar

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests


class TestFilesAndTrees:
    def test_a_file_is_the_sha256_of_its_bytes(self) -> None:
        assert ArtifactDigests.of_bytes(b"abc") == "sha256:" + hashlib.sha256(b"abc").hexdigest()

    def test_the_form_is_checked(self) -> None:
        assert ArtifactDigests.is_digest("sha256:" + "0" * 64)
        assert not ArtifactDigests.is_digest("sha256:" + "G" * 64)
        assert not ArtifactDigests.is_digest("md5:" + "0" * 32)

    def test_a_tree_digest_does_not_depend_on_the_order_of_files(self) -> None:
        a = [("b.md", "644", b"two"), ("a/x.py", "755", b"one")]
        assert ArtifactDigests.of_tree(a) == ArtifactDigests.of_tree(list(reversed(a)))

    @pytest.mark.parametrize(
        "change", [("a/x.py", "644", b"one"), ("a/x.py", "755", b"ONE"), ("a/y.py", "755", b"one")]
    )
    def test_a_tree_digest_moves_with_a_mode_a_content_or_a_path(self, change) -> None:
        base = [("a/x.py", "755", b"one")]
        assert ArtifactDigests.of_tree(base) != ArtifactDigests.of_tree([change])

    @pytest.mark.parametrize("path", ["", "/abs", "../up", "a/../b", "a//b", "a\\b", "./a"])
    def test_a_path_that_leaves_the_folder_is_refused(self, path: str) -> None:
        with pytest.raises(ValueError):
            ArtifactDigests.of_tree([(path, "644", b"x")])

    def test_one_path_twice_is_refused(self) -> None:
        with pytest.raises(ValueError):
            ArtifactDigests.of_tree([("a", "644", b"x"), ("a", "644", b"y")])

    def test_a_model_is_the_digest_of_its_files_digests(self) -> None:
        files = {
            "w.bin": ArtifactDigests.of_bytes(b"w"),
            "config.json": ArtifactDigests.of_bytes(b"c"),
        }
        assert ArtifactDigests.of_model(files) == ArtifactDigests.of_model(
            dict(reversed(files.items()))
        )
        with pytest.raises(ValueError):
            ArtifactDigests.of_model({"w.bin": "not a digest"})


class TestAToolList:
    TOOLS: ClassVar[list[dict]] = [
        {
            "name": "search",
            "description": "Find things",
            "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
        },
        {"name": "read", "description": "Read a thing", "inputSchema": {"type": "object"}},
    ]

    def test_order_and_serialisation_do_not_matter(self) -> None:
        shuffled = [dict(reversed(list(tool.items()))) for tool in reversed(self.TOOLS)]
        assert ArtifactDigests.of_tool_list(self.TOOLS) == ArtifactDigests.of_tool_list(shuffled)

    def test_text_is_normalised(self) -> None:
        composed = [{"name": "café", "description": "x"}]
        decomposed = [{"name": "café", "description": "x"}]
        assert ArtifactDigests.of_tool_list(composed) == ArtifactDigests.of_tool_list(decomposed)

    def test_a_changed_description_is_a_new_artifact(self) -> None:
        changed = [
            dict(self.TOOLS[0], description="Find things, then send them away"),
            self.TOOLS[1],
        ]
        assert ArtifactDigests.of_tool_list(changed) != ArtifactDigests.of_tool_list(self.TOOLS)

    def test_fields_that_are_not_what_the_server_says_it_can_do_are_left_out(self) -> None:
        noisy = [dict(tool, _meta={"request": 7}) for tool in self.TOOLS]
        assert ArtifactDigests.of_tool_list(noisy) == ArtifactDigests.of_tool_list(self.TOOLS)

    def test_a_nameless_tool_and_a_repeated_name_are_refused(self) -> None:
        with pytest.raises(ValueError):
            ArtifactDigests.of_tool_list([{"description": "x"}])
        with pytest.raises(ValueError):
            ArtifactDigests.of_tool_list([self.TOOLS[0], self.TOOLS[0]])
