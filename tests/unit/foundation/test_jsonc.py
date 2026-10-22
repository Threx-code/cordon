"""JSON-with-comments parsing: comments and trailing commas tolerated, strings left intact."""

from __future__ import annotations

from cordon_scanner.foundation import jsonc


class TestLoads:
    def test_plain_json(self):
        assert jsonc.loads('{"a": 1, "b": [2, 3]}') == {"a": 1, "b": [2, 3]}

    def test_line_comment(self):
        assert jsonc.loads('{\n  // a note\n  "a": 1\n}') == {"a": 1}

    def test_block_comment(self):
        assert jsonc.loads('{/* x */ "a": 1 /* y */}') == {"a": 1}

    def test_trailing_comma_object_and_array(self):
        assert jsonc.loads('{"a": [1, 2,], "b": 3,}') == {"a": [1, 2], "b": 3}

    def test_url_in_string_survives(self):
        # The // in a URL must not be read as a comment.
        assert jsonc.loads('{"u": "https://example.com/x"}') == {"u": "https://example.com/x"}

    def test_slashes_and_commas_in_strings_survive(self):
        assert jsonc.loads('{"cmd": "a // b", "p": "x,]"}') == {"cmd": "a // b", "p": "x,]"}

    def test_garbage_is_none(self):
        assert jsonc.loads("not json at all {") is None

    def test_non_string_is_none(self):
        assert jsonc.loads(None) is None
        assert jsonc.loads(b"{}") is None

    def test_devcontainer_shape(self):
        text = (
            "{\n"
            "  // dev container\n"
            '  "image": "ubuntu:24.04",\n'
            '  "postCreateCommand": "curl -LsSf https://astral.sh/uv/install.sh | sh",\n'
            "}\n"
        )
        got = jsonc.loads(text)
        assert got["image"] == "ubuntu:24.04"
        assert "astral.sh" in got["postCreateCommand"]
