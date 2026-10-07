"""The data YAML reader: lockfile shapes it must read, and hostile shapes it must refuse."""

from __future__ import annotations

import pytest

from cordon_scanner.core.datayaml import MAX_DEPTH, DataYaml, DataYamlError


class TestLockfileShapes:
    def test_quoted_keys_holding_colons(self) -> None:
        text = (
            "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"
            '"lodash@npm:^4.17.20, lodash@npm:^4.17.21":\n'
            "  version: 4.17.21\n"
            '  resolution: "lodash@npm:4.17.21"\n'
            '  dependencies:\n    js-tokens: "npm:^4.0.0"\n'
        )
        data = DataYaml.load(text)
        entry = data["lodash@npm:^4.17.20, lodash@npm:^4.17.21"]
        assert entry["version"] == "4.17.21" and entry["dependencies"] == {
            "js-tokens": "npm:^4.0.0"
        }
        assert data["__metadata"]["version"] == "8", "a version stays a string"

    def test_flow_mappings_and_sequences(self) -> None:
        text = (
            "packages:\n"
            "  fsevents@2.3.3:\n"
            "    resolution: {integrity: sha512-abc==, tarball: 'https://x.invalid/f.tgz'}\n"
            "    engines: {node: ^8.16.0 || ^10.6.0 || >=11.0.0}\n"
            "    os: [darwin]\n"
            "    hasBin: true\n"
        )
        entry = DataYaml.load(text)["packages"]["fsevents@2.3.3"]
        assert entry["resolution"] == {
            "integrity": "sha512-abc==",
            "tarball": "https://x.invalid/f.tgz",
        }
        assert entry["os"] == ["darwin"] and entry["hasBin"] is True
        assert entry["engines"]["node"] == "^8.16.0 || ^10.6.0 || >=11.0.0"

    def test_sequences_of_mappings_and_versions_as_strings(self) -> None:
        text = "deps:\n  - name: a\n    version: 1.10\n  - name: b\n    version: 2.0\nplain: [1.0, '2']\n"
        data = DataYaml.load(text)
        assert data["deps"] == [{"name": "a", "version": "1.10"}, {"name": "b", "version": "2.0"}]
        assert data["plain"] == ["1.0", "2"]

    def test_a_flow_mapping_across_lines(self) -> None:
        data = DataYaml.load("a: {x: 1,\n  y: 2}\nb: c\n")
        assert data == {"a": {"x": "1", "y": "2"}, "b": "c"}

    def test_comments_and_block_scalars(self) -> None:
        data = DataYaml.load(
            "# head\na: b # trailing\nurl: http://h/#frag\ntext: |\n  one\n  two\n"
        )
        assert data == {"a": "b", "url": "http://h/#frag", "text": "one\ntwo"}


class TestHostileInput:
    @pytest.mark.parametrize(
        "text",
        [
            "a: &x [1]\nb: *x\n",
            "a: !!python/object:os.system x\n",
            "<<: {a: 1}\n",
            "? complex\n: v\n",
        ],
    )
    def test_anchors_tags_merge_and_complex_keys_are_refused(self, text) -> None:
        with pytest.raises(DataYamlError):
            DataYaml.load(text)

    def test_depth_is_bounded(self) -> None:
        text = (
            "".join(f"{'  ' * n}k{n}:\n" for n in range(MAX_DEPTH + 5))
            + f"{'  ' * (MAX_DEPTH + 5)}v: 1\n"
        )
        with pytest.raises(DataYamlError):
            DataYaml.load(text)

    def test_flow_depth_is_bounded(self) -> None:
        with pytest.raises(DataYamlError):
            DataYaml.load("a: " + "[" * (MAX_DEPTH + 5) + "]" * (MAX_DEPTH + 5) + "\n")

    def test_a_duplicate_key_keeps_the_first(self) -> None:
        assert DataYaml.load("a: first\na: second\n") == {"a": "first"}

    def test_unterminated_input_is_an_error_not_a_guess(self) -> None:
        for text in ('"a: 1\n', "a: {x: 1\n", "a: b\n  c: d\n"):
            with pytest.raises(DataYamlError):
                DataYaml.load(text)
