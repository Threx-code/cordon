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
        assert data == {"a": "b", "url": "http://h/#frag", "text": "one\ntwo\n"}

    @pytest.mark.parametrize("header", ["|2", "|-2", "|2-", ">+1", ">1+", "|2 # note", "|-", ">"])
    def test_every_block_scalar_header(self, header: str) -> None:
        # ingress-nginx's index.yaml writes `artifacthub.io/changes: |2`; read as an unreadable
        # index until compared with a real one, which lost every chart in it.
        data = DataYaml.load(f"changes: {header}\n   - one\n   - two\nversion: 4.8.0\n")
        assert data["version"] == "4.8.0"
        assert "- one" in data["changes"]

    def test_a_scalar_that_starts_below_its_key(self) -> None:
        # ansible.netcommon's galaxy.yml: the description wrapped under its key. Read as an
        # unreadable file until compared with ansible-galaxy, which lost the collection's
        # dependencies with it.
        text = (
            "dependencies:\n"
            '  "ansible.utils": ">=3.0.0"\n'
            "description:\n"
            "  Ansible Collection with common content to help automate\n"
            "  the management of network devices.\n"
            "summary:\n"
            '  "quoted, and\n'
            '  wrapped"\n'
            "name: netcommon\n"
        )
        data = DataYaml.load(text)
        assert data["dependencies"] == {"ansible.utils": ">=3.0.0"}
        assert data["description"] == (
            "Ansible Collection with common content to help automate the management of network devices."
        )
        assert data["summary"] == "quoted, and wrapped"
        assert data["name"] == "netcommon"

    def test_a_key_in_a_scalar_below_its_key_is_still_an_error(self) -> None:
        with pytest.raises(DataYamlError, match="mapping values are not allowed"):
            DataYaml.load("a:\n  plain text\n  then: a key\n")


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

    def test_a_control_character_is_an_error_as_yaml_has_it(self) -> None:
        # YAML 1.2 §5.1. A damaged file must not pass for one that is merely not this format.
        with pytest.raises(DataYamlError, match="U\\+0000"):
            DataYaml.load("\x00{[<256: abc\nkey: value\n")


class TestScalarsAsYamlReadsThem:
    """Block and multi-line scalars, each expected value PyYAML's for the same text. Found reading
    real repositories: Kubernetes manifests whose container images were lost when the document
    was refused, Gateway API CRDs, Compose templates and Actions definitions."""

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("a: |\n  one\n\n  two\nb: x\n", {"a": "one\n\ntwo\n", "b": "x"}),
            ("a: |\n  one\n    two\n  three\n", {"a": "one\n  two\nthree\n"}),
            ("a: |\n  # not a comment\n  x # y\n", {"a": "# not a comment\nx # y\n"}),
            ("a: |-\n  one\n  two\n\n", {"a": "one\ntwo"}),
            ("a: |+\n  one\n\n\nb: x\n", {"a": "one\n\n\n", "b": "x"}),
            (
                "a: >\n  one\n  two\n\n  three\n    indented\n  four\n",
                {"a": "one two\nthree\n  indented\nfour\n"},
            ),
            ("  k: |2\n      four\n    two\n", {"k": "  four\ntwo\n"}),
            ("- |\n  one\n  two\n- x\n", ["one\ntwo\n", "x"]),
            ("- k: |\n    one\n  j: x\n", [{"k": "one\n", "j": "x"}]),
            ("a: |\n  [ unbalanced\n  more\nb: x\n", {"a": "[ unbalanced\nmore\n", "b": "x"}),
            ("a: |\nb: x\n", {"a": "", "b": "x"}),
            ("a: |\n  one", {"a": "one"}),
            ("a: |\n\n  one\n", {"a": "\none\n"}),
        ],
    )
    def test_block_scalars(self, text: str, expected: object) -> None:
        assert DataYaml.load(text) == expected

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            # A Gateway API CRD's description: brackets, a colon and escaped quotes inside it.
            (
                'd: "Config: remove: [\\"h1\\", \\"h3\\"] \\n\n  Output: GET"\nt: x\n',
                {"d": 'Config: remove: ["h1", "h3"] \n Output: GET', "t": "x"},
            ),
            ('a: "x\n\n  y"\n', {"a": "x\ny"}),
            ('a: "one \\\n  two"\n', {"a": "one two"}),
            ('a: "x # not\n  y" # c\nb: x\n', {"a": "x # not y", "b": "x"}),
            ("a: 'it''s\n  more'\n", {"a": "it's more"}),
            ('- "one\n  two"\n- b\n', ["one two", "b"]),
            ('a: "x\n  [ y\n  #z"\n', {"a": "x [ y #z"}),
            ("a: one\n  two\n\n  three\nb: x\n", {"a": "one two\nthree", "b": "x"}),
            # A plain description with a brace in it opens no flow collection.
            (
                "d: type FooStatus struct{\n  stat\nt: x\n",
                {"d": "type FooStatus struct{ stat", "t": "x"},
            ),
        ],
    )
    def test_multi_line_scalars(self, text: str, expected: object) -> None:
        assert DataYaml.load(text) == expected

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            # Compose's healthcheck: the flow sequence on the line below its key.
            ('test:\n  ["CMD", "curl", "-f"]\n', {"test": ["CMD", "curl", "-f"]}),
            ("- - a\n  - b\n- - - c\n", [["a", "b"], [["c"]]]),
            (
                'x: "#!/bin/sh\\nset -e ; # not a comment \\"q\\""\n',
                {"x": '#!/bin/sh\nset -e ; # not a comment "q"'},
            ),
        ],
    )
    def test_collections_and_escapes(self, text: str, expected: object) -> None:
        assert DataYaml.load(text) == expected

    def test_a_quoted_scalar_left_open_is_an_error(self) -> None:
        with pytest.raises(DataYamlError, match="unterminated quoted string"):
            DataYaml.load('a: "one\n  two\nb: c\n')
