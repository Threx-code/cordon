"""Swift, opam, Yarn and Bun lock files on the shapes written less often: refusals and skipped entries (`swift.py`, `ocaml/opam.py`, `javascript/yarn.py`, `javascript/bun.py`)."""

from __future__ import annotations

import json
from typing import Any

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def lock(eco: str, path: str, text: str) -> Any:
        return EcosystemRegistry.BY_ID[eco].parse_lockfile(_Kit.fc(path, text))


class TestSwift:
    def test_a_resolved_file_without_pins_is_refused_and_a_pin_that_is_not_an_object_is_skipped(
        self,
    ) -> None:
        assert _Kit.lock("swift", "Package.resolved", "{}").parse_error == "no `pins` list"
        text = json.dumps(
            {
                "version": 2,
                "pins": [
                    "junk",
                    {
                        "identity": "a",
                        "location": "https://github.com/o/a.git",
                        "state": {"version": "1.0.0", "revision": "abc"},
                    },
                ],
            }
        )
        assert [e.name for e in _Kit.lock("swift", "Package.resolved", text).entries] != []

    def test_a_project_pinning_a_full_url_keeps_it(self) -> None:
        project = EcosystemRegistry.BY_ID["swift"].pinned_project(
            [("https://example.invalid/a.git", "1.0.0")]
        )
        assert project is not None
        assert "https://example.invalid/a.git" in next(iter(project.values()))


class TestOpam:
    def test_a_lock_file_without_depends_is_refused(self) -> None:
        graph = _Kit.lock("opam", "p.opam.locked", 'opam-version: "2.0"\nname: "p"\n')
        assert graph.parse_error == "an opam lock file without depends"

    def test_a_lock_file_that_stops_before_its_closing_bracket_is_refused(self) -> None:
        text = 'opam-version: "2.0"\ndepends: [\n  "ocaml" {= "5.1.0"}\n]\nname: "p"\n'
        graph = _Kit.lock("opam", "p.opam.locked", text)
        assert graph.parse_error == "an opam lock file that does not end where opam lock ends it"


class TestYarn:
    def test_a_berry_lock_that_is_not_a_mapping_is_refused(self) -> None:
        graph = _Kit.lock("npm", "yarn.lock", "- __metadata: 1\n")
        assert graph.parse_error == "top level is not a mapping"

    def test_a_berry_lock_with_nothing_readable_beside_its_metadata_is_refused(self) -> None:
        graph = _Kit.lock(
            "npm", "yarn.lock", "__metadata:\n  version: 6\nfirst: text\nsecond: text\n"
        )
        assert graph.parse_error == "no entry could be read"

    def test_a_classic_lock_whose_headers_are_unreadable_is_refused_with_the_count(self) -> None:
        graph = _Kit.lock("npm", "yarn.lock", '# yarn lockfile v1\n\nnot a header\n  version "1"\n')
        assert graph.parse_error == "1 entry header(s) could not be read"


class TestBun:
    def test_a_bun_lock_whose_packages_is_not_an_object_has_no_entries(self) -> None:
        graph = _Kit.lock("npm", "bun.lock", json.dumps({"lockfileVersion": 1, "packages": []}))
        assert graph.entries == ()

    def test_a_workspace_that_is_not_an_object_and_a_package_with_no_name_are_skipped(self) -> None:
        text = json.dumps(
            {
                "lockfileVersion": 1,
                "workspaces": {"": {"dependencies": {"a": "1"}}, "x": "junk"},
                "packages": {"a": ["a@1.0.0", "", {}, "sha512-aaa"], "b": [""], "c": "text"},
            }
        )
        assert [e.name for e in _Kit.lock("npm", "bun.lock", text).entries] == ["a"]

    def test_a_berry_dependency_written_without_a_protocol_resolves_to_its_npm_descriptor(
        self,
    ) -> None:
        text = (
            "__metadata:\n  version: 6\n\n"
            '"a@npm:^1.0.0":\n  version: 1.0.0\n  resolution: "a@npm:1.0.0"\n'
            "  dependencies:\n    b: ^2.0.0\n\n"
            '"b@npm:^2.0.0":\n  version: 2.0.0\n  resolution: "b@npm:2.0.0"\n'
        )
        entries = {e.name: e for e in _Kit.lock("npm", "yarn.lock", text).entries}
        assert entries["a"].dependencies == ("b",)
