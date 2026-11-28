"""deno.lock and deno.json on the shapes they write less often: JSR and npm entries given as lists, nameless keys, comments with escapes and import maps in scopes (`ecosystems/packages/javascript/deno.py`)."""

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
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["npm"]


class TestLock:
    def lock(self, data: dict[str, Any]) -> Any:
        return _Kit.adapter().parse_lockfile(_Kit.fc("deno.lock", json.dumps(data)))

    def test_a_jsr_package_names_the_jsr_and_npm_packages_it_needs_and_keys_without_a_version_are_skipped(
        self,
    ) -> None:
        graph = self.lock(
            {
                "version": "4",
                "jsr": {
                    "@std/path@1.0.0": {
                        "integrity": "a" * 64,
                        "dependencies": ["jsr:@std/fs@^1.0.0", "npm:chalk@5.3.0", "https://x/y.ts"],
                    },
                    "@std/bare": {},
                },
            }
        )
        [entry] = graph.entries
        assert entry.integrity == "sha256-hex:" + "a" * 64
        assert entry.dependencies == ("@jsr/std__fs", "chalk")

    def test_npm_entries_without_a_name_and_version_are_skipped_and_dependency_lists_name_their_packages(
        self,
    ) -> None:
        graph = self.lock(
            {
                "version": "4",
                "npm": {
                    "chalk@5.3.0": {
                        "integrity": "sha512-aaa",
                        "dependencies": ["ansi-styles@4.0.0"],
                    },
                    "nameless": {},
                },
            }
        )
        [entry] = graph.entries
        assert (entry.name, entry.version) == ("chalk", "5.3.0")
        assert entry.dependencies == ("ansi-styles",)


class TestConfig:
    def read(self, text: str) -> Any:
        return _Kit.adapter().parse_manifest(_Kit.fc("deno.jsonc", text))

    def test_a_comment_and_an_escaped_quote_in_a_string_do_not_break_the_reader(self) -> None:
        manifest = self.read(
            '{\n  // the import map\n  "imports": {"say": "npm:say@1.0.0", "q": "npm:q@2.0.0"},\n'
            '  "name": "a \\"quoted\\" name"\n}\n'
        )
        assert {d.name for d in manifest.dependencies} == {"say", "q"}

    def test_imports_in_scopes_are_read_and_non_text_targets_are_skipped(self) -> None:
        manifest = self.read(
            '{"imports": {"a": "npm:a@1.0.0", "n": 5},'
            ' "scopes": {"./vendor/": {"b": "npm:b@2.0.0", "m": null}, "./x/": "text"}}'
        )
        assert {d.name for d in manifest.dependencies} == {"a", "b"}
