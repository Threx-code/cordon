"""Bun's `bun.lock` and Deno's `deno.lock`, in the formats the tools write.

Each fixture is the shape the real tool produces: Bun's trailing commas and array entries, Deno's
version 3 nesting and version 4 top-level `npm` map with peer suffixes. A lockfile that cannot be
read says so rather than returning an empty graph that looks like a project with no dependencies.
"""

from __future__ import annotations

from cordon_scanner.core.content import FileContent
from cordon_scanner.core.limits import Limits
from cordon_scanner.core.models import Scope
from cordon_scanner.ecosystems.npm import BunLock, NpmEcosystem
from cordon_scanner.ecosystems.registry import EcosystemRegistry


class Locks:
    BUN = """{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "app",
      "dependencies": {
        "react": "^18.3.1",
        "@acme/ui": "workspace:*",
      },
      "devDependencies": {
        "typescript": "^5.6.0",
      },
    },
    "packages/ui": {
      "name": "@acme/ui",
      "dependencies": {
        "clsx": "^2.1.1",
      },
    },
  },
  "packages": {
    "@acme/ui": ["@acme/ui@workspace:packages/ui"],
    "clsx": ["clsx@2.1.1", "", {}, "sha512-eYm0QWBtUrBWZWG0d386OGAw16Z995PiOVo2B7bjWSbHedGl5e0ZWaq65kOGgUSNesEIDkB9ISbTg/JK9dhCZA=="],
    "js-tokens": ["js-tokens@4.0.0", "", {}, "sha512-RdJUflcE3cUzKiMqQgsCu06FPu9UdIJO0beYbPhHN4k6apgJtifcoCtT9bcxOpYBtpD2kCM6Sbzg4CausW/PKQ=="],
    "loose-envify": ["loose-envify@1.4.0", "", { "dependencies": { "js-tokens": "^3.0.0 || ^4.0.0" }, "bin": { "loose-envify": "cli.js" } }, "sha512-lyuxPGr/Wfhrlem2CL/UcnUc1zcqKAImBDzukY7Y5F/yQiNdko6+fRLevlw1HgMySw7f611UIY408EtxRSoK3Q=="],
    "react": ["react@18.3.1", "", { "dependencies": { "loose-envify": "^1.1.0" } }, "sha512-wS+hAgJShR0KhEvPJArfuPVN1+Hz1t0Y6n5jLrGQbkb4urgPE/0Rve+1kMB1v/oWgHgm4WIcV+i7F2pTVj+2iQ=="],
    "typescript": ["typescript@5.6.3", "", { "bin": { "tsc": "bin/tsc" } }, "sha512-hjcS1mhfuyi4WW8IWtjP7brDrG2cuDZukyrYrSauoXGNgx0S7zceP07adYkJycEr56BOUTNPzbInooiN3fn1qw=="],
    "private-thing": ["private-thing@1.0.0", "https://npm.acme.internal/", {}, "sha512-AAAA"],
    "fork": ["fork@github:acme/fork#0a1b2c3", {}, "0a1b2c3"],
    "react/loose-envify": ["loose-envify@1.3.0", "", {}, "sha512-BBBB"],
  }
}
"""

    DENO_V4 = """{
  "version": "4",
  "specifiers": {
    "jsr:@std/path@1": "1.0.8",
    "npm:chalk@5": "5.3.0",
    "npm:preact@10": "10.24.3",
    "npm:preact-render-to-string@6": "6.5.11_preact@10.24.3"
  },
  "jsr": {
    "@std/path@1.0.8": { "integrity": "548fa456bb6a04d3c1a1e7477986b6cffbce95102d0bb447c67c4ee70e0364be" }
  },
  "npm": {
    "chalk@5.3.0": { "integrity": "sha512-dLitG79d+GV1Nb/VYcCDFivJeK1hiukt9QjRNVOsUtTy1rR1YJsmpGGTZ3qJos+uw7WmWF4wUwBd9jxjocFC2w==" },
    "preact-render-to-string@6.5.11_preact@10.24.3": {
      "integrity": "sha512-ubnauqoGczeGISiOh6RjX0/cdaF8v/oDXIjO85XALCQjwQP+SB4RDXXtvZ6yTYSjG+PC1QRP2AhPgCLsM2Jc6Q==",
      "dependencies": ["preact"]
    },
    "preact@10.24.3": { "integrity": "sha512-Z2dPnBnMUfyQfSQ+GBdsGa16hz35YmLmtTLhM169uW944hYL6xzTYkJjC07j+Wosz733pMWx0fgON3JNw1jJQA==" }
  },
  "remote": {
    "https://deno.land/std@0.200.0/path/mod.ts": "abc"
  },
  "workspace": { "dependencies": ["jsr:@std/path@1", "npm:chalk@5", "npm:preact@10"] }
}
"""

    DENO_V3 = """{
  "version": "3",
  "packages": {
    "specifiers": { "npm:lodash@4": "npm:lodash@4.17.21" },
    "npm": {
      "lodash@4.17.21": { "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==", "dependencies": {} }
    }
  },
  "remote": {}
}
"""

    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @classmethod
    def entries(cls, path: str, text: str) -> dict[str, object]:
        graph = NpmEcosystem().parse_lockfile(cls.fc(path, text))
        assert graph.parse_error is None, graph.parse_error
        return {f"{e.name}@{e.version}" if e.version else e.name: e for e in graph.entries}


class TestTrailingCommas:
    def test_commas_before_a_close_are_removed(self):
        assert BunLock.without_trailing_commas('{"a": [1, 2,], "b": {"c": 1,\n},}') == (
            '{"a": [1, 2], "b": {"c": 1\n}}'
        )

    def test_commas_inside_strings_are_kept(self):
        text = '{"a": "x,}", "b": "y,]", "c": "q\\\\",}'
        assert BunLock.without_trailing_commas(text) == '{"a": "x,}", "b": "y,]", "c": "q\\\\"}'

    def test_ordinary_commas_are_kept(self):
        assert BunLock.without_trailing_commas("[1, 2, 3]") == "[1, 2, 3]"


class TestBunLock:
    def test_the_router_reads_it(self):
        assert EcosystemRegistry.lockfile_ecosystem("apps/web/bun.lock") == "npm"

    def test_registry_packages_carry_version_and_integrity(self):
        found = Locks.entries("bun.lock", Locks.BUN)
        react = found["react@18.3.1"]
        assert (
            react.integrity.startswith("sha512-") and react.direct and react.scope is Scope.RUNTIME
        )
        assert react.dependencies == ("loose-envify",)
        assert not found["loose-envify@1.4.0"].direct

    def test_a_nested_copy_is_its_own_entry_and_not_direct(self):
        found = Locks.entries("bun.lock", Locks.BUN)
        assert "loose-envify@1.3.0" in found and not found["loose-envify@1.3.0"].direct

    def test_dev_dependencies_are_dev(self):
        assert Locks.entries("bun.lock", Locks.BUN)["typescript@5.6.3"].scope is Scope.DEV

    def test_a_workspace_package_is_local(self):
        ui = Locks.entries("bun.lock", Locks.BUN)["@acme/ui"]
        assert ui.local and ui.version == ""

    def test_a_private_registry_is_recorded_as_where_it_resolved(self):
        assert (
            Locks.entries("bun.lock", Locks.BUN)["private-thing@1.0.0"].resolved_from
            == "https://npm.acme.internal/"
        )

    def test_a_git_dependency_resolves_off_the_registry(self):
        fork = Locks.entries("bun.lock", Locks.BUN)["fork"]
        assert (
            fork.resolved_from == "github:acme/fork#0a1b2c3"
            and fork.integrity is None
            and not fork.local
        )

    def test_an_unreadable_lock_says_so(self):
        graph = NpmEcosystem().parse_lockfile(Locks.fc("bun.lock", "{ not json"))
        assert graph.parse_error and "bun.lock" in graph.parse_error

    def test_malformed_entries_are_skipped_not_fatal(self):
        text = (
            '{"packages": {"a": "not-an-array", "b": [], "c": [7], "d": ["d@1.0.0", "", {}, 42]}}'
        )
        found = Locks.entries("bun.lock", text)
        assert list(found) == ["d@1.0.0"] and found["d@1.0.0"].integrity is None


class TestDenoLock:
    def test_the_router_reads_it(self):
        assert EcosystemRegistry.lockfile_ecosystem("deno.lock") == "npm"

    def test_version_4_npm_packages_come_out_with_peer_suffixes_removed(self):
        found = Locks.entries("deno.lock", Locks.DENO_V4)
        npm = {k: v for k, v in found.items() if (v.resolved_from or "").find("://") < 0}
        assert set(npm) == {"chalk@5.3.0", "preact@10.24.3", "preact-render-to-string@6.5.11"}
        assert found["preact-render-to-string@6.5.11"].dependencies == ("preact",)
        assert all(e.integrity.startswith("sha512-") for e in npm.values())

    def test_jsr_packages_and_remote_modules_are_recorded_under_their_own_identity(self):
        """A JSR package is not the npm package of the same name; a remote module is one module
        at one version however many of its files were fetched."""
        found = Locks.entries("deno.lock", Locks.DENO_V4)
        assert found["@jsr/std__path@1.0.8"].alias == "@std/path"
        assert found["@jsr/std__path@1.0.8"].resolved_from == "https://jsr.io/@std/path/1.0.8"
        assert found["std@0.200.0"].resolved_from.startswith("https://deno.land/std@0.200.0/")

    def test_direct_packages_come_from_the_workspace_list(self):
        found = Locks.entries("deno.lock", Locks.DENO_V4)
        assert found["chalk@5.3.0"].direct and found["preact@10.24.3"].direct
        assert not found["preact-render-to-string@6.5.11"].direct

    def test_version_3_nests_under_packages(self):
        found = Locks.entries("deno.lock", Locks.DENO_V3)
        assert list(found) == ["lodash@4.17.21"] and found["lodash@4.17.21"].direct

    def test_jsr_and_remote_imports_are_not_npm_packages(self):
        names = {
            e.name
            for e in NpmEcosystem().parse_lockfile(Locks.fc("deno.lock", Locks.DENO_V4)).entries
        }
        assert "@std/path" not in names and not any(n.startswith("https://") for n in names)
        assert "@jsr/std__path" in names

    def test_an_unreadable_lock_says_so(self):
        assert NpmEcosystem().parse_lockfile(Locks.fc("deno.lock", "[1]")).parse_error

    def test_a_lock_with_no_npm_section_is_empty_not_an_error(self):
        graph = NpmEcosystem().parse_lockfile(
            Locks.fc("deno.lock", '{"version": "4", "remote": {}}')
        )
        assert graph.parse_error is None and graph.entries == ()
