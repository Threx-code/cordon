"""Defects an independent end-to-end review found, each with its reproduction.

Every one of these was reachable by running the tool, and none was reachable by
running its test suite -- which is the point of keeping them together. Three
were first-run experiences: a macOS user scanning an installed tree, a typed
Python codebase, and a repository somebody had made deep.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.models import Category
from cordon_scanner.detect.binary import BinaryDetector
from cordon_scanner.detect.secrets import NOT_A_SECRET
from support import assemble

JAVA_CLASS = b"\xca\xfe\xba\xbe" + (0).to_bytes(2, "big") + (65).to_bytes(2, "big") + b"\x00" * 40
FAT_MACHO = b"\xca\xfe\xba\xbe" + (2).to_bytes(4, "big") + b"\x00" * 40
THIN_MACHO = b"\xcf\xfa\xed\xfe" + b"\x00" * 40
ELF = b"\x7fELF" + b"\x00" * 40


def flagged(root) -> set[str]:
    return {
        f.rule_id
        for f in Scanner().scan(root).findings
        if f.category in (Category.MALICIOUS, Category.SUSPICIOUS)
    }


class TestASharedObjectIsMachOOnMacOs:
    """`.so` was listed only under ELF. Every compiled Python extension on a
    Mac is a Mach-O `.so`, so scanning any macOS virtualenv reported each of
    them as a file contradicting its own name -- 245 high-severity findings in
    one `site-packages`, and the first thing a Mac user would have seen."""

    @pytest.mark.parametrize("raw", [ELF, THIN_MACHO, FAT_MACHO])
    def test_neither_format_contradicts_a_dot_so(self, raw: bytes) -> None:
        found = BinaryDetector.identify(raw)
        assert BinaryDetector.mismatch("lib/_ssl.cpython-312-darwin.so", found) is None

    def test_a_dot_so_holding_a_script_still_does(self, tmp_path) -> None:
        assert (
            BinaryDetector.mismatch("lib/x.so", BinaryDetector.identify(b"#!/bin/sh\n")) is not None
        )


class TestCafebabeIsTwoFormats:
    """Java class files and Mach-O universal binaries begin with the same four
    bytes. What follows is a class-file version in one and a slice count in the
    other, and the ranges do not overlap."""

    def test_a_universal_binary_is_mach_o(self) -> None:
        assert BinaryDetector.identify(FAT_MACHO).name == "Mach-O executable"
        assert BinaryDetector.mismatch("lib/fat.dylib", BinaryDetector.identify(FAT_MACHO)) is None

    def test_a_class_file_is_still_a_class_file(self) -> None:
        assert BinaryDetector.identify(JAVA_CLASS).name == "Java class"
        assert BinaryDetector.mismatch("A.class", BinaryDetector.identify(JAVA_CLASS)) is None

    def test_a_class_file_wearing_a_dylib_name_is_reported(self) -> None:
        assert BinaryDetector.mismatch("x.dylib", BinaryDetector.identify(JAVA_CLASS)) is not None


class TestATypeAnnotationAssignsNothing:
    """`session_token: AuthenticationBackendXY` declares a type. There is no
    value in the file at all, and a typed codebase produces these by the
    hundred."""

    @pytest.mark.parametrize(
        "value",
        [
            "AuthenticationBackendXY",
            "HTTPPasswordMgrWithDefaultRealm",
            "SomeVeryLongTypeNameHere",
            "OptionalStr",
        ],
    )
    def test_a_type_name_is_not_a_credential(self, value: str) -> None:
        assert NOT_A_SECRET.match(value.encode()) is not None

    @pytest.mark.parametrize(
        "line",
        ["session_token: AuthenticationBackendXY", "passwd: HTTPPasswordMgrWithDefaultRealm"],
    )
    def test_end_to_end(self, tmp_path, line: str) -> None:
        (tmp_path / "a.py").write_text(f"{line}\n", encoding="utf-8")
        assert "SECRET.GENERIC.ASSIGNMENT.001" not in flagged(tmp_path)

    @pytest.mark.parametrize(
        "value", ["aB3kQ9mZ2xT7vL4nR8wY", "S3cr3tP4ssw0rdXyz9Qq", "glpat-AAAAAAAAAAAAAAAA"]
    )
    def test_key_material_is_still_key_material(self, value: str) -> None:
        assert NOT_A_SECRET.match(value.encode()) is None


class TestASphinxRoleIsDocumentation:
    """Prose reaches the assignment rule because the name group matches inside
    a word: "bypasses" ends in "pass" plus "es". A role after it has a colon
    and no whitespace, which is the shape the unquoted branch looks for."""

    @pytest.mark.parametrize(
        "value",
        ["meth:`cordon.registry.Registry.new`", "class:`~cordon.Scanner`", "ref:`configuration`"],
    )
    def test_a_cross_reference_is_not_a_credential(self, value: str) -> None:
        assert NOT_A_SECRET.match(value.encode()) is not None


class TestADeepTreeIsNotASilentSkip:
    """`max_path_depth` incremented a counter shared with `node_modules` and
    every configured exclusion, so it reached no finding. A payload under
    seventy directories gave `files_scanned: 1`, `complete: true`, no findings
    and exit 0 -- a one-command evasion of the whole scan."""

    @staticmethod
    def build(tmp_path, depth: int):
        deep = tmp_path
        for index in range(depth):
            deep = deep / f"d{index:02d}"
        deep.mkdir(parents=True)
        (deep / "payload.py").write_text("import os\n", encoding="utf-8")
        (tmp_path / "top.py").write_text("x = 1\n", encoding="utf-8")
        return tmp_path

    def test_the_scan_says_it_did_not_finish(self, tmp_path) -> None:
        result = Scanner().scan(self.build(tmp_path, 70))
        assert result.complete is False

    def test_and_names_what_it_could_not_reach(self, tmp_path) -> None:
        result = Scanner().scan(self.build(tmp_path, 70))
        reported = [f for f in result.findings if f.rule_id == "OPERATIONAL.WALK.TOO_DEEP"]
        assert len(reported) == 1
        assert "not examined" in reported[0].message

    def test_an_ordinary_tree_says_nothing(self, tmp_path) -> None:
        result = Scanner().scan(self.build(tmp_path, 3))
        assert result.complete is True
        assert not [f for f in result.findings if f.rule_id == "OPERATIONAL.WALK.TOO_DEEP"]


class TestTRexIsAlsoADinosaur:
    """Every other miner name in the list is a coined word. `t-rex` is a key in
    rich's emoji table, which pip vendors and many projects vendor after it."""

    def test_an_emoji_table_is_not_a_cryptominer(self, tmp_path) -> None:
        (tmp_path / "codes.py").write_text(
            'EMOJI = {\n    "t-rex": "\\U0001F996",\n    "sauropod": "\\U0001F995",\n}\n',
            encoding="utf-8",
        )
        assert "SUSPECT.CRYPTOMINER.001" not in flagged(tmp_path)

    def test_the_miner_with_its_flags_still_is(self, tmp_path) -> None:
        line = assemble("t-", "rex.exe -a ethash -o strat", "um+tcp://eth.pool.invalid:4444")
        (tmp_path / "run.sh").write_text(f"#!/bin/sh\n{line}\n", encoding="utf-8")
        assert "SUSPECT.CRYPTOMINER.001" in flagged(tmp_path)

    def test_the_unambiguous_names_are_untouched(self, tmp_path) -> None:
        line = assemble("xm", "rig --don", "ate-level 1")
        (tmp_path / "run.sh").write_text(f"#!/bin/sh\n{line}\n", encoding="utf-8")
        assert "SUSPECT.CRYPTOMINER.001" in flagged(tmp_path)


class TestCargoBuildOutputIsActuallyPruned:
    """`target/debug` and `target/release` were in a set matched against a
    single directory *name*, so neither string could ever match and Rust build
    output was never pruned at all."""

    def test_build_output_is_skipped(self, tmp_path) -> None:
        for part in ("target/debug", "target/release", "src", "mytarget"):
            (tmp_path / part).mkdir(parents=True)
        (tmp_path / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        (tmp_path / "mytarget" / "keep.rs").write_text("fn keep() {}\n", encoding="utf-8")
        for part in ("target/debug", "target/release"):
            (tmp_path / part / "app").write_text("junk\n", encoding="utf-8")

        result = Scanner().scan(tmp_path)
        assert result.stats.files_scanned == 2, "src/main.rs and mytarget/keep.rs, nothing else"

    def test_a_directory_merely_called_target_is_not(self, tmp_path) -> None:
        """`target` is an ordinary directory name in plenty of projects, so the
        relative path is what identifies the artefact directory."""
        (tmp_path / "target").mkdir()
        (tmp_path / "target" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        assert Scanner().scan(tmp_path).stats.files_scanned == 1


class TestAnInstallHookInASubdirectory:
    """`os.path.normpath` on Windows rewrites `/` as `\\`.

    Scan paths are POSIX everywhere, so a `postinstall` naming
    `scripts/setup.js` resolved to `scripts\\setup.js`, matched nothing, and the
    file was never marked as running at install time. Every `MALWARE.*`
    composite requiring install-hook context then downgraded to its `SUSPECT.*`
    counterpart -- weaker findings on Windows for one of the commonest layouts
    there is, and silently, because a finding was still produced.

    It survived because every corpus sample put its hook at the top level,
    where there is no separator to rewrite.
    """

    KNOWN = frozenset(
        {"package.json", "postinstall.js", "scripts/setup.js", "packages/api/build/run.js"}
    )

    @staticmethod
    def resolve(manifest: str, command: str) -> set[str]:
        from cordon_scanner.core.engine import Engine
        from cordon_scanner.core.models import Hook

        hook = Hook(kind="npm", path=manifest, name="postinstall", command=command)
        return Engine._hook_script_paths(manifest, [hook], TestAnInstallHookInASubdirectory.KNOWN)

    @pytest.mark.parametrize(
        ("manifest", "command", "expected"),
        [
            ("package.json", "node scripts/setup.js", {"scripts/setup.js"}),
            ("package.json", "node ./scripts/setup.js", {"scripts/setup.js"}),
            ("package.json", "node postinstall.js", {"postinstall.js"}),
            ("packages/api/package.json", "node build/run.js", {"packages/api/build/run.js"}),
        ],
    )
    def test_a_nested_target_resolves(self, manifest, command, expected) -> None:
        assert self.resolve(manifest, command) == expected

    def test_the_resolution_does_not_depend_on_the_host_separator(self) -> None:
        """The guard that makes this platform-independent rather than merely
        passing on the platform it was written on: resolution must go through
        `posixpath`, whose behaviour is the same everywhere, and not through
        `os.path`, whose behaviour is not."""
        import ntpath
        import posixpath
        import unittest.mock

        from cordon_scanner.core import engine

        # `ntpath` is what `os.path` *is* on Windows. Substituting it here
        # reproduces the Windows result on any host: if anything in the
        # resolution still reaches for the platform's own module, this fails.
        with unittest.mock.patch.object(engine, "posixpath", posixpath):
            assert self.resolve("package.json", "node scripts/setup.js") == {"scripts/setup.js"}
        assert ntpath.normpath("scripts/setup.js") == "scripts\\setup.js", (
            "the bug this guards against: the Windows normpath rewrites the separator"
        )

    def test_traversal_out_of_the_tree_is_still_refused(self) -> None:
        assert self.resolve("package.json", "node ../../etc/evil.js") == set()
