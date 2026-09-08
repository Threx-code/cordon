"""File content handling and filesystem traversal.

These are the two places hostile input first reaches the scanner, so the tests
are weighted toward what happens with input designed to be awkward rather than
toward the happy path.
"""

from __future__ import annotations

import os
import sys

import pytest

from cordon.core.content import FileContent, Skipped, SkipReason
from cordon.core.limits import DEFAULT_LIMITS
from cordon.core.walker import PathGlob, Walker

EXT_MAP = (
    (".py", "python"),
    (".js", "javascript"),
    (".ts", "typescript"),
    (".sh", "shell"),
)


# ---------------------------------------------------------------------------
# FileContent
# ---------------------------------------------------------------------------


class TestFileContent:
    def test_basic_properties(self) -> None:
        content = FileContent.from_bytes("src/app.py", b"print('hello')\n")
        assert content.extension == ".py"
        assert content.basename == "app.py"
        assert not content.is_binary
        assert content.text == "print('hello')\n"
        assert len(content) == 15

    def test_hash_is_content_addressed(self) -> None:
        a = FileContent.from_bytes("a.py", b"same")
        b = FileContent.from_bytes("b.py", b"same")
        c = FileContent.from_bytes("a.py", b"different")
        assert a.sha256 == b.sha256
        assert a.sha256 != c.sha256

    def test_binary_detection(self) -> None:
        assert FileContent.from_bytes("x.png", b"\x89PNG\x00\x00").is_binary
        assert not FileContent.from_bytes("x.py", b"clean text").is_binary

    def test_binary_sniff_is_bounded(self) -> None:
        """A NUL far past the sniff window does not make a file binary. That is
        the same tradeoff grep -I makes, and both outcomes are visible."""
        content = FileContent.from_bytes("x.txt", b"a" * 20000 + b"\x00")
        assert not content.is_binary

    def test_line_translation(self) -> None:
        content = FileContent.from_bytes("x.py", b"one\ntwo\nthree\n")
        assert content.line_count == 4  # trailing newline opens a fourth line
        assert content.line_of(0) == 1
        assert content.line_of(4) == 2
        assert content.line_of(8) == 3
        assert content.column_of(5) == 2
        assert content.line_text(2) == "two"

    def test_line_text_out_of_range_is_empty(self) -> None:
        content = FileContent.from_bytes("x.py", b"one\n")
        assert content.line_text(0) == ""
        assert content.line_text(99) == ""

    def test_longest_line(self) -> None:
        content = FileContent.from_bytes("x.js", b"short\n" + b"x" * 5000 + b"\nshort\n")
        assert content.longest_line == 5000

    def test_longest_line_without_trailing_newline(self) -> None:
        content = FileContent.from_bytes("x.js", b"ab\n" + b"y" * 100)
        assert content.longest_line == 100

    def test_decodes_permissively(self) -> None:
        """A file that is mostly valid UTF-8 with stray bytes is common, and is
        also what an encoding trick looks like. Refusing to decode would skip
        both; replacing bad bytes scans both."""
        content = FileContent.from_bytes("x.py", b"valid \xff\xfe invalid")
        assert "valid" in content.text

    def test_handles_utf8_bom(self) -> None:
        content = FileContent.from_bytes("x.py", b"\xef\xbb\xbfprint(1)")
        assert content.text == "print(1)"

    def test_shebang_detection(self) -> None:
        assert (
            FileContent.from_bytes("run", b"#!/usr/bin/env python3\n").shebang
            == "/usr/bin/env python3"
        )
        assert FileContent.from_bytes("run", b"no shebang").shebang is None

    def test_slice_is_bounded(self) -> None:
        content = FileContent.from_bytes("x.py", b"0123456789")
        assert content.slice(2, 5) == b"234"
        assert content.slice(-10, 3) == b"012"
        assert content.slice(5, 9999) == b"56789"
        assert content.slice(9999, 10000) == b""


class TestFileContentLoading:
    def test_loads_a_real_file(self, tmp_path) -> None:
        path = tmp_path / "app.py"
        path.write_bytes(b"print(1)\n")
        content = FileContent.load(path, "app.py")
        assert isinstance(content, FileContent)
        assert content.raw == b"print(1)\n"

    def test_missing_file_is_skipped_not_raised(self, tmp_path) -> None:
        """One unreadable file must never abort a scan of ten thousand."""
        result = FileContent.load(tmp_path / "absent.py", "absent.py")
        assert isinstance(result, Skipped)
        assert result.reason == SkipReason.UNREADABLE

    @pytest.mark.skipif(sys.platform == "win32", reason="symlink semantics differ")
    def test_symlinks_are_never_followed(self, tmp_path) -> None:
        """Following a symlink is how a scanner is induced to read a private key
        outside the scan root and print it as evidence."""
        secret = tmp_path / "secret"
        secret.write_bytes(b"PRIVATE KEY MATERIAL")
        link = tmp_path / "innocent.py"
        link.symlink_to(secret)

        result = FileContent.load(link, "innocent.py")
        assert isinstance(result, Skipped)
        assert result.reason == SkipReason.SYMLINK

    def test_oversized_file_is_truncated_not_dropped(self, tmp_path) -> None:
        """A payload appended to a large generated file is still worth finding,
        and the truncation is recorded so nothing claims full coverage."""
        path = tmp_path / "big.js"
        path.write_bytes(b"x" * 5000)
        limits = DEFAULT_LIMITS.merged(max_file_bytes=1000)
        content = FileContent.load(path, "big.js", limits)
        assert isinstance(content, FileContent)
        assert content.truncated
        assert len(content.raw) == 1000
        assert content.size == 5000

    @pytest.mark.skipif(sys.platform == "win32", reason="FIFOs are POSIX")
    def test_non_regular_files_are_skipped(self, tmp_path) -> None:
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo)
        result = FileContent.load(fifo, "pipe")
        assert isinstance(result, Skipped)
        assert result.reason == SkipReason.NOT_REGULAR


class TestLanguageSniffing:
    def test_extension_wins_when_present(self) -> None:
        content = FileContent.from_bytes("a.py", b"code")
        assert content.sniff_language(EXT_MAP) == "python"

    def test_shebang_used_when_no_extension(self) -> None:
        """A file declaring an interpreter is telling you what will execute it,
        which beats any inference from its name."""
        content = FileContent.from_bytes("script", b"#!/usr/bin/env python\n")
        assert content.sniff_language(EXT_MAP) == "python"

    def test_unknown_returns_none(self) -> None:
        assert FileContent.from_bytes("data.xyz", b"?").sniff_language(EXT_MAP) is None


# ---------------------------------------------------------------------------
# Path matching
# ---------------------------------------------------------------------------


class TestPathMatching:
    @pytest.mark.parametrize(
        ("path", "pattern", "expected"),
        [
            ("node_modules/a.js", "node_modules/", True),
            ("src/node_modules/a.js", "node_modules/", True),
            ("src/app.py", "node_modules/", False),
            ("src/app.py", "*.py", True),
            ("src/app.py", "src/*.py", True),
            ("src/deep/app.py", "src/*.py", False),
            ("src/deep/app.py", "**/*.py", True),
            ("app.py", "**/*.py", True),
            ("src/gen.pb.go", "**/*.pb.go", True),
            ("vendor/x", "vendor", True),
            ("a/vendor/x", "vendor", True),
        ],
    )
    def test_matching(self, path: str, pattern: str, expected: bool) -> None:
        assert PathGlob.matches(path, pattern) is expected

    def test_star_does_not_cross_directory_boundaries(self) -> None:
        """`fnmatch`'s `*` matches `/`, so `src/*.py` would silently match
        `src/deep/app.py`. For an exclusion that means removing far more than
        the author intended, which is silent over-exclusion: the exact failure
        the walker exists to prevent."""
        assert PathGlob.matches("src/app.py", "src/*.py")
        assert not PathGlob.matches("src/deep/app.py", "src/*.py")
        assert not PathGlob.matches("a/b/c.py", "a/*.py")

    def test_doublestar_does_cross_directory_boundaries(self) -> None:
        assert PathGlob.matches("src/deep/nested/app.py", "src/**/*.py")
        assert PathGlob.matches("app.py", "**/*.py")

    def test_question_mark_does_not_cross_boundaries(self) -> None:
        assert PathGlob.matches("ab.py", "a?.py")
        assert not PathGlob.matches("a/b.py", "a?b.py")

    def test_character_class(self) -> None:
        assert PathGlob.matches("a1.py", "a[0-9].py")
        assert not PathGlob.matches("ax.py", "a[0-9].py")


# ---------------------------------------------------------------------------
# Walker
# ---------------------------------------------------------------------------


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print(1)")
    (tmp_path / "src" / "util.py").write_text("print(2)")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "index.js").write_text("x")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.js").write_text("vendored")
    (tmp_path / "README.md").write_text("docs")
    return tmp_path


class TestWalker:
    def test_finds_files(self, tree) -> None:
        walker = Walker()
        paths = {e.rel_path for e in walker.walk(tree)}
        assert "src/app.py" in paths
        assert "README.md" in paths

    def test_prunes_dependency_directories(self, tree) -> None:
        walker = Walker()
        paths = {e.rel_path for e in walker.walk(tree)}
        assert not any(p.startswith("node_modules/") for p in paths)
        assert walker.stats.dirs_pruned >= 1

    def test_vendor_is_scanned_by_default(self, tree) -> None:
        """Vendored code ships, is rarely reviewed, and is therefore one of the
        better places to hide a payload. Excluding it by default would be
        exactly the wrong default."""
        walker = Walker()
        paths = {e.rel_path for e in walker.walk(tree)}
        assert "vendor/lib.js" in paths

    def test_order_is_deterministic(self, tree) -> None:
        """Filesystem order varies between systems and between runs. Constraint
        C5 requires identical content to produce identical output."""
        first = [e.rel_path for e in Walker().walk(tree)]
        second = [e.rel_path for e in Walker().walk(tree)]
        assert first == second == sorted(first)

    def test_exclusions_are_counted_per_pattern(self, tree) -> None:
        """A scan states how many files each pattern removed, so an exclusion
        that removed far more than intended is visible."""
        walker = Walker(exclude=["*.md"])
        list(walker.walk(tree))
        assert walker.stats.excluded_by_pattern["*.md"] == 1
        assert walker.stats.total_excluded == 1

    def test_unmatched_exclusion_is_reported(self, tree) -> None:
        """An entry for a path that does not exist is a hole held open for a
        file nobody would notice appearing."""
        walker = Walker(exclude=["does-not-exist/"])
        list(walker.walk(tree))
        assert "does-not-exist/" in walker.stats.unmatched_patterns

    def test_matched_exclusion_is_not_reported_as_unmatched(self, tree) -> None:
        walker = Walker(exclude=["*.md"])
        list(walker.walk(tree))
        assert walker.stats.unmatched_patterns == ()

    def test_include_restricts(self, tree) -> None:
        walker = Walker(include=["**/*.py"])
        paths = {e.rel_path for e in walker.walk(tree)}
        assert paths == {"src/app.py", "src/util.py"}

    def test_max_files_limit_is_recorded(self, tree) -> None:
        """Reaching a limit is reported. A silent stop is indistinguishable from
        a clean scan."""
        walker = Walker(limits=DEFAULT_LIMITS.merged(max_files=2))
        entries = list(walker.walk(tree))
        assert len(entries) == 2
        assert walker.stats.limit_hit is not None
        assert "max_files" in walker.stats.limit_hit

    def test_max_total_bytes_limit_is_recorded(self, tree) -> None:
        walker = Walker(limits=DEFAULT_LIMITS.merged(max_total_bytes=1))
        list(walker.walk(tree))
        assert walker.stats.limit_hit is not None
        assert "max_total_bytes" in walker.stats.limit_hit

    @pytest.mark.skipif(sys.platform == "win32", reason="symlink semantics differ")
    def test_symlinks_are_reported_not_followed(self, tmp_path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret").write_text("KEY")
        root = tmp_path / "repo"
        root.mkdir()
        (root / "link").symlink_to(outside / "secret")

        walker = Walker()
        entries = list(walker.walk(root))
        assert len(entries) == 1
        assert entries[0].is_symlink
        assert walker.stats.symlinks_skipped == 1

    @pytest.mark.skipif(sys.platform == "win32", reason="symlink semantics differ")
    def test_symlink_loop_terminates(self, tmp_path) -> None:
        root = tmp_path / "repo"
        (root / "a").mkdir(parents=True)
        (root / "a" / "loop").symlink_to(root, target_is_directory=True)
        entries = list(Walker().walk(root))
        assert isinstance(entries, list)

    def test_single_file_target(self, tree) -> None:
        entries = list(Walker().walk(tree / "src" / "app.py"))
        assert len(entries) == 1
        assert entries[0].rel_path == "app.py"

    def test_unreadable_directory_is_recorded_not_fatal(self, tmp_path) -> None:
        root = tmp_path / "repo"
        blocked = root / "blocked"
        blocked.mkdir(parents=True)
        (root / "ok.py").write_text("x")
        (blocked / "hidden.py").write_text("y")
        blocked.chmod(0o000)
        try:
            walker = Walker()
            paths = {e.rel_path for e in walker.walk(root)}
            assert "ok.py" in paths
        finally:
            blocked.chmod(0o755)


# ---------------------------------------------------------------------------
# Cross-platform behaviour
# ---------------------------------------------------------------------------


class TestLineEndings:
    """The same content must scan identically however it was checked out.

    Determinism is a stated guarantee, and it has to hold across platforms as
    well as across runs. A CRLF checkout that measures lines differently from an
    LF checkout means two engineers on different operating systems get different
    findings from the same commit, which is indistinguishable from a bug in the
    rules.
    """

    LF = b"const value = 1;\nconst other = 2;\n"
    CRLF = b"const value = 1;\r\nconst other = 2;\r\n"

    def test_line_text_strips_both_terminators(self) -> None:
        """A stray carriage return would otherwise reach every evidence
        snippet taken from a Windows-authored file."""
        assert FileContent.from_bytes("a.js", self.CRLF).line_text(1) == "const value = 1;"

    def test_longest_line_agrees_across_line_endings(self) -> None:
        assert (
            FileContent.from_bytes("a.js", self.LF).longest_line
            == FileContent.from_bytes("a.js", self.CRLF).longest_line
        )

    def test_line_numbering_agrees_across_line_endings(self) -> None:
        lf = FileContent.from_bytes("a.js", self.LF)
        crlf = FileContent.from_bytes("a.js", self.CRLF)
        assert lf.line_count == crlf.line_count

    def test_a_file_with_no_trailing_newline(self) -> None:
        content = FileContent.from_bytes("a.js", b"only line")
        assert content.line_text(1) == "only line"
        assert content.longest_line == 9

    def test_an_empty_file(self) -> None:
        content = FileContent.from_bytes("a.js", b"")
        assert content.longest_line == 0
        assert content.line_text(1) == ""

    def test_findings_are_identical_across_line_endings(self, tmp_path) -> None:
        """The end-to-end version: the same payload in LF and CRLF form must
        produce the same findings."""
        from cordon import Scanner
        from cordon.core.config import Config

        payload = b"const p = atob(BLOB);\neval(p);\n"

        lf_dir = tmp_path / "lf"
        lf_dir.mkdir()
        (lf_dir / "a.js").write_bytes(payload)

        crlf_dir = tmp_path / "crlf"
        crlf_dir.mkdir()
        (crlf_dir / "a.js").write_bytes(payload.replace(b"\n", b"\r\n"))

        scanner = Scanner(Config.default().with_overrides(use_cache=False))
        lf_rules = sorted(f.rule_id for f in scanner.scan(lf_dir).findings)
        crlf_rules = sorted(f.rule_id for f in scanner.scan(crlf_dir).findings)
        assert lf_rules == crlf_rules


class TestPathPortability:
    def test_reported_paths_always_use_forward_slashes(self, tmp_path) -> None:
        """Findings, suppressions and baselines all key on the path. A backslash
        on one platform and a forward slash on another would make a suppression
        written on one machine silently inert on another."""
        root = tmp_path / "repo"
        (root / "src" / "deep").mkdir(parents=True)
        (root / "src" / "deep" / "app.py").write_text("x = 1\n")

        paths = [entry.rel_path for entry in Walker().walk(root)]
        assert "src/deep/app.py" in paths
        assert not any("\\" in p for p in paths)
