"""A `..` that stays inside the archive is resolved; one that climbs out, or one after a link, is refused.

Review 98 G6: sdists built with `pkg-0.3.1/../README.md` (it unpacks as `README.md`, inside the
destination) were blocked on SUSPECT.ARCHIVE.PATH_ESCAPE.001 and their member never read. An
extractor writes `a/../x` through `a` once `a` is a symlink, so after any link member the name is
refused as before; and a name that climbs above the archive's root is always refused.
"""

from __future__ import annotations

import io
import tarfile
import zipfile

from cordon_scanner.sources.archive import ArchiveReader, Rejection


class InnerDotKit:
    @staticmethod
    def tar(members: list[tuple[str, bytes | None, str]]) -> bytes:
        """`(name, data, link target)`: data None and a target make a symlink."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data, target in members:
                info = tarfile.TarInfo(name)
                if data is None:
                    info.type, info.linkname = tarfile.SYMTYPE, target
                    archive.addfile(info)
                else:
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def read(data: bytes, name: str = "p-1.0.tar.gz"):
        return ArchiveReader.extract(data, path=name)


class TestTheName:
    def test_an_inner_dotdot_collapses_when_asked(self) -> None:
        assert (
            ArchiveReader.safe_member_name("pkg-0.3.1/../README.md", collapse=True) == "README.md"
        )

    def test_it_is_refused_by_default(self) -> None:
        assert ArchiveReader.safe_member_name("pkg-0.3.1/../README.md") is None

    def test_a_climb_above_the_root_is_always_refused(self) -> None:
        assert ArchiveReader.safe_member_name("pkg/../../etc/x", collapse=True) is None
        assert ArchiveReader.safe_member_name("../x", collapse=True) is None


class TestTheReaders:
    def test_a_tar_member_with_an_inner_dotdot_is_read(self) -> None:
        result = InnerDotKit.read(InnerDotKit.tar([("pkg-0.3.1/../README.md", b"hello\n", "")]))
        assert "README.md" in {m.name for m in result.members}
        assert not [r for r in result.rejected if r.reason == Rejection.TRAVERSAL]

    def test_after_a_link_it_is_refused(self) -> None:
        data = InnerDotKit.tar([("pkg/a", None, "b"), ("pkg/a/../x.js", b"x\n", "")])
        result = InnerDotKit.read(data)
        assert [r for r in result.rejected if r.reason == Rejection.TRAVERSAL]

    def test_a_zip_member_with_an_inner_dotdot_is_read(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("pkg/../README.md", "hello\n")
        result = InnerDotKit.read(buffer.getvalue(), "p-1.0.zip")
        assert "README.md" in {m.name for m in result.members}
