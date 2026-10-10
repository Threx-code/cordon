"""The content proof (`intel/upstream_advisories.ContentProof`): the release archive a recipe pins,
beside the tag's tree by git blob id. Found measuring 1,575 packages whose upstream was both named
exactly and inferable: the inferred commit disagreed 14 times (monorepo component tags, registry
patched versions, mislabelled releases), which a bare inference would have reported as fact."""

from __future__ import annotations

import hashlib
import io
import tarfile

from cordon_scanner.intel import gitfetch
from cordon_scanner.intel.gitfetch import GitPack
from cordon_scanner.intel.upstream_advisories import Archive, ContentProof, TagInference


class TestTheProof:
    """`ContentProof`: the release archive the recipe pins, beside the tag's tree by blob id."""

    TAG_FILES = {f"src/file{i}.c": f"int f{i};\n".encode() for i in range(120)} | {
        "ChangeLog": b"",
        "win/build.bat": b"echo hi\n",
        ".github/ci.yml": b"x\n",
    }

    @staticmethod
    def release(files: dict[str, bytes]) -> bytes:
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:gz") as archive:
            for path, data in files.items():
                member = tarfile.TarInfo(f"proj-1.0/{path}")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return out.getvalue()

    def check(self, monkeypatch, release_files: dict[str, bytes], tag_files=None, digest=None):
        tag_files = self.TAG_FILES if tag_files is None else tag_files
        body = self.release(release_files)
        monkeypatch.setattr(ContentProof, "_download", staticmethod(lambda url: body))
        monkeypatch.setattr(ContentProof, "_results", {})
        monkeypatch.setattr(
            gitfetch.GitFetch,
            "tree",
            staticmethod(lambda repo, want: {p: GitPack.blob_id(d) for p, d in tag_files.items()}),
        )
        monkeypatch.setattr(TagInference, "_tips", {})
        monkeypatch.setattr(TagInference, "_refs", {})
        archive = Archive(
            ("https://example.invalid/proj-1.0.tar.gz",),
            digest or f"sha256:{hashlib.sha256(body).hexdigest()}",
        )
        return ContentProof.check(archive, "https://github.com/a/proj", "c" * 40, "v1.0")

    def test_a_release_holding_the_tags_files_is_proven(self, monkeypatch) -> None:
        release = {p: d for p, d in self.TAG_FILES.items() if not p.startswith(".")}
        release["configure"] = b"#!/bin/sh\n"  # a release may add generated files
        outcome, detail = self.check(monkeypatch, release)
        assert outcome == "proven", detail

    def test_one_changed_file_refutes_it(self, monkeypatch) -> None:
        release = {p: d for p, d in self.TAG_FILES.items() if not p.startswith(".")}
        release["src/file7.c"] = b"int f7 = 1;\n"  # a neighbouring version
        outcome, detail = self.check(monkeypatch, release)
        assert outcome == "refuted" and "src/file7.c" in detail

    def test_gits_end_of_line_conversion_and_a_filled_placeholder_are_not_differences(
        self, monkeypatch
    ) -> None:
        release = {p: d for p, d in self.TAG_FILES.items() if not p.startswith(".")}
        release["win/build.bat"] = b"echo hi\r\n"
        release["ChangeLog"] = b"2024-11-10  version 1.0\n"
        outcome, detail = self.check(monkeypatch, release)
        assert outcome == "proven", detail
        assert "end-of-line" in detail and "filled by the release" in detail

    def test_too_little_in_common_proves_nothing(self, monkeypatch) -> None:
        release = {"src/file1.c": self.TAG_FILES["src/file1.c"]}
        outcome, _ = self.check(monkeypatch, release)
        assert outcome == "unprovable"

    def test_a_release_not_matching_the_recipes_digest_is_not_used(self, monkeypatch) -> None:
        outcome, detail = self.check(monkeypatch, {"a": b"x"}, digest="sha256:" + "0" * 64)
        assert outcome == "unprovable" and "digest" in detail
