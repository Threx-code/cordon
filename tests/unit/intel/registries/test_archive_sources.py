"""The verified archive of a release (`archive_sources/`), read from the registries' real documents.

Fixtures in `archives/` are real answers captured on 2026-11-26 (public metadata only). What is tested is where the archive is, which
digests it must match, and that nothing that does not match is returned."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.error
from datetime import datetime
from email.message import Message
from typing import Any, ClassVar

import pytest

from cordon_scanner.intel.registries import registry_request
from cordon_scanner.intel.registries.archive_sources.base import ArchiveFetch, Located
from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources
from cordon_scanner.intel.registries.record_sources.base import Release
from cordon_scanner.intel.registries.registry_request import RegistryError, RegistryRequest
from support import ROOT

DATA = ROOT / "tests" / "unit" / "intel" / "registries" / "archives"


class Fixtures:
    """The real documents the sources are tested on, and archives made for the checks."""

    @staticmethod
    def load(name: str) -> Any:
        return json.loads((DATA / name).read_text(encoding="utf-8"))

    @staticmethod
    def text(name: str) -> str:
        return (DATA / name).read_text(encoding="utf-8")


class TestDigests:
    DATA_ = b"the archive"

    def sha(self, algorithm: str = "sha256") -> tuple[str, str]:
        return algorithm, hashlib.new(algorithm, self.DATA_).hexdigest()

    def test_a_matching_digest_passes(self) -> None:
        assert ArchiveFetch.digest_ok(self.DATA_, (self.sha(),))

    def test_every_stated_digest_must_match(self) -> None:
        wrong = ("sha512", "0" * 128)
        assert not ArchiveFetch.digest_ok(self.DATA_, (self.sha(), wrong))
        assert ArchiveFetch.digest_ok(self.DATA_, (self.sha(), self.sha("sha512")))

    def test_no_digest_stated_is_never_a_pass(self) -> None:
        assert not ArchiveFetch.digest_ok(self.DATA_, ())

    def test_the_case_of_the_stated_digest_does_not_matter(self) -> None:
        algorithm, hexdigest = self.sha()
        assert ArchiveFetch.digest_ok(self.DATA_, ((algorithm, hexdigest.upper()),))

    def test_the_strength_is_the_strongest_stated(self) -> None:
        located = Located("https://x.invalid/a", "a", (("md5", "0" * 32), ("sha256", "0" * 64)))
        assert located.strength == "sha256"


class TestCondaArchive:
    def locate(self, version: str, edit: Any = None) -> Located | None:
        source = ArchiveSources.of("conda")
        assert source is not None
        (document,) = source.documents("zlib", version)
        content = Fixtures.load("conda_package.json")
        if edit:
            edit(content)
        return source.locate("zlib", version, {document.url: content})

    def test_the_newest_conda_file_of_linux_64_with_its_sha256(self) -> None:
        found = self.locate("1.3.2")
        assert found is not None
        listed = [
            f
            for f in Fixtures.load("conda_package.json")["files"]
            if f["version"] == "1.3.2"
            and f["basename"].startswith("linux-64/")
            and f["basename"].endswith(".conda")
        ]
        newest = max(listed, key=lambda f: f["upload_time"])
        assert found.url == "https:" + newest["download_url"] and found.url.startswith(
            "https://conda.anaconda.org/conda-forge/linux-64/"
        )
        assert found.filename == newest["basename"].split("/")[1] and found.digests == (
            ("sha256", newest["sha256"]),
        )
        assert len(listed) >= 1 and len(newest["sha256"]) == 64

    def test_a_version_the_channel_does_not_list_has_no_archive(self) -> None:
        assert self.locate("9.9.9") is None

    def test_noarch_comes_before_linux_64(self) -> None:
        def add_noarch(document: dict[str, Any]) -> None:
            entry = dict(next(f for f in document["files"] if f["version"] == "1.3.2"))
            entry |= {
                "basename": "noarch/zlib-1.3.2-py_0.conda",
                "download_url": "//conda.anaconda.org/conda-forge/noarch/zlib-1.3.2-py_0.conda",
                "sha256": "ab" * 32,
            }
            document["files"].append(entry)

        found = self.locate("1.3.2", add_noarch)
        assert found is not None and found.url.endswith("/noarch/zlib-1.3.2-py_0.conda")

    def test_a_file_that_states_no_sha256_is_no_archive(self) -> None:
        def strip(document: dict[str, Any]) -> None:
            for entry in document["files"]:
                entry.pop("sha256", None)

        assert self.locate("1.3.2", strip) is None

    def test_a_download_address_that_is_not_a_scheme_relative_one_is_refused(self) -> None:
        def move(document: dict[str, Any]) -> None:
            for entry in document["files"]:
                entry["download_url"] = "https://evil.example.invalid/x.conda"

        assert self.locate("1.3.2", move) is None


class TestAnsibleArchive:
    NAME = "community.general"

    def locate(self, version: str = "14.0.1", edit: Any = None) -> Located | None:
        source = ArchiveSources.of("ansible")
        assert source is not None
        (document,) = source.documents(self.NAME, version)
        content = Fixtures.load("ansible_version.json")
        if edit:
            edit(content)
        return source.locate(self.NAME, version, {document.url: content})

    def test_the_artifact_its_sha256_and_the_download_address(self) -> None:
        found = self.locate()
        assert found is not None
        assert found.filename == "community-general-14.0.1.tar.gz"
        assert found.digests == (
            ("sha256", "816291784a3369a888119a6a5d00593beec44d919605ac6553b0a54274470beb"),
        )
        assert found.url.startswith(
            "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/artifacts/"
        )

    def test_the_download_is_allowed_one_signed_redirect_inside_the_registrys_own_host(
        self,
    ) -> None:
        source = ArchiveSources.of("ansible")
        assert (
            source is not None and source.REDIRECTS >= 1 and {"galaxy.ansible.com"} == source.HOSTS
        )

    def test_a_download_address_off_the_registrys_artifact_path_is_refused(self) -> None:
        def move(document: dict[str, Any]) -> None:
            document["download_url"] = "https://galaxy.ansible.com/somewhere/else.tar.gz"

        assert self.locate(edit=move) is None

    def test_another_version_than_the_one_asked_is_not_its_archive(self) -> None:
        assert self.locate("14.0.2") is None

    @pytest.mark.parametrize("name", ["general", "a.b.c", "Community.General", "../x.y", ""])
    def test_a_name_that_is_not_namespace_dot_name_asks_for_nothing(self, name: str) -> None:
        assert ArchiveSources.of("ansible").documents(name, "1.0.0") == ()  # type: ignore[union-attr]


class TestTheFetch:
    def stub(
        self, monkeypatch: pytest.MonkeyPatch, data: bytes, **kw: Any
    ) -> list[tuple[str, str, int]]:
        calls: list[tuple[str, str, int]] = []

        def fetch_bytes(url: str, allow: Any, *, redirects: int = 0, public: bool = False) -> bytes:
            calls.append((url, "ansible" if allow("galaxy.ansible.com") else "", redirects))
            return data

        monkeypatch.setattr(RegistryRequest, "fetch_bytes", staticmethod(fetch_bytes))
        source = ArchiveSources.of("ansible")
        assert source is not None
        (document,) = source.documents("community.general", "14.0.1")
        monkeypatch.setattr(
            "cordon_scanner.intel.registries.archive_sources.base.RecordFetch.documents",
            staticmethod(lambda *_a, **_k: {document.url: Fixtures.load("ansible_version.json")}),
        )
        return calls

    def test_an_archive_that_matches_is_returned_under_its_filename(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data = b"x"
        located = Fixtures.load("ansible_version.json")
        located["artifact"]["sha256"] = hashlib.sha256(data).hexdigest()
        calls = self.stub(monkeypatch, data)
        source = ArchiveSources.of("ansible")
        assert source is not None
        monkeypatch.setattr(
            "cordon_scanner.intel.registries.archive_sources.base.RecordFetch.documents",
            staticmethod(
                lambda *_a, **_k: {source.documents("community.general", "14.0.1")[0].url: located}
            ),
        )
        archive = ArchiveFetch.archive(source, "community.general", "14.0.1")
        assert archive.data == data and archive.filename == "community-general-14.0.1.tar.gz"
        assert calls[0][1:] == ("ansible", source.REDIRECTS)

    def test_bytes_that_do_not_match_the_published_digest_are_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.stub(monkeypatch, b"tampered")
        source = ArchiveSources.of("ansible")
        assert source is not None
        with pytest.raises(RegistryError, match="does not match the sha256 ansible publishes"):
            ArchiveFetch.archive(source, "community.general", "14.0.1")

    def test_a_registry_that_has_no_such_name_is_an_error_not_an_empty_archive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "cordon_scanner.intel.registries.archive_sources.base.RecordFetch.documents",
            staticmethod(lambda *_a, **_k: None),
        )
        source = ArchiveSources.of("conda")
        assert source is not None
        with pytest.raises(RegistryError, match="has no zlib"):
            ArchiveFetch.archive(source, "zlib", "1.3.2")


class TestRedirects:
    """`RegistryRequest.fetch_bytes` follows a redirect only where the ecosystem allows it, and only inside its own hosts."""

    class Response:
        def __init__(self, body: bytes) -> None:
            self.body = body

        def __enter__(self) -> TestRedirects.Response:
            return self

        def __exit__(self, *_a: Any) -> None:
            return None

        def read(self, size: int = -1) -> bytes:
            body, self.body = self.body, b""
            return body

    def opener(self, steps: list[Any], seen: list[str]) -> Any:
        class Opener:
            def open(self_, request: Any, timeout: float = 0) -> Any:
                seen.append(request.full_url)
                step = steps.pop(0)
                if isinstance(step, bytes):
                    return TestRedirects.Response(step)
                headers = Message()
                headers["Location"] = step
                raise urllib.error.HTTPError(request.full_url, 302, "Found", headers, None)

        return Opener()

    def run(
        self, monkeypatch: pytest.MonkeyPatch, steps: list[Any], redirects: int
    ) -> tuple[bytes | None, list[str], str]:
        seen: list[str] = []
        monkeypatch.setattr(
            registry_request.urllib.request, "build_opener", lambda *_a: self.opener(steps, seen)
        )
        monkeypatch.setattr(
            registry_request.Download,
            "read",
            staticmethod(lambda response, limit: response.read(limit)),
        )
        try:
            return (
                RegistryRequest.fetch_bytes(
                    "https://galaxy.ansible.com/a",
                    lambda host: host == "galaxy.ansible.com",
                    redirects=redirects,
                ),
                seen,
                "",
            )
        except RegistryError as exc:
            return None, seen, str(exc)

    def test_no_redirect_is_followed_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        body, seen, error = self.run(monkeypatch, ["https://galaxy.ansible.com/b"], 0)
        assert body is None and seen == ["https://galaxy.ansible.com/a"] and "HTTP 302" in error

    def test_one_redirect_inside_the_hosts_is_followed_when_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        body, seen, _ = self.run(monkeypatch, ["https://galaxy.ansible.com/b", b"data"], 1)
        assert body == b"data" and seen == [
            "https://galaxy.ansible.com/a",
            "https://galaxy.ansible.com/b",
        ]

    def test_a_redirect_to_another_host_is_refused_before_it_is_requested(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        body, seen, error = self.run(monkeypatch, ["https://evil.example.invalid/b", b"data"], 2)
        assert body is None and seen == ["https://galaxy.ansible.com/a"] and "allowlist" in error

    def test_a_redirect_to_plain_http_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        body, _, error = self.run(monkeypatch, ["http://galaxy.ansible.com/b", b"data"], 2)
        assert body is None and "allowlist" in error

    def test_the_hops_are_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        body, seen, error = self.run(monkeypatch, ["https://galaxy.ansible.com/b"] * 5, 1)
        assert body is None and len(seen) == 2 and "HTTP 302" in error


class TestThePreviousRelease:
    def releases(self, rows: list[tuple[str, str, str]]) -> list[Release]:
        return [Release(v, datetime.fromisoformat(t), "", w) for v, t, w in rows]

    def previous(
        self, monkeypatch: pytest.MonkeyPatch, rows: list[tuple[str, str, str]], version: str
    ) -> str | None:
        monkeypatch.setattr(ArchiveFetch, "releases", staticmethod(lambda *_a: self.releases(rows)))
        return ArchiveFetch.previous("conda", "zlib", version)

    def test_the_highest_below_it_that_was_published_before_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = [
            ("1.2.0", "2020-01-01", ""),
            ("1.3.1", "2024-01-01", ""),
            ("1.3.2", "2025-01-01", ""),
        ]
        assert self.previous(monkeypatch, rows, "1.3.2") == "1.3.1"

    def test_a_maintained_line_is_compared_with_its_own_line_not_the_newest_release_in_time(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = [
            ("4.21.1", "2024-01-01", ""),
            ("5.0.1", "2024-09-01", ""),
            ("4.21.2", "2024-10-01", ""),
        ]
        assert self.previous(monkeypatch, rows, "4.21.2") == "4.21.1"

    def test_a_withdrawn_release_is_not_the_previous_one_but_the_asked_one_may_be(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = [
            ("1.0", "2020-01-01", ""),
            ("1.1", "2021-01-01", "yanked"),
            ("1.2", "2022-01-01", "yanked"),
        ]
        assert self.previous(monkeypatch, rows, "1.2") == "1.0"

    def test_the_first_release_has_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert self.previous(monkeypatch, [("1.0", "2020-01-01", "")], "1.0") is None

    def test_a_version_the_registry_does_not_list_has_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert self.previous(monkeypatch, [("1.0", "2020-01-01", "")], "2.0") is None


class TestTheTables:
    @pytest.mark.parametrize("source", ArchiveSources.SOURCES, ids=lambda s: s.ecosystem)
    def test_a_source_admits_its_own_hosts_and_refuses_an_address_or_a_local_name(
        self, source: Any
    ) -> None:
        for host in source.HOSTS:
            assert source.allows(host)
        for host in ("127.0.0.1", "localhost", "169.254.169.254", "printer.local", "intranet"):
            assert not source.allows(host)
        if not source.PUBLIC:
            assert not source.allows("evil.example.invalid")

    def test_every_archive_ecosystem_is_compared_and_has_a_record_source(self) -> None:
        from cordon_scanner.cli.commands.review import COMPARABLE
        from cordon_scanner.intel.registries.record_sources.table import RecordSources
        from cordon_scanner.intel.registries.release_history import ReleaseHistory

        for ecosystem in ArchiveSources.ids():
            assert ecosystem in COMPARABLE
            # Its history comes from its registry record, or from the reader kept apart until the record exists.
            assert RecordSources.of(ecosystem) is not None or ecosystem in ReleaseHistory.readers()

    def test_the_release_history_is_the_one_the_record_reads(self) -> None:
        from cordon_scanner.intel.registries.record_sources.base import RecordBuilder
        from cordon_scanner.intel.registries.record_sources.table import RecordSources

        source = RecordSources.of("conda")
        assert source is not None
        (document,) = source.documents("zlib", "1.3.2")
        content = json.loads(
            (ROOT / "tests/unit/intel/registries/records/conda.json").read_text(encoding="utf-8")
        )
        releases = RecordBuilder.releases_of(source, "zlib", "1.3.2", {document.url: content})
        assert {r.version for r in releases} >= {"1.2.8", "1.3.2"}
        record = source.record("zlib", "1.3.2", {document.url: content})
        assert record is not None and record.prior_versions == len(releases) - 1


class TestTheEntryPoints:
    def test_an_ecosystem_with_no_archive_source_has_no_verified_archive(self) -> None:
        with pytest.raises(RegistryError, match="no verified archive"):
            ArchiveSources.package_archive("nonesuch", "x", "1.0")

    def test_no_version_named_is_the_registrys_newest_release_not_withdrawn(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from datetime import datetime

        rows = [
            Release("1.0.0", datetime(2020, 1, 1), ""),
            Release("1.10.0", datetime(2021, 1, 1), ""),
            Release("1.9.0", datetime(2022, 1, 1), ""),
            Release("2.0.0", datetime(2023, 1, 1), withdrawn="yanked"),
        ]
        monkeypatch.setattr(ArchiveFetch, "releases", staticmethod(lambda e, n, v: rows))
        assert ArchiveFetch.latest("cargo", "x") == "1.10.0"
        asked: list[str] = []
        monkeypatch.setattr(
            ArchiveFetch, "archive", staticmethod(lambda source, n, v: asked.append(v) or "archive")
        )
        assert ArchiveSources.package_archive("cargo", "x", None) == "archive" and asked == [
            "1.10.0"
        ]

    def test_an_image_with_no_tag_named_is_the_tag_latest(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked: list[str] = []
        monkeypatch.setattr(
            ArchiveFetch, "archive", staticmethod(lambda source, n, v: asked.append(v) or "archive")
        )
        assert ArchiveSources.package_archive("image", "nginx", None) == "archive" and asked == [
            "latest"
        ]

    def test_a_registry_with_nothing_unwithdrawn_names_no_current_version(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from datetime import datetime

        monkeypatch.setattr(
            ArchiveFetch,
            "releases",
            staticmethod(
                lambda e, n, v: [Release("1.0", datetime(2020, 1, 1), withdrawn="yanked")]
            ),
        )
        with pytest.raises(RegistryError, match="names no current version"):
            ArchiveFetch.latest("cargo", "x")

    def test_the_previous_release_comes_from_the_release_history_of_a_source(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            ArchiveFetch, "previous", staticmethod(lambda e, n, v: f"{e}/{n}/{v}/before")
        )
        assert (
            ArchiveSources.previous("ansible", "community.general", "14.0.1")
            == "ansible/community.general/14.0.1/before"
        )


class TestBazelArchive:
    def locate(self, edit: Any = None) -> Located | None:
        source = ArchiveSources.of("bazel")
        assert source is not None
        (document,) = source.documents("abseil-cpp", "20240116.2")
        content = Fixtures.load("bazel_source.json")
        if edit:
            edit(content)
        return source.locate("abseil-cpp", "20240116.2", {document.url: content})

    def test_the_url_and_the_integrity_read_as_a_hex_sha256(self) -> None:
        found = self.locate()
        assert found is not None
        assert (
            found.url
            == "https://github.com/abseil/abseil-cpp/releases/download/20240116.2/abseil-cpp-20240116.2.tar.gz"
        )
        assert found.filename == "abseil-cpp-20240116.2.tar.gz"
        assert found.digests == (
            ("sha256", base64.b64decode("czcmuMOm05pBINfkXqi0GkNM2s3kAculAPFCNsSbOdw=").hex()),
        )

    def test_a_module_taken_from_a_git_repository_has_no_archive(self) -> None:
        def git(source: dict[str, Any]) -> None:
            source["type"] = "git_repository"

        assert self.locate(git) is None

    @pytest.mark.parametrize(
        "integrity", ["", "sha1-AAAA", "sha256-@@@@", "md5-AAAA", "sha256-" + "AA"]
    )
    def test_an_integrity_that_is_not_a_whole_sri_digest_is_no_check(self, integrity: str) -> None:
        def put(source: dict[str, Any]) -> None:
            source["integrity"] = integrity

        assert self.locate(put) is None

    def test_a_url_that_is_not_https_has_no_archive(self) -> None:
        def put(source: dict[str, Any]) -> None:
            source["url"] = "http://example.invalid/a.tar.gz"

        assert self.locate(put) is None

    @pytest.mark.parametrize(
        ("name", "version"),
        [("", "1"), ("A", "1"), ("a/b", "1"), ("a", "../x"), ("a", ""), ("a b", "1")],
    )
    def test_a_name_or_version_that_is_not_one_asks_for_nothing(
        self, name: str, version: str
    ) -> None:
        assert ArchiveSources.of("bazel").documents(name, version) == ()  # type: ignore[union-attr]


class TestOpamArchive:
    def locate(self, document: str | None = None) -> Located | None:
        source = ArchiveSources.of("opam")
        assert source is not None
        (wanted,) = source.documents("dune", "3.5.0")
        return source.locate(
            "dune",
            "3.5.0",
            {wanted.url: document if document is not None else Fixtures.text("opam_dune.3.5.0")},
        )

    def test_the_source_and_every_checksum_the_file_states(self) -> None:
        found = self.locate()
        assert (
            found is not None
            and found.url == "https://github.com/ocaml/dune/releases/download/3.5.0/dune-3.5.0.tbz"
        )
        assert dict(found.digests) == {
            "sha256": "77bd4c6704359fae1969636cfc3cd7a517ba3604819ef89c919c0762b5093610",
            "sha512": "acaed76ab8618977118579641a1f6734ed4a225ab46494c6c5fd8e1bf9a0889e62db9adc7bd11770da602f4dd4785cef5ece4ad26512d08b64b8f3bd8954c80d",
        }
        assert found.strength == "sha512"

    def test_a_git_source_has_no_archive(self) -> None:
        assert (
            self.locate(
                Fixtures.text("opam_dune.3.5.0").replace(
                    "https://github.com/ocaml/dune/releases/download/3.5.0/dune-3.5.0.tbz",
                    "git+https://github.com/ocaml/dune.git",
                )
            )
            is None
        )

    def test_a_url_block_with_no_checksum_is_no_archive(self) -> None:
        stripped = "\n".join(
            line for line in Fixtures.text("opam_dune.3.5.0").splitlines() if "sha" not in line
        )
        assert self.locate(stripped) is None

    def test_a_file_with_no_url_block_is_no_archive(self) -> None:
        assert self.locate('opam-version: "2.0"\n') is None

    def test_a_checksum_that_is_the_wrong_width_is_ignored(self) -> None:
        broken = Fixtures.text("opam_dune.3.5.0").replace("sha256=77bd", "sha256=77b")
        found = self.locate(broken)
        assert found is not None and set(dict(found.digests)) == {"sha512"}

    @pytest.mark.parametrize(
        ("name", "version"), [("", "1"), ("a/b", "1"), ("a", ""), ("a", "../1"), ("a b", "1")]
    )
    def test_a_name_or_version_that_is_not_one_asks_for_nothing(
        self, name: str, version: str
    ) -> None:
        assert ArchiveSources.of("opam").documents(name, version) == ()  # type: ignore[union-attr]


class TestConanArchive:
    def bound(self, edit: Any = None) -> dict[str, Any]:
        source = ArchiveSources.of("conan")
        assert source is not None
        (config,) = source.documents("zlib", "1.4")
        found = {config.url: Fixtures.text("conan_config.yml")}
        (more,) = source.followed("zlib", "1.4", found)
        found[more.url] = Fixtures.text("conan_conandata.yml")
        if edit:
            edit(found)
        return found

    def test_the_config_names_the_folder_and_the_conandata_the_source(self) -> None:
        source = ArchiveSources.of("conan")
        assert source is not None
        documents = self.bound()
        assert [u.rsplit("/", 2)[-2:] for u in documents] == [
            ["zlib", "config.yml"],
            ["all", "conandata.yml"],
        ]
        found = source.locate("zlib", "1.4", documents)
        assert found is not None
        assert found.url == "https://zlib.net/fossils/zlib-1.4.tar.gz"
        assert found.digests == (
            ("sha256", "02dd159783677a749c04adbdd02b55b8a2bcc7e054f51b76b549199a916ad584"),
        )

    def test_a_version_the_recipe_does_not_list_asks_for_no_conandata(self) -> None:
        source = ArchiveSources.of("conan")
        assert source is not None
        (config,) = source.documents("zlib", "9.9")
        assert source.followed("zlib", "9.9", {config.url: Fixtures.text("conan_config.yml")}) == ()

    def test_a_folder_that_is_not_a_plain_folder_name_is_not_followed(self) -> None:
        source = ArchiveSources.of("conan")
        assert source is not None
        (config,) = source.documents("zlib", "1.4")
        bad = Fixtures.text("conan_config.yml").replace("all", "../x")
        assert source.followed("zlib", "1.4", {config.url: bad}) == ()

    def test_a_source_with_no_sha256_is_no_archive(self) -> None:
        source = ArchiveSources.of("conan")
        assert source is not None

        def strip(found: dict[str, Any]) -> None:
            key = next(u for u in found if u.endswith("conandata.yml"))
            found[key] = "\n".join(line for line in found[key].splitlines() if "sha256" not in line)

        assert source.locate("zlib", "1.4", self.bound(strip)) is None

    def test_a_url_that_is_not_https_is_not_taken(self) -> None:
        source = ArchiveSources.of("conan")
        assert source is not None

        def http(found: dict[str, Any]) -> None:
            key = next(u for u in found if u.endswith("conandata.yml"))
            found[key] = found[key].replace("https://", "http://")

        assert source.locate("zlib", "1.4", self.bound(http)) is None

    @pytest.mark.parametrize("name", ["", "../x", "a/b", "A", "a b"])
    def test_a_name_that_is_not_a_recipe_asks_for_nothing(self, name: str) -> None:
        assert ArchiveSources.of("conan").documents(name, "1.0") == ()  # type: ignore[union-attr]


class TestCranArchive:
    def locate(self, latest: str = "2.6.1") -> Located | None:
        source = ArchiveSources.of("cran")
        assert source is not None
        first, second = source.documents("R6", "2.5.1")
        return source.locate(
            "R6",
            "2.5.1",
            {
                first.url: Fixtures.load("cran_version.json"),
                second.url: Fixtures.load("cran_latest.json") | {"Version": latest},
            },
        )

    def test_an_older_release_is_under_the_archive_with_the_md5_cran_publishes(self) -> None:
        found = self.locate()
        assert found is not None
        assert found.url == "https://cran.r-project.org/src/contrib/Archive/R6/R6_2.5.1.tar.gz"
        assert (
            found.digests == (("md5", "e84fd376e246738402e5529b6d52e101"),)
            and found.strength == "md5"
        )

    def test_the_current_release_is_under_src_contrib(self) -> None:
        found = self.locate("2.5.1")
        assert (
            found is not None
            and found.url == "https://cran.r-project.org/src/contrib/R6_2.5.1.tar.gz"
        )

    def test_a_document_for_another_version_is_not_this_archive(self) -> None:
        source = ArchiveSources.of("cran")
        assert source is not None
        first, _ = source.documents("R6", "2.5.0")
        assert source.locate("R6", "2.5.0", {first.url: Fixtures.load("cran_version.json")}) is None

    def test_a_release_with_no_md5_has_no_archive(self) -> None:
        source = ArchiveSources.of("cran")
        assert source is not None
        first, _ = source.documents("R6", "2.5.1")
        document = Fixtures.load("cran_version.json")
        del document["MD5sum"]
        assert source.locate("R6", "2.5.1", {first.url: document}) is None

    @pytest.mark.parametrize("name", ["", "1abc", "a/b", "a..b", "a b"])
    def test_a_name_that_is_not_a_package_asks_for_nothing(self, name: str) -> None:
        assert ArchiveSources.of("cran").documents(name, "1.0") == ()  # type: ignore[union-attr]


class TestPublicHosts:
    def test_an_address_or_a_local_name_is_never_public(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.hosts import PublicHost

        for host in (
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.5",
            "[::1]",
            "localhost",
            "intranet",
            "printer.local",
            "db.internal",
            "x.localhost",
            "",
            "-a.example.com",
            "a..b.com",
        ):
            assert not PublicHost.named(host), host

    def test_a_dotted_public_looking_name_passes_the_name_check(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.hosts import PublicHost

        for host in (
            "github.com",
            "objects.githubusercontent.com",
            "a-b.example.org",
            "GITHUB.COM",
        ):
            assert PublicHost.named(host), host


class TestThePinnedConnection:
    """One lookup, one connection: the addresses checked are the ones connected to, so a name that answers differently the second
    time cannot turn the download on the network the scan runs in."""

    class Resolver:
        def __init__(self, *answers: list[str]) -> None:
            self.answers, self.asked = list(answers), 0

        def __call__(self, host: str, port: int) -> list[tuple[int, str]]:
            self.asked += 1
            return [(2, a) for a in self.answers[min(self.asked, len(self.answers)) - 1]]

    @staticmethod
    def connection(monkeypatch: pytest.MonkeyPatch, resolver: Any, *, public_only: bool) -> Any:
        import socket

        from cordon_scanner.foundation.network.pinned import Pinned, PinnedConnection

        connected: list[Any] = []

        class Socket:
            def __init__(self, *_a: Any) -> None:
                pass

            def settimeout(self, _t: Any) -> None:
                pass

            def connect(self, target: Any) -> None:
                connected.append(target)

        class Context:
            def wrap_socket(self, sock: Any, server_hostname: str) -> Any:
                connected.append(("tls", server_hostname))
                return sock

        monkeypatch.setattr(Pinned, "addresses", staticmethod(resolver))
        monkeypatch.setattr(socket, "socket", Socket)
        connection = PinnedConnection("example.com", 443)
        connection.public_only = public_only
        connection._context = Context()  # type: ignore[assignment]
        return connection, connected

    def test_the_name_is_resolved_once_and_the_connection_goes_to_the_checked_address(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        resolver = self.Resolver(["140.82.112.3"], ["169.254.169.254"])
        connection, connected = self.connection(monkeypatch, resolver, public_only=True)
        connection.connect()
        assert resolver.asked == 1
        assert connected == [("140.82.112.3", 443), ("tls", "example.com")]

    @pytest.mark.parametrize(
        "private", ["169.254.169.254", "10.1.2.3", "127.0.0.1", "192.168.0.9", "::1", "fd00::1"]
    )
    def test_a_name_that_resolves_to_a_private_address_is_refused_before_any_connection(
        self, monkeypatch: pytest.MonkeyPatch, private: str
    ) -> None:
        connection, connected = self.connection(
            monkeypatch, self.Resolver([private]), public_only=True
        )
        with pytest.raises(OSError, match="not a public one"):
            connection.connect()
        assert connected == []

    def test_one_private_address_among_public_ones_refuses_the_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        connection, connected = self.connection(
            monkeypatch, self.Resolver(["140.82.112.3", "10.0.0.5"]), public_only=True
        )
        with pytest.raises(OSError, match="not a public one"):
            connection.connect()
        assert connected == []

    def test_a_registry_on_a_list_is_not_held_to_the_public_rule(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        connection, connected = self.connection(
            monkeypatch, self.Resolver(["10.1.2.3"]), public_only=False
        )
        connection.connect()
        assert connected[0] == ("10.1.2.3", 443)

    def test_a_name_with_no_address_is_an_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        connection, _ = self.connection(monkeypatch, self.Resolver([]), public_only=True)
        with pytest.raises(OSError, match="no address"):
            connection.connect()

    def test_the_sources_whose_host_no_list_can_hold_ask_for_the_public_rule(self) -> None:
        pinned = {s.ecosystem for s in ArchiveSources.SOURCES if s.PUBLIC}
        assert {"bazel", "opam", "conan", "vcpkg", "helm", "cocoapods"} <= pinned
        assert not any(
            s.PUBLIC
            for s in ArchiveSources.SOURCES
            if s.ecosystem in ("npm", "pypi", "cargo", "maven")
        )

    def test_the_download_passes_the_public_rule_to_the_connection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[bool] = []
        monkeypatch.setattr(
            RegistryRequest,
            "fetch_bytes",
            staticmethod(
                lambda url, allow, *, redirects=0, public=False: seen.append(public) or b"x"
            ),
        )
        ArchiveFetch.download(
            ArchiveSources.of("bazel"),
            Located("https://example.com/a", "a", (("sha256", "0" * 64),)),
        )  # type: ignore[arg-type]
        ArchiveFetch.download(
            ArchiveSources.of("npm"),
            Located("https://registry.npmjs.org/a", "a", (("sha256", "0" * 64),)),
        )  # type: ignore[arg-type]
        assert seen == [True, False]

    def test_an_image_registry_is_pulled_through_the_pinned_opener(self) -> None:
        from cordon_scanner.foundation.network.pinned import PinnedHTTPS
        from cordon_scanner.intel.registries.registry_image import RegistryImage

        handlers = RegistryImage("ghcr.io", "a/b", public_only=True).opener.handlers
        assert any(isinstance(h, PinnedHTTPS) and h.public_only for h in handlers)


HEX40 = "11bd71901bbe5b1630ceea73d27597364c9af683"


class Archives:
    @staticmethod
    def tarball(
        files: dict[str, bytes | str], *, comment: str = "", executable: tuple[str, ...] = ()
    ) -> bytes:
        """A tar of `files` (a `str` value is a symlink target), with a pax global header naming `comment` as a code host writes it."""
        import io
        import tarfile

        buffer = io.BytesIO()
        headers = {"comment": comment} if comment else None
        with tarfile.open(
            fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT, pax_headers=headers
        ) as archive:
            for name, content in files.items():
                info = tarfile.TarInfo(name)
                if isinstance(content, str):
                    info.type, info.linkname = tarfile.SYMTYPE, content
                    archive.addfile(info)
                else:
                    info.size, info.mode = len(content), 0o755 if name in executable else 0o644
                    archive.addfile(info, io.BytesIO(content))
        return buffer.getvalue()


class TestGitTar:
    #: The tree id git itself gives these files (`git write-tree` after `git add`): a file, a nested file, an executable, a symlink.
    TREE = "6c576e17fab23f51e5291ef48600bcced09d41cd"
    FILES: ClassVar[dict[str, bytes | str]] = {
        "a": b"hello\n",
        "sub/b": b"world\n",
        "run.sh": b"#!/bin/sh\necho hi\n",
        "l": "a",
        "deep/er/c": b"x",
    }

    def test_the_tree_hash_is_the_one_git_computes(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import GitTar

        assert GitTar.tree_sha1(Archives.tarball(self.FILES, executable=("run.sh",))) == self.TREE

    def test_the_order_the_files_are_in_does_not_change_it(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import GitTar

        reversed_files = dict(reversed(list(self.FILES.items())))
        assert (
            GitTar.tree_sha1(Archives.tarball(reversed_files, executable=("run.sh",))) == self.TREE
        )

    def test_a_changed_byte_the_executable_bit_or_a_link_target_changes_it(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import GitTar

        assert GitTar.tree_sha1(Archives.tarball(self.FILES)) != self.TREE
        assert (
            GitTar.tree_sha1(
                Archives.tarball(self.FILES | {"a": b"hellO\n"}, executable=("run.sh",))
            )
            != self.TREE
        )
        assert (
            GitTar.tree_sha1(Archives.tarball(self.FILES | {"l": "sub/b"}, executable=("run.sh",)))
            != self.TREE
        )

    @pytest.mark.parametrize("path", ["../escape", "/abs", "a/../b", "./x/../../y"])
    def test_a_path_that_leaves_the_tree_is_no_tree(self, path: str) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import GitTar

        assert GitTar.tree_sha1(Archives.tarball({path: b"x"})) == ""

    def test_something_that_is_not_a_tar_is_no_tree_and_names_no_commit(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import GitTar

        assert GitTar.tree_sha1(b"not a tar") == "" and GitTar.commit(b"not a tar") == ""

    def test_the_commit_is_the_one_the_pax_header_names(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import GitTar

        assert GitTar.commit(Archives.tarball({"a": b"x"}, comment=HEX40)) == HEX40
        assert GitTar.commit(Archives.tarball({"a": b"x"})) == ""
        assert GitTar.commit(Archives.tarball({"a": b"x"}, comment="not a commit")) == ""

    def test_the_three_git_checks_in_a_digest(self) -> None:
        named = Archives.tarball({"a": b"x"}, comment=HEX40)
        unnamed = Archives.tarball({"a": b"x"})
        assert ArchiveFetch.digest_ok(named, (("git-commit", HEX40),))
        assert not ArchiveFetch.digest_ok(named, (("git-commit", "0" * 40),))
        assert not ArchiveFetch.digest_ok(unnamed, (("git-commit", HEX40),))
        assert ArchiveFetch.digest_ok(named, (("git-tag", ""),)) and not ArchiveFetch.digest_ok(
            unnamed, (("git-tag", ""),)
        )

    def test_the_strength_of_a_tag_is_below_a_commit_below_a_tree(self) -> None:
        def strength(*digests: tuple[str, str]) -> str:
            return Located("https://x.invalid/a", "a", digests).strength

        assert strength(("git-tree-sha1", "a" * 40)) == "git-tree-sha1"
        assert strength(("git-commit", "a" * 40)) == "git-commit"
        assert strength(("git-tag", "")) == "git-tag"
        assert strength(("md5", "0" * 32), ("git-tag", "")) == "md5"


class TestActionsSwiftNix:
    @pytest.mark.parametrize("ecosystem", ["actions", "swift"])
    def test_a_tag_is_the_hosts_tarball_of_it_and_the_other_spelling_is_the_fallback(
        self, ecosystem: str
    ) -> None:
        source = ArchiveSources.of(ecosystem)
        assert source is not None and source.documents("actions/checkout", "v4.2.2") == ()
        found = source.locate("actions/checkout", "v4.2.2", {})
        assert found is not None
        assert found.url == "https://codeload.github.com/actions/checkout/tar.gz/refs/tags/v4.2.2"
        assert found.fallbacks == (
            "https://codeload.github.com/actions/checkout/tar.gz/refs/tags/4.2.2",
        )
        assert found.digests == (("git-tag", ""),)

    def test_a_commit_pin_is_checked_against_that_commit(self) -> None:
        found = ArchiveSources.of("actions").locate("actions/checkout", HEX40, {})  # type: ignore[union-attr]
        assert (
            found is not None
            and found.url.endswith(f"/tar.gz/{HEX40}")
            and found.digests == (("git-commit", HEX40),)
        )

    def test_an_action_in_a_folder_is_its_repositorys(self) -> None:
        found = ArchiveSources.of("actions").locate("github/codeql-action/analyze", "v3", {})  # type: ignore[union-attr]
        assert found is not None and "/github/codeql-action/" in found.url

    def test_a_nix_input_is_owner_slash_repo_only(self) -> None:
        source = ArchiveSources.of("nix")
        assert source is not None
        assert source.locate("NixOS/nixpkgs", HEX40, {}) is not None
        assert source.locate("NixOS/nixpkgs/extra", HEX40, {}) is None

    @pytest.mark.parametrize(
        ("name", "version"),
        [
            ("", "v1"),
            ("a", "v1"),
            ("a/b", ""),
            ("../b", "v1"),
            ("a/..", "v1"),
            ("a/b", "../x"),
            ("a/b", "-x"),
            ("a/b", "x y"),
            ("a b/c", "v1"),
        ],
    )
    def test_a_name_or_ref_that_is_not_one_has_no_archive(self, name: str, version: str) -> None:
        assert ArchiveSources.of("actions").locate(name, version, {}) is None  # type: ignore[union-attr]


class TestComposerArchive:
    def locate(self, edit: Any = None) -> Located | None:
        source = ArchiveSources.of("composer")
        assert source is not None
        (document,) = source.documents("psr/log", "3.0.2")
        content = json.loads(
            (ROOT / "tests/unit/intel/registries/records/composer.json").read_text(encoding="utf-8")
        )
        if edit:
            edit(content)
        return source.locate("psr/log", "3.0.2", {document.url: content})

    def test_the_commit_the_registry_names_is_the_commit_the_tarball_must_be_of(self) -> None:
        found = self.locate()
        assert found is not None
        assert (
            found.url
            == "https://codeload.github.com/php-fig/log/tar.gz/f16e1d5863e37f8d8c2a01719f5b34baa2b714d3"
        )
        assert found.digests == (("git-commit", "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3"),)

    def test_a_source_that_is_not_on_github_has_no_archive(self) -> None:
        def move(content: dict[str, Any]) -> None:
            content["packages"]["psr/log"][0]["source"] = {
                "type": "git",
                "url": "https://git.example.invalid/x.git",
                "reference": HEX40,
            }

        assert self.locate(move) is None

    def test_a_reference_that_is_not_a_commit_has_no_archive(self) -> None:
        def branch(content: dict[str, Any]) -> None:
            content["packages"]["psr/log"][0]["source"]["reference"] = "main"

        assert self.locate(branch) is None


class TestCocoapodsArchive:
    def locate(self, edit: Any = None) -> Located | None:
        source = ArchiveSources.of("cocoapods")
        assert source is not None
        (document,) = source.documents("Alamofire", "5.9.1")
        content = Fixtures.load("cocoapods_spec.json")
        if edit:
            edit(content)
        return source.locate("Alamofire", "5.9.1", {document.url: content})

    def test_a_git_source_at_a_tag(self) -> None:
        found = self.locate()
        assert found is not None
        assert (
            found.url == "https://codeload.github.com/Alamofire/Alamofire/tar.gz/refs/tags/5.9.1"
            and found.digests == (("git-tag", ""),)
        )

    def test_a_commit_the_podspec_names_is_checked(self) -> None:
        def pinned(content: dict[str, Any]) -> None:
            content["source"] = {
                "git": "https://github.com/Alamofire/Alamofire.git",
                "commit": HEX40,
            }

        found = self.locate(pinned)
        assert found is not None and found.digests == (("git-commit", HEX40),)

    def test_an_archive_source_needs_the_digest_the_podspec_states(self) -> None:
        def archive(content: dict[str, Any]) -> None:
            content["source"] = {
                "http": "https://example.com/files/x-5.9.1.zip",
                "sha256": "ab" * 32,
            }

        found = self.locate(archive)
        assert (
            found is not None
            and found.digests == (("sha256", "ab" * 32),)
            and found.filename == "x-5.9.1.zip"
        )

        def undigested(content: dict[str, Any]) -> None:
            content["source"] = {"http": "https://example.com/files/x-5.9.1.zip"}

        assert self.locate(undigested) is None

    def test_a_git_source_on_another_host_has_no_archive(self) -> None:
        def elsewhere(content: dict[str, Any]) -> None:
            content["source"] = {"git": "https://git.example.invalid/x.git", "tag": "5.9.1"}

        assert self.locate(elsewhere) is None

    def test_another_version_than_the_one_asked_is_not_its_archive(self) -> None:
        def other(content: dict[str, Any]) -> None:
            content["version"] = "5.9.2"

        assert self.locate(other) is None

    @pytest.mark.parametrize("name", ["", "../x", "a/b", "a b", "a?b"])
    def test_a_name_that_is_not_a_pod_asks_for_nothing(self, name: str) -> None:
        assert ArchiveSources.of("cocoapods").documents(name, "1.0") == ()  # type: ignore[union-attr]


class TestTerraformArchive:
    def locate(self, name: str, version: str, document: dict[str, Any]) -> Located | None:
        source = ArchiveSources.of("terraform")
        assert source is not None
        (wanted,) = source.documents(name, version)
        return source.locate(name, version, {wanted.url: document})

    def test_a_provider_is_the_zip_on_hashicorps_host_with_the_sha256_the_registry_states(
        self,
    ) -> None:
        found = self.locate(
            "hashicorp/random", "3.6.0", Fixtures.load("terraform_provider_download.json")
        )
        assert found is not None
        assert (
            found.url
            == "https://releases.hashicorp.com/terraform-provider-random/3.6.0/terraform-provider-random_3.6.0_linux_amd64.zip"
        )
        assert found.digests == (
            ("sha256", "aa57384b85622a9f7bfb5d4512ca88e61f22a9cea9f30febaa4c98c68ff0dc21"),
        )

    def test_a_download_address_on_another_host_is_refused(self) -> None:
        document = Fixtures.load("terraform_provider_download.json") | {
            "download_url": "https://evil.example.invalid/a.zip"
        }
        assert self.locate("hashicorp/random", "3.6.0", document) is None

    def test_a_module_is_the_tag_of_the_repository_the_registry_names(self) -> None:
        found = self.locate(
            "terraform-aws-modules/vpc/aws", "5.8.1", Fixtures.load("terraform_module.json")
        )
        assert found is not None
        assert (
            found.url
            == "https://codeload.github.com/terraform-aws-modules/terraform-aws-vpc/tar.gz/refs/tags/v5.8.1"
        )
        assert found.digests == (("git-tag", ""),)

    def test_the_two_forms_ask_for_their_own_documents(self) -> None:
        source = ArchiveSources.of("terraform")
        assert source is not None
        assert source.documents("hashicorp/random", "3.6.0")[0].url.endswith(
            "/providers/hashicorp/random/3.6.0/download/linux/amd64"
        )
        assert source.documents("a/b/c", "1.0.0")[0].url.endswith("/modules/a/b/c/1.0.0")

    @pytest.mark.parametrize("name", ["", "a", "a/b/c/d", "../b", "a/ b"])
    def test_a_name_that_is_not_a_provider_or_module_asks_for_nothing(self, name: str) -> None:
        assert ArchiveSources.of("terraform").documents(name, "1.0.0") == ()  # type: ignore[union-attr]


class TestJuliaArchive:
    def locate(self, version: str = "0.7.0", versions: str | None = None) -> Located | None:
        source = ArchiveSources.of("julia")
        assert source is not None
        package, listing = source.documents("ZipFile", version)
        return source.locate(
            "ZipFile",
            version,
            {
                package.url: Fixtures.text("julia_package.toml"),
                listing.url: versions
                if versions is not None
                else Fixtures.text("julia_versions.toml"),
            },
        )

    def test_the_package_server_serves_the_tree_the_registry_names(self) -> None:
        found = self.locate()
        assert found is not None
        assert (
            found.url
            == "https://pkg.julialang.org/package/a5390f91-8eb1-5f08-bee0-b1d1ffed6cea/c191e56c849b1784cacbf7cd5e52cc672f1ae2db"
        )
        assert found.digests == (("git-tree-sha1", "c191e56c849b1784cacbf7cd5e52cc672f1ae2db"),)

    def test_a_version_the_registry_does_not_list_has_no_archive(self) -> None:
        assert self.locate("9.9.9") is None

    def test_the_regional_servers_the_package_server_redirects_to_are_allowed_and_no_other_host(
        self,
    ) -> None:
        source = ArchiveSources.of("julia")
        assert source is not None
        assert source.allows("pkg.julialang.org") and source.allows("eu-central.pkg.julialang.org")
        assert not source.allows("evilpkg.julialang.org.example.com") and not source.allows(
            "julialang.org"
        )

    def test_a_tree_that_is_not_a_hash_is_no_archive(self) -> None:
        assert self.locate(versions='["0.7.0"]\ngit-tree-sha1 = "nothex"\n') is None

    @pytest.mark.parametrize("name", ["", "1Abc", "a/b", "a-b", "a b"])
    def test_a_name_that_is_not_a_package_asks_for_nothing(self, name: str) -> None:
        assert ArchiveSources.of("julia").documents(name, "1.0.0") == ()  # type: ignore[union-attr]


class TestHelmArchive:
    NAME = "cert-manager/cert-manager"

    def locate(self, edit: Any = None) -> Located | None:
        source = ArchiveSources.of("helm")
        assert source is not None
        (document,) = source.documents(self.NAME, "1.19.0")
        content = Fixtures.load("helm_version.json")
        if edit:
            edit(content)
        return source.locate(self.NAME, "1.19.0", {document.url: content})

    def test_the_chart_archive_and_the_sha256_of_the_index(self) -> None:
        found = self.locate()
        assert found is not None
        assert found.url == "https://charts.jetstack.io/charts/cert-manager-v1.19.0.tgz"
        assert found.filename == "cert-manager-v1.19.0.tgz"
        assert found.digests == (
            ("sha256", "b581634069151fce8073d0e08d454e712daf7f9bfb9df00b35d5fdcba01936b8"),
        )

    def test_the_document_asked_for_is_the_charts_version(self) -> None:
        source = ArchiveSources.of("helm")
        assert source is not None
        assert source.documents(self.NAME, "1.19.0")[0].url.endswith(
            "/packages/helm/cert-manager/cert-manager/1.19.0"
        )

    def test_a_chart_with_no_digest_or_an_oci_address_has_no_archive(self) -> None:
        def stripped(content: dict[str, Any]) -> None:
            del content["digest"]

        def oci(content: dict[str, Any]) -> None:
            content["content_url"] = "oci://registry.example.invalid/charts/x"

        assert self.locate(stripped) is None and self.locate(oci) is None

    def test_the_chart_repository_host_must_be_a_public_name_and_is_connected_pinned(self) -> None:
        source = ArchiveSources.of("helm")
        assert source is not None and source.PUBLIC
        assert (
            source.allows("charts.jetstack.io")
            and not source.allows("10.0.0.7")
            and not source.allows("charts.corp")
        )

    @pytest.mark.parametrize("name", ["", "a/b/c", "../x", "A/B", "a b"])
    def test_a_name_that_is_not_a_chart_asks_for_nothing(self, name: str) -> None:
        assert ArchiveSources.of("helm").documents(name, "1.0.0") == ()  # type: ignore[union-attr]


class TestTheFallbacks:
    def test_a_404_moves_to_the_next_address_and_any_other_failure_stops(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source = ArchiveSources.of("actions")
        assert source is not None
        located = Located(
            "https://codeload.github.com/a/b/tar.gz/refs/tags/v1",
            "b-v1.tar.gz",
            (("git-tag", ""),),
            ("https://codeload.github.com/a/b/tar.gz/refs/tags/1",),
        )
        asked: list[str] = []

        def fetch(url: str, allow: Any, **_k: Any) -> bytes:
            asked.append(url)
            if url.endswith("/v1"):
                raise RegistryError("HTTP 404 from codeload.github.com")
            return b"bytes"

        monkeypatch.setattr(RegistryRequest, "fetch_bytes", staticmethod(fetch))
        assert ArchiveFetch.download(source, located) == b"bytes" and len(asked) == 2

        def refuse(url: str, allow: Any, **_k: Any) -> bytes:
            raise RegistryError("HTTP 500 from codeload.github.com")

        monkeypatch.setattr(RegistryRequest, "fetch_bytes", staticmethod(refuse))
        with pytest.raises(RegistryError, match="HTTP 500"):
            ArchiveFetch.download(source, located)


class FakeRegistry:
    """An OCI registry answering as the real ones do: an index of manifests, each naming one layer, every blob under its sha256."""

    def __init__(self) -> None:
        self.layer = b"bottle bytes"
        self.layer_digest = "sha256:" + hashlib.sha256(self.layer).hexdigest()
        self.child = json.dumps(
            {"schemaVersion": 2, "layers": [{"digest": self.layer_digest, "size": len(self.layer)}]}
        ).encode()
        self.child_digest = "sha256:" + hashlib.sha256(self.child).hexdigest()
        self.index = json.dumps(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "digest": "sha256:" + "0" * 64,
                        "annotations": {"org.opencontainers.image.ref.name": "1.8.1.sequoia"},
                    },
                    {
                        "digest": self.child_digest,
                        "annotations": {"org.opencontainers.image.ref.name": "1.8.1.arm64_sonoma"},
                    },
                ],
            }
        ).encode()
        self.asked: list[tuple[str, str]] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        registry = self

        class Image:
            def __init__(
                self, host: str | None, repository: str, *, public_only: bool = False
            ) -> None:
                registry.asked.append((host or "hub", repository))

            def manifest(self, reference: str) -> tuple[bytes, str]:
                return (
                    (registry.index, "")
                    if not reference.startswith("sha256:")
                    else (registry.child, "")
                )

            def blob(self, digest: str, pull: Any) -> bytes:
                assert digest == registry.layer_digest
                return registry.layer

            def pull(self, reference: str) -> tuple[bytes, Any]:
                registry.asked.append(("pull", reference))
                return b"layout", None

        monkeypatch.setattr(
            "cordon_scanner.intel.registries.archive_sources.oci.RegistryImage", Image
        )


class TestHomebrewArchive:
    def test_the_bottle_is_the_layer_of_the_first_platform_the_version_has(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = FakeRegistry()
        registry.install(monkeypatch)
        archive = ArchiveSources.of("homebrew").fetch("jq", "1.8.1")  # type: ignore[union-attr]
        assert archive is not None and archive.data == registry.layer
        assert archive.strength == "oci-tag" and archive.filename == "jq-1.8.1.bottle.tar.gz"
        assert registry.asked[0] == ("ghcr.io", "homebrew/core/jq")

    def test_a_versioned_formula_is_the_repository_with_a_slash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = FakeRegistry()
        registry.install(monkeypatch)
        ArchiveSources.of("homebrew").fetch("openssl@3", "3.5.0")  # type: ignore[union-attr]
        assert registry.asked[0] == ("ghcr.io", "homebrew/core/openssl/3")

    def test_a_version_with_no_platform_we_know_has_no_bottle(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = FakeRegistry()
        registry.index = json.dumps(
            {
                "manifests": [
                    {
                        "digest": "sha256:" + "0" * 64,
                        "annotations": {"org.opencontainers.image.ref.name": "1.0.bsd"},
                    }
                ]
            }
        ).encode()
        registry.install(monkeypatch)
        assert ArchiveSources.of("homebrew").fetch("jq", "1.0") is None  # type: ignore[union-attr]

    def test_bytes_that_are_not_the_layers_digest_are_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = FakeRegistry()
        registry.install(monkeypatch)
        registry.layer_digest = "sha256:" + hashlib.sha256(b"something else").hexdigest()
        registry.child = json.dumps({"layers": [{"digest": registry.layer_digest}]}).encode()
        registry.child_digest = "sha256:" + hashlib.sha256(registry.child).hexdigest()
        registry.index = json.dumps(
            {
                "manifests": [
                    {
                        "digest": registry.child_digest,
                        "annotations": {"org.opencontainers.image.ref.name": "1.0.arm64_sonoma"},
                    }
                ]
            }
        ).encode()

        def lie(self: Any, digest: str, pull: Any) -> bytes:
            return b"not what the digest names"

        monkeypatch.setattr(
            "cordon_scanner.intel.registries.archive_sources.oci.RegistryImage.blob",
            lie,
            raising=False,
        )
        with pytest.raises(RegistryError, match="do not match its digest"):
            ArchiveSources.of("homebrew").fetch("jq", "1.0")  # type: ignore[union-attr]

    @pytest.mark.parametrize(
        ("name", "version"),
        [
            ("", "1"),
            ("../x", "1"),
            ("A", "1"),
            ("jq", ""),
            ("jq", "sha256:" + "a" * 64),
            ("jq", "-x"),
            ("a/b", "1"),
        ],
    )
    def test_a_name_or_version_that_is_not_one_has_no_bottle(self, name: str, version: str) -> None:
        assert ArchiveSources.of("homebrew").fetch(name, version) is None  # type: ignore[union-attr]


class TestImageArchive:
    def test_a_tag_is_pulled_as_an_oci_layout_and_reported_as_checked_by_the_tag_only(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = FakeRegistry()
        registry.install(monkeypatch)
        archive = ArchiveSources.of("image").fetch("nginx", "1.27")  # type: ignore[union-attr]
        assert archive is not None and archive.data == b"layout" and archive.strength == "oci-tag"
        assert registry.asked[0] == ("hub", "library/nginx") and ("pull", "1.27") in registry.asked

    def test_a_digest_is_checked_by_the_registry_reader_and_carries_no_weak_mark(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = FakeRegistry()
        registry.install(monkeypatch)
        reference = "sha256:" + "a" * 64
        archive = ArchiveSources.of("image").fetch("bitnami/nginx", reference)  # type: ignore[union-attr]
        assert (
            archive is not None and archive.strength == "" and ("pull", reference) in registry.asked
        )

    def test_another_registry_is_used_only_when_its_name_could_be_public(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = FakeRegistry()
        registry.install(monkeypatch)
        assert ArchiveSources.of("image").fetch("ghcr.io/org/app", "1.0") is not None  # type: ignore[union-attr]
        assert ArchiveSources.of("image").fetch("registry.corp/org/app", "1.0") is None  # type: ignore[union-attr]
        assert ArchiveSources.of("image").fetch("10.0.0.7/org/app", "1.0") is None  # type: ignore[union-attr]

    @pytest.mark.parametrize(
        "name", ["", "localhost:5000/x", "127.0.0.1/x", "a//b", "A B", "../x", "a/" * 7 + "b"]
    )
    def test_a_name_that_is_not_a_public_image_has_no_archive(self, name: str) -> None:
        assert ArchiveSources.of("image").fetch(name, "1.0") is None  # type: ignore[union-attr]

    def test_the_hub_spellings_name_the_same_repository(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.intel.registries.archive_sources.oci import ImageRef

        assert (
            ImageRef.of("docker.io/library/nginx")
            == ImageRef.of("nginx")
            == (None, "library/nginx")
        )
        assert ImageRef.of("docker.io/bitnami/nginx") == (None, "bitnami/nginx")


class TestThePulledHook:
    def test_a_source_that_pulls_is_not_asked_for_documents(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        FakeRegistry().install(monkeypatch)
        monkeypatch.setattr(
            "cordon_scanner.intel.registries.archive_sources.base.RecordFetch.documents",
            staticmethod(lambda *_a, **_k: pytest.fail("asked for documents")),
        )
        source = ArchiveSources.of("image")
        assert source is not None
        assert ArchiveFetch.archive(source, "nginx", "1.27").data == b"layout"


class TestReleaseHistory:
    """Row 8: when each release was published, for every ecosystem, from the history the registry record is read from."""

    def test_every_ecosystem_with_a_record_source_has_a_history_and_extensions_are_read_apart(
        self,
    ) -> None:
        from cordon_scanner.intel.registries.record_sources.table import RecordSources
        from cordon_scanner.intel.registries.release_history import ReleaseHistory

        assert (
            RecordSources.ids() <= ReleaseHistory.covered() and "vscode" in ReleaseHistory.covered()
        )

    def test_extensions_have_one_id_and_the_old_spelling_is_its_alias(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from datetime import datetime

        from cordon_scanner.intel.registries.openvsx import OpenVsx
        from cordon_scanner.intel.registries.release_history import ReleaseHistory

        asked: list[tuple[str, str]] = []
        when = datetime(2025, 1, 1)
        monkeypatch.setattr(
            OpenVsx,
            "timeline",
            classmethod(lambda cls, n, v: asked.append((n, v)) or {"1.0.0": when}),
        )
        assert ReleaseHistory.timeline("vscode", "Acme.tool", "1.0.0") == {"1.0.0": when}
        assert ReleaseHistory.timeline("openvsx", "Acme.tool", "1.0.0") == {"1.0.0": when}
        assert asked == [("Acme.tool", "1.0.0")] * 2

    def test_a_recorded_ecosystems_times_are_the_records_releases_with_a_zone(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.intel.registries.release_history import ReleaseHistory

        source = ArchiveSources.of("conda")
        assert source is not None
        document = json.loads(
            (ROOT / "tests/unit/intel/registries/records/conda.json").read_text(encoding="utf-8")
        )
        (wanted,) = source.documents("zlib", "1.3.2")
        monkeypatch.setattr(
            "cordon_scanner.intel.registries.record_sources.base.RecordFetch.documents",
            staticmethod(lambda *_a, **_k: {wanted.url: document}),
        )
        timeline = ReleaseHistory.timeline("conda", "zlib", "1.3.2")
        assert {"1.2.8", "1.3.1", "1.3.2"} <= set(timeline) and all(
            t.tzinfo is not None for t in timeline.values()
        )
        assert timeline["1.2.8"] < timeline["1.3.2"]

    def test_a_registry_that_cannot_be_read_gives_no_history_not_an_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.intel.registries.release_history import ReleaseHistory

        def refuse(*_a: Any, **_k: Any) -> Any:
            raise RegistryError("HTTP 500")

        monkeypatch.setattr(
            "cordon_scanner.intel.registries.record_sources.base.RecordFetch.documents",
            staticmethod(refuse),
        )
        assert ReleaseHistory.timeline("conda", "zlib", "1.3.2") == {}

    def test_an_ecosystem_with_no_source_at_all_gives_no_history(self) -> None:
        from cordon_scanner.intel.registries.release_history import ReleaseHistory

        assert ReleaseHistory.timeline("nonesuch", "x", "1") == {}


class TestVcpkgArchive:
    NAME = "zlib"

    def bound(self, edit: Any = None) -> dict[str, Any]:
        source = ArchiveSources.of("vcpkg")
        assert source is not None
        (listing,) = source.documents(self.NAME, "1.4")
        found: dict[str, Any] = {listing.url: Fixtures.load("vcpkg_versions.json")}
        (tree,) = source.followed(self.NAME, "1.4", found)
        found[tree.url] = Fixtures.load("vcpkg_tree.json")
        for blob in source.followed(self.NAME, "1.4", found):
            found[blob.url] = Fixtures.load(
                "vcpkg_blob_portfile.json"
                if blob.url.endswith("70441b06a856824248bc5a81a9cc6adc57636a36")
                else "vcpkg_blob_manifest.json"
            )
        if edit:
            edit(found)
        return found

    def test_the_versions_file_names_the_tree_then_the_tree_the_two_blobs(self) -> None:
        found = self.bound()
        assert [u.rsplit("/", 2)[-2] for u in found][1:] == ["trees", "blobs", "blobs"]
        assert next(iter(found)).endswith("/versions/z-/zlib.json")

    def test_the_port_that_downloads_its_source_gives_the_archive_and_its_sha512(self) -> None:
        source = ArchiveSources.of("vcpkg")
        assert source is not None
        found = source.locate(self.NAME, "1.4", self.bound())
        assert found is not None
        assert found.url == "https://github.com/madler/zlib/archive/v1.4.tar.gz"
        stated = re.search(
            r"SHA512 ([0-9a-f]{128})",
            base64.b64decode(Fixtures.load("vcpkg_blob_portfile.json")["content"]).decode(),
        ).group(1)  # type: ignore[union-attr]
        assert found.digests == (("sha512", stated),)

    def test_a_blob_that_is_not_the_one_the_tree_names_is_not_read(self) -> None:
        source = ArchiveSources.of("vcpkg")
        assert source is not None

        def tamper(found: dict[str, Any]) -> None:
            key = next(u for u in found if u.endswith("70441b06a856824248bc5a81a9cc6adc57636a36"))
            content = base64.b64decode(found[key]["content"]).replace(b"madler/zlib", b"evil/zlib")
            found[key] = found[key] | {"content": base64.b64encode(content).decode()}

        assert source.locate(self.NAME, "1.4", self.bound(tamper)) is None

    def test_a_version_the_registry_does_not_list_has_no_tree(self) -> None:
        source = ArchiveSources.of("vcpkg")
        assert source is not None
        (listing,) = source.documents(self.NAME, "9.9")
        assert (
            source.followed(self.NAME, "9.9", {listing.url: Fixtures.load("vcpkg_versions.json")})
            == ()
        )

    def test_a_port_revision_is_the_version_after_a_hash(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.vcpkg import VcpkgArchive

        listing = Fixtures.load("vcpkg_versions.json")
        assert VcpkgArchive.tree("1.4", listing) == VcpkgArchive.tree("1.4#0", listing) != ""
        assert VcpkgArchive.tree("1.3.2#3", listing) not in ("", VcpkgArchive.tree("1.4", listing))

    def test_a_variable_the_port_leaves_unresolved_has_no_archive(self) -> None:
        source = ArchiveSources.of("vcpkg")
        assert source is not None

        def unresolved(found: dict[str, Any]) -> None:
            key = next(u for u in found if u.endswith("70441b06a856824248bc5a81a9cc6adc57636a36"))
            found[key] = found[key] | {
                "content": base64.b64encode(
                    b"vcpkg_from_github(REPO a/b REF ${SOMETHING} SHA512 " + b"ab" * 64 + b")"
                ).decode()
            }
            blob = hashlib.sha1(
                b"blob %d\0" % len(base64.b64decode(found[key]["content"]))
                + base64.b64decode(found[key]["content"]),
                usedforsecurity=False,
            ).hexdigest()
            del found[key]
            found[key.rsplit("/", 1)[0] + "/" + blob] = {
                "encoding": "base64",
                "content": base64.b64encode(b"x").decode(),
            }

        assert source.locate(self.NAME, "1.4", self.bound(unresolved)) is None

    @pytest.mark.parametrize("name", ["", "Zlib", "a/b", "../x", "a b"])
    def test_a_name_that_is_not_a_port_asks_for_nothing(self, name: str) -> None:
        assert ArchiveSources.of("vcpkg").documents(name, "1.0") == ()  # type: ignore[union-attr]


class TestNativeArchives:
    """The registries that publish their own archive and digest, read from their real documents."""

    @staticmethod
    def locate(ecosystem: str, name: str, version: str, *documents: Any) -> Located | None:
        source = ArchiveSources.of(ecosystem)
        assert source is not None
        wanted = source.documents(name, version)
        assert wanted, f"{ecosystem}: no documents for {name}@{version}"
        found = dict(zip((d.url for d in wanted), documents, strict=False))
        for more, document in zip(
            source.followed(name, version, found), documents[len(found) :], strict=False
        ):
            found[more.url] = document
        return source.locate(name, version, found)

    def test_npm_the_tarball_and_the_sha512_integrity(self) -> None:
        found = self.locate("npm", "left-pad", "1.3.0", Fixtures.load("npm_version.json"))
        assert found is not None
        assert (
            found.url == "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            and found.filename == "left-pad-1.3.0.tgz"
        )
        assert found.digests == (
            (
                "sha512",
                base64.b64decode(Fixtures.load("npm_version.json")["dist"]["integrity"][7:]).hex(),
            ),
        )

    def test_npm_a_scoped_name_is_asked_as_it_is_written(self) -> None:
        (document,) = ArchiveSources.of("npm").documents("@scope/demo", "1.0.0")  # type: ignore[union-attr]
        assert document.url == "https://registry.npmjs.org/@scope/demo/1.0.0"

    def test_npm_a_release_with_only_the_legacy_sha1_has_no_archive(self) -> None:
        document = Fixtures.load("npm_version.json")
        document["dist"]["integrity"] = ""
        assert self.locate("npm", "left-pad", "1.3.0", document) is None

    def test_npm_a_tarball_on_another_host_has_no_archive(self) -> None:
        document = Fixtures.load("npm_version.json")
        document["dist"]["tarball"] = "https://evil.example.invalid/x.tgz"
        assert self.locate("npm", "left-pad", "1.3.0", document) is None

    def test_pypi_the_source_distribution_with_its_sha256(self) -> None:
        found = self.locate("pypi", "six", "1.16.0", Fixtures.load("pypi_version.json"))
        sdist = next(
            f for f in Fixtures.load("pypi_version.json")["urls"] if f["packagetype"] == "sdist"
        )
        assert found is not None and found.filename == "six-1.16.0.tar.gz"
        assert found.url == sdist["url"] and found.digests == (
            ("sha256", sdist["digests"]["sha256"]),
        )

    def test_pypi_a_release_with_only_a_wheel_gets_the_wheel(self) -> None:
        document = Fixtures.load("pypi_version.json")
        document["urls"] = [f for f in document["urls"] if f["packagetype"] != "sdist"]
        found = self.locate("pypi", "six", "1.16.0", document)
        assert found is not None and found.filename.endswith(".whl")

    def test_pypi_a_file_on_another_host_has_no_archive(self) -> None:
        document = Fixtures.load("pypi_version.json")
        for f in document["urls"]:
            f["url"] = "https://evil.example.invalid/" + f["filename"]
        assert self.locate("pypi", "six", "1.16.0", document) is None

    def test_cargo_the_checksum_and_the_static_host(self) -> None:
        found = self.locate("cargo", "fnv", "1.0.7", Fixtures.load("cargo_version.json"))
        assert found is not None
        assert found.url == "https://static.crates.io/crates/fnv/fnv-1.0.7.crate"
        assert found.digests == (
            ("sha256", "3f9eec918d3f24069decb9af1554cad7c880e2da24a9afd88aca000531ab82c1"),
        )

    def test_cargo_a_document_for_another_version_is_not_this_archive(self) -> None:
        assert self.locate("cargo", "fnv", "1.0.6", Fixtures.load("cargo_version.json")) is None

    def test_rubygems_the_sha_and_the_gem(self) -> None:
        found = self.locate("rubygems", "rake", "13.0.6", Fixtures.load("rubygems_version.json"))
        assert found is not None and found.url == "https://rubygems.org/gems/rake-13.0.6.gem"
        assert found.digests == (
            ("sha256", "5ce4bf5037b4196c24ac62834d8db1ce175470391026bd9e557d669beeb19097"),
        )

    def test_nuget_the_registration_names_the_catalog_whose_hash_is_the_nupkgs(self) -> None:
        found = self.locate(
            "nuget",
            "Newtonsoft.Json",
            "13.0.3",
            Fixtures.load("nuget_registration.json"),
            Fixtures.load("nuget_catalog.json"),
        )
        assert found is not None
        assert (
            found.url
            == "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
        )
        assert found.digests == (
            ("sha512", base64.b64decode(Fixtures.load("nuget_catalog.json")["packageHash"]).hex()),
        )

    def test_nuget_a_catalog_address_off_the_registrys_own_path_is_not_followed(self) -> None:
        source = ArchiveSources.of("nuget")
        assert source is not None
        (document,) = source.documents("Newtonsoft.Json", "13.0.3")
        registration = Fixtures.load("nuget_registration.json") | {
            "catalogEntry": "https://evil.example.invalid/x.json"
        }
        assert source.followed("Newtonsoft.Json", "13.0.3", {document.url: registration}) == ()

    def test_nuget_a_hash_that_is_not_sha512_is_no_check(self) -> None:
        catalog = Fixtures.load("nuget_catalog.json") | {"packageHashAlgorithm": "SHA256"}
        assert (
            self.locate(
                "nuget",
                "Newtonsoft.Json",
                "13.0.3",
                Fixtures.load("nuget_registration.json"),
                catalog,
            )
            is None
        )

    def test_gomod_the_zip_is_held_to_the_h1_the_checksum_database_records(self) -> None:
        found = self.locate(
            "gomod", "github.com/pkg/errors", "v0.9.1", Fixtures.text("gomod_sumdb.txt")
        )
        assert found is not None
        assert found.url == "https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.zip"
        assert found.digests == (("go-h1", "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4="),)

    def test_gomod_a_version_recorded_without_its_v_is_asked_for_with_it(self) -> None:
        source = ArchiveSources.of("gomod")
        assert source is not None
        assert source.documents("github.com/pkg/errors", "0.9.1")[0].url.endswith(
            "/lookup/github.com/pkg/errors@v0.9.1"
        )
        found = self.locate(
            "gomod", "github.com/pkg/errors", "0.9.1", Fixtures.text("gomod_sumdb.txt")
        )
        assert found is not None and found.url.endswith("/@v/v0.9.1.zip")

    def test_gomod_upper_case_is_escaped_in_both_addresses(self) -> None:
        source = ArchiveSources.of("gomod")
        assert source is not None
        assert "/github.com/!azure/go@" in source.documents("github.com/Azure/go", "v1.0.0")[0].url
        recorded = "github.com/Azure/go v1.0.0 h1:" + base64.b64encode(b"\x01" * 32).decode() + "\n"
        found = source.locate("github.com/Azure/go", "v1.0.0", {"u": recorded})
        assert found is not None and "/github.com/!azure/go/@v/v1.0.0.zip" in found.url

    def test_gomod_the_h1_is_compared_as_written_not_lower_cased(self) -> None:
        import io
        import zipfile

        from cordon_scanner.intel.registries.archive_sources.git import GoZip

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("m@v1/a.go", "package m\n")
        recorded = GoZip.h1(buffer.getvalue())
        assert recorded != recorded.lower()
        assert ArchiveFetch.digest_ok(buffer.getvalue(), (("go-h1", recorded),))
        assert not ArchiveFetch.digest_ok(buffer.getvalue(), (("go-h1", recorded.lower()),))

    def test_gomod_a_line_for_the_go_mod_file_is_not_the_zip(self) -> None:
        only_mod = "\n".join(
            line for line in Fixtures.text("gomod_sumdb.txt").splitlines() if "/go.mod" in line
        )
        assert self.locate("gomod", "github.com/pkg/errors", "v0.9.1", only_mod) is None

    def test_hex_the_checksum_and_the_tarball(self) -> None:
        found = self.locate("hex", "jason", "1.4.4", Fixtures.load("hex_release.json"))
        assert found is not None and found.url == "https://repo.hex.pm/tarballs/jason-1.4.4.tar"
        assert found.digests == (
            ("sha256", "c5eb0cab91f094599f94d55bc63409236a8ec69a21a67814529e8d5f6cc90b3b"),
        )

    def test_pub_the_archive_sha256_of_the_version_asked(self) -> None:
        document = Fixtures.load("pub_package.json")
        newest = document["versions"][-1]
        found = self.locate("pub", "equatable", newest["version"], document)
        assert found is not None and found.url == newest["archive_url"]
        assert found.digests == (("sha256", newest["archive_sha256"]),)
        assert self.locate("pub", "equatable", "0.0.0-none", document) is None

    def test_maven_the_jar_and_the_strongest_digest_kept_beside_it(self) -> None:
        source = ArchiveSources.of("maven")
        assert source is not None
        base = "https://repo.maven.apache.org/maven2/commons-io/commons-io/2.18.0/commons-io-2.18.0.jar"
        assert [d.url for d in source.documents("commons-io:commons-io", "2.18.0")] == [
            f"{base}.{a}" for a in ("sha512", "sha256", "sha1", "md5")
        ]
        stated = {f"{base}.sha1": Fixtures.text("maven_commons_io.jar.sha1")}
        found = source.locate("commons-io:commons-io", "2.18.0", stated)
        assert (
            found is not None
            and found.url == base
            and found.digests == (("sha1", "44084ef756763795b31c578403dd028ff4a22950"),)
        )
        stronger = stated | {f"{base}.sha512": "ab" * 64 + "  commons-io-2.18.0.jar\n"}
        again = source.locate("commons-io:commons-io", "2.18.0", stronger)
        assert again is not None and again.digests == (("sha512", "ab" * 64),)

    def test_maven_a_digest_file_of_the_wrong_width_is_skipped(self) -> None:
        source = ArchiveSources.of("maven")
        assert source is not None
        base = "https://repo.maven.apache.org/maven2/commons-io/commons-io/2.18.0/commons-io-2.18.0.jar"
        broken = {
            f"{base}.sha512": "abcd",
            f"{base}.sha1": Fixtures.text("maven_commons_io.jar.sha1"),
        }
        found = source.locate("commons-io:commons-io", "2.18.0", broken)
        assert found is not None and found.digests[0][0] == "sha1"

    def test_gradle_is_maven_central_under_its_own_name(self) -> None:
        maven, gradle = ArchiveSources.of("maven"), ArchiveSources.of("gradle")
        assert maven is not None and gradle is not None and gradle.ecosystem == "gradle"
        assert maven.documents("g:a", "1.0") == gradle.documents("g:a", "1.0") != ()

    @pytest.mark.parametrize(
        ("ecosystem", "name", "version"),
        [
            ("npm", "", "1"),
            ("pypi", "a/../b", "1"),
            ("cargo", "a/b", "1"),
            ("rubygems", "a b", "1"),
            ("nuget", "../x", "1"),
            ("gomod", "a//b", "v1"),
            ("hex", "a?b", "1"),
            ("pub", "", "1"),
            ("maven", "a", "1"),
            ("maven", "a:b:c", "1"),
            ("maven", "a:b", "../1"),
        ],
    )
    def test_a_name_or_version_that_is_not_one_asks_for_nothing(
        self, ecosystem: str, name: str, version: str
    ) -> None:
        assert ArchiveSources.of(ecosystem).documents(name, version) == ()  # type: ignore[union-attr]

    def test_vscode_the_open_vsx_reader_is_the_source_and_the_marketplace_names_no_digest(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.intel.base import PackageArchive
        from cordon_scanner.intel.registries.openvsx import OpenVsx

        monkeypatch.setattr(
            OpenVsx,
            "archive",
            classmethod(lambda cls, n, v: PackageArchive("vscode", n, v, f"{n}-{v}.vsix", b"x")),
        )
        archive = ArchiveSources.package_archive("vscode", "Acme.tool", "1.0.0")
        assert (archive.ecosystem, archive.filename) == ("vscode", "Acme.tool-1.0.0.vsix")
        assert ArchiveSources.of("vscode").fetch("", "1.0.0") is None  # type: ignore[union-attr]

    def test_hackage_the_content_md5_header_is_the_digest(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data = b"tarball"
        stated = base64.b64encode(hashlib.md5(data, usedforsecurity=False).digest()).decode()
        monkeypatch.setattr(
            RegistryRequest, "headers", staticmethod(lambda url, allow: {"content-md5": stated})
        )
        monkeypatch.setattr(
            RegistryRequest, "fetch_bytes", staticmethod(lambda url, allow, **k: data)
        )
        archive = ArchiveSources.of("hackage").fetch("tagged", "0.8.6")  # type: ignore[union-attr]
        assert (
            archive is not None
            and archive.strength == "md5"
            and archive.filename == "tagged-0.8.6.tar.gz"
        )

    def test_hackage_bytes_that_do_not_match_or_no_header_are_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stated = base64.b64encode(hashlib.md5(b"tarball", usedforsecurity=False).digest()).decode()
        monkeypatch.setattr(
            RegistryRequest, "headers", staticmethod(lambda url, allow: {"content-md5": stated})
        )
        monkeypatch.setattr(
            RegistryRequest, "fetch_bytes", staticmethod(lambda url, allow, **k: b"tampered")
        )
        with pytest.raises(RegistryError, match="does not match the md5"):
            ArchiveSources.of("hackage").fetch("tagged", "0.8.6")  # type: ignore[union-attr]
        monkeypatch.setattr(RegistryRequest, "headers", staticmethod(lambda url, allow: {}))
        with pytest.raises(RegistryError, match="states no MD5"):
            ArchiveSources.of("hackage").fetch("tagged", "0.8.6")  # type: ignore[union-attr]


class TestArchivesThatExpand:
    """A small download must not become gigabytes in memory: what a tar or zip declares is held to a bound before it is read."""

    @staticmethod
    def gz(files: dict[str, bytes]) -> bytes:
        import gzip
        import io
        import tarfile

        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, content in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        return gzip.compress(buffer.getvalue())

    def test_a_small_archive_that_declares_more_than_the_bound_gives_no_tree(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import GitTar, Unpacked

        data = self.gz({"zeros": b"\0" * (3 << 20)})
        assert len(data) < 8 << 10 and GitTar.tree_sha1(data) != ""
        monkeypatch.setattr(Unpacked, "LIMIT", 1 << 20)
        monkeypatch.setattr(Unpacked, "FLOOR", 1 << 10)
        assert GitTar.tree_sha1(data) == ""

    def test_the_bound_is_twenty_times_the_download_up_to_the_ceiling_and_never_below_the_floor(
        self,
    ) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import Unpacked

        assert Unpacked.bound(b"x" * 100) == Unpacked.FLOOR
        assert Unpacked.bound(b"x" * (1 << 20)) == 20 << 20
        assert Unpacked.bound(b"x" * (100 << 20)) == Unpacked.LIMIT

    def test_a_zip_that_declares_more_than_the_bound_gives_no_h1(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import io
        import zipfile

        from cordon_scanner.intel.registries.archive_sources.git import GoZip, Unpacked

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("m@v1/big", b"\0" * (3 << 20))
        assert GoZip.h1(buffer.getvalue()).startswith("h1:")
        monkeypatch.setattr(Unpacked, "LIMIT", 1 << 20)
        monkeypatch.setattr(Unpacked, "FLOOR", 1 << 10)
        assert GoZip.h1(buffer.getvalue()) == ""

    def test_the_commit_is_read_from_the_first_header_alone(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import GitTar

        data = Archives.tarball({"a": b"x" * 1000}, comment=HEX40)
        assert GitTar.commit(data) == HEX40 and GitTar.commit(data[:600]) in ("", HEX40)


class TestJuliaOnARealPackage:
    """The tarball the package server serves for ZipFile 0.7.0 holds the package's own files with no wrapping directory, and its
    git tree hash is the `git-tree-sha1` General records for that version (both real, fetched 2026-11-26)."""

    def test_the_real_tarball_hashes_to_the_tree_the_registry_records(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import GitTar

        data = (DATA / "julia_zipfile_0.7.0.tgz").read_bytes()
        source = ArchiveSources.of("julia")
        assert source is not None
        package, listing = source.documents("ZipFile", "0.7.0")
        found = source.locate(
            "ZipFile",
            "0.7.0",
            {
                package.url: Fixtures.text("julia_package.toml"),
                listing.url: Fixtures.text("julia_versions.toml"),
            },
        )
        assert found is not None and found.digests == (
            ("git-tree-sha1", "c191e56c849b1784cacbf7cd5e52cc672f1ae2db"),
        )
        assert GitTar.tree_sha1(data) == "c191e56c849b1784cacbf7cd5e52cc672f1ae2db"
        assert ArchiveFetch.digest_ok(data, found.digests)

    def test_a_tarball_with_one_file_changed_does_not_match(self) -> None:
        import io
        import tarfile

        data = (DATA / "julia_zipfile_0.7.0.tgz").read_bytes()
        out = io.BytesIO()
        with (
            tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as source,
            tarfile.open(fileobj=out, mode="w:gz") as target,
        ):
            for member in source:
                handle = source.extractfile(member) if member.isfile() else None
                content = handle.read() if handle else b""
                if member.name == "LICENSE.md":
                    content += b" "
                    member.size = len(content)
                target.addfile(member, io.BytesIO(content) if member.isfile() else None)
        assert not ArchiveFetch.digest_ok(
            out.getvalue(), (("git-tree-sha1", "c191e56c849b1784cacbf7cd5e52cc672f1ae2db"),)
        )


class TestAPortfileWithParenthesesInIt:
    def call(self, text: str) -> list[str]:
        from cordon_scanner.intel.registries.archive_sources.vcpkg import Portfile

        return Portfile.call(text, "vcpkg_from_github")

    def test_a_patch_name_with_balanced_parentheses_does_not_end_the_call(self) -> None:
        words = self.call(
            "vcpkg_from_github(\n  REPO a/b\n  REF v1\n  SHA512 "
            + "ab" * 64
            + "\n  PATCHES fix(x).patch other.patch\n)\nlater()"
        )
        assert words[:4] == ["REPO", "a/b", "REF", "v1"] and words[-2:] == [
            "fix(x).patch",
            "other.patch",
        ]

    def test_a_comment_and_a_quoted_string_may_hold_a_parenthesis(self) -> None:
        words = self.call('vcpkg_from_github(\n  REPO a/b # the (old) name\n  REF "v)1"\n)')
        assert words == ["REPO", "a/b", "REF", "v)1"]

    def test_a_call_that_is_never_closed_is_no_call(self) -> None:
        assert self.call("vcpkg_from_github(REPO a/b") == []
        assert self.call('vcpkg_from_github(REPO "a/b') == []

    def test_the_archive_is_still_found_when_a_patch_name_has_parentheses(self) -> None:
        source = ArchiveSources.of("vcpkg")
        assert source is not None
        text = (
            base64.b64decode(Fixtures.load("vcpkg_blob_portfile.json")["content"])
            .decode()
            .replace("0001-no-version-script-on-ohos.patch", "fix(x).patch")
        )
        words = self.call(text)
        assert "REPO" in words and "fix(x).patch" in words
