"""The verified archive of a release (`archive_sources/`), read from the registries' real documents.

Fixtures in `archives/` are real answers captured on 2026-11-26 (public metadata only). What is tested is where the archive is, which
digests it must match, and that nothing that does not match is returned."""

from __future__ import annotations

import base64
import hashlib
import json
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


def load(name: str) -> Any:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def text(name: str) -> str:
    return (DATA / name).read_text(encoding="utf-8")


def locate(ecosystem: str, name: str, version: str, files: dict[str, str]) -> Located | None:
    source = ArchiveSources.of(ecosystem)
    assert source is not None
    wanted = source.documents(name, version)
    documents = {
        d.url: load(files[d.url.rsplit("/", 1)[-1] or d.url.rsplit("/", 2)[-2]]) for d in wanted
    }
    return source.locate(name, version, documents)


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
        content = load("conda_package.json")
        if edit:
            edit(content)
        return source.locate("zlib", version, {document.url: content})

    def test_the_newest_conda_file_of_linux_64_with_its_sha256(self) -> None:
        found = self.locate("1.3.2")
        assert found is not None
        listed = [
            f
            for f in load("conda_package.json")["files"]
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
        content = load("ansible_version.json")
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

        def fetch_bytes(
            url: str, ecosystem: str, *, redirects: int = 0, allow: Any = None
        ) -> bytes:
            calls.append((url, ecosystem, redirects))
            return data

        monkeypatch.setattr(RegistryRequest, "fetch_bytes", staticmethod(fetch_bytes))
        source = ArchiveSources.of("ansible")
        assert source is not None
        (document,) = source.documents("community.general", "14.0.1")
        monkeypatch.setattr(
            "cordon_scanner.intel.registries.archive_sources.base.RecordFetch.documents",
            staticmethod(lambda *_a, **_k: {document.url: load("ansible_version.json")}),
        )
        return calls

    def test_an_archive_that_matches_is_returned_under_its_filename(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data = b"x"
        located = load("ansible_version.json")
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
                    "https://galaxy.ansible.com/a", "ansible", redirects=redirects
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
    def test_each_sources_hosts_are_the_download_allowlist_of_its_ecosystem(
        self, source: Any
    ) -> None:
        from cordon_scanner.intel.registries.archive_sources.upstream import UpstreamArchive

        if isinstance(source, UpstreamArchive) or not source.HOSTS:
            # The project's own host is no list: a public host, and the digest the registry states.
            assert source.ecosystem not in registry_request.ARCHIVE_HOSTS
            assert not source.HOSTS
        else:
            assert registry_request.ARCHIVE_HOSTS[source.ecosystem] == source.HOSTS

    def test_every_archive_ecosystem_is_compared_and_has_a_record_source(self) -> None:
        from cordon_scanner.cli.commands.review import COMPARABLE
        from cordon_scanner.intel.registries.record_sources.table import RecordSources

        for ecosystem in ArchiveSources.ids():
            assert ecosystem in COMPARABLE and RecordSources.of(ecosystem) is not None

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
    def test_an_ecosystem_with_no_archive_source_goes_to_the_registry_clients_own_readers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.intel.registries.registry_client import RegistryClient

        asked: list[tuple[str, str, str | None]] = []
        monkeypatch.setattr(
            RegistryClient,
            "package_archive",
            staticmethod(lambda e, n, v: asked.append((e, n, v)) or "archive"),
        )
        assert ArchiveSources.package_archive("cargo", "fnv", "1.0.7") == "archive" and asked == [
            ("cargo", "fnv", "1.0.7")
        ]

    def test_a_latest_that_has_no_name_is_an_error_not_a_guess(self) -> None:
        with pytest.raises(RegistryError, match="name a version"):
            ArchiveSources.package_archive("conda", "zlib", None)

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
        content = load("bazel_source.json")
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
            {wanted.url: document if document is not None else text("opam_dune.3.5.0")},
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
                text("opam_dune.3.5.0").replace(
                    "https://github.com/ocaml/dune/releases/download/3.5.0/dune-3.5.0.tbz",
                    "git+https://github.com/ocaml/dune.git",
                )
            )
            is None
        )

    def test_a_url_block_with_no_checksum_is_no_archive(self) -> None:
        stripped = "\n".join(
            line for line in text("opam_dune.3.5.0").splitlines() if "sha" not in line
        )
        assert self.locate(stripped) is None

    def test_a_file_with_no_url_block_is_no_archive(self) -> None:
        assert self.locate('opam-version: "2.0"\n') is None

    def test_a_checksum_that_is_the_wrong_width_is_ignored(self) -> None:
        broken = text("opam_dune.3.5.0").replace("sha256=77bd", "sha256=77b")
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
        found = {config.url: text("conan_config.yml")}
        (more,) = source.followed("zlib", "1.4", found)
        found[more.url] = text("conan_conandata.yml")
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
        assert source.followed("zlib", "9.9", {config.url: text("conan_config.yml")}) == ()

    def test_a_folder_that_is_not_a_plain_folder_name_is_not_followed(self) -> None:
        source = ArchiveSources.of("conan")
        assert source is not None
        (config,) = source.documents("zlib", "1.4")
        bad = text("conan_config.yml").replace("all", "../x")
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
                first.url: load("cran_version.json"),
                second.url: load("cran_latest.json") | {"Version": latest},
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
        assert source.locate("R6", "2.5.0", {first.url: load("cran_version.json")}) is None

    def test_a_release_with_no_md5_has_no_archive(self) -> None:
        source = ArchiveSources.of("cran")
        assert source is not None
        first, _ = source.documents("R6", "2.5.1")
        document = load("cran_version.json")
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

    def test_a_dotted_name_is_public_when_every_address_it_resolves_to_is_global(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import socket

        from cordon_scanner.intel.registries.archive_sources.hosts import PublicHost

        def resolves(*addresses: str) -> Any:
            return lambda *_a, **_k: [(2, 1, 6, "", (a, 443)) for a in addresses]

        monkeypatch.setattr(socket, "getaddrinfo", resolves("140.82.112.3"))
        assert PublicHost.ok("github.com")
        monkeypatch.setattr(socket, "getaddrinfo", resolves("140.82.112.3", "10.1.2.3"))
        assert not PublicHost.ok("github.com")
        monkeypatch.setattr(socket, "getaddrinfo", resolves("169.254.169.254"))
        assert not PublicHost.ok("metadata.example.com")

    def test_a_name_that_does_not_resolve_is_not_public(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import socket

        from cordon_scanner.intel.registries.archive_sources.hosts import PublicHost

        def fail(*_a: Any, **_k: Any) -> Any:
            raise OSError("no such host")

        monkeypatch.setattr(socket, "getaddrinfo", fail)
        assert not PublicHost.ok("example.com")


HEX40 = "11bd71901bbe5b1630ceea73d27597364c9af683"


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

        assert GitTar.tree_sha1(tarball(self.FILES, executable=("run.sh",))) == self.TREE

    def test_the_order_the_files_are_in_does_not_change_it(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import GitTar

        reversed_files = dict(reversed(list(self.FILES.items())))
        assert GitTar.tree_sha1(tarball(reversed_files, executable=("run.sh",))) == self.TREE

    def test_a_changed_byte_the_executable_bit_or_a_link_target_changes_it(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import GitTar

        assert GitTar.tree_sha1(tarball(self.FILES)) != self.TREE
        assert (
            GitTar.tree_sha1(tarball(self.FILES | {"a": b"hellO\n"}, executable=("run.sh",)))
            != self.TREE
        )
        assert (
            GitTar.tree_sha1(tarball(self.FILES | {"l": "sub/b"}, executable=("run.sh",)))
            != self.TREE
        )

    @pytest.mark.parametrize("path", ["../escape", "/abs", "a/../b", "./x/../../y"])
    def test_a_path_that_leaves_the_tree_is_no_tree(self, path: str) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import GitTar

        assert GitTar.tree_sha1(tarball({path: b"x"})) == ""

    def test_something_that_is_not_a_tar_is_no_tree_and_names_no_commit(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import GitTar

        assert GitTar.tree_sha1(b"not a tar") == "" and GitTar.commit(b"not a tar") == ""

    def test_the_commit_is_the_one_the_pax_header_names(self) -> None:
        from cordon_scanner.intel.registries.archive_sources.git import GitTar

        assert GitTar.commit(tarball({"a": b"x"}, comment=HEX40)) == HEX40
        assert GitTar.commit(tarball({"a": b"x"})) == ""
        assert GitTar.commit(tarball({"a": b"x"}, comment="not a commit")) == ""

    def test_the_three_git_checks_in_a_digest(self) -> None:
        named = tarball({"a": b"x"}, comment=HEX40)
        unnamed = tarball({"a": b"x"})
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
        content = load("cocoapods_spec.json")
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
        found = self.locate("hashicorp/random", "3.6.0", load("terraform_provider_download.json"))
        assert found is not None
        assert (
            found.url
            == "https://releases.hashicorp.com/terraform-provider-random/3.6.0/terraform-provider-random_3.6.0_linux_amd64.zip"
        )
        assert found.digests == (
            ("sha256", "aa57384b85622a9f7bfb5d4512ca88e61f22a9cea9f30febaa4c98c68ff0dc21"),
        )

    def test_a_download_address_on_another_host_is_refused(self) -> None:
        document = load("terraform_provider_download.json") | {
            "download_url": "https://evil.example.invalid/a.zip"
        }
        assert self.locate("hashicorp/random", "3.6.0", document) is None

    def test_a_module_is_the_tag_of_the_repository_the_registry_names(self) -> None:
        found = self.locate("terraform-aws-modules/vpc/aws", "5.8.1", load("terraform_module.json"))
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
                package.url: text("julia_package.toml"),
                listing.url: versions if versions is not None else text("julia_versions.toml"),
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
        content = load("helm_version.json")
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

    def test_the_chart_repository_host_must_be_public(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import socket

        source = ArchiveSources.of("helm")
        assert source is not None
        monkeypatch.setattr(
            socket, "getaddrinfo", lambda *_a, **_k: [(2, 1, 6, "", ("10.0.0.7", 443))]
        )
        assert not source.allows("charts.jetstack.io")

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

        def fetch(url: str, ecosystem: str, **_k: Any) -> bytes:
            asked.append(url)
            if url.endswith("/v1"):
                raise RegistryError("HTTP 404 from codeload.github.com")
            return b"bytes"

        monkeypatch.setattr(RegistryRequest, "fetch_bytes", staticmethod(fetch))
        assert ArchiveFetch.download(source, located) == b"bytes" and len(asked) == 2

        def refuse(url: str, ecosystem: str, **_k: Any) -> bytes:
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
            def __init__(self, host: str | None, repository: str) -> None:
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

    def test_another_registry_is_used_only_when_its_host_is_public(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import socket

        registry = FakeRegistry()
        registry.install(monkeypatch)
        monkeypatch.setattr(
            socket, "getaddrinfo", lambda *_a, **_k: [(2, 1, 6, "", ("140.82.112.3", 443))]
        )
        assert ArchiveSources.of("image").fetch("ghcr.io/org/app", "1.0") is not None  # type: ignore[union-attr]
        monkeypatch.setattr(
            socket, "getaddrinfo", lambda *_a, **_k: [(2, 1, 6, "", ("10.0.0.7", 443))]
        )
        assert ArchiveSources.of("image").fetch("registry.corp.example/org/app", "1.0") is None  # type: ignore[union-attr]

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
