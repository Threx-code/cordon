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
from typing import Any

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

        if isinstance(source, UpstreamArchive):
            # The project's own host is no list: a public host, and the digest the registry states.
            assert source.ecosystem not in registry_request.ARCHIVE_HOSTS
            assert source.HOSTS == frozenset()
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
