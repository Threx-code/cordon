"""How a vcpkg port's source is found: the port's files at a version, fetched by git and kept,
the Qt helpers' data in both layouts, and every portfile form the reader evaluates or declines."""

from __future__ import annotations

import json

import pytest

from cordon_scanner.intel.advisories.upstream.base import VCPKG_RAW, Unnamed, Upstream
from cordon_scanner.intel.advisories.upstream.fetch import Fetch
from cordon_scanner.intel.advisories.upstream.inference import TagInference
from cordon_scanner.intel.advisories.upstream.vcpkg import VcpkgPorts
from cordon_scanner.intel.provenance.gitfetch import GitFetch, GitFetchError
from cordon_scanner.intel.registries.registry_request import PackageNotFound, RegistryError

BASE = "b" * 40
TREE = "1" * 40
BLOB = "2" * 40
COMMIT = "0123456789abcdef0123456789abcdef01234567"
SHA512 = "a" * 128
HOW = "vcpkg port"


class Ports:
    """Helpers for test_vcpkg_ports.py: the registry and git, served from dicts."""

    @staticmethod
    def serve(monkeypatch: pytest.MonkeyPatch, pages: dict[str, object]) -> list[str]:
        asked: list[str] = []

        def get(url: str, limit: int = 0) -> bytes:
            asked.append(url)
            if url not in pages:
                raise PackageNotFound(url)
            page = pages[url]
            return page if isinstance(page, bytes) else json.dumps(page).encode()

        monkeypatch.setattr(Fetch, "get", staticmethod(get))
        monkeypatch.setattr(Fetch, "resolved", {})
        monkeypatch.setattr(TagInference, "refs", staticmethod(lambda repository: {}))
        return asked

    @staticmethod
    def git(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
        trees: dict[str, dict[str, str]],
        blobs: dict[str, bytes],
    ) -> list[str]:
        monkeypatch.setenv("CORDON_CACHE_DIR", str(tmp_path / "cache"))
        fetched: list[str] = []

        def tree(repository: str, want: str) -> dict[str, str]:
            fetched.append(want)
            if want not in trees:
                raise GitFetchError("no such tree")
            return trees[want]

        def blob(repository: str, want: str) -> bytes:
            fetched.append(want)
            return blobs[want]

        monkeypatch.setattr(GitFetch, "tree", staticmethod(tree))
        monkeypatch.setattr(GitFetch, "blob", staticmethod(blob))
        return fetched

    @staticmethod
    def database(at: str, *entries: dict[str, object]) -> dict[str, object]:
        return {f"{VCPKG_RAW}/{at}/versions/z-/zlib.json": {"versions": list(entries)}}


class TestTheCache:
    def test_a_git_object_is_fetched_once(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("CORDON_CACHE_DIR", str(tmp_path))
        calls: list[int] = []
        first = VcpkgPorts._cached("blob", BLOB, lambda: calls.append(1) or b"body")
        again = VcpkgPorts._cached("blob", BLOB, lambda: calls.append(1) or b"other")
        assert (first, again, calls) == (b"body", b"body", [1])

    def test_an_unwritable_cache_still_answers(self, monkeypatch, tmp_path) -> None:
        blocker = tmp_path / "file"
        blocker.write_text("", encoding="utf-8")
        monkeypatch.setenv("CORDON_CACHE_DIR", str(blocker))
        assert VcpkgPorts._cached("blob", BLOB, lambda: b"body") == b"body"


class TestTheManifest:
    def test_a_manifest_that_is_not_an_object_reads_as_empty(self, monkeypatch) -> None:
        Ports.serve(monkeypatch, {f"{VCPKG_RAW}/{BASE}/ports/zlib/vcpkg.json": [1]})
        assert VcpkgPorts.manifest(BASE, "zlib") == {}


class TestAtVersion:
    def test_the_portfile_is_read_from_the_tree_the_database_names(
        self, monkeypatch, tmp_path
    ) -> None:
        Ports.serve(
            monkeypatch,
            Ports.database(
                BASE,
                {"version": "1.3", "port-version": 1, "git-tree": "9" * 40},
                {"version": "1.3", "git-tree": TREE},
            ),
        )
        fetched = Ports.git(
            monkeypatch, tmp_path, {TREE: {"portfile.cmake": BLOB}}, {BLOB: b"vcpkg_from_github()"}
        )
        assert VcpkgPorts.at_version(BASE, "zlib", "1.3#2") == ("vcpkg_from_github()", "1.3")
        # Kept: the same tree and blob are not fetched again.
        VcpkgPorts.at_version(BASE, "zlib", "1.3")
        assert fetched == [TREE, BLOB]

    def test_a_version_newer_than_the_baseline_is_found_in_the_current_database(
        self, monkeypatch, tmp_path
    ) -> None:
        asked = Ports.serve(
            monkeypatch,
            {
                **Ports.database(BASE, {"version": "1.2", "git-tree": "9" * 40}),
                **Ports.database("HEAD", {"version-semver": "1.4.0", "git-tree": TREE}),
            },
        )
        Ports.git(monkeypatch, tmp_path, {TREE: {"portfile.cmake": BLOB}}, {BLOB: b"text"})
        assert VcpkgPorts.at_version(BASE, "zlib", "1.4.0") == ("text", "1.4.0")
        assert len(asked) == 2

    def test_a_version_in_no_database_is_unnamed(self, monkeypatch) -> None:
        Ports.serve(monkeypatch, {})
        found = VcpkgPorts.at_version(BASE, "zlib", "9")
        assert isinstance(found, Unnamed) and "holds no 9" in found.reason

    def test_an_entry_without_a_git_tree_is_unnamed(self, monkeypatch) -> None:
        Ports.serve(monkeypatch, Ports.database(BASE, {"version": "1", "git-tree": "nope"}, "x"))
        found = VcpkgPorts.at_version(BASE, "zlib", "1")
        assert isinstance(found, Unnamed) and "no git tree" in found.reason

    def test_a_tree_without_a_portfile_is_unnamed(self, monkeypatch, tmp_path) -> None:
        Ports.serve(monkeypatch, Ports.database(BASE, {"version": "1", "git-tree": TREE}))
        Ports.git(monkeypatch, tmp_path, {TREE: {"vcpkg.json": BLOB}}, {})
        found = VcpkgPorts.at_version(BASE, "zlib", "1")
        assert isinstance(found, Unnamed) and "no portfile.cmake" in found.reason

    def test_a_tree_git_cannot_fetch_is_unnamed(self, monkeypatch, tmp_path) -> None:
        Ports.serve(monkeypatch, Ports.database(BASE, {"version": "1", "git-tree": TREE}))
        Ports.git(monkeypatch, tmp_path, {}, {})
        found = VcpkgPorts.at_version(BASE, "zlib", "1")
        assert isinstance(found, Unnamed) and "could not be fetched" in found.reason


class TestFileAtVersion:
    def test_another_file_of_the_port_is_read_from_the_same_tree(
        self, monkeypatch, tmp_path
    ) -> None:
        Ports.serve(
            monkeypatch, Ports.database(BASE, {"version-date": "2024-01-02", "git-tree": TREE})
        )
        Ports.git(monkeypatch, tmp_path, {TREE: {"port.data.cmake": BLOB}}, {BLOB: b"data"})
        assert VcpkgPorts.file_at_version(BASE, "zlib", "2024-01-02", "port.data.cmake") == "data"

    def test_a_file_the_tree_lacks_is_an_error(self, monkeypatch, tmp_path) -> None:
        Ports.serve(monkeypatch, Ports.database(BASE, {"version": "1", "git-tree": TREE}))
        Ports.git(monkeypatch, tmp_path, {TREE: {}}, {})
        with pytest.raises(ValueError, match=r"no port\.data\.cmake"):
            VcpkgPorts.file_at_version(BASE, "zlib", "1", "port.data.cmake")


class TestQt:
    @staticmethod
    def missing(name: str) -> str:
        raise RegistryError(name)

    def test_a_module_pinned_to_a_commit_is_that_commit(self) -> None:
        data = f'set(qtsvg_REF "{COMMIT}")'
        found = VcpkgPorts.qt("qtsvg", "6.8.0", lambda name: data, HOW)
        assert isinstance(found, Upstream) and found.query == {"commit": COMMIT}

    def test_without_port_data_and_without_qtbase_it_is_unnamed(self) -> None:
        found = VcpkgPorts.qt("qtsvg", "6.8.0", self.missing, HOW)
        assert isinstance(found, Unnamed) and "could not be read" in found.reason

    def test_unreadable_qtbase_data_is_unnamed(self) -> None:
        found = VcpkgPorts.qt("qtsvg", "6.8.0", self.missing, HOW, qtbase=self.missing)
        assert isinstance(found, Unnamed) and "could not be read" in found.reason

    def test_a_module_qtbase_fetches_from_github_is_its_tag(self) -> None:
        files = {
            "cmake/qt_port_details.cmake": "set(QT_VERSION 6.5.0)\nset(QT_FROM_GITHUB qtsvg qtnet)",
            "cmake/qt_port_data.cmake": "",
        }
        found = VcpkgPorts.qt("qtsvg", "6.5.0", self.missing, HOW, qtbase=files.__getitem__)
        assert isinstance(found, Upstream)
        assert found.query["version"] == "v6.5.0"
        assert found.query["package"]["name"] == "https://github.com/qt/qtsvg"


class TestCommandsAndArguments:
    def test_a_comment_between_arguments_is_skipped(self) -> None:
        assert VcpkgPorts._arguments("A # note\nB", {}) == ["A", "B"]
        assert VcpkgPorts._arguments("A # note to the end", {}) == ["A"]

    def test_an_unclosed_reference_is_unknown(self) -> None:
        assert VcpkgPorts._arguments('"${VERSION"', {"VERSION": "1"}) == [None]


class TestRegex:
    def test_an_oversized_pattern_or_input_is_not_evaluated(self) -> None:
        assert VcpkgPorts._regex("a" * 513, "a", None) is None
        assert VcpkgPorts._regex("a", "a" * 4097, None) is None

    def test_a_pattern_that_does_not_compile_is_not_evaluated(self) -> None:
        assert VcpkgPorts._regex("(", "a", None) is None

    def test_a_replacement_naming_a_missing_group_is_not_evaluated(self) -> None:
        assert VcpkgPorts._regex("(a)", "a", "\\5") is None


class TestStringCommands:
    @staticmethod
    def value(portfile: str) -> Upstream | Unnamed:
        return VcpkgPorts.source(
            portfile + "\nvcpkg_from_github(REPO o/r REF ${OUT})", "1.2.3", "zlib", HOW
        )

    def test_replace_builds_the_ref(self) -> None:
        found = self.value("string(REPLACE . _ OUT v${VERSION})")
        assert isinstance(found, Upstream) and found.query["version"] == "v1_2_3"

    def test_replace_of_an_unknown_value_is_unknown(self) -> None:
        found = self.value("string(REPLACE . _ OUT ${NOWHERE})")
        assert isinstance(found, Unnamed) and "REF is computed" in found.reason

    def test_case_changes_build_the_ref(self) -> None:
        lower = self.value("string(TOLOWER V${VERSION}-RC OUT)")
        upper = self.value("string(TOUPPER v${VERSION}-rc OUT)")
        assert isinstance(lower, Upstream) and lower.query["version"] == "v1.2.3-rc"
        assert isinstance(upper, Upstream) and upper.query["version"] == "V1.2.3-RC"

    def test_any_other_string_operation_leaves_the_value_unknown(self) -> None:
        found = self.value("set(OUT v1)\nstring(LENGTH abc OUT)")
        assert isinstance(found, Unnamed) and "REF is computed" in found.reason


class TestRead:
    def test_a_distfile_pins_its_archive(self) -> None:
        portfile = (
            f"vcpkg_download_distfile(A URLS https://example.org/z-1.tar.gz "
            f"FILENAME z-1.tar.gz SHA512 {SHA512})"
        )
        _, archive = VcpkgPorts.read(portfile, "1", "zlib", HOW)
        assert archive is not None
        assert archive.urls == ("https://example.org/z-1.tar.gz",)

    def test_a_sourceforge_download_pins_sourceforges_address(self) -> None:
        portfile = f"vcpkg_from_sourceforge(REPO proj REF 1.0 FILENAME p.tgz SHA512 {SHA512})"
        found, archive = VcpkgPorts.read(portfile, "1", "zlib", HOW)
        assert isinstance(found, Unnamed) and "SourceForge" in found.reason
        assert archive is not None
        assert archive.urls == ("https://downloads.sourceforge.net/project/proj/1.0/p.tgz",)

    def test_a_sourceforge_file_with_no_folder_is_at_the_projects_root(self) -> None:
        keyed = {"REPO": ["proj"], "REF": [""], "FILENAME": ["p.tgz"]}
        urls = VcpkgPorts._archive_urls("vcpkg_from_sourceforge", keyed)  # type: ignore[arg-type]
        assert urls == ["https://downloads.sourceforge.net/project/proj/p.tgz"]

    def test_a_sourceforge_download_without_a_file_pins_nothing(self) -> None:
        keyed = {"REPO": ["proj"]}
        assert VcpkgPorts._archive_urls("vcpkg_from_sourceforge", keyed) == []  # type: ignore[arg-type]

    def test_conditional_fetches_naming_nothing_give_the_first_reason(self) -> None:
        portfile = "if(A)\nvcpkg_from_github(REPO o/r REF ${NOPE})\nendif()"
        found, _ = VcpkgPorts.read(portfile, "1", "zlib", HOW)
        assert isinstance(found, Unnamed) and "REF is computed" in found.reason


class TestFetched:
    @pytest.mark.parametrize(
        ("portfile", "reason"),
        [
            ("vcpkg_download_distfile(A URLS ${NOPE} FILENAME z.tgz)", "download URL is computed"),
            (
                "vcpkg_from_github(REPO o/r REF v1 GITHUB_HOST https://ghe.example.com)",
                "other than github.com",
            ),
            ("vcpkg_from_gitlab(REPO o/r REF v1)", "GitLab host or repository is computed"),
            ("vcpkg_from_bitbucket(REF v1)", "Bitbucket repository is computed"),
        ],
    )
    def test_a_source_that_cannot_be_named_says_why(self, portfile: str, reason: str) -> None:
        found = VcpkgPorts.source(portfile, "1", "zlib", HOW)
        assert isinstance(found, Unnamed) and reason in found.reason

    def test_a_bitbucket_repository_is_named(self) -> None:
        found = VcpkgPorts.source("vcpkg_from_bitbucket(REPO o/r REF v1)", "1", "zlib", HOW)
        assert isinstance(found, Upstream)
        assert found.query["package"]["name"] == "https://bitbucket.org/o/r"


class TestQtBeforePortData:
    def test_a_module_qtbase_pins_to_a_commit_is_that_commit(self) -> None:
        files = {
            "cmake/qt_port_details.cmake": "set(QT_VERSION 6.5.0)",
            "cmake/qt_port_data.cmake": f"set(qtsvg_REF {COMMIT})",
        }
        found = VcpkgPorts.qt_before_port_data("qtsvg", "6.5.0", HOW, files.__getitem__)
        assert isinstance(found, Upstream) and found.query == {"commit": COMMIT}
