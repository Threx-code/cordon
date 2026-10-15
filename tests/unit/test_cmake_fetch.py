"""`SUSPECT.BUILD.CMAKE_FETCH_UNVERIFIED.001`: a fetch call with no hash, and nothing else (review 98)."""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config

RULE = "SUSPECT.BUILD.CMAKE_FETCH_UNVERIFIED.001"


class CmakeHelpers:
    @staticmethod
    def flagged(tmp_path, text: str, name: str = "CMakeLists.txt") -> bool:
        (tmp_path / name).write_text(text, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return any(f.rule_id == RULE for f in result.findings)


class TestCmakeFetch:
    @pytest.mark.parametrize(
        "text",
        [
            "FetchContent_Declare(gtest\n  URL https://example.com/googletest-1.15.2.tar.gz\n)\n",
            "ExternalProject_Add(zlib\n  URL https://example.com/zlib.tar.gz\n  PREFIX z)\n",
        ],
    )
    def test_a_fetch_with_no_hash_is_reported(self, tmp_path, text: str) -> None:
        assert CmakeHelpers.flagged(tmp_path, text)

    @pytest.mark.parametrize(
        "text",
        [
            # Verified.
            "FetchContent_Declare(gtest\n  URL https://example.com/g.tar.gz\n"
            "  URL_HASH SHA256=0000000000000000000000000000000000000000000000000000000000000000\n)\n",
            # Not a fetch: a project's homepage, a variable, a documentation link.
            "project(rocksdb HOMEPAGE_URL https://rocksdb.org/ LANGUAGES CXX)\n",
            "set(JSON_TEST_DATA_URL https://example.com/data)\n",
            "# See URL https://llvm.org/docs/CommandGuide/llvm-ar.html\nfind_program(LLVMAR llvm-ar)\n",
        ],
    )
    def test_anything_else_is_not(self, tmp_path, text: str) -> None:
        assert not CmakeHelpers.flagged(tmp_path, text)

    def test_a_vcpkg_port_naming_its_forge_is_not_a_fetch(self, tmp_path) -> None:
        port = tmp_path / "ports" / "pixman"
        port.mkdir(parents=True)
        text = (
            "vcpkg_from_gitlab(\n  GITLAB_URL https://gitlab.freedesktop.org\n  OUT_SOURCE_PATH S\n"
            "  REPO pixman/pixman\n  REF pixman-0.42.2\n  SHA512 00\n)\n"
        )
        assert not CmakeHelpers.flagged(port, text, "portfile.cmake")
