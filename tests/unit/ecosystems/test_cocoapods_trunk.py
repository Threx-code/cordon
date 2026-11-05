"""CocoaPods' public spec repository, under every name a Podfile.lock gives it."""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems.packages.cocoapods import PodfileLock


class TestTrunk:
    @pytest.mark.parametrize(
        "repository",
        [
            None,
            "trunk",
            "https://github.com/CocoaPods/Specs.git",
            "https://github.com/cocoapods/specs.git",
            "https://github.com/CocoaPods/Specs",
            "https://cdn.cocoapods.org/",
        ],
    )
    def test_trunk(self, repository: str | None) -> None:
        assert PodfileLock.is_trunk(repository)

    @pytest.mark.parametrize(
        "repository",
        [
            "https://github.com/aliyun/aliyun-specs.git",
            "https://mirrors.tuna.tsinghua.edu.cn/git/CocoaPods/Specs.git",
            "https://github.com/cocoapods/specs-private.git",
        ],
    )
    def test_not_trunk(self, repository: str) -> None:
        assert not PodfileLock.is_trunk(repository)
