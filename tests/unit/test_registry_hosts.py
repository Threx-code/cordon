"""Which hosts are an ecosystem's registry (review 98): exact or a subdomain, never a substring."""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems.base import RegistryHosts
from cordon_scanner.ecosystems.registry import EcosystemRegistry


class TestRegistryHosts:
    KNOWN = frozenset({"registry.npmjs.org", "mirrors.aliyun.com/pypi"})

    @pytest.mark.parametrize(
        "url",
        [
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "https://user:token@registry.npmjs.org:443/x",
            "https://mirrors.aliyun.com/pypi/packages/x.whl",
        ],
    )
    def test_the_registry_and_its_listed_paths(self, url: str) -> None:
        assert RegistryHosts.matches(url, self.KNOWN)

    @pytest.mark.parametrize(
        "url",
        [
            # The registry's name inside somebody else's host.
            "https://registry.npmjs.org.example.net/x.tgz",
            "https://evilregistry.npmjs.org-cdn.example/x.tgz",
            # The mirror's host, outside the path the mirror serves the registry from.
            "https://mirrors.aliyun.com/other/x.tgz",
        ],
    )
    def test_a_look_alike_is_not_the_registry(self, url: str) -> None:
        assert not RegistryHosts.matches(url, self.KNOWN)


class TestPublicMirrors:
    @pytest.mark.parametrize(
        ("ecosystem", "url"),
        [
            ("npm", "https://registry.npm.taobao.org/react/-/react-18.2.0.tgz"),
            ("pypi", "https://pypi.tuna.tsinghua.edu.cn/packages/x/requests-2.31.0.whl"),
            ("rubygems", "https://gems.ruby-china.com/gems/rails-7.1.0.gem"),
        ],
    )
    def test_a_public_mirror_serves_the_registry(self, ecosystem: str, url: str) -> None:
        implementation = EcosystemRegistry.get(ecosystem)
        assert implementation is not None
        assert implementation.is_registry_host(url)
