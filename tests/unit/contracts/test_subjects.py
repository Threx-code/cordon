"""`CanonicalIds.canonical_id`: what a tool says becomes one name (design spec 3.1 to 3.3).

Every input here is a benign, public name or an invented one (`example`).
"""

from __future__ import annotations

import pytest

from cordon_scanner.contracts.name_fold import NameFolds
from cordon_scanner.contracts.subjects import (
    CanonicalIds,
    InvalidSubject,
    SubjectKind,
    SubjectParts,
)
from cordon_scanner.ecosystems.registry import EcosystemRegistry

ID = CanonicalIds.canonical_id


class TestPackages:
    @pytest.mark.parametrize(
        ("parts", "expected"),
        [
            ({"ecosystem": "npm", "name": "Left-Pad"}, "pkg:npm/left-pad"),
            ({"ecosystem": "npm", "name": "@Types/Node"}, "pkg:npm/%40types/node"),
            ({"ecosystem": "npm", "namespace": "@babel", "name": "core"}, "pkg:npm/%40babel/core"),
            (
                {"ecosystem": "pypi", "name": "Django_Rest.Framework"},
                "pkg:pypi/django-rest-framework",
            ),
            ({"ecosystem": "python", "name": "Requests"}, "pkg:pypi/requests"),
            ({"ecosystem": "cargo", "name": "Serde_Json"}, "pkg:cargo/Serde_Json"),
            ({"ecosystem": "rust", "name": "tokio"}, "pkg:cargo/tokio"),
            ({"ecosystem": "gem", "name": "Rails"}, "pkg:gem/Rails"),
            (
                {"ecosystem": "maven", "namespace": "org.apache.commons", "name": "commons-lang3"},
                "pkg:maven/org.apache.commons/commons-lang3",
            ),
            (
                {"ecosystem": "go", "namespace": "github.com/Gin-Gonic", "name": "gin"},
                "pkg:golang/github.com/gin-gonic/gin",
            ),
            ({"ecosystem": "nuget", "name": "Newtonsoft.Json"}, "pkg:nuget/newtonsoft.json"),
        ],
    )
    def test_the_name_is_folded_the_way_its_registry_folds_it(self, parts, expected) -> None:
        assert ID(SubjectKind.PACKAGE, parts) == expected

    def test_two_spellings_are_one_subject(self) -> None:
        a = ID(SubjectKind.PACKAGE, {"ecosystem": "pypi", "name": "Foo_Bar"})
        b = ID(SubjectKind.PACKAGE, {"ecosystem": "PyPI", "name": "foo.bar"})
        assert a == b

    def test_a_version_is_not_part_of_the_name(self) -> None:
        with pytest.raises(InvalidSubject):
            ID(SubjectKind.PACKAGE, {"ecosystem": "npm", "name": "left pad"})

    @pytest.mark.parametrize("name", ["", "   ", "a/../b", "a//"])
    def test_a_name_that_is_not_a_name_is_refused(self, name: str) -> None:
        with pytest.raises(InvalidSubject):
            ID(SubjectKind.PACKAGE, {"ecosystem": "npm", "name": name, "namespace": "x/../y"})


#: Every ecosystem, with a name written in mixed case with every separator, and the id it has always had (or, for
#: the ecosystems that did not fold before, the id its own registry's rule gives).
MIXED = "Ab_C.d-E"
STORED_IDS: dict[str, str] = {
    "npm": "pkg:npm/ab_c.d-e",
    "pypi": "pkg:pypi/ab-c-d-e",
    "nuget": "pkg:nuget/ab_c.d-e",
    "composer": "pkg:composer/ab_c.d-e",
    "gomod": "pkg:golang/ab_c.d-e",
    "hex": "pkg:hex/ab_c.d-e",
    "swift": "pkg:swift/ab_c.d-e",
    "cocoapods": "pkg:cocoapods/ab_c.d-e",
    "cargo": f"pkg:cargo/{MIXED}",
    "rubygems": f"pkg:gem/{MIXED}",
    "maven": f"pkg:maven/{MIXED}",
    "gradle": f"pkg:gradle/{MIXED}",
    "actions": "pkg:actions/ab_c.d-e",
    "image": "pkg:image/ab_c.d-e",
    "conda": "pkg:conda/ab_c.d-e",
    "homebrew": "pkg:homebrew/ab_c.d-e",
    "terraform": "pkg:terraform/ab_c.d-e",
    "vcpkg": "pkg:vcpkg/ab_c.d-e",
    "vscode": "pkg:vscode/ab_c.d-e",
    "ansible": "pkg:ansible/ab_c.d-e",
    "pub": "pkg:pub/ab_c.d-e",
    "bazel": f"pkg:bazel/{MIXED}",
    "cran": f"pkg:cran/{MIXED}",
    "hackage": f"pkg:hackage/{MIXED}",
    "julia": f"pkg:julia/{MIXED}",
    "opam": f"pkg:opam/{MIXED}",
    "conan": f"pkg:conan/{MIXED}",
    "nix": f"pkg:nix/{MIXED}",
    "helm": f"pkg:helm/{MIXED}",
}


class TestEveryEcosystemFoldsItsOwnWay:
    def test_the_table_names_every_registered_ecosystem(self) -> None:
        assert set(STORED_IDS) == set(EcosystemRegistry.BY_ID)

    @pytest.mark.parametrize("ecosystem", sorted(EcosystemRegistry.BY_ID))
    def test_a_name_gets_the_id_its_registry_gives(self, ecosystem: str) -> None:
        got = ID(SubjectKind.PACKAGE, {"ecosystem": ecosystem, "name": MIXED})
        assert got == STORED_IDS[ecosystem]

    @pytest.mark.parametrize("ecosystem", sorted(EcosystemRegistry.BY_ID))
    def test_the_id_follows_the_fold_the_adapter_declares(self, ecosystem: str) -> None:
        fold = NameFolds.BY_ID[ecosystem]
        name = ID(SubjectKind.PACKAGE, {"ecosystem": ecosystem, "name": MIXED}).rsplit("/", 1)[-1]
        assert name == SubjectParts.fold(MIXED, fold.lower, fold.one_separator)

    def test_the_table_holds_exactly_the_registered_ecosystems(self) -> None:
        assert set(NameFolds.BY_ID) == set(EcosystemRegistry.BY_ID)

    @pytest.mark.parametrize("ecosystem", sorted(EcosystemRegistry.BY_ID))
    def test_a_purl_type_that_is_not_the_id_folds_as_its_ecosystem_does(
        self, ecosystem: str
    ) -> None:
        purl_type = EcosystemRegistry.BY_ID[ecosystem].purl_type
        if purl_type in NameFolds.BY_TYPE:
            assert NameFolds.BY_TYPE[purl_type] == NameFolds.BY_ID[ecosystem]

    @pytest.mark.parametrize(
        ("ecosystem", "name", "expected"),
        [
            ("docker", "Library/Nginx", "pkg:oci/Library/Nginx"),
            ("golang", "Gin", "pkg:golang/gin"),
            ("go", "Gin", "pkg:golang/gin"),
            ("gem", "Rails", "pkg:gem/Rails"),
            ("github", "Foo", "pkg:github/foo"),
            ("bitbucket", "Foo", "pkg:bitbucket/foo"),
            ("unheard-of", "Foo", "pkg:unheard-of/Foo"),
        ],
    )
    def test_a_name_an_ecosystem_goes_by_keeps_its_id(self, ecosystem, name, expected) -> None:
        assert ID(SubjectKind.PACKAGE, {"ecosystem": ecosystem, "name": name}) == expected


class TestTheOtherKinds:
    @pytest.mark.parametrize(
        ("kind", "parts", "expected"),
        [
            (
                SubjectKind.CONTAINER_IMAGE,
                {"name": "nginx:1.27"},
                "pkg:oci/library/nginx?repository_url=docker.io",
            ),
            (
                SubjectKind.CONTAINER_IMAGE,
                {"name": "Ghcr.io/Org/App@sha256:" + "a" * 64},
                "pkg:oci/org/app?repository_url=ghcr.io",
            ),
            (
                SubjectKind.CONTAINER_IMAGE,
                {"name": "app", "registry": "Registry.Example.com/"},
                "pkg:oci/app?repository_url=registry.example.com",
            ),
            (
                SubjectKind.CI_ACTION,
                {"host": "github", "owner": "Actions", "repo": "Checkout"},
                "ci:github/actions/checkout",
            ),
            (
                SubjectKind.CI_ACTION,
                {"host": "github", "owner": "a", "repo": "b", "path": "sub/Action"},
                "ci:github/a/b/sub/Action",
            ),
            (
                SubjectKind.CI_ACTION,
                {"host": "gitlab", "project": "Group/Project", "component": "build"},
                "ci:gitlab/group/project/build",
            ),
            (
                SubjectKind.IDE_EXTENSION,
                {"marketplace": "VSCode", "publisher": "ms-python", "name": "Python"},
                "ext:vscode/ms-python.python",
            ),
            (
                SubjectKind.AGENT_SKILL,
                {"source": "gh", "locator": "Owner/Repo/skills/Deploy"},
                "skill:gh/owner/repo/skills/Deploy",
            ),
            (
                SubjectKind.AGENT_SKILL,
                {"source": "local", "locator": ".claude/skills/deploy"},
                "skill:local/.claude/skills/deploy",
            ),
            (
                SubjectKind.AGENT_SKILL,
                {"source": "archive", "locator": "sha256:" + "B" * 64},
                "skill:archive/sha256-" + "b" * 64,
            ),
            (
                SubjectKind.MCP_SERVER,
                {"transport": "npm", "locator": "@Modelcontextprotocol/Server-Filesystem"},
                "mcp:npm/%40modelcontextprotocol/server-filesystem",
            ),
            (
                SubjectKind.MCP_SERVER,
                {"transport": "remote", "locator": "https://MCP.Example.com:443/sse/"},
                "mcp:remote/mcp.example.com/sse",
            ),
            (
                SubjectKind.MCP_SERVER,
                {"transport": "local", "locator": "/usr/bin/NPX  -y   @x/y"},
                "mcp:local/npx -y @x/y",
            ),
            (
                SubjectKind.AI_MODEL,
                {"provider": "OpenAI", "name": "gpt-example"},
                "model:openai/gpt-example",
            ),
            (
                SubjectKind.AI_MODEL,
                {"provider": "huggingface", "name": "org/Model-7B"},
                "pkg:huggingface/org/Model-7B",
            ),
            (SubjectKind.AGENT, {"product": "Claude Code"}, "agent:claude-code"),
            (
                SubjectKind.SOURCE_REPOSITORY,
                {"scm": "GitHub", "owner": "Org", "name": "Repo.git"},
                "repo:github/org/repo",
            ),
            (
                SubjectKind.BUILD_ARTIFACT,
                {"scope": "Acme-Prod", "name": "app/Image"},
                "art:acme-prod/app/Image",
            ),
            (
                SubjectKind.THIRD_PARTY_INTEGRATION,
                {"vendor": "Slack", "integration": "Incoming   Webhooks"},
                "int:slack/incoming-webhooks",
            ),
            (
                SubjectKind.THIRD_PARTY_INTEGRATION,
                {"vendor": " GitHub ", "integration": "Copilot Chat"},
                "int:github/copilot-chat",
            ),
        ],
    )
    def test_each_kind_has_its_canonical_form(self, kind, parts, expected) -> None:
        assert ID(kind, parts) == expected

    @pytest.mark.parametrize(
        ("kind", "parts"),
        [
            (SubjectKind.CI_ACTION, {"host": "bitbucket", "owner": "a", "repo": "b"}),
            (SubjectKind.IDE_EXTENSION, {"marketplace": "nowhere", "publisher": "a", "name": "b"}),
            (SubjectKind.AGENT_SKILL, {"source": "local", "locator": "../outside"}),
            (SubjectKind.AGENT_SKILL, {"source": "archive", "locator": "not-a-digest"}),
            (
                SubjectKind.MCP_SERVER,
                {"transport": "remote", "locator": "http://insecure.example.com"},
            ),
            (SubjectKind.MCP_SERVER, {"transport": "carrier-pigeon", "locator": "x"}),
            (SubjectKind.MCP_SERVER, {"transport": "remote", "locator": "https://host/a b"}),
            (SubjectKind.MCP_SERVER, {"transport": "remote", "locator": "https://host/a\x00b"}),
            (SubjectKind.SOURCE_REPOSITORY, {"scm": "svn", "owner": "a", "name": "b"}),
            (SubjectKind.AGENT, {"product": "  "}),
            (SubjectKind.THIRD_PARTY_INTEGRATION, {"vendor": "slack"}),
            (SubjectKind.THIRD_PARTY_INTEGRATION, {"vendor": "a/b", "integration": "c"}),
            (SubjectKind.THIRD_PARTY_INTEGRATION, {"vendor": "a", "integration": "c?d"}),
            (SubjectKind.THIRD_PARTY_INTEGRATION, {"vendor": " ", "integration": "c"}),
        ],
    )
    def test_what_cannot_be_made_canonical_is_refused_and_names_the_part(self, kind, parts) -> None:
        with pytest.raises(InvalidSubject) as raised:
            ID(kind, parts)
        assert ":" in str(raised.value)

    def test_every_kind_is_handled(self) -> None:
        handled = {
            SubjectKind.PACKAGE,
            SubjectKind.CONTAINER_IMAGE,
            SubjectKind.CI_ACTION,
            SubjectKind.IDE_EXTENSION,
            SubjectKind.AGENT_SKILL,
            SubjectKind.MCP_SERVER,
            SubjectKind.AI_MODEL,
            SubjectKind.AGENT,
            SubjectKind.SOURCE_REPOSITORY,
            SubjectKind.BUILD_ARTIFACT,
            SubjectKind.THIRD_PARTY_INTEGRATION,
        }
        assert handled == set(SubjectKind)

    def test_an_id_is_its_own_fixed_point(self) -> None:
        """Asking again with the same parts, in another order or with other blanks, gives the same id."""
        first = ID(SubjectKind.PACKAGE, {"ecosystem": "npm", "name": "@Scope/Name"})
        second = ID(SubjectKind.PACKAGE, {"name": " @scope/name ", "ecosystem": "NPM"})
        assert first == second == "pkg:npm/%40scope/name"
