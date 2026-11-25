"""Rows BP-3-14 and BP-3-16: an MCP config entry resolves through its package spec to (subject, version, archive digest); a name from a
private registry leaves the tenant only as the keyed hash.

The registry is a fake that records what it was asked, so the tests check both what the resolver reads out of the arguments and what
it does not take.
"""

from __future__ import annotations

from typing import Any

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.resolve.mcp import McpResolver, RegistryArchive
from cordon_scanner.decide.resolve.resolution import NotFound, SourceUnavailable
from kits.tenant_keys import StaticTenantKeys

ARCHIVE = b"the archive bytes as the registry serves them"


class FakeRegistry:
    def __init__(self, host: str = "registry.npmjs.org") -> None:
        self.asked: list[tuple[str, str, str | None, str | None]] = []
        self.down = False
        self.missing: set[str] = set()
        self.host = host

    def archive(
        self, ecosystem: str, name: str, selector: str | None, index: str | None
    ) -> RegistryArchive:
        self.asked.append((ecosystem, name, selector, index))
        if self.down:
            raise SourceUnavailable("no network")
        if name in self.missing:
            raise NotFound(name)
        return RegistryArchive(version="1.4.2", content=ARCHIVE, registry=index or self.host)


class Config:
    @staticmethod
    def entry(command: str, *args: str) -> dict[str, Any]:
        return {"command": command, "args": list(args)}


class TestAnNpxEntry:
    def test_it_resolves_to_the_package_the_version_and_the_archive_digest(self) -> None:
        registry = FakeRegistry()
        found = McpResolver.resolve(Config.entry("npx", "-y", "@x/y"), registry)
        assert found.resolved
        assert (found.kind, found.subject_id) == ("mcp_server", "mcp:npm/%40x/y")
        assert found.version == "1.4.2"
        assert found.digest == ArtifactDigests.of_bytes(ARCHIVE)
        assert found.ecosystem == "npm" and found.artifact().ecosystem == "npm"
        assert registry.asked == [("npm", "@x/y", None, None)]

    @pytest.mark.parametrize(
        ("spec", "name", "selector"),
        [
            ("@x/y@1.2.0", "@x/y", "1.2.0"),
            ("@x/y@latest", "@x/y", "latest"),
            ("@x/y@^1.2", "@x/y", "^1.2"),
            ("tool@2", "tool", "2"),
            ("tool", "tool", None),
        ],
    )
    def test_the_spec_is_split_into_the_name_and_what_selects_the_version(
        self, spec: str, name: str, selector: str | None
    ) -> None:
        registry = FakeRegistry()
        McpResolver.resolve(Config.entry("npx", "--yes", spec, "--flag-of-the-server"), registry)
        assert registry.asked == [("npm", name, selector, None)]

    def test_the_package_may_be_named_by_a_flag_and_the_command_after_it_is_not_the_package(
        self,
    ) -> None:
        for args in (
            ["-p", "@x/y@1.0", "x-cli"],
            ["--package=@x/y@1.0", "x-cli"],
            ["--package", "@x/y@1.0", "--", "x-cli"],
        ):
            registry = FakeRegistry()
            McpResolver.resolve(Config.entry("npx", *args), registry)
            assert registry.asked == [("npm", "@x/y", "1.0", None)], args

    def test_a_named_registry_is_passed_on_and_the_name_is_then_private(self) -> None:
        registry = FakeRegistry()
        found = McpResolver.resolve(
            Config.entry("npx", "--registry", "https://npm.corp.example.com/", "@acme/tool"),
            registry,
        )
        assert registry.asked == [("npm", "@acme/tool", None, "npm.corp.example.com")]
        keys = StaticTenantKeys()
        outbound = found.outbound_subject("tenant-1", keys)
        assert outbound.startswith("hash:mcp/") and "acme" not in outbound

    def test_a_name_from_the_public_registry_stays_plain(self) -> None:
        found = McpResolver.resolve(Config.entry("npx", "-y", "@x/y"), FakeRegistry())
        assert found.outbound_subject("tenant-1", StaticTenantKeys()) == found.subject_id

    def test_a_private_name_may_be_opted_in_to_plain(self) -> None:
        found = McpResolver.resolve(
            Config.entry("npx", "--registry=https://npm.corp.example.com", "@acme/tool"),
            FakeRegistry(),
        )
        assert (
            found.outbound_subject("tenant-1", StaticTenantKeys(), plain_opt_in=True)
            == found.subject_id
        )

    def test_the_program_may_be_a_path_or_have_a_windows_suffix(self) -> None:
        for command in ("/usr/local/bin/npx", "npx.cmd", "C:\\tools\\NPX.EXE"):
            assert McpResolver.resolve(
                Config.entry(command, "-y", "tool"), FakeRegistry()
            ).resolved, command


class TestAUvxEntry:
    @pytest.mark.parametrize(
        ("args", "name", "selector"),
        [
            (["tool"], "tool", None),
            (["tool==2.0.1"], "tool", "==2.0.1"),
            (["tool>=2,<3"], "tool", ">=2,<3"),
            (["tool@2.0"], "tool", "2.0"),
            (["tool[extra]==2.0"], "tool", "==2.0"),
            (["--from", "tool==2.0", "tool-cli"], "tool", "==2.0"),
            (["--python", "3.12", "--isolated", "tool"], "tool", None),
        ],
    )
    def test_it_resolves_through_pypi(
        self, args: list[str], name: str, selector: str | None
    ) -> None:
        registry = FakeRegistry("pypi.org")
        found = McpResolver.resolve(Config.entry("uvx", *args), registry)
        assert found.resolved and found.subject_id == f"mcp:pypi/{name}"
        assert registry.asked == [("pypi", name, selector, None)]

    def test_an_index_flag_names_the_registry(self) -> None:
        registry = FakeRegistry("pypi.org")
        McpResolver.resolve(
            Config.entry("uvx", "--index-url", "https://pypi.corp.example/simple", "tool"), registry
        )
        assert registry.asked[0][3] == "pypi.corp.example"


class TestWhatIsNotRead:
    @pytest.mark.parametrize(
        ("config", "reason"),
        [
            (Config.entry("npx", "-y", "--some-new-flag", "tool"), "unparseable"),
            (Config.entry("npx", "-y", "--registry"), "unparseable"),
            (Config.entry("npx"), "unparseable"),
            (Config.entry("npx", "github:owner/repo"), "not_a_registry_package"),
            (Config.entry("npx", "git+https://example.invalid/r.git"), "not_a_registry_package"),
            (Config.entry("npx", "https://example.invalid/pkg.tgz"), "not_a_registry_package"),
            (Config.entry("npx", "./local-dir"), "not_a_registry_package"),
            (Config.entry("npx", "owner/repo"), "not_a_registry_package"),
            (
                Config.entry("uvx", "--from", "git+https://example.invalid/r.git", "tool"),
                "not_a_registry_package",
            ),
            (Config.entry("uvx", "--unknown", "tool"), "unparseable"),
            (Config.entry("node", "server.js"), "local_command"),
            (Config.entry("python", "-m", "server"), "local_command"),
            (Config.entry("/opt/server/run"), "local_command"),
            (Config.entry("docker", "run", "-i", "image@sha256:" + "0" * 64), "local_command"),
            ({"command": 5}, "unparseable"),
            ({}, "unparseable"),
            ({"command": "npx", "args": "tool"}, "unparseable"),
            ({"command": "npx", "args": ["tool", 3]}, "unparseable"),
        ],
    )
    def test_each_is_unresolved_with_its_reason_and_the_registry_is_not_asked(
        self, config: dict[str, Any], reason: str
    ) -> None:
        registry = FakeRegistry()
        found = McpResolver.resolve(config, registry)
        assert (found.resolved, found.reason, found.digest) == (False, reason, None)
        assert registry.asked == []

    def test_the_subject_of_an_unreadable_entry_names_it_by_hash_only(self) -> None:
        found = McpResolver.resolve(
            Config.entry("node", "/home/me/private-project/server.js"), FakeRegistry()
        )
        assert "private-project" not in found.subject_id and found.subject_id.startswith(
            "mcp:unparsed/"
        )


class TestARemoteServer:
    def test_a_url_entry_is_unresolved_until_the_tool_list_is_known(self) -> None:
        found = McpResolver.resolve({"url": "https://mcp.example.com/sse"}, FakeRegistry())
        assert (found.resolved, found.reason) == (False, "remote_server")
        assert found.subject_id == "mcp:remote/mcp.example.com/sse"

    def test_with_the_tool_list_it_resolves_to_the_canonical_digest(self) -> None:
        tools = [
            {"name": "b", "description": "second", "inputSchema": {"type": "object"}},
            {"name": "a", "description": "first"},
        ]
        found = McpResolver.remote("https://mcp.example.com/sse", tools)
        assert found.resolved and found.digest == ArtifactDigests.of_tool_list(reversed(tools))

    def test_a_tool_list_that_changes_is_another_digest(self) -> None:
        url = "https://mcp.example.com/sse"
        before = McpResolver.remote(url, [{"name": "a", "description": "reads files"}])
        after = McpResolver.remote(
            url, [{"name": "a", "description": "reads files and sends them"}]
        )
        assert before.digest != after.digest

    def test_a_url_that_is_not_https_is_unparseable(self) -> None:
        assert McpResolver.remote("http://mcp.example.com", []).reason == "unparseable"
        assert (
            McpResolver.resolve({"url": "http://mcp.example.com"}, FakeRegistry()).reason
            == "unparseable"
        )


class TestWhenTheRegistryCannotAnswer:
    def test_an_unreachable_registry_leaves_the_name_unresolved(self) -> None:
        registry = FakeRegistry()
        registry.down = True
        found = McpResolver.resolve(Config.entry("npx", "-y", "@x/y@1.0"), registry)
        assert (found.resolved, found.reason, found.digest) == (False, "source_unreachable", None)
        assert found.subject_id == "mcp:npm/%40x/y" and found.version == "1.0"
        assert found.evidence().unresolved is True

    def test_a_package_that_does_not_exist(self) -> None:
        registry = FakeRegistry()
        registry.missing.add("ghost")
        assert McpResolver.resolve(Config.entry("npx", "ghost"), registry).reason == "not_found"
