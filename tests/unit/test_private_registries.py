"""Private registries asked with the operator's credential, and the credential kept where it belongs.

The transport is substituted at `urllib.request.build_opener`, so every request -- its URL and its
headers -- is seen, and nothing reaches a network."""

from __future__ import annotations

import hashlib
import io
import json
import urllib.error
from email.message import Message
from typing import Any

import pytest

from cordon_scanner.intel.private_registries import PrivateRegistries, PrivateRegistry
from cordon_scanner.intel.registry_client import PackageNotFound, RegistryError

TOKEN = "s3cr3t-registry-token-value"
NPM = PrivateRegistry("https://npm.acme.example", "ACME_NPM_TOKEN")
PYPI = PrivateRegistry("https://pypi.acme.example/simple", "ACME_PYPI_TOKEN")
OCI = PrivateRegistry("https://registry.acme.example", "ACME_OCI_TOKEN")


class FakeNetwork:
    """URL -> (status, body, headers). Every request is kept, headers and all."""

    def __init__(self, answers: dict[str, tuple[int, Any, dict[str, str]]]) -> None:
        self.answers = answers
        self.requests: list[tuple[str, dict[str, str]]] = []

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc) -> None:
            return None

    def opener(self, *handlers: Any) -> FakeNetwork:
        return self

    def open(self, request, timeout: float = 0):
        url = request.full_url
        self.requests.append((url, dict(request.header_items())))
        status, body, headers = self.answers.get(url, (404, b"", {}))
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        if status >= 300:
            message = Message()
            for key, value in headers.items():
                message[key] = value
            raise urllib.error.HTTPError(url, status, "status", message, io.BytesIO(data))
        return FakeNetwork.Response(data)


class PrivateHelpers:
    @staticmethod
    @pytest.fixture
    def network(monkeypatch):
        def install(answers):
            fake = FakeNetwork(answers)
            monkeypatch.setattr("urllib.request.build_opener", fake.opener)
            monkeypatch.setenv(NPM.variable, TOKEN)
            monkeypatch.setenv(PYPI.variable, "deploy:" + TOKEN)
            monkeypatch.setenv(OCI.variable, TOKEN)
            return fake

        return install


network = PrivateHelpers.network


class TestConfiguration:
    @pytest.mark.conformance("x", "x.private-registries")
    def test_url_and_variable_pairs(self) -> None:
        parsed = PrivateRegistries.parse(
            [
                "https://NPM.acme.example/=ACME_NPM_TOKEN, https://pypi.acme.example/simple=ACME_PYPI_TOKEN"
            ]
        )
        assert parsed == (
            PrivateRegistry("https://npm.acme.example", "ACME_NPM_TOKEN"),
            PrivateRegistry("https://pypi.acme.example/simple", "ACME_PYPI_TOKEN"),
        )

    @pytest.mark.conformance("x", "x.private-registries")
    @pytest.mark.parametrize(
        "value",
        [
            "http://npm.acme.example=VAR",
            "https://user:pw@npm.acme.example=VAR",
            "https://npm.acme.example?t=1=VAR",
            "https://npm.acme.example=" + TOKEN + "!",
            "npm.acme.example",
        ],
    )
    def test_anything_else_is_refused_without_repeating_it(self, value) -> None:
        with pytest.raises(ValueError) as refused:
            PrivateRegistries.parse([value])
        assert TOKEN not in str(refused.value) and "pw" not in str(refused.value)

    @pytest.mark.conformance("x", "x.private-registries")
    def test_what_came_from_a_registry_is_matched_to_it(self) -> None:
        configured = (NPM, OCI)
        assert (
            PrivateRegistries.matching(
                configured, "npm", "@acme/ui", "https://npm.acme.example/@acme/ui/-/ui-1.0.0.tgz"
            )
            == NPM
        )
        assert (
            PrivateRegistries.matching(
                configured,
                "npm",
                "left-pad",
                "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            )
            is None
        )
        # A host that merely starts like it is a different host.
        assert (
            PrivateRegistries.matching(
                configured, "npm", "x", "https://npm.acme.example.evil.example/x.tgz"
            )
            is None
        )
        assert (
            PrivateRegistries.matching(configured, "image", "registry.acme.example/team/api", None)
            == OCI
        )
        assert PrivateRegistries.matching(configured, "image", "ghcr.io/acme/api", None) is None


class TestTheCredentialStaysWhereItBelongs:
    @pytest.mark.conformance("x", "x.private-registries")
    def test_an_npm_registry_is_asked_with_its_token(self, network) -> None:
        fake = network(
            {
                "https://npm.acme.example/@acme/ui": (
                    200,
                    {
                        "versions": {
                            "1.0.0": {
                                "dist": {
                                    "integrity": "sha512-" + "A" * 86 + "==",
                                    "shasum": "c" * 40,
                                }
                            }
                        },
                        "dist-tags": {"latest": "1.2.0"},
                    },
                    {},
                )
            }
        )
        facts = PrivateRegistries.facts(NPM, "npm", "@acme/ui", "1.0.0")
        assert facts.digests[0] == "sha512-" + "A" * 86 + "==" and facts.latest == "1.2.0"
        [(url, headers)] = fake.requests
        assert (
            url == "https://npm.acme.example/@acme/ui"
            and headers["Authorization"] == f"Bearer {TOKEN}"
        )

    @pytest.mark.conformance("x", "x.private-registries")
    def test_a_python_index_is_asked_through_pep_691_with_basic_credentials(self, network) -> None:
        fake = network(
            {
                "https://pypi.acme.example/simple/acme-core/": (
                    200,
                    {
                        "files": [
                            {
                                "filename": "acme_core-2.0.0-py3-none-any.whl",
                                "hashes": {"sha256": "a" * 64},
                            },
                            {
                                "filename": "acme_core-1.0.0.tar.gz",
                                "hashes": {"sha256": "b" * 64},
                                "yanked": "broken",
                            },
                        ]
                    },
                    {},
                )
            }
        )
        assert PrivateRegistries.facts(PYPI, "pypi", "acme_core", "2.0.0").digests == (
            "sha256:" + "a" * 64,
        )
        assert PrivateRegistries.facts(PYPI, "pypi", "acme.core", "1.0.0").yanked_reason == "yanked"
        assert fake.requests[0][1]["Authorization"].startswith("Basic ")

    @pytest.mark.conformance("x", "x.private-registries")
    def test_a_container_registry_issues_its_own_token_on_its_own_host(self, network) -> None:
        manifest = json.dumps(
            {"schemaVersion": 2, "config": {"digest": "sha256:" + "c" * 64}}
        ).encode()
        fake = network(
            {
                "https://registry.acme.example/v2/": (
                    401,
                    b"",
                    {
                        "WWW-Authenticate": 'Bearer realm="https://registry.acme.example/token",service="registry"'
                    },
                ),
                "https://registry.acme.example/token?service=registry&scope=repository%3Ateam%2Fapi%3Apull": (
                    200,
                    {"token": "issued"},
                    {},
                ),
                "https://registry.acme.example/v2/team/api/tags/list": (200, {"tags": ["1.0"]}, {}),
                "https://registry.acme.example/v2/team/api/manifests/1.0": (200, manifest, {}),
            }
        )
        facts = PrivateRegistries.facts(OCI, "image", "registry.acme.example/team/api", "1.0")
        assert facts.digests == (f"sha256:{hashlib.sha256(manifest).hexdigest()}",)
        assert fake.requests[-1][1]["Authorization"] == "Bearer issued"

    @pytest.mark.conformance("x", "x.private-registries")
    def test_a_token_service_on_another_host_is_never_sent_the_credential(self, network) -> None:
        fake = network(
            {
                "https://registry.acme.example/v2/": (
                    401,
                    b"",
                    {"WWW-Authenticate": 'Bearer realm="https://collector.evil.example/token"'},
                )
            }
        )
        with pytest.raises(RegistryError, match="another host"):
            PrivateRegistries.facts(OCI, "image", "registry.acme.example/team/api", "1.0")
        assert all("evil.example" not in url for url, _ in fake.requests)

    @pytest.mark.conformance("x", "x.private-registries")
    def test_a_redirect_is_not_followed_and_no_message_repeats_the_token(self, network) -> None:
        network(
            {
                "https://npm.acme.example/x": (
                    302,
                    b"",
                    {"Location": "https://collector.evil.example/x"},
                )
            }
        )
        with pytest.raises(RegistryError) as refused:
            PrivateRegistries.facts(NPM, "npm", "x", "1.0.0")
        assert TOKEN not in str(refused.value)
        with pytest.raises(RegistryError, match="anywhere but"):
            PrivateRegistries.get(NPM, "https://collector.evil.example/x", TOKEN)

    @pytest.mark.conformance("x", "x.private-registries")
    def test_a_refused_or_missing_credential_names_the_variable_never_the_value(
        self, network, monkeypatch
    ) -> None:
        network({"https://npm.acme.example/x": (401, b"", {})})
        with pytest.raises(RegistryError) as refused:
            PrivateRegistries.facts(NPM, "npm", "x", "1.0.0")
        assert "ACME_NPM_TOKEN" in str(refused.value) and TOKEN not in str(refused.value)
        monkeypatch.delenv(NPM.variable)
        with pytest.raises(RegistryError, match="ACME_NPM_TOKEN is not set"):
            PrivateRegistries.facts(NPM, "npm", "x", "1.0.0")

    def test_unknown_packages(self, network) -> None:
        network({})
        with pytest.raises(PackageNotFound):
            PrivateRegistries.facts(NPM, "npm", "absent", "1.0.0")


class TestTheScanAsksThem:
    @pytest.mark.conformance("x", "x.private-registries")
    def test_a_private_dependency_is_verified_against_its_own_registry(
        self, tmp_path, monkeypatch
    ) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config
        from cordon_scanner.intel.registry_client import PackageFacts

        asked: list[str] = []

        def facts(registry, ecosystem, name, version):
            asked.append(f"{registry.host} {name} {version}")
            return PackageFacts(name=name, version=version, digests=("sha512-" + "B" * 86 + "==",))

        monkeypatch.setattr(PrivateRegistries, "facts", staticmethod(facts))
        lock = {
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "dependencies": {"@acme/ui": "1.0.0"}},
                "node_modules/@acme/ui": {
                    "version": "1.0.0",
                    "resolved": "https://npm.acme.example/@acme/ui/-/ui-1.0.0.tgz",
                    "integrity": "sha512-" + "A" * 86 + "==",
                },
            },
        }
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "dependencies": {"@acme/ui": "1.0.0"}})
        )
        (tmp_path / "package-lock.json").write_text(json.dumps(lock))
        config = Config.default().with_overrides(
            use_cache=False, offline=False, private_registries=((NPM.base, NPM.variable),)
        )
        result = Scanner(config).scan(tmp_path)
        assert asked == ["npm.acme.example @acme/ui 1.0.0"]
        assert any(f.rule_id == "SUSPECT.PROVENANCE.MISMATCH.001" for f in result.findings)
        assert TOKEN not in json.dumps(result.to_dict())

    @pytest.mark.conformance("x", "x.private-registries")
    def test_the_option_is_the_operators_alone(self, tmp_path) -> None:
        from cordon_scanner.cli.main import CommandLine
        from cordon_scanner.core.config import Config

        assert (
            CommandLine.run(
                [
                    "scan",
                    str(tmp_path),
                    "--offline",
                    "--registry-token",
                    "http://npm.acme.example=VAR",
                ]
            )
            == 3
        )
        # A repository's configuration has no key for it at all: naming one is refused.
        from cordon_scanner.core.errors import ConfigError

        (tmp_path / "cordon.yaml").write_text(
            "version: 1\nprivate_registries:\n  - https://collector.evil.example=HOME\n"
        )
        with pytest.raises(ConfigError, match="private_registries"):
            Config.from_untrusted_file(tmp_path / "cordon.yaml")
