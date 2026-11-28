"""The install commands a coding agent runs, recognised for every ecosystem (`AgentCalls.INSTALLERS`), and the name and version each
spells (`InstallSpec`). Each command is the form its package manager documents for adding one package."""

from __future__ import annotations

import pytest

from cordon_scanner.cloud.agent.agent_hook import AgentCalls, NotInstalled
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.ecosystems.specs.install_specs import InstallSpec

#: (ecosystem, the command, the reference the hook asks about, the name and the version the spec gives)
COMMANDS = [
    ("npm", "npm install left-pad@1.3.0", "npm:left-pad@1.3.0", "left-pad", "1.3.0"),
    ("npm", "yarn add lodash", "npm:lodash", "lodash", None),
    ("pypi", "pip install requests==2.31.0", "pypi:requests==2.31.0", "requests", "2.31.0"),
    ("pypi", "uv add httpx", "pypi:httpx", "httpx", None),
    ("cargo", "cargo add serde@1.0.210", "cargo:serde@1.0.210", "serde", "1.0.210"),
    ("cargo", "cargo add regex", "cargo:regex", "regex", None),
    ("gomod", "go get golang.org/x/net@v0.20.0", "gomod:golang.org/x/net@v0.20.0", "golang.org/x/net", "v0.20.0"),
    ("gomod", "go install golang.org/x/tools/cmd/goimports@latest", "gomod:golang.org/x/tools/cmd/goimports@latest", "golang.org/x/tools/cmd/goimports", None),
    ("rubygems", "gem install nokogiri", "rubygems:nokogiri", "nokogiri", None),
    ("rubygems", "bundle add rack", "rubygems:rack", "rack", None),
    ("composer", "composer require monolog/monolog:^3.0", "composer:monolog/monolog:^3.0", "monolog/monolog", None),
    ("composer", "composer global require phpunit/phpunit", "composer:phpunit/phpunit", "phpunit/phpunit", None),
    ("nuget", "dotnet add package Newtonsoft.Json", "nuget:Newtonsoft.Json", "Newtonsoft.Json", None),
    ("nuget", "dotnet add app.csproj package Serilog", "nuget:Serilog", "Serilog", None),
    ("nuget", "nuget install Newtonsoft.Json", "nuget:Newtonsoft.Json", "Newtonsoft.Json", None),
    ("pub", "dart pub add http:^1.0.0", "pub:http:^1.0.0", "http", None),
    ("pub", "flutter pub add provider", "pub:provider", "provider", None),
    ("hex", "mix archive.install hex phx_new", "hex:phx_new", "phx_new", None),
    ("maven", "mvn dependency:get -Dartifact=org.apache.logging.log4j:log4j-core:2.14.1", "maven:org.apache.logging.log4j:log4j-core:2.14.1", "org.apache.logging.log4j:log4j-core", "2.14.1"),
    ("conda", "conda install numpy=1.26.4", "conda:numpy=1.26.4", "numpy", "1.26.4"),
    ("conda", "mamba install pandas", "conda:pandas", "pandas", None),
    ("homebrew", "brew install jq", "homebrew:jq", "jq", None),
    ("image", "docker pull nginx:1.25", "image:nginx:1.25", "nginx", "1.25"),
    ("image", "podman pull alpine", "image:alpine", "alpine", None),
    ("helm", "helm pull bitnami/redis", "helm:bitnami/redis", "bitnami/redis", None),
    ("helm", "helm install my-release bitnami/redis", "helm:bitnami/redis", "bitnami/redis", None),
    ("ansible", "ansible-galaxy collection install community.general", "ansible:community.general", "community.general", None),
    ("nix", "nix profile install nixpkgs#hello", "nix:nixpkgs#hello", "hello", None),
    ("nix", "nix-env -iA nixpkgs.hello", "nix:nixpkgs.hello", "nixpkgs.hello", None),
    ("swift", "swift package add-dependency https://github.com/apple/swift-argument-parser", "swift:https://github.com/apple/swift-argument-parser", "https://github.com/apple/swift-argument-parser", None),
    ("vcpkg", "vcpkg install zlib", "vcpkg:zlib", "zlib", None),
    ("conan", "conan install --requires=zlib/1.3.1", "conan:zlib/1.3.1", "zlib", "1.3.1"),
    ("cran", "Rscript -e 'install.packages(\"jsonlite\")'", "cran:jsonlite", "jsonlite", None),
    ("hackage", "cabal install aeson-2.2.3.0", "hackage:aeson-2.2.3.0", "aeson", "2.2.3.0"),
    ("hackage", "stack install pandoc", "hackage:pandoc", "pandoc", None),
    ("julia", "julia -e 'using Pkg; Pkg.add(\"JSON\")'", "julia:JSON", "JSON", None),
    ("opam", "opam install dune.3.15.3", "opam:dune.3.15.3", "dune", "3.15.3"),
    ("opam", "opam install cohttp", "opam:cohttp", "cohttp", None),
    ("vscode", "code --install-extension ms-python.python", "vscode:ms-python.python", "ms-python.python", None),
    ("vscode", "cursor --install-extension esbenp.prettier-vscode@11.0.0", "vscode:esbenp.prettier-vscode@11.0.0", "esbenp.prettier-vscode", "11.0.0"),
]  # fmt: skip


class Hook:
    @staticmethod
    def of(command: str) -> dict:
        return {"tool_name": "Bash", "tool_input": {"command": command}}


class TestEveryEcosystemIsRecognisedOrSaysWhy:
    def test_the_table_holds_exactly_the_registered_ecosystems(self) -> None:
        assert set(AgentCalls.INSTALLERS) == set(EcosystemRegistry.BY_ID)

    def test_an_ecosystem_with_no_install_command_says_why(self) -> None:
        for ecosystem, installers in AgentCalls.INSTALLERS.items():
            if isinstance(installers, NotInstalled):
                assert len(installers.reason.split()) >= 10, ecosystem

    def test_every_ecosystem_that_has_commands_has_a_case_here(self) -> None:
        with_commands = {
            e for e, i in AgentCalls.INSTALLERS.items() if not isinstance(i, NotInstalled)
        }
        assert {c[0] for c in COMMANDS} == with_commands

    def test_every_ecosystem_names_how_its_install_word_is_split(self) -> None:
        assert set(InstallSpec.KINDS) == set(EcosystemRegistry.BY_ID)


class TestTheCommandsOfEachManager:
    @pytest.mark.parametrize(
        ("ecosystem", "command", "reference", "name", "version"),
        COMMANDS,
        ids=[f"{c[0]}:{c[1][:40]}" for c in COMMANDS],
    )
    def test_the_install_is_gated_with_its_package(
        self, ecosystem: str, command: str, reference: str, name: str, version: str | None
    ) -> None:
        call = AgentCalls.of(Hook.of(command))
        assert call is not None and (call.what, call.resolver) == ("install", "package")
        assert call.reference == reference
        eco, _, spec = call.reference.partition(":")
        assert eco == ecosystem
        assert InstallSpec.split(ecosystem, spec) == (name, version)

    @pytest.mark.parametrize(
        "command",
        [
            "pip install -r requirements.txt",
            "npm install",
            "cargo build",
            "go build ./...",
            "docker ps",
            "brew update",
            "helm list",
            "terraform init",
            "gradle build",
            "pod install",
            "git clone https://example.invalid/x.git",
        ],
    )
    def test_a_command_that_installs_no_named_package_is_an_ordinary_command(
        self, command: str
    ) -> None:
        call = AgentCalls.of(Hook.of(command))
        assert call is not None and call.what == "run_command"
