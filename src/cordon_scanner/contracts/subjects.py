"""The subjects a decision is about, and the one canonical id each has (design spec 3.1 to 3.3).

A tool says what it sees in its own terms -- "npm install @Scope/Left_Pad", "uses: Actions/Checkout@v4",
"nginx:1.27" -- and Cordon decides on one stable name for the thing. This module turns what a tool says
into that name: `CanonicalIds.canonical_id(kind, parts)`.

```
  package            pkg:<type>/<namespace>/<name>                       purl, registry-specific folding
  container image    pkg:oci/<name>?repository_url=<registry>             tag and digest are not the subject
  CI action          ci:github/<owner>/<repo>[/<path>]  ci:gitlab/<project>/<component>
  IDE extension      ext:<marketplace>/<publisher>.<name>
  agent skill        skill:<source>/<locator>                              gh | registry | local | archive
  MCP server         mcp:<transport>/<locator>                             npm | pypi | oci | remote | local
  AI model           model:<provider>/<name>   or   pkg:huggingface/<repo>
  agent              agent:<product>
  source repository  repo:<scm>/<owner>/<name>
  build artifact     art:<tenant-scope>/<name>
  third-party integ. int:<vendor>/<integration>                          version or contract digest
```

Pure and total: the same parts give the same id on every platform and in every run (no locale, no
environment, no filesystem), and a part that cannot be made canonical raises `InvalidSubject` naming it,
never a guess. A version is not part of an id: decisions bind to digests, and names only resolve (I2).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import StrEnum
from typing import ClassVar, Final
from urllib.parse import quote, urlsplit

from cordon_scanner.contracts.name_fold import NameFolds


class SubjectKind(StrEnum):
    """The kinds of thing Cordon decides on."""

    PACKAGE = "package"
    CONTAINER_IMAGE = "container_image"
    CI_ACTION = "ci_action"
    IDE_EXTENSION = "ide_extension"
    AGENT_SKILL = "agent_skill"
    MCP_SERVER = "mcp_server"
    AI_MODEL = "ai_model"
    AGENT = "agent"
    SOURCE_REPOSITORY = "source_repository"
    BUILD_ARTIFACT = "build_artifact"
    THIRD_PARTY_INTEGRATION = "third_party_integration"


class InvalidSubject(ValueError):
    """A part of a subject is missing or cannot be made canonical; the message names the part."""


_SEGMENT: Final = re.compile(r"[^\s/\\?#]+")


class SubjectParts:
    """The vocabulary and the checks the canonical forms share: what each registry folds, and what a part may be."""

    #: The purl type of each name an ecosystem goes by.
    PURL_TYPES: ClassVar[dict[str, str]] = {
        "go": "golang",
        "gomod": "golang",
        "rust": "cargo",
        "crates": "cargo",
        "crates.io": "cargo",
        "rubygems": "gem",
        "ruby": "gem",
        "python": "pypi",
        "node": "npm",
        "dotnet": "nuget",
        "php": "composer",
        "java": "maven",
        "docker": "oci",
        # The container-image subject kind owns `pkg:oci/`; a package whose ecosystem is `image` keeps its own type.
        "image": "image",
    }
    SKILL_SOURCES: ClassVar[tuple[str, ...]] = ("gh", "registry", "local", "archive")
    MCP_TRANSPORTS: ClassVar[tuple[str, ...]] = ("npm", "pypi", "oci", "remote", "local")
    SOURCE_CONTROL: ClassVar[tuple[str, ...]] = ("github", "gitlab", "bitbucket", "git")
    MARKETPLACES: ClassVar[tuple[str, ...]] = ("vscode", "openvsx", "jetbrains")
    DEFAULT_REGISTRY: ClassVar[str] = "docker.io"

    @staticmethod
    def is_registry(first: str) -> bool:
        """Whether the first part of an image name is a registry host, not a repository."""
        return "." in first or ":" in first or first == "localhost"

    @classmethod
    def purl_type(cls, ecosystem: str) -> str:
        key = ecosystem.strip().lower()
        purl_type = cls.PURL_TYPES.get(key, key)
        if not re.fullmatch(r"[a-z][a-z0-9.+-]*", purl_type):
            raise InvalidSubject(f"ecosystem: {ecosystem!r} is not a package type")
        return purl_type

    @staticmethod
    def collapse(text: str) -> str:
        """`text` with each run of `-`, `_` and `.` written as one `-` (PEP 503)."""
        out: list[str] = []
        for char in text:
            if char in "-_.":
                if not out or out[-1] != "-":
                    out.append("-")
            else:
                out.append(char)
        return "".join(out)

    @classmethod
    def fold(cls, text: str, lower: bool, one_separator: bool) -> str:
        text = cls.collapse(text) if one_separator else text
        return text.lower() if lower else text

    @staticmethod
    def need(parts: Mapping[str, str], field: str) -> str:
        value = parts.get(field)
        if value is None or not str(value).strip():
            raise InvalidSubject(f"{field}: is required")
        return str(value).strip()

    @staticmethod
    def optional(parts: Mapping[str, str], field: str) -> str | None:
        value = parts.get(field)
        return str(value).strip() or None if value is not None else None

    @classmethod
    def choice(cls, parts: Mapping[str, str], field: str, allowed: tuple[str, ...]) -> str:
        value = cls.need(parts, field).lower()
        if value not in allowed:
            raise InvalidSubject(f"{field}: {value!r} is not one of {', '.join(allowed)}")
        return value

    @staticmethod
    def single(text: str, field: str) -> str:
        text = text.strip()
        if not _SEGMENT.fullmatch(text):
            raise InvalidSubject(f"{field}: {text!r} is not one name")
        return text

    @classmethod
    def path(cls, text: str, field: str) -> list[str]:
        pieces = [piece for piece in text.strip().replace("\\", "/").split("/") if piece]
        if not pieces or any(
            not _SEGMENT.fullmatch(piece) or piece in (".", "..") for piece in pieces
        ):
            raise InvalidSubject(f"{field}: {text!r} is not a path of names")
        return pieces

    @classmethod
    def relative(cls, text: str) -> list[str]:
        pieces = cls.path(text, "locator")
        if text.strip().startswith(("/", "\\")) or ".." in pieces:
            raise InvalidSubject(f"locator: {text!r} is not a relative path inside the folder")
        return pieces

    @staticmethod
    def digest(text: str, field: str) -> str:
        value = text.strip().lower().removeprefix("sha256:")
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise InvalidSubject(f"{field}: {text!r} is not a sha256 digest")
        return f"sha256-{value}"

    @classmethod
    def remote(cls, locator: str) -> str:
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in locator.strip()):
            raise InvalidSubject(f"locator: {locator!r} has a blank or a control character in it")
        url = urlsplit(locator.strip())
        if url.scheme.lower() != "https" or not url.hostname:
            raise InvalidSubject(f"locator: {locator!r} is not an https URL")
        port = f":{url.port}" if url.port not in (None, 443) else ""
        path = url.path.rstrip("/")
        return f"{url.hostname.lower()}{port}{path}"


class CanonicalIds:
    """`canonical_id(kind, parts)`: the one name for a subject, whatever way a tool spelled it."""

    @classmethod
    def canonical_id(cls, kind: SubjectKind, parts: Mapping[str, str]) -> str:
        """The canonical subject id of `kind` for the fields a tool gave (`parts`), per kind:

        package: ecosystem, name, [namespace]; container_image: name, [registry]; ci_action: host
        (github | gitlab), owner, repo, [path]; ide_extension: marketplace, publisher, name;
        agent_skill: source, locator; mcp_server: transport, locator; ai_model: provider, name;
        agent: product; source_repository: scm, owner, name; build_artifact: scope, name;
        third_party_integration: vendor, integration."""
        kind = SubjectKind(kind)
        build = {
            SubjectKind.PACKAGE: cls._package,
            SubjectKind.CONTAINER_IMAGE: cls._image,
            SubjectKind.CI_ACTION: cls._action,
            SubjectKind.IDE_EXTENSION: cls._extension,
            SubjectKind.AGENT_SKILL: cls._skill,
            SubjectKind.MCP_SERVER: cls._mcp,
            SubjectKind.AI_MODEL: cls._model,
            SubjectKind.AGENT: cls._agent,
            SubjectKind.SOURCE_REPOSITORY: cls._repository,
            SubjectKind.BUILD_ARTIFACT: cls._artifact,
            SubjectKind.THIRD_PARTY_INTEGRATION: cls._integration,
        }[kind]
        return build(parts)

    # -- the kinds -------------------------------------------------------------------------------

    @classmethod
    def _package(cls, parts: Mapping[str, str]) -> str:
        purl_type = SubjectParts.purl_type(SubjectParts.need(parts, "ecosystem"))
        name = SubjectParts.need(parts, "name")
        namespace = SubjectParts.optional(parts, "namespace")
        if namespace is None and "/" in name:
            namespace, _, name = name.rpartition("/")
        fold = NameFolds.of(SubjectParts.need(parts, "ecosystem"), purl_type)
        if namespace:
            namespace = "/".join(
                SubjectParts.fold(piece, fold.lower, False)
                for piece in SubjectParts.path(namespace, "namespace")
            )
        name = SubjectParts.fold(SubjectParts.single(name, "name"), fold.lower, fold.one_separator)
        encoded = quote(name, safe="")
        if namespace:
            encoded_namespace = "/".join(quote(piece, safe="") for piece in namespace.split("/"))
            return f"pkg:{purl_type}/{encoded_namespace}/{encoded}"
        return f"pkg:{purl_type}/{encoded}"

    @classmethod
    def _image(cls, parts: Mapping[str, str]) -> str:
        name = SubjectParts.need(parts, "name").split("@", 1)[0]
        if ":" in name.rsplit("/", 1)[-1]:
            name = name.rsplit(":", 1)[0]
        registry = SubjectParts.optional(parts, "registry")
        pieces = SubjectParts.path(name, "name")
        if registry is None and len(pieces) > 1 and SubjectParts.is_registry(pieces[0]):
            registry, pieces = pieces[0], pieces[1:]
        registry = (registry or SubjectParts.DEFAULT_REGISTRY).lower().rstrip("/")
        pieces = [piece.lower() for piece in pieces]
        if registry == SubjectParts.DEFAULT_REGISTRY and len(pieces) == 1:
            pieces = ["library", *pieces]
        return f"pkg:oci/{quote('/'.join(pieces), safe='/')}?repository_url={quote(registry, safe='.:-')}"

    @classmethod
    def _action(cls, parts: Mapping[str, str]) -> str:
        host = SubjectParts.need(parts, "host").lower()
        if host == "github":
            owner = SubjectParts.need(parts, "owner").lower()
            repo = SubjectParts.need(parts, "repo").lower()
            path = SubjectParts.optional(parts, "path")
            tail = "/" + "/".join(SubjectParts.path(path, "path")) if path else ""
            return f"ci:github/{SubjectParts.single(owner, 'owner')}/{SubjectParts.single(repo, 'repo')}{tail}"
        if host == "gitlab":
            project = "/".join(
                piece.lower()
                for piece in SubjectParts.path(SubjectParts.need(parts, "project"), "project")
            )
            component = "/".join(
                SubjectParts.path(SubjectParts.need(parts, "component"), "component")
            )
            return f"ci:gitlab/{project}/{component}"
        raise InvalidSubject(f"host: {host!r} is not one of github, gitlab")

    @classmethod
    def _extension(cls, parts: Mapping[str, str]) -> str:
        marketplace = SubjectParts.choice(parts, "marketplace", SubjectParts.MARKETPLACES)
        publisher = SubjectParts.single(SubjectParts.need(parts, "publisher"), "publisher").lower()
        name = SubjectParts.single(SubjectParts.need(parts, "name"), "name").lower()
        return f"ext:{marketplace}/{publisher}.{name}"

    @classmethod
    def _skill(cls, parts: Mapping[str, str]) -> str:
        source = SubjectParts.choice(parts, "source", SubjectParts.SKILL_SOURCES)
        locator = SubjectParts.need(parts, "locator")
        if source == "local":
            return f"skill:local/{'/'.join(SubjectParts.relative(locator))}"
        if source == "archive":
            return f"skill:archive/{SubjectParts.digest(locator, 'locator')}"
        pieces = SubjectParts.path(locator, "locator")
        # A GitHub skill is owner/repo[/path]: the owner and the repository are case-insensitive, the
        # path is not. A registry skill is a name.
        folded = 2 if source == "gh" else len(pieces)
        pieces = [piece.lower() for piece in pieces[:folded]] + pieces[folded:]
        return f"skill:{source}/{'/'.join(pieces)}"

    @classmethod
    def _mcp(cls, parts: Mapping[str, str]) -> str:
        transport = SubjectParts.choice(parts, "transport", SubjectParts.MCP_TRANSPORTS)
        locator = SubjectParts.need(parts, "locator")
        build = {
            "npm": cls._mcp_package,
            "pypi": cls._mcp_package,
            "oci": cls._mcp_image,
            "remote": cls._mcp_remote,
            "local": cls._mcp_local,
        }[transport]
        return f"mcp:{transport}/{build(transport, locator, parts)}"

    @classmethod
    def _mcp_package(cls, transport: str, locator: str, parts: Mapping[str, str]) -> str:
        return cls._package({"ecosystem": transport, "name": locator}).split("/", 1)[1]

    @classmethod
    def _mcp_image(cls, transport: str, locator: str, parts: Mapping[str, str]) -> str:
        image = cls._image(
            {"name": locator, "registry": SubjectParts.optional(parts, "registry") or ""}
        )
        return image.split("/", 1)[1]

    @classmethod
    def _mcp_remote(cls, transport: str, locator: str, parts: Mapping[str, str]) -> str:
        return SubjectParts.remote(locator)

    @classmethod
    def _mcp_local(cls, transport: str, locator: str, parts: Mapping[str, str]) -> str:
        words = locator.split()
        program = words[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        return " ".join([program, *words[1:]])

    @classmethod
    def _model(cls, parts: Mapping[str, str]) -> str:
        provider = SubjectParts.single(SubjectParts.need(parts, "provider"), "provider").lower()
        name = SubjectParts.need(parts, "name")
        if provider == "huggingface":
            return f"pkg:huggingface/{'/'.join(quote(piece, safe='') for piece in SubjectParts.path(name, 'name'))}"
        return f"model:{provider}/{SubjectParts.single(name, 'name')}"

    @classmethod
    def _agent(cls, parts: Mapping[str, str]) -> str:
        product = "-".join(SubjectParts.need(parts, "product").lower().split())
        if not _SEGMENT.fullmatch(product):
            raise InvalidSubject(f"product: {product!r} is not a name")
        return f"agent:{product}"

    @classmethod
    def _repository(cls, parts: Mapping[str, str]) -> str:
        scm = SubjectParts.choice(parts, "scm", SubjectParts.SOURCE_CONTROL)
        owner = SubjectParts.single(SubjectParts.need(parts, "owner"), "owner")
        name = SubjectParts.single(SubjectParts.need(parts, "name"), "name")
        name = name[:-4] if name.endswith(".git") else name
        if scm != "git":
            owner, name = owner.lower(), name.lower()
        return f"repo:{scm}/{owner}/{name}"

    @classmethod
    def _integration(cls, parts: Mapping[str, str]) -> str:
        """`int:<vendor>/<integration>`: an external API, SaaS app or connector a tenant allows software or an agent to call.
        Both names are case-insensitive and a run of blanks in one is written as one `-`."""
        vendor = cls._dashed(SubjectParts.need(parts, "vendor"), "vendor")
        integration = cls._dashed(SubjectParts.need(parts, "integration"), "integration")
        return f"int:{vendor}/{integration}"

    @staticmethod
    def _dashed(text: str, field: str) -> str:
        name = "-".join(text.lower().split())
        if not _SEGMENT.fullmatch(name):
            raise InvalidSubject(f"{field}: {name!r} is not a name")
        return name

    @classmethod
    def _artifact(cls, parts: Mapping[str, str]) -> str:
        scope = SubjectParts.single(SubjectParts.need(parts, "scope"), "scope").lower()
        return (
            f"art:{scope}/{'/'.join(SubjectParts.path(SubjectParts.need(parts, 'name'), 'name'))}"
        )


__all__ = ["CanonicalIds", "InvalidSubject", "SubjectKind", "SubjectParts"]
