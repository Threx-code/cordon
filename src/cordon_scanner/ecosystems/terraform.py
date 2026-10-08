"""Terraform (and OpenTofu): providers and modules.

```
  *.tf, *.tf.json        terraform { required_providers { name = { source, version,
                         configuration_aliases } } required_version }, provider blocks (with an
                         alias), and module blocks (source and version): from a registry
                         (`ns/name/provider`, or on another host), git (`git::https://...?ref=`,
                         `github.com/org/repo`), an archive URL, S3 / GCS, or a local path
  .terraform.lock.hcl    every provider Terraform selected: version, the constraints it met, and
                         its hashes -- `h1:` over the package, `zh:` the SHA-256 of each platform's
                         zip as the registry publishes it
```

A provider is a plugin binary Terraform runs with the cloud credentials the configuration holds:
recorded as a tool. A module is configuration Terraform evaluates. The lock covers every module of
the configuration rooted beside it; a module the configuration calls by local path is resolved by
that lock. Modules are not locked: a registry module at an exact version, or a git module at a
commit, is pinned; anything else is what the registry or the ref says on the day.

The configuration's resources are the IaC detectors' to judge; their findings stay apart from the
package findings here.
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.models import Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.core.content import FileContent


DEFAULT_REGISTRY = "registry.terraform.io"
PUBLIC_REGISTRIES = frozenset({DEFAULT_REGISTRY, "registry.opentofu.org"})


class HclError(ValueError):
    """Not readable HCL. The message never repeats the file's content."""


@dataclass
class Expression:
    """A value that is not a literal (a reference, a call, an interpolated string): kept as text."""

    text: str


@dataclass
class Block:
    type: str
    labels: list[str]
    attributes: dict[str, Any] = field(default_factory=dict)
    blocks: list[Block] = field(default_factory=list)


class HclLexer:
    """Tokens of HCL's native syntax: identifiers, numbers, strings (template literals, kept whole
    with their interpolations), heredocs, punctuation, and newlines, which end attributes."""

    PUNCTUATION: ClassVar[tuple[str, ...]] = (
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "=>",
        "...",
        "{",
        "}",
        "[",
        "]",
        "(",
        ")",
        "=",
        ":",
        ",",
        ".",
        "?",
        "+",
        "-",
        "*",
        "/",
        "%",
        "<",
        ">",
        "!",
    )
    MAX_TOKENS: ClassVar[int] = 1_000_000

    @staticmethod
    def tokens(text: str) -> list[tuple[str, str]]:
        # A Windows checkout's `\r\n`: the heredoc opener expects `\n` straight after its
        # marker and the closing line `[ \t]*$`, so with CRLF neither matched, the heredoc ran
        # on, and every block after it was lost. Only line ends change; nothing reads a column.
        text = text.replace("\r\n", "\n")
        out: list[tuple[str, str]] = []
        index, length = 0, len(text)
        while index < length:
            char = text[index]
            if char == "\n":
                out.append(("nl", "\n"))
                index += 1
            elif char in " \t\r":
                index += 1
            elif char == "#" or text.startswith("//", index):
                end = text.find("\n", index)
                index = length if end < 0 else end
            elif text.startswith("/*", index):
                end = text.find("*/", index + 2)
                if end < 0:
                    raise HclError("an unterminated comment")
                out.extend(("nl", "\n") for _ in range(text.count("\n", index, end)))
                index = end + 2
            elif char == '"':
                index, value, literal = HclLexer.string(text, index)
                out.append(("str" if literal else "template", value))
            elif text.startswith("<<", index) and re.match(
                r"<<-?[A-Za-z_][A-Za-z0-9_]*\n", text[index:]
            ):
                heredoc = re.match(r"<<-?([A-Za-z_][A-Za-z0-9_]*)\n", text[index:])
                if heredoc is None:
                    raise HclError("a heredoc without its marker")
                marker = heredoc.group(1)
                closing = re.compile(rf"(?m)^[ \t]*{re.escape(marker)}[ \t]*$").search(
                    text, index + heredoc.end()
                )
                if closing is None:
                    raise HclError("an unterminated heredoc")
                out.append(("template", text[index + heredoc.end() : closing.start()]))
                out.extend(
                    ("nl", "\n") for _ in range(text.count("\n", index, closing.start()) - 1)
                )
                index = closing.end()
            elif char.isalpha() or char == "_":
                word = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*").match(text, index)
                if word is None:
                    raise HclError("an unreadable identifier")
                out.append(("ident", word.group(0)))
                index = word.end()
            elif char.isdigit():
                number = re.compile(r"\d+(?:\.\d+)?(?:[eE][+-]?\d+)?").match(text, index)
                if number is None:
                    raise HclError("an unreadable number")
                out.append(("number", number.group(0)))
                index = number.end()
            else:
                symbol = next((p for p in HclLexer.PUNCTUATION if text.startswith(p, index)), None)
                if symbol is None:
                    raise HclError("a character that is not part of HCL")
                out.append(("punct", symbol))
                index += len(symbol)
            if len(out) > HclLexer.MAX_TOKENS:
                raise HclError("more tokens than a configuration holds")
        return out

    @staticmethod
    def string(text: str, index: int) -> tuple[int, str, bool]:
        """`(end, value, literal)` for the quoted string at `index`: literal when it holds no
        `${...}` or `%{...}`, whose braces and nested strings are followed to their close."""
        index += 1
        buffer: list[str] = []
        literal = True
        while index < len(text):
            char = text[index]
            if char == "\n":
                raise HclError("a string that does not close on its line")
            if char == "\\" and index + 1 < len(text):
                buffer.append(
                    {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(
                        text[index + 1], text[index + 1]
                    )
                )
                index += 2
                continue
            if char == '"':
                return index + 1, "".join(buffer), literal
            if text.startswith(("${", "%{"), index) and not text.startswith(
                ("$${", "%%{"), index - 1 if index else 0
            ):
                literal = False
                depth, start = 0, index
                while index < len(text):
                    if text[index] == "{":
                        depth += 1
                    elif text[index] == "}":
                        depth -= 1
                        if depth == 0:
                            index += 1
                            break
                    elif text[index] == '"' and depth > 0:
                        index, _value, _literal = HclLexer.string(text, index)
                        continue
                    index += 1
                else:
                    raise HclError("an interpolation that does not close")
                buffer.append(text[start:index])
                continue
            buffer.append(char)
            index += 1
        raise HclError("an unterminated string")


class HclParser:
    MAX_DEPTH: ClassVar[int] = 64

    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.index = 0

    def peek(self) -> tuple[str, str] | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self) -> tuple[str, str]:
        token = self.peek()
        if token is None:
            raise HclError("the file ends inside a block")
        self.index += 1
        return token

    def body(self, close: str | None, depth: int) -> Block:
        if depth > HclParser.MAX_DEPTH:
            raise HclError("blocks nested too deeply")
        block = Block("", [])
        while True:
            token = self.peek()
            if token is None:
                if close is not None:
                    raise HclError("a block that does not close")
                return block
            if token == ("punct", close or ""):
                self.take()
                return block
            if token[0] == "nl":
                self.take()
                continue
            kind, name = self.take()
            if kind != "ident":
                raise HclError("a line that is neither an attribute nor a block")
            following = self.peek()
            if following == ("punct", "="):
                self.take()
                block.attributes[name] = self.expression(depth + 1, stops=("nl", close))
                continue
            labels: list[str] = []
            while (label := self.peek()) is not None and label[0] in ("str", "ident"):
                labels.append(self.take()[1])
            if self.peek() != ("punct", "{"):
                raise HclError("a block without its opening brace")
            self.take()
            inner = self.body("}", depth + 1)
            inner.type, inner.labels = name, labels
            block.blocks.append(inner)

    def expression(self, depth: int, stops: tuple[str | None, ...]) -> Any:
        """A value up to the end of its line (or its enclosing bracket): a literal string,
        object or tuple when it is one, otherwise the expression's text."""
        if depth > HclParser.MAX_DEPTH:
            raise HclError("a value nested too deeply")
        start = self.index
        first = self.peek()
        value: Any = None
        if first is not None and first[0] == "str":
            self.take()
            value = first[1]
        elif first == ("punct", "{"):
            self.take()
            value = self.object(depth + 1)
        elif first == ("punct", "["):
            self.take()
            value = self.tuple(depth + 1)
        # Anything further on the line (an operator, a traversal) makes it an expression.
        nesting = 0
        while (token := self.peek()) is not None:
            if nesting == 0 and (token[0] in stops or token[1] in stops or token == ("punct", ",")):
                break
            if token[1] in ("{", "[", "("):
                nesting += 1
            elif token[1] in ("}", "]", ")"):
                if nesting == 0:
                    break
                nesting -= 1
            elif token[0] == "nl" and nesting == 0:
                break
            self.take()
            value = None
        if value is None:
            return Expression(HclParser.render(self.tokens[start : self.index]))
        return value

    @staticmethod
    def render(tokens: list[tuple[str, str]]) -> str:
        """An expression's text as written: `time.secondary`, `var.x + 1`."""
        out = ""
        previous = ""
        for kind, text in tokens:
            if kind == "nl":
                continue
            # Tight around traversal, separators and brackets (`f(a, b)[0].x`), spaced elsewhere.
            tight = (
                text in (".", ",", ")", "]")
                or previous in (".", "(", "[")
                or (text in ("(", "[") and previous in ("word", ")", "]"))
            )
            if out and not tight:
                out += " "
            out += f'"{text}"' if kind in ("str", "template") else text
            previous = text if kind == "punct" else "word"
        return out

    def object(self, depth: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        while True:
            token = self.take()
            if token[0] == "nl" or token == ("punct", ","):
                continue
            if token == ("punct", "}"):
                return out
            if token[0] not in ("ident", "str"):
                # A computed key (`(var.x) = ...`): read past it.
                self.expression(depth + 1, stops=("=", ":"))
                key = None
            else:
                key = token[1]
            separator = self.take()
            if separator[1] not in ("=", ":"):
                raise HclError("an object item without = or :")
            value = self.expression(depth + 1, stops=("nl", "}", ","))
            if key is not None:
                out[key] = value

    def tuple(self, depth: int) -> list[Any]:
        out: list[Any] = []
        while True:
            token = self.peek()
            if token is None:
                raise HclError("a tuple that does not close")
            if token[0] == "nl" or token == ("punct", ","):
                self.take()
                continue
            if token == ("punct", "]"):
                self.take()
                return out
            out.append(self.expression(depth + 1, stops=("nl", "]", ",")))

    @staticmethod
    def parse(text: str) -> Block:
        return HclParser(HclLexer.tokens(text)).body(None, 0)


class ModuleSource:
    """A module `source` as a spec, and the name it is known by."""

    REGISTRY: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:(?P<host>[a-z0-9.\-]+\.[a-z]{2,}(?::\d+)?)/)?(?P<namespace>[A-Za-z0-9][\w\-]*)/(?P<name>[A-Za-z0-9][\w\-]*)/(?P<provider>[a-z0-9][a-z0-9\-]*)(?://(?P<sub>.+))?$"
    )

    @staticmethod
    def read(source: str, version: str | None) -> tuple[str, str, str | None]:
        """`(name, spec, registry)`: registry is a host other than the public registries."""
        if source.startswith(("./", "../")):
            return source.rstrip("/"), f"path:{source}", None
        registry = ModuleSource.REGISTRY.match(source)
        if registry and not source.startswith(("github.com/", "bitbucket.org/")):
            host = registry.group("host")
            name = f"{registry.group('namespace')}/{registry.group('name')}/{registry.group('provider')}"
            private = f"registry:{host}" if host and host not in PUBLIC_REGISTRIES else None
            return (f"{host}/{name}" if private else name), (version or "*"), private
        url = source
        for prefix in ("git::", "hg::"):
            if url.startswith(prefix):
                url = "git+" + url.removeprefix(prefix)
        # An archive in a bucket: `s3::https://...` and `gcs::https://...` are the URL fetched.
        url = url.removeprefix("s3::").removeprefix("gcs::")
        if url.startswith(("github.com/", "bitbucket.org/")):
            url = "git+https://" + url
        if url.startswith("git@"):
            url = "git+ssh://" + url.replace(":", "/", 1)
        ref = None
        if "?" in url:
            url, _, query = url.partition("?")
            ref = next(
                (v for k, _, v in (p.partition("=") for p in query.split("&")) if k == "ref"), None
            )
        if url.startswith("git+"):
            # `git+https://host/org/repo.git//subdir`: the repository, then the subdirectory.
            scheme, _, rest = url.partition("://")
            base = f"{scheme}://{rest.split('//', 1)[0]}"
            spec = base + (f"#{ref}" if ref else "")
        else:
            base = spec = url
        name = re.sub(r"\.(?:git|zip|tar\.gz|tgz)$", "", base.rstrip("/").rsplit("/", 1)[-1])
        return name or source, spec, None


class TerraformConfiguration:
    """The .tf / .tf.json files of one module directory, read one file at a time."""

    @staticmethod
    def blocks(content: FileContent) -> Block:
        if content.basename.endswith(".json"):
            return TerraformConfiguration.from_json(content)
        return HclParser.parse(content.text)

    @staticmethod
    def from_json(content: FileContent) -> Block:
        data = BaseEcosystem._json_object(content.text)
        root = Block("", [])

        def entries(value: object) -> list[dict[str, Any]]:
            return [
                v for v in (value if isinstance(value, list) else [value]) if isinstance(v, dict)
            ]

        for terraform in entries(data.get("terraform")):
            block = Block(
                "terraform", [], {k: v for k, v in terraform.items() if k != "required_providers"}
            )
            for providers in entries(terraform.get("required_providers")):
                block.blocks.append(Block("required_providers", [], dict(providers)))
            root.blocks.append(block)
        for kind in ("module", "provider"):
            for group in entries(data.get(kind)):
                for label, bodies in group.items():
                    for body in entries(bodies):
                        root.blocks.append(Block(kind, [label], dict(body)))
        return root

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            root = TerraformConfiguration.blocks(content)
        except (HclError, json.JSONDecodeError, ValueError) as exc:
            return BaseEcosystem._err(
                content, ecosystem, f"not readable Terraform configuration: {exc}"
            )
        declared: list[DeclaredDependency] = []
        sources: list[str] = []
        for block in root.blocks:
            if block.type == "terraform":
                required = block.attributes.get("required_version")
                if isinstance(required, str):
                    declared.append(
                        DeclaredDependency(
                            name="terraform",
                            spec=required,
                            scope=Scope.PLATFORM,
                            field_name="required_version",
                        )
                    )
                for providers in (b for b in block.blocks if b.type == "required_providers"):
                    for local_name, requirement in providers.attributes.items():
                        declared.append(TerraformConfiguration.provider(local_name, requirement))
            elif block.type == "module" and block.labels:
                source = block.attributes.get("source")
                if not isinstance(source, str):
                    continue
                version = block.attributes.get("version")
                name, spec, registry = ModuleSource.read(
                    source, version if isinstance(version, str) else None
                )
                declared.append(
                    DeclaredDependency(
                        name=name,
                        spec=spec,
                        scope=Scope.RUNTIME,
                        field_name=f"module.{block.labels[0]}",
                        alias=block.labels[0],
                        source=registry,
                        # Terraform's lock holds providers only: a module is whatever its version
                        # or ref names when `terraform init` runs.
                        note="a module: Terraform locks providers, not modules, so init fetches what the version or ref names on the day",
                    )
                )
            elif block.type == "provider" and block.labels:
                alias = block.attributes.get("alias")
                if isinstance(alias, str):
                    sources.append(f"provider {block.labels[0]} alias {alias}")
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            sources=tuple(sources),
        )

    @staticmethod
    def provider(local_name: str, requirement: Any) -> DeclaredDependency:
        """`aws = { source = "hashicorp/aws", version = "~> 5.0" }`, or the pre-0.13 `aws = "~> 5.0"`."""
        source = f"hashicorp/{local_name}"
        version = "*"
        aliases: list[str] = []
        if isinstance(requirement, str):
            version = requirement
        elif isinstance(requirement, dict):
            if isinstance(requirement.get("source"), str):
                source = requirement["source"]
            if isinstance(requirement.get("version"), str):
                version = requirement["version"]
            listed = requirement.get("configuration_aliases")
            aliases = (
                [a.text if isinstance(a, Expression) else str(a) for a in listed]
                if isinstance(listed, list)
                else []
            )
        name, registry = TerraformProviders.address(source)
        return DeclaredDependency(
            name=name,
            spec=version,
            scope=Scope.TOOL,
            field_name=f"required_providers.{local_name}",
            alias=local_name if local_name != name.rsplit("/", 1)[-1] else None,
            source=registry,
            platform=tuple(f"configuration alias {a}" for a in aliases),
        )


class TerraformProviders:
    @staticmethod
    def address(source: str) -> tuple[str, str | None]:
        """`(name, registry)` of a provider source: `hashicorp/aws` on the public registry, the full
        address on any other host (a private registry)."""
        parts = source.lower().split("/")
        if len(parts) == 3:
            host, namespace, kind = parts
            if host in PUBLIC_REGISTRIES:
                return f"{namespace}/{kind}", None
            return f"{host}/{namespace}/{kind}", f"registry:{host}"
        if len(parts) == 2:
            return source.lower(), None
        return f"hashicorp/{source.lower()}", None


class TerraformLock:
    """.terraform.lock.hcl."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            root = HclParser.parse(content.text)
        except HclError as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"not a readable lock file: {exc}",
            )
        entries: list[LockEntry] = []
        for block in root.blocks:
            if block.type != "provider" or not block.labels:
                continue
            version = block.attributes.get("version")
            if not isinstance(version, str):
                return LockGraph(
                    path=content.path,
                    ecosystem=ecosystem,
                    parse_error="a locked provider without its version",
                )
            name, registry = TerraformProviders.address(block.labels[0])
            # A provider from another host came from outside the public registry: where it came
            # from is recorded as that host, for the source rules to report.
            origin = f"https://{block.labels[0].lower()}" if registry else None
            hashes = [h for h in block.attributes.get("hashes") or [] if isinstance(h, str)]
            # A zip hash is the SHA-256 the registry publishes for a platform's archive; h1 covers
            # the package's contents. The first of the zip hashes is what the registry can confirm.
            zipped = [h for h in hashes if h.startswith("zh:")]
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=zipped[0] if zipped else hashes[0] if hashes else None,
                    resolved_from=origin,
                    scope=Scope.TOOL,
                )
            )
        if not entries and "provider" in content.text:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="a lock file whose providers could not be read",
            )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))


class TerraformEcosystem(BaseEcosystem):
    """Terraform providers and modules."""

    id = "terraform"
    purl_type = "terraform"
    manifest_globs: tuple[str, ...] = ("**/*.tf", "**/*.tf.json")
    lockfile_globs: tuple[str, ...] = ("**/.terraform.lock.hcl",)
    registry_hosts: frozenset[str] = frozenset({"registry.terraform.io", "registry.opentofu.org"})

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        return self.parse_in_tree(content, {content.path: content})

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        """A module directory without a lock of its own is resolved by the lock of the root
        module above it, which Terraform writes for the whole configuration."""
        manifest = TerraformConfiguration.parse(content, self.id)
        directory = content.path.rpartition("/")[0]
        if (
            manifest.parse_error
            or (f"{directory}/.terraform.lock.hcl" if directory else ".terraform.lock.hcl") in files
        ):
            return manifest
        ancestor = directory
        while ancestor:
            ancestor = ancestor.rpartition("/")[0]
            if (f"{ancestor}/.terraform.lock.hcl" if ancestor else ".terraform.lock.hcl") in files:
                return dataclasses.replace(manifest, locked_by=ancestor)
        return manifest

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return TerraformLock.parse(content, self.id)


__all__ = [
    "Block",
    "HclLexer",
    "HclParser",
    "ModuleSource",
    "TerraformConfiguration",
    "TerraformEcosystem",
    "TerraformLock",
    "TerraformProviders",
]
