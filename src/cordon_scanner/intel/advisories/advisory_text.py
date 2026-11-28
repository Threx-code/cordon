"""The vulnerable functions an advisory's own text names, for ecosystems whose sources list none.

The Go vulnerability database lists vulnerable symbols for nearly every record; the PyPI and npm
sources essentially never do (measured: none of 247 records sampled across twelve popular
packages carried `affected_functions`). Their prose usually does -- "`yaml.load()` deserialises
arbitrary objects", "the `merge`, `mergeWith` and `defaultsDeep` functions" -- and that is what
this reads, at database build time, from the summary and details.

A name taken from prose can be incomplete: an advisory mentions the function its reporter found,
not every function that reaches the flaw. So these symbols carry a `text:` prefix and the
reachability tier uses them in one direction only -- to say first-party code calls a function
the advisory names, and to put that finding first. They never lower a finding: "calls none of
the functions this paragraph mentions" is not evidence the vulnerable code is unreachable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

PREFIX: Final = "text:"
MAX_TEXT: Final = 20_000
MAX_SYMBOLS: Final = 20

_CODE_SPAN = re.compile(r"`([^`\n]{1,120})`")
# Bounded: advisory text comes from an external source, and nested unbounded repetition
# over it is a backtracking hazard the pattern validator refuses.
_CALL = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]{0,80}(?:\.[A-Za-z_$][\w$]{0,80}){1,8})[ \t]{0,4}\("
)
_LEADING = re.compile(r"^[A-Za-z_$][\w$]{0,80}(?:\.[A-Za-z_$][\w$]{0,80}){0,8}")
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z`])|\n\s*\n")
_ADVICE = re.compile(
    r"\b(?:instead|use|using\s+the\s+safe|is\s+safe|are\s+safe|safe\s+alternative|recommend\w*|workaround|mitigat\w*|upgrade|patched|fixed\s+in)\b",
    re.I,
)
_LIST_GLUE = re.compile(r"`[^`]{0,60}`|,|\b(?:and|or)\b|\s")
_NOT_NAMES: Final = frozenset(
    {"true", "false", "null", "none", "undefined", "this", "self", "new", "return", "import",
     "require", "async", "await", "function", "class", "object", "string", "number", "args", "kwargs"}
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class Qualified:
    """An ecosystem whose code names a package's functions through a head the package's own name gives: `yaml.load`,
    `tokio::io::ReadHalf::unsplit`, `Plug.Crypto.verify/4`. `heads` is the key of `HEADS` that derives them from the name;
    `separators` are the other spellings of a dot that the ecosystem writes (`::`, `\\`, `#`); `anywhere`: the head may
    follow other segments (Haskell's `Data.Aeson.decode` names the package's module in the middle)."""

    heads: str
    separators: tuple[str, ...] = ()
    anywhere: bool = False


@dataclass(frozen=True, slots=True)
class Bare:
    """An ecosystem whose functions have no qualifier (C and C++ libraries, a formula's library): a function named in the
    advisory of its own package is that package's."""


@dataclass(frozen=True, slots=True)
class NoSymbols:
    """An ecosystem whose packages are not called by other code, and why."""

    reason: str


SymbolRule = Qualified | Bare | NoSymbols


class AdvisoryTextSymbols:
    """`text:`-prefixed vulnerable function names read from an advisory's prose."""

    #: How each ecosystem's code names a package's functions, by ecosystem id (one table: `S25`). A name is taken only when
    #: it is written with a head its own package's name gives, so a function of another library is never claimed.
    RULES: Final[dict[str, SymbolRule]] = {
        "npm": Qualified("published"),
        "pypi": Qualified("python"),
        "conda": Qualified("python"),
        "cargo": Qualified("crate", ("::",)),
        "gomod": Qualified("last-segment"),
        "maven": Qualified("group"),
        "gradle": Qualified("group"),
        "nuget": Qualified("published"),
        "composer": Qualified("camel", ("::", "\\")),
        "rubygems": Qualified("camel", ("::", "#")),
        "hex": Qualified("camel"),
        "opam": Qualified("camel"),
        "hackage": Qualified("camel", anywhere=True),
        "swift": Qualified("camel"),
        "cocoapods": Qualified("published"),
        "julia": Qualified("published"),
        "cran": Qualified("published", ("::",)),
        "pub": Qualified("published"),
        "ansible": Qualified("published"),
        "conan": Bare(),
        "vcpkg": Bare(),
        "homebrew": Bare(),
        "nix": Bare(),
        "bazel": Bare(),
        "vscode": NoSymbols(
            "an editor runs an extension through the entry point its manifest names; no other code imports or calls one of its functions"
        ),
        "actions": NoSymbols(
            "an action is run whole by a workflow step (`uses:`); no code calls a function of it"
        ),
        "helm": NoSymbols(
            "a chart is rendered into manifests by Helm; no code imports or calls a function of it"
        ),
        "terraform": NoSymbols(
            "a module or provider is configured by blocks, never called as a function by other code"
        ),
        "image": NoSymbols(
            "an image is run as a container; no code imports or calls a function of it"
        ),
    }
    APPLIES_TO: Final = frozenset(e for e, rule in RULES.items() if not isinstance(rule, NoSymbols))
    """The ecosystems whose advisory prose is read for function names."""
    NAMED_AS_PUBLISHED: Final = frozenset({"npm"})
    """Ecosystems whose code imports a package by its published name (no import-name table)."""

    @staticmethod
    def _camel(text: str) -> str:
        return "".join(part[:1].upper() + part[1:] for part in re.split(r"[-_.]", text) if part)

    @classmethod
    def heads_of(cls, kind: str, package: str) -> tuple[str, list[str]]:
        """The name a package's code is written under, and every head a reference to it may use."""
        lowered = package.lower()
        if kind == "published":
            heads = [package]
            if lowered in ("lodash", "lodash-es", "underscore"):
                heads.append("_")
            return package, heads
        if kind == "python":
            from cordon_scanner.ecosystems.packages.python.import_names import PythonImportNames

            normalized = lowered.replace("_", "-")
            aliases = list(PythonImportNames.aliases(normalized))
            canonical = aliases[0] if aliases else normalized.replace("-", "_")
            return canonical, list(
                dict.fromkeys([canonical, *aliases, normalized.replace("-", "_")])
            )
        if kind == "crate":
            crate = lowered.replace("-", "_")
            return crate, [crate]
        if kind == "last-segment":
            segments = [x for x in package.split("/") if x]
            if segments and re.fullmatch(r"v\d+", segments[-1]) and len(segments) > 1:
                segments = segments[:-1]
            last = segments[-1] if segments else package
            return last, [last]
        if kind == "group":
            group = package.partition(":")[0]
            return group, [group]
        # "camel": the CamelCase of the name (`plug` -> `Plug`, `rexml` -> `Rexml`, `active-support` -> `ActiveSupport`),
        # and of its last path segment for a `vendor/name`.
        whole = cls._camel(package.replace("/", "."))
        last = cls._camel(package.rpartition("/")[2])
        heads = list(dict.fromkeys([whole, last, package.rpartition("/")[2].upper(), last.upper()]))
        return last, [h for h in heads if h]

    @classmethod
    def import_names(cls, ecosystem: str, package: str) -> tuple[str, list[str]]:
        """The canonical name a package's code is written under, and every head a reference to it may use."""
        rule = cls.RULES.get(ecosystem)
        return cls.heads_of(rule.heads if isinstance(rule, Qualified) else "published", package)

    @staticmethod
    def _spelled(span: str, rule: SymbolRule) -> str:
        """A name in the ecosystem's own spelling, as dots: `tokio::io::ReadHalf<T>::unsplit` -> `tokio.io.ReadHalf.unsplit`,
        `Plug.Crypto.verify/4` -> `Plug.Crypto.verify`."""
        if not isinstance(rule, Qualified) or not rule.separators:
            return span
        out = re.sub(r"<[^<>]{0,60}>", "", span)
        for separator in rule.separators:
            out = out.replace(separator, ".")
        return re.sub(r"/\d+$", "", out).lstrip(".")

    @classmethod
    def extract(cls, ecosystem: str, package: str, text: str) -> tuple[str, ...]:
        if ecosystem not in cls.APPLIES_TO or not text:
            return ()
        rule = cls.RULES[ecosystem]
        canonical, heads = cls.import_names(ecosystem, package)
        anywhere = isinstance(rule, Qualified) and rule.anywhere
        found: list[str] = []

        def add(dotted: str) -> None:
            segments = dotted.split(".")
            for index in range(len(segments) if anywhere else 1):
                for head in heads:
                    size = head.count(".") + 1
                    if (
                        ".".join(segments[index : index + size]) == head
                        and len(segments) > index + size
                    ):
                        found.append(f"{PREFIX}{canonical}.{'.'.join(segments[index + size :])}")
                        return

        for sentence in _SENTENCE.split(text[:MAX_TEXT]):
            # Advice names the fix, not the flaw: "use `yaml.safe_load` instead". Positive-only
            # use means a fix taken for the flaw would tell people the safe call is the bad one.
            if _ADVICE.search(sentence):
                continue
            for span in _CODE_SPAN.finditer(sentence):
                inner = cls._spelled(span.group(1).strip(), rule)
                leading = _LEADING.match(inner)
                if leading is None:
                    continue
                name = leading.group(0)
                if "." in name:
                    add(name)
                elif (
                    len(name) >= 3
                    and not name.isupper()
                    and name.lower() not in _NOT_NAMES
                    and name not in heads
                    and (
                        inner.startswith(f"{name}(") or cls._named_as_function(sentence, span.end())
                    )
                ):
                    found.append(f"{PREFIX}{canonical}.{name}")
            for call in _CALL.finditer(cls._spelled(sentence, rule)):
                add(call.group(1))
        return tuple(dict.fromkeys(found))[:MAX_SYMBOLS]

    @staticmethod
    def _named_as_function(sentence: str, end: int) -> bool:
        """Whether the words right after a code span call it a function: "`merge` function", or the
        end of a list -- "`merge`, `mergeWith`, and `defaultsDeep` functions". Anywhere else in the
        sentence is not enough: "the `backend` option ... calls" names a setting, not a function."""
        tail = _LIST_GLUE.sub("", sentence[end : end + 120]).lower()
        return tail.startswith(("function", "method"))

    @staticmethod
    def is_text(symbols: tuple[str, ...] | list[str]) -> bool:
        return bool(symbols) and all(s.startswith(PREFIX) for s in symbols)

    @staticmethod
    def matches(used: str, named: str) -> bool:
        """Whether a first-party reference is the function an advisory names.

        Exact after normalising npm subpath imports (`lodash/merge` is `lodash.merge`). A prefix is
        not a match: constructing `jinja2.Environment` is not calling `Environment.from_string`.
        """
        return used.replace("/", ".") == named.removeprefix(PREFIX)
