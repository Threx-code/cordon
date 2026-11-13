"""Census A (pypi-98): whether install-time code reaches a payload.

Extracted from `capability/detector.py` so the install-composite gate can grow without that module. The gate
is the claim that a composite which says "code runs when the package is installed"
(`MALWARE.INSTALL.CONSUMER_CODE.001`) is the malicious finding only when a payload is reachable from
the install code -- egress, a fetch-and-run, a credential read, reconnaissance, a wallet/miner,
destruction, anti-analysis, or a decode-then-run -- or when it spawns a native binary the package
itself ships. A compiler SPAWN, or a spawn of a shipped *script* the scanner reads on its own, is
build/setup work, not malware. Persistence installed at install time is its own payload and is not
gated here; a dropper already requires a fetch-and-run, which is a payload.

`CapabilityDetector` holds the escalation and calls these static methods. `CapabilityHit` and
`FileContent` are imported only for typing, so this module imports no engine code and does not cycle
with `capability/detector.py`.
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import FileUnit, ScanContext
    from cordon_scanner.detect.code.capability.hits import CapabilityHit
    from cordon_scanner.foundation.content import FileContent


class InstallPayload:
    """The payload test the install-composite gate uses. Stateless; call the static methods."""

    #: Install composites escalated on a capability a build legitimately has (a compiler SPAWN), so
    #: the malicious finding only when a payload is reachable. INSTALL.PERSIST is not here --
    #: persistence installed at install time is itself the payload -- and DROPPER already requires a
    #: fetch-and-run, which is a payload.
    GATED: ClassVar[frozenset[str]] = frozenset({"MALWARE.INSTALL.CONSUMER_CODE.001"})

    #: Capabilities that make install-reachable code a payload on their own (cordon-f6, census A).
    _ALWAYS: ClassVar[frozenset[Capability]] = frozenset(
        {
            Capability.EGRESS,
            Capability.FETCH_EXEC,
            Capability.CREDENTIAL,
            Capability.RECONNAISSANCE,
            Capability.WALLET,
            Capability.MINE,
            Capability.DESTROY,
            Capability.ANTI_ANALYSIS,
        }
    )

    @classmethod
    def gate(
        cls,
        rule_id: str,
        installing: bool,
        local_by_capability: dict[Capability, CapabilityHit],
        window: Iterable[CapabilityHit],
        unit: FileUnit,
        ctx: ScanContext,
    ) -> bool:
        """Whether to hold an install composite rather than let it escalate to the malicious install
        finding: it is a gated rule, it runs at install, and no payload is reachable -- neither a
        payload capability nor a spawn of a shipped native binary. The window already excludes what
        `install_deferred_lines` proves the hook never reaches, and unparsable code counts as
        reaching everything, so holding here can only hold a block, never add one (census A)."""
        if rule_id not in cls.GATED or not installing:
            return False
        caps = set(local_by_capability)
        if Capability.FETCH_EXEC in caps and cls.execs_only_shipped_files(unit.content, window):
            caps.discard(Capability.FETCH_EXEC)  # not a payload: the package's own text
        for read in (Capability.RECONNAISSANCE, Capability.CREDENTIAL):
            if read in caps and cls.reads_only_settings(unit.content, window, read):
                caps.discard(read)  # a platform lookup or a named setting: build work
        return not cls.has_payload(caps) and not cls.spawns_shipped_file(
            unit.content, window, ctx.shipped_native_paths, unit.path
        )

    @classmethod
    def execs_only_shipped_files(
        cls, content: FileContent, window: Iterable[CapabilityHit]
    ) -> bool:
        """Whether every fetch-and-run hit of the install window is `exec` of text read from a file the package
        ships (reviews/pypi-98/24, F1): the hit is `unsourced` (nothing fetched or decoded reaches it) AND the
        path read is shown to be the package's own. `unsourced` alone is not enough: it is also true of an exec of
        a file named on the command line or in the environment. A path is the package's own when it is a relative
        literal, or built only from such literals, `__file__` and the working directory, through names assigned
        once in the file; anything else (a parameter, argv, the environment, an attribute, a call, a temp or
        absolute path) is not, and the hit stays a payload."""
        hits = [h for h in window if h.capability is Capability.FETCH_EXEC]
        if not hits or not all(h.unsourced for h in hits):
            return False
        try:
            tree = PythonSyntax.parse(content.text)
        except (SyntaxError, ValueError, RecursionError):
            # S2: a fallback; a file that does not parse is unresolved and keeps the hit a payload
            return False
        reads = _ShippedReads(tree)
        return all(reads.at(h.line) for h in hits)

    @staticmethod
    def reads_only_settings(
        content: FileContent, window: Iterable[CapabilityHit], capability: Capability
    ) -> bool:
        """Whether every hit of `capability` in the install window is a platform lookup or the read of a setting
        named by a literal that is not another service's credential (`LegitimateUse.a_setting`; reviews/pypi-98/24,
        R1): a build chooses its compiler by the platform. The hostname, the user, the whole environment and a
        well-known credential are not."""
        from cordon_scanner.detect.code.capability.legitimate_use import LegitimateUse

        hits = [h for h in window if h.capability is capability]
        return bool(hits) and all(LegitimateUse.a_setting(content, h) for h in hits)

    @classmethod
    def has_payload(cls, caps: set[Capability]) -> bool:
        """Whether install-reachable capabilities include a payload. A decode/decompress counts only
        together with a way to run what it produced; SPAWN/PERSIST/DELAY/FLOW/AGENT/TARGETING do not
        count alone -- build tools spawn compilers and write caches."""
        if caps & cls._ALWAYS:
            return True
        return bool(
            caps & {Capability.DECODE, Capability.DECOMPRESS}
            and caps & {Capability.EXECUTE, Capability.DESERIALIZE, Capability.DYNAMIC_DISPATCH}
        )

    _UNPACKER_CALL: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"^(?:[^\n]{0,80}?\(\s{0,4}\[?\s{0,4}[`'\"]|\s{0,16})(?:sudo\s{1,4})?"
        rb"(?:tar|bsdtar|gtar|unzip|gunzip|bunzip2|unxz|xz|zstd|7z|7za)(?=[\s`'\",)\]])"
        rb"(?![^\n]{0,240}?(?:&&|\|\||;[ \t]{0,8}[^\s}]|\||\$\())"
    )
    """A spawn whose program is an archive tool, and which runs nothing after it on the line."""

    @classmethod
    def spawns_unpacker(cls, content: FileContent, hit: CapabilityHit) -> bool:
        """Whether a spawn hit only unpacks an archive: `execSync(`tar -xzf "${tgz}"`)`.

        A dropper runs what it fetched. Unpacking a downloaded release is how an npm package
        installs its platform binary, and it runs nothing: the binary runs later, by a spawn of
        its own that still counts. Measured in the long tail, `tar -xzf` beside the download was
        the dropper's third signal in most of the benign install scripts it blocked (review 98).
        """
        if hit.capability is not Capability.SPAWN:
            return False
        raw = content.raw
        start = raw.rfind(b"\n", 0, hit.byte_start) + 1
        end = raw.find(b"\n", hit.byte_start)
        line = raw[start : end if end != -1 else len(raw)]
        return bool(
            cls._UNPACKER_CALL.search(line[hit.byte_start - start :])
            or cls._UNPACKER_CALL.match(line)
        )

    #: A path-like token in a spawn's argument: `./dist/pip_security`, `rootkit/dist/pip_security`.
    _PATH_TOKEN: ClassVar[re.Pattern[bytes]] = re.compile(rb"[A-Za-z0-9_./\\-]{2,}")

    @classmethod
    def spawns_shipped_file(
        cls,
        content: FileContent,
        window: Iterable[CapabilityHit],
        native_paths: frozenset[str],
        self_path: str,
    ) -> bool:
        """Whether a spawn in the install window runs a native binary the package itself ships.

        A build spawns a system tool by bare name -- `cc`, `make`, `protoc`; a dropper spawns the
        author's own compiled file by path -- `./dist/pip_security` -- which no reader of the install
        script can see. Keying on the spawn target resolving to a shipped ELF/PE/Mach-O
        (`ctx.shipped_native_paths`) keeps that dropper blocked while a compiler-spawn `setup.py`, and
        one spawning a shipped *script* the scanner reads on its own, both clear.
        """
        if not native_paths:
            return False
        basenames = {p.rsplit("/", 1)[-1] for p in native_paths if p != self_path and "/" in p}
        tails = tuple(p for p in native_paths if p != self_path)
        raw = content.raw
        for hit in window:
            if hit.capability is not Capability.SPAWN:
                continue
            span = raw[hit.byte_start : min(hit.byte_end + 160, len(raw))]
            for tok in cls._PATH_TOKEN.findall(span):
                t = tok.decode("utf-8", "replace").replace("\\", "/").strip("./")
                if not t:
                    continue
                base = t.rsplit("/", 1)[-1]
                if "/" in t and any(p.endswith((t, "/" + base)) for p in tails):
                    return True
                if "/" not in t and base in basenames:
                    return True
        return False


class _ShippedReads:
    """Whether the `exec` or `eval` on a line reads a file whose path is the package's own."""

    _OWN_CALLS: ClassVar[frozenset[str]] = frozenset(
        {
            "join",
            "dirname",
            "abspath",
            "realpath",
            "normpath",
            "Path",
            "getcwd",
            "basename",
            "convert_path",
        }
    )
    _OWN_ATTRS: ClassVar[frozenset[str]] = frozenset({"parent", "resolve", "absolute"})
    _READS: ClassVar[frozenset[str]] = frozenset({"read", "readlines", "read_text"})

    def __init__(self, tree: ast.AST) -> None:
        self.tree = tree
        self.files: dict[str, ast.expr] = {}
        self.names: dict[str, list[ast.expr]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.With | ast.AsyncWith):
                for item in node.items:
                    path = self._opened(item.context_expr)
                    if path is not None and isinstance(item.optional_vars, ast.Name):
                        self.files[item.optional_vars.id] = path
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.names.setdefault(target.id, []).append(node.value)
                        path = self._opened(node.value)
                        if path is not None:
                            self.files[target.id] = path

    @staticmethod
    def _opened(node: ast.AST) -> ast.expr | None:
        """The path argument of an `open(...)` call, else None."""
        if (
            isinstance(node, ast.Call)
            and node.args
            and ast.unparse(node.func).rsplit(".", 1)[-1] == "open"
        ):
            return node.args[0]
        return None

    def at(self, line: int) -> bool:
        calls = [
            n
            for n in ast.walk(self.tree)
            if isinstance(n, ast.Call)
            and getattr(n, "lineno", 0) == line
            and isinstance(n.func, ast.Name)
            and n.func.id in ("exec", "eval")
            and n.args
        ]
        return bool(calls) and all(self._read_path(c.args[0]) for c in calls)

    def _read_path(self, node: ast.AST) -> bool:
        """`compile(<read>, ...)`, `<f>.read()` or `open(<path>).read()`: the file read is the package's own."""
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "compile"
            and node.args
        ):
            return self._read_path(node.args[0])
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in self._READS
        ):
            return False
        source = node.func.value
        path = self.files.get(source.id) if isinstance(source, ast.Name) else self._opened(source)
        return path is not None and self._own(path, 0)

    def _own(self, node: ast.AST, depth: int, seen: frozenset[str] = frozenset()) -> bool:
        if depth > 6:
            return False
        if isinstance(node, ast.Constant):
            value = node.value
            return (
                isinstance(value, str)
                and not value.startswith(("/", "~", "\\"))
                and "://" not in value
                and ":" not in value[:2]
            )
        if isinstance(node, ast.Name):
            if node.id == "__file__" or node.id in seen:
                return True  # a name that depends on itself adds nothing: its other values decide
            values = self.names.get(node.id, [])
            return bool(values) and all(self._own(v, depth + 1, seen | {node.id}) for v in values)
        if isinstance(node, ast.Call):
            named = ast.unparse(node.func).rsplit(".", 1)[-1]
            return named in self._OWN_CALLS and all(
                self._own(a, depth + 1, seen) for a in node.args
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div | ast.Add):
            return self._own(node.left, depth + 1, seen) and self._own(node.right, depth + 1, seen)
        if isinstance(node, ast.Attribute) and node.attr in self._OWN_ATTRS:
            return self._own(node.value, depth + 1, seen)
        return False


__all__ = ["InstallPayload"]
