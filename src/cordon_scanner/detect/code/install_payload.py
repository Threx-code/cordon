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
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

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
        # An `exec` of a version file is NOT discarded: it was the only thing holding three half-A droppers
        # whose own payload is a spawn the gate does not count (reviews/pypi-98/26).
        for read in (Capability.RECONNAISSANCE, Capability.CREDENTIAL):
            if read in caps and cls.reads_only_settings(unit.content, window, read):
                caps.discard(read)  # a platform lookup or a named setting: build work
        if Capability.DESTROY in caps and cls.removes_only_own_tree(unit.content, window):
            caps.discard(Capability.DESTROY)  # a build step clearing its own output
        return not cls.has_payload(caps) and not cls.spawns_shipped_file(
            unit.content, window, ctx.shipped_native_paths, unit.path
        )

    @staticmethod
    def removes_only_own_tree(content: FileContent, window: Iterable[CapabilityHit]) -> bool:
        """Whether every deletion hit of the install window is a removal call whose target is shown to be the
        package's own tree: a path rooted in `__file__`, the working directory, a relative literal or a temp
        directory, or a command's output-dir attribute the file never assigns (reviews/pypi-98/24, D1). A `..`
        component, an install destination (`self.root`, `self.prefix`), the home directory, an absolute path,
        argv, the environment, an unresolved name and a shell `rm` are not, and the hit stays a payload."""
        hits = [h for h in window if h.capability is Capability.DESTROY]
        if not hits:
            return False
        try:
            tree = PythonSyntax.parse(content.text)
        except (SyntaxError, ValueError, RecursionError):
            # S2: a fallback; a file that does not parse is unresolved and keeps the hit a payload
            return False
        if re.search(
            rb"\brm\s+-|Remove-Item|\brd\s+/s|rimraf|FileUtils|RemoveAll|dd\s+if=|mkfs|shred|vssadmin",
            content.raw,
        ):
            return False  # a shell or other-language deletion beside the calls: not shown to be the package's own
        own = _ShippedReads(tree)
        # every removal in the file, not only the window's hit: the window keeps one hit of a capability
        return all(own.removes_at(h.line) for h in hits) and own.every_removal_is_own()

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

    #: A command's own output directories: setuptools' finalize step or the user's command line decides them,
    #: unless this file assigns them (then they are traced like any name). Not `root` or `prefix`: those are
    #: where the user installs to.
    _OUTPUT_ATTRS: ClassVar[frozenset[str]] = frozenset(
        {"build_dir", "build_lib", "build_temp", "dist_dir", "bdist_dir"}
    )
    _REMOVERS: ClassVar[frozenset[str]] = frozenset({"rmtree", "remove", "rmdir", "unlink"})
    _TEMP: ClassVar[frozenset[str]] = frozenset(
        {"mkdtemp", "gettempdir", "TemporaryDirectory", "mktemp"}
    )

    def __init__(self, tree: ast.AST) -> None:
        self.tree = tree
        self.names: dict[str, list[ast.expr]] = {}
        #: `self.<attr>` values the file assigns; None as a value is "assigned, from something unseen".
        self.attrs: dict[str, list[ast.expr | None]] = {}
        self.wild_setattr = False
        learners: dict[type, Callable[[Any], None]] = {
            ast.With: self._learn_with, ast.AsyncWith: self._learn_with,
            ast.Assign: self._learn_assignment, ast.AugAssign: self._learn_assignment,
            ast.AnnAssign: self._learn_assignment, ast.Call: self._note_attribute_writes,
        }  # fmt: skip
        for node in ast.walk(tree):
            learn = learners.get(type(node))
            if learn is not None:
                learn(node)

    def _learn_with(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            if isinstance(item.optional_vars, ast.Name):
                self.names.setdefault(item.optional_vars.id, []).append(item.context_expr)

    def _learn_assignment(self, node: ast.Assign | ast.AugAssign | ast.AnnAssign) -> None:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        for target in targets:
            if isinstance(target, ast.Name) and value is not None:
                self.names.setdefault(target.id, []).append(value)
            elif self._is_self_attr(target):
                self.attrs.setdefault(target.attr, []).append(value)  # type: ignore[attr-defined]

    @staticmethod
    def _is_self_attr(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
        )

    def _note_attribute_writes(self, call: ast.Call) -> None:
        """`setattr(self, "x", v)` and `self.set_undefined_options(...)` assign command attributes."""
        named = ast.unparse(call.func).rsplit(".", 1)[-1]
        if named == "setattr" and len(call.args) >= 2:
            name, value = call.args[1], call.args[2] if len(call.args) > 2 else None
            if isinstance(name, ast.Constant) and isinstance(name.value, str):
                self.attrs.setdefault(name.value, []).append(value)
            else:
                self.wild_setattr = True
        elif named == "set_undefined_options":
            for sub in ast.walk(call):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    self.attrs.setdefault(sub.value, []).append(None)

    def every_removal_is_own(self) -> bool:
        """Whether every removal call of the file targets the package's own tree (`removes_at` for each)."""
        lines = {
            n.lineno
            for n in ast.walk(self.tree)
            if isinstance(n, ast.Call) and ast.unparse(n.func).rsplit(".", 1)[-1] in self._REMOVERS
        }
        return all(self.removes_at(line) for line in lines)

    def removes_at(self, line: int) -> bool:
        """Whether every removal call on `line` (rmtree, remove, rmdir, unlink) targets the package's own tree
        (D1): `_own` in removal mode. No removal call on the line (a shell `rm`, say) is not shown to be."""
        calls = [
            n
            for n in ast.walk(self.tree)
            if isinstance(n, ast.Call)
            and getattr(n, "lineno", 0) == line
            and ast.unparse(n.func).rsplit(".", 1)[-1] in self._REMOVERS
            and n.args
        ]
        return bool(calls) and all(self._own(c.args[0], 0, removal=True) for c in calls)

    def _own(
        self,
        node: ast.AST,
        depth: int,
        seen: frozenset[str] = frozenset(),
        *,
        removal: bool = False,
    ) -> bool:
        """Whether a path expression is the package's own. In `removal` mode a temp directory and a command's
        output-dir attribute (that this file never assigns) are too, and a `..` component or a second step
        up (`dirname` of `dirname`, `.parent.parent`) is not: an own root must not be left."""
        if depth > 6:
            return False
        if isinstance(node, ast.Constant):
            value = node.value
            return (
                isinstance(value, str)
                and not value.startswith(("/", "~", "\\"))
                and "://" not in value
                and ":" not in value[:2]
                and not (removal and ".." in value.replace("\\", "/").split("/"))
            )
        if isinstance(node, ast.Name):
            if node.id == "__file__" or node.id in seen:
                return True  # a name that depends on itself adds nothing: its other values decide
            values = self.names.get(node.id, [])
            return bool(values) and all(
                self._own(v, depth + 1, seen | {node.id}, removal=removal) for v in values
            )
        if isinstance(node, ast.Call):
            named = ast.unparse(node.func).rsplit(".", 1)[-1]
            if removal and named in self._TEMP:
                return True
            if (
                removal
                and named == "dirname"
                and self._steps_up(node.args[0] if node.args else node)
            ):
                return False
            return named in self._OWN_CALLS and all(
                self._own(a, depth + 1, seen, removal=removal) for a in node.args
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div | ast.Add):
            return self._own(node.left, depth + 1, seen, removal=removal) and self._own(
                node.right, depth + 1, seen, removal=removal
            )
        if isinstance(node, ast.Attribute):
            if removal and self._is_self_attr(node):
                return self._own_attr(node.attr, depth, seen)
            if removal and ast.unparse(node) == "os.curdir":
                return True
            if node.attr in self._OWN_ATTRS:
                if removal and node.attr == "parent" and self._steps_up(node.value):
                    return False
                return self._own(node.value, depth + 1, seen, removal=removal)
        return False

    @staticmethod
    def _steps_up(node: ast.AST) -> bool:
        """Whether `node` is already one step up from where it started (`dirname(...)`, `....parent`)."""
        return (isinstance(node, ast.Call) and ast.unparse(node.func).endswith("dirname")) or (
            isinstance(node, ast.Attribute) and node.attr == "parent"
        )

    def _own_attr(self, attr: str, depth: int, seen: frozenset[str]) -> bool:
        """`self.<attr>` in a removal: an output directory the file never assigns is the package's own (setuptools'
        finalize step or the user's command line sets it); one it assigns, or any other attribute, is only as
        own as every value assigned to it."""
        if attr not in self._OUTPUT_ATTRS:
            return False
        values = self.attrs.get(attr, [])
        if not values:
            return not self.wild_setattr
        return all(v is not None and self._own(v, depth + 1, seen, removal=True) for v in values)


__all__ = ["InstallPayload"]
