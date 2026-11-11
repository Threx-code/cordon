"""Which lines of a Python file write a file that gives someone else a way in, read from its syntax tree.

`authorized_keys` takes a key line and lets whoever holds the key log in as that user. A sudoers file
(`/etc/sudoers`, `/etc/sudoers.d/<name>`) says who may become root, `/etc/passwd` and `/etc/shadow`
say who exists, and `~/.ssh/rc` runs a command at every login. A package has no business writing any
of them: an SSH library reads `authorized_keys` to check a key, a dotfile manager writes the user's
own profile, and neither writes these. Written, they are a backdoor (graphicsctxr appends a key from a
module constant to `~/.ssh/authorized_keys` and sets its mode through a helper).

The path is followed to where it is used (`py_flow.py`): built with `/`, `os.path.join`, an f-string
or `expanduser`, held in a constant or handed through the file's own helpers. A write is an act that
puts content there: `open` in a mode that writes, `write_text`/`write_bytes`, a copy, move or rename
onto it, `os.open` for writing, or a shell command that redirects, `tee`s, copies or moves into it. A
read, a mode change, an existence check and a message that names the file are not writes.

`hits` returns `(line, kind)` for each write, or an empty list when the file holds no such name.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar, Final

from cordon_scanner.analysis.python.py_flow import Label
from cordon_scanner.analysis.python.py_persist import PythonPersistence

#: The files, as one path piece or a whole path names them. A bare `passwd` or `shadow` is a word
#: (a password prompt, a CSS property), so those two count only with their directory.
BACKDOOR_NAME: Final = re.compile(
    r"(?i)authorized_keys2?\b|sudoers(?:\.d)?\b|/etc/(?:passwd|shadow|gshadow)\b|\.ssh/rc\b"
)

#: A shell command that puts content into a file: a redirect, `tee`, a copy, a move, `install`,
#: `ln`, `sed -i`, `dd of=`.
SHELL_WRITE: Final = re.compile(
    r"(?:>>?|\btee\b|\bcp\b|\bmv\b|\binstall\b|\bln\b|\bsed\s+-[a-z]*i\b|\bdd\b[^;&|]*\bof=)"
)


class BackdoorWrites(PythonPersistence):
    """The writes of a backdoor file's path in one syntax tree."""

    #: Calls whose second argument is the destination.
    DESTINATION_SECOND: ClassVar[frozenset[str]] = frozenset(
        {
            "copy",
            "copy2",
            "copyfile",
            "copyfileobj",
            "copytree",
            "move",
            "rename",
            "replace",
            "symlink",
            "link",
        }
    )
    #: Methods on the path itself that put content there.
    WRITING_METHODS: ClassVar[frozenset[str]] = frozenset(
        {"write_text", "write_bytes", "touch", "hardlink_to", "symlink_to"}
    )
    #: Methods of a path that move it onto a destination given as the argument.
    MOVING_METHODS: ClassVar[frozenset[str]] = frozenset({"rename", "replace"})

    def seed(self, node: ast.AST) -> Label | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
            text = node.value if isinstance(node.value, str) else node.value.decode("latin-1")
            if BACKDOOR_NAME.search(text):
                self.texts.setdefault(node.lineno, []).append(text)
                return node.lineno
        return None

    def _written_by(self, node: ast.Call) -> set[Label]:
        name = self.name(node.func)
        dotted = self.dotted(node.func)
        if name in self.functions or name in self.records:
            return set()  # followed into the function
        if dotted == "os.open":
            return self._os_open_writes(node)
        if name == "open":
            if self._opens_to_write(node):
                return self.given(node, self.TEXT_KEYWORDS) | self.receiver(node)
            return set()
        if name in self.WRITING_METHODS and isinstance(node.func, ast.Attribute):
            return self.receiver(node)
        if name in self.MOVING_METHODS and isinstance(node.func, ast.Attribute) and node.args:
            return self.taint(node.args[0])
        if name in self.DESTINATION_SECOND and len(node.args) >= 2:
            return self.taint(node.args[1])
        if dotted in self.PROCESS or name in self.PROCESS:
            command = self._command_text(node)
            if command is not None and SHELL_WRITE.search(command):
                return self.given(node, self.TEXT_KEYWORDS)
        return set()

    def _command_text(self, node: ast.Call) -> str | None:
        """The command text with the seed literals as written, and the rest of a string built
        around them kept: `"echo k >> " + path` and an f-string both leave their redirect."""
        argv = node.args[0] if node.args else None
        if argv is None:
            return None
        parts: list[str] = []
        for part in ast.walk(argv):
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                parts.append(part.value)
        return " ".join(parts) if parts else None

    def _os_open_writes(self, node: ast.Call) -> set[Label]:
        """`os.open(path, os.O_WRONLY | os.O_APPEND)`: the path, when the flags write."""
        flags = node.args[1] if len(node.args) > 1 else None
        names = {n.attr for n in ast.walk(flags) if isinstance(n, ast.Attribute)} if flags else set()
        if names & {"O_WRONLY", "O_RDWR", "O_APPEND", "O_CREAT", "O_TRUNC"}:
            return self.taint(node.args[0])
        return set()

    @classmethod
    def hits(cls, tree: ast.AST) -> list[tuple[int, str, bool]]:
        """`(line, kind, carried)` for each write of a backdoor file's path. `carried`: what is
        written is the package's own -- a literal, a module constant, a decode or reversal of one --
        not a value the caller hands in or the user's own file."""
        analysis = cls(tree)
        if not analysis.index() or not analysis.seeds:
            return []
        analysis.flow()
        content = ContentOrigin(tree)
        out: list[tuple[int, str, bool]] = []
        seen: set[int] = set()
        for node in analysis.calls:
            for label in analysis._written_by(node):
                for text in analysis.texts.get(label, ()):
                    match = BACKDOOR_NAME.search(text)
                    if match and node.lineno not in seen:
                        seen.add(node.lineno)
                        out.append((node.lineno, cls._kind(match.group(0)), content.carried_by(node)))
        return sorted(out)

    @staticmethod
    def _kind(found: str) -> str:
        found = found.lower()
        if found.startswith("authorized_keys"):
            return "authorized_keys"
        if found.startswith("sudoers"):
            return "sudoers"
        if found.endswith("rc"):
            return "ssh rc"
        return "account file"


class ContentOrigin:
    """What a write puts in the file, and whether the package itself supplies it."""

    #: Methods that return the text they are given, changed in form only.
    SHAPES: ClassVar[frozenset[str]] = frozenset(
        {"strip", "lstrip", "rstrip", "encode", "decode", "format", "join", "replace", "lower", "upper", "title", "casefold", "removeprefix", "removesuffix"}
    )
    #: Calls that decode a literal.
    DECODERS: ClassVar[frozenset[str]] = frozenset(
        {"b64decode", "urlsafe_b64decode", "b32decode", "b16decode", "a85decode", "b85decode", "fromhex", "unhexlify", "a2b_base64", "a2b_hex", "decompress", "loads"}
    )
    WRITES: ClassVar[frozenset[str]] = frozenset({"write", "writelines"})

    def __init__(self, tree: ast.AST) -> None:
        self.parent: dict[int, ast.AST] = {}
        self.module: dict[str, list[ast.AST]] = {}
        self.function: dict[int, dict[str, list[ast.AST]]] = {}
        self.params: dict[int, set[str]] = {}
        self.calls: dict[str, list[ast.Call]] = {}
        self.attrs: dict[str, list[tuple[ast.AST, ast.AST | None]]] = {}
        self.functions: dict[str, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                self.parent[id(child)] = node
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign | ast.AnnAssign) and getattr(node, "value", None) is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                scope = self._function_of(node)
                table = self.module if scope is None else self.function.setdefault(id(scope), {})
                for target in targets:
                    if isinstance(target, ast.Name):
                        table.setdefault(target.id, []).append(node.value)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                        self.attrs.setdefault(target.attr, []).append((node.value, self._function_of(node)))
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                self.functions.setdefault(node.name, node)
            if isinstance(node, ast.Call):
                called = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
                if called:
                    self.calls.setdefault(called, []).append(node)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                a = node.args
                names = [x.arg for x in (*a.posonlyargs, *a.args, *a.kwonlyargs)]
                names += [x.arg for x in (a.vararg, a.kwarg) if x is not None]
                self.params[id(node)] = set(names)

    def _function_of(self, node: ast.AST) -> ast.AST | None:
        cur = self.parent.get(id(node))
        while cur is not None:
            if isinstance(cur, ast.FunctionDef | ast.AsyncFunctionDef):
                return cur
            cur = self.parent.get(id(cur))
        return None

    def carried_by(self, call: ast.Call) -> bool:
        """Whether every value this write puts in the file is the package's own. A write whose
        content cannot be found (a handle passed on, a descriptor) is not carried."""
        values = self._contents(call)
        scope = self._function_of(call)
        return bool(values) and all(self.carried(v, scope, 0) for v in values)

    def _contents(self, call: ast.Call) -> list[ast.AST]:
        name = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", None)
        if name in ("write_text", "write_bytes") and call.args:
            return [call.args[0]]
        if name in BackdoorWrites.DESTINATION_SECOND and call.args:
            return [call.args[0]]
        if name == "open":
            attr = self.parent.get(id(call))
            outer = self.parent.get(id(attr)) if attr is not None else None
            if isinstance(attr, ast.Attribute) and attr.attr in self.WRITES and isinstance(outer, ast.Call) and outer.args:
                return [outer.args[0]]  # open(p, "a").write(x)
            handle = self._handle(call)
            if handle is None:
                return []
            scope = self._function_of(call) or self._root(call)
            out: list[ast.AST] = []
            for n in ast.walk(scope):
                if (
                    isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Attribute)
                    and n.func.attr in self.WRITES
                    and isinstance(n.func.value, ast.Name)
                    and n.func.value.id == handle
                    and n.args
                ):
                    out.append(n.args[0])
            return out
        if name in BackdoorWrites.PROCESS or (isinstance(call.func, ast.Attribute) and BackdoorWrites.dotted(call.func) in BackdoorWrites.PROCESS):
            argv = call.args[0] if call.args else None
            text = " ".join(
                p.value for p in ast.walk(argv) if isinstance(p, ast.Constant) and isinstance(p.value, str)
            ) if argv is not None else ""
            return [ast.Constant(value=text)] if re.search(r"\b(?:echo|printf)\b", text) and not any(
                isinstance(p, ast.Name | ast.Attribute | ast.Subscript) for p in ast.walk(argv)
            ) else []
        return []

    def _root(self, node: ast.AST) -> ast.AST:
        cur = node
        while id(cur) in self.parent:
            cur = self.parent[id(cur)]
        return cur

    def _handle(self, call: ast.Call) -> str | None:
        """The name an `open(...)` is bound to: `with open(p, "a") as f`, `f = open(p, "a")`."""
        parent = self.parent.get(id(call))
        if isinstance(parent, ast.withitem) and isinstance(parent.optional_vars, ast.Name):
            return parent.optional_vars.id
        if isinstance(parent, ast.Assign) and len(parent.targets) == 1 and isinstance(parent.targets[0], ast.Name):
            return parent.targets[0].id
        return None

    def _argument_carried(self, function: ast.AST, param: str, depth: int) -> bool:
        """A parameter is the package's own when the file's calls to the function all pass a
        carried value for it (a helper hop); with no call in the file it is the caller's."""
        args = function.args  # type: ignore[attr-defined]
        positional = [x.arg for x in (*args.posonlyargs, *args.args)]
        if positional and positional[0] in ("self", "cls"):
            positional = positional[1:]
        sites = self.calls.get(function.name, [])  # type: ignore[attr-defined]
        if function.name == "__init__":  # type: ignore[attr-defined]
            klass = self.parent.get(id(function))
            sites = self.calls.get(getattr(klass, "name", ""), [])
        if param not in (*positional, *(x.arg for x in args.kwonlyargs)):
            return False
        if not sites:
            defaults = dict(zip(reversed(positional), reversed(args.defaults), strict=False))
            default = defaults.get(param)
            return default is not None and self.carried(default, None, depth + 1)
        for site in sites:
            value = next((k.value for k in site.keywords if k.arg == param), None)
            if value is None and param in positional and positional.index(param) < len(site.args):
                value = site.args[positional.index(param)]
            if value is None or not self.carried(value, self._function_of(site), depth + 1):
                return False
        return True

    def _unsupplied(self, node: ast.AST, scope: ast.AST | None) -> bool:
        if not (isinstance(node, ast.Name) and scope is not None and node.id in self.params.get(id(scope), set())):
            return False
        args = scope.args  # type: ignore[attr-defined]
        positional = [x.arg for x in (*args.posonlyargs, *args.args)]
        if positional and positional[0] in ("self", "cls"):
            positional = positional[1:]
        name = scope.name  # type: ignore[attr-defined]
        sites = self.calls.get(getattr(self.parent.get(id(scope)), "name", "") if name == "__init__" else name, [])
        if node.id not in positional:
            return False
        defaults = dict(zip(reversed(positional), reversed(args.defaults), strict=False))
        default = defaults.get(node.id)
        fills = any(
            any(k.arg == node.id for k in site.keywords) or positional.index(node.id) < len(site.args) for site in sites
        )
        return isinstance(default, ast.Constant) and default.value is None and not fills

    def _helper_returns(self, value: ast.AST, helper: ast.AST, depth: int) -> bool:
        """A return that is made of the helper's parameters and constants only."""
        params = self.params.get(id(helper), set())
        for part in ast.walk(value):
            if (
                isinstance(part, ast.Name)
                and part.id not in params
                and part.id not in self.module
                and part.id not in ("base64", "bytes", "str", "codecs", "binascii", "reversed")
            ):
                return False
        return True

    def carried(self, node: ast.AST | None, scope: ast.AST | None, depth: int) -> bool:
        if node is None or depth > 8:
            return False
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str | bytes)
        if isinstance(node, ast.JoinedStr):
            return all(self.carried(v.value if isinstance(v, ast.FormattedValue) else v, scope, depth + 1) for v in node.values)
        if isinstance(node, ast.BinOp):
            return self.carried(node.left, scope, depth + 1) and self.carried(node.right, scope, depth + 1)
        if isinstance(node, ast.Subscript):
            return self.carried(node.value, scope, depth + 1)
        if isinstance(node, ast.List | ast.Tuple):
            return all(self.carried(e, scope, depth + 1) for e in node.elts)
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name in self.SHAPES and isinstance(func, ast.Attribute):
                return self.carried(func.value, scope, depth + 1) and all(self.carried(a, scope, depth + 1) for a in node.args)
            if name in self.DECODERS or name in ("reversed", "bytes", "str", "bytearray"):
                return bool(node.args) and all(self.carried(a, scope, depth + 1) for a in node.args)
            helper = self.functions.get(name) if isinstance(func, ast.Name) else None
            if helper is not None:
                # The file's own helper over carried arguments: `_d("<b64>")` returns what it was given, changed.
                returns = [n.value for n in ast.walk(helper) if isinstance(n, ast.Return) and n.value is not None]
                args_ok = all(self.carried(a, scope, depth + 1) for a in (*node.args, *(k.value for k in node.keywords)))
                return args_ok and bool(returns) and all(self._helper_returns(r, helper, depth) for r in returns)
            return False
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            # `supplied or DEFAULT`: a parameter that defaults to nothing and that no call in the file
            # fills in is not supplied, so the value is the default's.
            present = [v for v in node.values if not self._unsupplied(v, scope)]
            return bool(present) and all(self.carried(v, scope, depth + 1) for v in present)
        if isinstance(node, ast.Dict):
            return all(self.carried(v, scope, depth + 1) for v in (*node.keys, *node.values) if v is not None)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
            assigned = self.attrs.get(node.attr, [])
            return bool(assigned) and all(self.carried(v, fn, depth + 1) for v, fn in assigned)
        if isinstance(node, ast.Name):
            if scope is not None and node.id in self.params.get(id(scope), set()):
                return self._argument_carried(scope, node.id, depth)
            sources = list(self.function.get(id(scope), {}).get(node.id, [])) if scope is not None else []
            sources += self.module.get(node.id, [])
            return bool(sources) and all(self.carried(v, scope, depth + 1) for v in sources)
        return False


__all__ = ["BackdoorWrites", "ContentOrigin"]
