"""What the drop-point composite counts as its two halves: loot read, and a destination that is a request.

`SUSPECT.EXFIL.DROP_POINT.001` pairs a destination label (a webhook, paste or interaction host, a
public-IP URL) with a credential or reconnaissance hit within 200 lines, and asks for no request: the
label is the egress. Measured on 26 legitimate PyPI units it blocked (reviews/pypi-98/21), the pair was
made of text and settings, not of a read and a send:

* **text** (T): a credential hit on a line that is only text in a parsed file (`PythonSyntax.text_only_lines`:
  a docstring, a help block, the lines a multi-line string continues on), or in a template (`.html`, `.j2`, ...), is not a read. A string that is
  itself run (an argument of `exec`, `eval`, `compile`, `os.system`, `os.popen` or a `subprocess`
  call, directly or through one name) is code and keeps its hits;
* **a destination named** (D): a label that is only a message (`print`, a logger, an exception, a
  help text) or only an operand of `in` (a deny-list) is not where anything is sent. A label whose
  use the file does not resolve counts as reached: a name loaded anywhere else, a dict item, an
  attribute, a collection iterated;
* **a setting read** (C): an environment read judged by the tree, not by the hit's text: a key that is a
  literal, or a name every literal of which the file shows (a loop over a literal collection, a
  parameter every call site passes a literal to), and none a well-known service's credential
  (`CREDENTIAL_HOMES`).

Python is read only where it parses; anything else keeps the old reading. Every doubt keeps the hit.
"""

from __future__ import annotations

import ast
import bisect
import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.shared.credential_homes import CREDENTIAL_HOMES
from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.detect.code.capability.legitimate_use import LegitimateUse
from cordon_scanner.detect.code.store_flow import PythonStoreFlow
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent

TextRange = tuple[int, int, ast.Constant]


class DropPointLoot:
    """The loot half and the destination half of `SUSPECT.EXFIL.DROP_POINT.001`, read by the tree."""

    LABEL_RULE: ClassVar[str] = "INTEL.EGRESS.DROP_POINT.001"
    #: Callees that run a string: the text handed to them is code, whatever it looks like.
    RUNNERS: ClassVar[frozenset[str]] = frozenset(
        {
            "exec", "eval", "compile", "os.system", "os.popen", "system", "popen",
            "subprocess.run", "subprocess.call", "subprocess.check_call",
            "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput",
            "subprocess.getstatusoutput", "check_output", "check_call", "Popen", "run",
            "getoutput",
        }
    )  # fmt: skip
    #: Methods that write a message for a person, and what the receiver's name must hold to be one.
    LOG_METHODS: ClassVar[frozenset[str]] = frozenset(
        {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log", "echo", "secho", "print"}
    )  # fmt: skip
    LOG_RECEIVERS: ClassVar[tuple[str, ...]] = (
        "log",
        "console",
        "click",
        "typer",
        "warnings",
        "rich",
    )
    #: The parsed flow facts that say a read value reaches what a request sends.
    SENT_FACTS: ClassVar[frozenset[str]] = frozenset(
        {"AST.PY.ENVIRONMENT_SENT", "AST.PY.SECRET_SENT", "AST.PY.CREDSTORE_SENT"}
    )
    #: Expressions a literal becomes part of, still the same text.
    _CARRIERS: ClassVar[tuple[type, ...]] = (
        ast.JoinedStr,
        ast.BinOp,
        ast.Starred,
        ast.FormattedValue,
        ast.List,
        ast.Tuple,
        ast.Set,
        ast.Dict,
    )
    _CONSTRUCTORS: ClassVar[frozenset[str]] = frozenset(
        {"frozenset", "set", "list", "tuple", "dict", "sorted"}
    )
    _ADDRESS: ClassVar[re.Pattern[str]] = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
    _READERS: ClassVar[frozenset[str]] = frozenset({"get", "getenv", "pop"})
    _WHOLE: ClassVar[frozenset[str]] = frozenset({"copy", "items", "keys", "values"})
    _COMPREHENSIONS: ClassVar[tuple[type, ...]] = (
        ast.ListComp,
        ast.SetComp,
        ast.GeneratorExp,
        ast.DictComp,
    )

    # -- The tree --------------------------------------------------------------------------------

    @staticmethod
    def tree(content: FileContent, language: str | None) -> ast.AST | None:
        """The parsed file, or None where it is not Python, does not parse, or its bytes are not what
        the tree's offsets count (a non-UTF-8 file)."""
        if language != "python":
            return None
        text = content.text
        if not text.isascii() and text.encode("utf-8") != content.raw:
            return None
        try:
            tree: ast.AST = PythonSyntax.shared(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            # S2: a fallback; a file that does not parse keeps the old, text reading of its hits
            return None
        return tree

    @staticmethod
    def _line_starts(content: FileContent, tree: ast.AST) -> list[int]:
        def compute() -> list[int]:
            raw = content.raw
            starts = [0]
            at = raw.find(b"\n")
            while at != -1:
                starts.append(at + 1)
                at = raw.find(b"\n", at + 1)
            return starts

        found: list[int] = PythonSyntax.memo(tree, "drop-point-line-starts", compute)
        return found

    @classmethod
    def _strings(cls, content: FileContent, tree: ast.AST) -> tuple[list[int], list[TextRange]]:
        """Every text constant of the file as (first byte, end byte, node) by first byte, and the
        first bytes alone."""

        def compute() -> tuple[list[int], list[TextRange]]:
            starts = cls._line_starts(content, tree)
            out: list[TextRange] = []
            for node in PythonSyntax.of(tree, ast.Constant):
                if not isinstance(node.value, str | bytes) or node.end_lineno is None:
                    continue
                if node.end_col_offset is None:
                    continue
                try:
                    first = starts[node.lineno - 1] + node.col_offset
                    last = starts[node.end_lineno - 1] + node.end_col_offset
                except IndexError:
                    continue
                out.append((first, last, node))
            out.sort(key=lambda item: item[0])
            return [item[0] for item in out], out

        found: tuple[list[int], list[TextRange]] = PythonSyntax.memo(
            tree, "drop-point-strings", compute
        )
        return found

    @classmethod
    def _string_holding(
        cls, content: FileContent, tree: ast.AST, first: int, last: int
    ) -> ast.Constant | None:
        """The text constant whose bytes hold [first, last), if one does."""
        starts, strings = cls._strings(content, tree)
        at = bisect.bisect_right(starts, first) - 1
        for index in range(at, max(at - 8, -1), -1):
            start, end, node = strings[index]
            if start <= first and last <= end + 1:
                return node
        return None

    # -- A callee's name ---------------------------------------------------------------------------

    @staticmethod
    def dotted(node: ast.AST) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    @classmethod
    def _runs_text(cls, tree: ast.AST) -> set[int]:
        """`id` of every text constant that is run: handed to a runner directly, inside an argument
        expression, or through a name assigned that text."""

        def compute() -> set[int]:
            assigned: dict[str, list[ast.AST]] = {}
            for node in PythonSyntax.of(tree, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned.setdefault(target.id, []).append(node.value)
            found: set[int] = {-1}
            seen_names: set[str] = set()
            pending: list[ast.AST] = []
            for call in PythonSyntax.of(tree, ast.Call):
                if cls.dotted(call.func) in cls.RUNNERS:
                    pending.extend(call.args)
                    pending.extend(kw.value for kw in call.keywords)
            while pending:
                node = pending.pop()
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str | bytes):
                        found.add(id(sub))
                    elif isinstance(sub, ast.Name) and sub.id not in seen_names:
                        seen_names.add(sub.id)
                        pending.extend(assigned.get(sub.id, ()))
            return found

        found: set[int] = PythonSyntax.memo(tree, "drop-point-runs-text", compute)
        return found

    # -- The loot half ---------------------------------------------------------------------------

    @classmethod
    def is_loot(cls, content: FileContent, language: str | None, hit: CapabilityHit) -> bool:
        """Whether a credential or reconnaissance hit is loot: not a setting by its text, not text,
        not a keyed setting read by the tree."""
        if hit.capability not in (Capability.CREDENTIAL, Capability.RECONNAISSANCE):
            return False
        if LegitimateUse.a_setting(content, hit):
            return False
        if LegitimateUse.is_template_or_markup(content.path):
            return False
        tree = cls.tree(content, language)
        if tree is None:
            return True
        if cls._is_text(content, tree, hit):
            return False
        return not cls._is_a_setting_read(tree, hit)

    @classmethod
    def _is_text(cls, content: FileContent, tree: ast.AST, hit: CapabilityHit) -> bool:
        """The hit sits on a line that is only text (`PythonSyntax.text_only_lines`, or a table written one
        string to a line that reaches no opener or runner), in a string the file does not run."""
        text_lines = PythonSyntax.text_only_lines(tree) | PythonStoreFlow.table_text_lines(tree)
        if hit.line not in text_lines:
            return False
        node = cls._string_holding(content, tree, hit.byte_start, hit.byte_end)
        return node is not None and id(node) not in cls._runs_text(tree)

    @classmethod
    def _is_a_setting_read(cls, tree: ast.AST, hit: CapabilityHit) -> bool:
        """The hit is an environment read the tree shows to read only named settings."""
        if hit.rule_id != "AST.PY.CREDENTIAL":
            return False
        reads = [r for r in cls._environment_reads(tree) if r[0].lineno == hit.line]
        if not reads:
            return False
        return all(cls._names_a_setting(tree, node, key) for node, key in reads)

    @classmethod
    def _environment_reads(cls, tree: ast.AST) -> list[tuple[Any, ast.AST | None]]:
        """(node, key) for every read of the environment: a keyed read has its key; a whole-environment
        read (`dict(os.environ)`, `.items()`, `.copy()`) has none."""

        def compute() -> list[tuple[Any, ast.AST | None]]:
            out: list[tuple[Any, ast.AST | None]] = []
            for node in PythonSyntax.of(tree, ast.Call, ast.Subscript):
                if isinstance(node, ast.Subscript):
                    if "environ" in cls.dotted(node.value):
                        out.append((node, node.slice))
                    continue
                name = cls.dotted(node.func)
                last = name.rsplit(".", 1)[-1]
                if last == "getenv" or (last in cls._READERS and "environ" in name):
                    out.append((node, node.args[0] if node.args else None))
                elif (last in cls._WHOLE and "environ" in name) or (
                    name == "dict" and node.args and "environ" in cls.dotted(node.args[0])
                ):
                    out.append((node, None))
            return out

        found: list[tuple[Any, ast.AST | None]] = PythonSyntax.memo(
            tree, "drop-point-environment-reads", compute
        )
        return found

    @classmethod
    def _names_a_setting(cls, tree: ast.AST, node: ast.AST, key: ast.AST | None) -> bool:
        if key is None:
            return False
        values: list[str] | None
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            values = [key.value]
        elif isinstance(key, ast.Name):
            values = cls._values_of(tree, node, key)
        else:
            values = None
        if not values:
            return False
        return not any(pattern.match(value) for value in values for pattern, _ in CREDENTIAL_HOMES)

    @classmethod
    def _literals(cls, node: ast.AST | None) -> list[str] | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, ast.Tuple | ast.List | ast.Set):
            out: list[str] = []
            for element in node.elts:
                part = cls._literals(element)
                if part is None:
                    return None
                out += part
            return out
        if isinstance(node, ast.Dict):
            keys: list[str] = []
            for dict_key in node.keys:
                part = cls._literals(dict_key)
                if part is None:
                    return None
                keys += part
            return keys
        return None

    @classmethod
    def _values_of(cls, tree: ast.AST, read: ast.AST, key: ast.Name) -> list[str] | None:
        """The literal names a computed key can take, or None where the file does not bound them: a
        loop or comprehension variable over a literal collection (a name bound once to one counts),
        or a parameter every call site of its function passes a literal to."""
        parents = PythonSyntax.parents(tree)
        bound: dict[str, list[ast.AST]] = {}
        for assign in PythonSyntax.of(tree, ast.Assign):
            for target in assign.targets:
                if isinstance(target, ast.Name):
                    bound.setdefault(target.id, []).append(assign.value)

        def literal_collection(node: ast.AST) -> list[str] | None:
            if isinstance(node, ast.Name):
                values = bound.get(node.id, [])
                return cls._literals(values[0]) if len(values) == 1 else None
            return cls._literals(node)

        function: ast.FunctionDef | ast.AsyncFunctionDef | None = None
        at: ast.AST | None = parents.get(id(read))
        while at is not None:
            loops: list[ast.AST] = []
            if isinstance(at, ast.For | ast.AsyncFor):
                loops = [at]
            elif isinstance(at, cls._COMPREHENSIONS):
                loops = list(at.generators)  # type: ignore[attr-defined]
            for loop in loops:
                target = loop.target  # type: ignore[attr-defined]
                if isinstance(target, ast.Name) and target.id == key.id:
                    return literal_collection(loop.iter)  # type: ignore[attr-defined]
            if function is None and isinstance(at, ast.FunctionDef | ast.AsyncFunctionDef):
                function = at
            at = parents.get(id(at))
        if function is None:
            return None
        names = [a.arg for a in function.args.args]
        if key.id not in names:
            return None
        position = names.index(key.id) - (1 if names[0] in ("self", "cls") else 0)
        found: list[str] = []
        calls = 0
        for call in PythonSyntax.of(tree, ast.Call):
            if cls.dotted(call.func).rsplit(".", 1)[-1] != function.name:
                continue
            calls += 1
            argument: ast.AST | None
            if 0 <= position < len(call.args):
                argument = call.args[position]
            else:
                argument = next((k.value for k in call.keywords if k.arg == key.id), None)
            part = cls._literals(argument) if argument is not None else None
            if part is None:
                return None  # a default or a computed argument: the file does not bound it
            found += part
        return found if calls else None

    # -- The destination half --------------------------------------------------------------------

    @classmethod
    def destination_is_only_named(
        cls, content: FileContent, language: str | None, label: CapabilityHit
    ) -> bool:
        """Whether the label's literal is a message or a membership operand and nothing else: no
        request is made to it. Unresolved is False: the label stays a destination."""
        tree = cls.tree(content, language)
        if tree is None:
            return False
        node = cls._string_holding(content, tree, label.byte_start, label.byte_end)
        if node is None:
            return False
        parents = PythonSyntax.parents(tree)
        top: ast.AST = node
        while True:
            parent = parents.get(id(top))
            if parent is None:
                return False
            carried = cls._carried_by(parents, top, parent)
            if carried is None:
                return cls._consumer_names_only(tree, parents, top, parent)
            top = carried

    @classmethod
    def _carried_by(
        cls, parents: dict[int, ast.AST], top: ast.AST, parent: ast.AST
    ) -> ast.AST | None:
        """The expression the text becomes part of (an f-string, a join, a collection, a formatted
        string, a `frozenset(...)`), or None where `parent` is what uses it."""
        if isinstance(parent, cls._CARRIERS):
            return parent
        call = parents.get(id(parent))
        if isinstance(parent, ast.Attribute) and isinstance(call, ast.Call):
            # "...{}".format(x): the formatted text is what goes on
            return call if call.func is parent and parent.attr == "format" else None
        if isinstance(parent, ast.Call) and top is not parent.func:
            last = cls.dotted(parent.func).rsplit(".", 1)[-1]
            return parent if last in cls._CONSTRUCTORS else None
        return None

    @classmethod
    def _consumer_names_only(
        cls, tree: ast.AST, parents: dict[int, ast.AST], top: ast.AST, parent: ast.AST
    ) -> bool:
        """Whether what uses the text only names it: a message, a membership test, a name that is."""
        if isinstance(parent, ast.Call) and top is not parent.func:
            return cls._is_a_message(tree, parent)
        if isinstance(parent, ast.keyword):
            call = parents.get(id(parent))
            return (
                isinstance(call, ast.Call)
                and parent.arg in ("help", "message", "description")
                and cls._is_a_message(tree, call)
            )
        if isinstance(parent, ast.Compare):
            return all(isinstance(op, ast.In | ast.NotIn) for op in parent.ops)
        if isinstance(parent, ast.Assign | ast.AnnAssign):
            return cls._only_membership(tree, parent)
        return False

    @classmethod
    def _is_a_message(cls, tree: ast.AST, call: ast.Call) -> bool:
        """A call that writes for a person: `print`, a logger's or a console's method, a warning, or
        an exception class the file does not define itself (one it defines may send)."""
        callee = cls.dotted(call.func)
        last = callee.rsplit(".", 1)[-1]
        if callee == "print":
            return True
        if last in cls.LOG_METHODS:
            receiver = callee.rsplit(".", 1)[0].lower() if "." in callee else ""
            return any(word in receiver for word in cls.LOG_RECEIVERS)
        if last.endswith(("Error", "Exception", "Warning")):
            defined = {c.name for c in PythonSyntax.of(tree, ast.ClassDef)}
            return last not in defined
        return False

    @classmethod
    def _only_membership(cls, tree: ast.AST, assign: ast.Assign | ast.AnnAssign) -> bool:
        """A name bound to the label and loaded only as an operand of `in` / `not in`: a deny-list.
        An attribute, a name loaded anywhere else, or one never loaded (another file may) is not."""
        targets = assign.targets if isinstance(assign, ast.Assign) else [assign.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            return False
        name = targets[0].id
        parents = PythonSyntax.parents(tree)
        loads = 0
        for use in PythonSyntax.of(tree, ast.Name):
            if use.id != name or not isinstance(use.ctx, ast.Load):
                continue
            loads += 1
            parent = parents.get(id(use))
            if not (
                isinstance(parent, ast.Compare)
                and all(isinstance(op, ast.In | ast.NotIn) for op in parent.ops)
            ):
                return False
        return loads > 0

    # -- The composite ---------------------------------------------------------------------------

    @classmethod
    def counted(
        cls,
        content: FileContent,
        language: str | None,
        hits: list[CapabilityHit],
        *,
        unresolved: bool = False,
    ) -> list[CapabilityHit]:
        """The hits `SUSPECT.EXFIL.DROP_POINT.001` counts: loot that is loot, and labels that are
        destinations. An environment read the file never sends is not loot (D3): where the parsed
        file shows no environment, secret or credential-store value reaching a request, and the
        package's calls are all known, a read is a setting the file holds."""
        loot = [
            h
            for h in hits
            if h.capability in (Capability.CREDENTIAL, Capability.RECONNAISSANCE)
            and cls.is_loot(content, language, h)
        ]
        unsent = cls._reads_never_sent(content, language, hits, loot, unresolved)
        out: list[CapabilityHit] = []
        for hit in hits:
            if hit.capability in (Capability.CREDENTIAL, Capability.RECONNAISSANCE):
                if hit not in loot or hit in unsent:
                    continue
            elif hit.rule_id == cls.LABEL_RULE and cls.destination_is_only_named(
                content, language, hit
            ):
                continue
            out.append(hit)
        return out

    @classmethod
    def _is_an_address(cls, content: FileContent, label: CapabilityHit) -> bool:
        """Whether the label is a public IP address written as a URL or a host, not a name."""
        text = content.raw[label.byte_start : label.byte_end].decode("utf-8", "replace")
        return cls._ADDRESS.search(text) is not None

    @classmethod
    def _reads_never_sent(
        cls,
        content: FileContent,
        language: str | None,
        hits: list[CapabilityHit],
        loot: list[CapabilityHit],
        unresolved: bool,
    ) -> list[CapabilityHit]:
        """The environment reads of a parsed file whose value the file never puts in a request body:
        none of the flow facts that say an environment, secret or credential store is sent holds, the
        existing store flow (`PythonStoreFlow`, body arguments only) finds the reads in no request
        body, and the package's calls are all known. Unresolved, or unparsed, is empty: they stay loot."""
        reads = [h for h in loot if h.rule_id == "AST.PY.CREDENTIAL"]
        if not reads or unresolved or cls.tree(content, language) is None:
            return []
        if any(h.rule_id in cls.SENT_FACTS for h in hits):
            return []
        if any(cls._is_an_address(content, h) for h in hits if h.rule_id == cls.LABEL_RULE):
            return []  # a fixed public address is the rule's core shape (cordon-a0, 11-13)
        egress = [
            h.line
            for h in hits
            if h.capability is Capability.EGRESS and not h.rule_id.startswith("INTEL.")
        ]
        reached = PythonStoreFlow.reaches(
            content.text, [h.line for h in reads], egress, body_only=True
        )
        return [] if reached is not False else reads


__all__ = ["DropPointLoot"]
