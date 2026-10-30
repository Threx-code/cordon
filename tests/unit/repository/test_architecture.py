"""The design rules: coupling and the SOLID principles, read from the source (review 27).

Each rule names what it holds and why. Where the code does not meet a rule yet, the site is listed
in architecture_debt.json, keyed by module and symbol so an edit elsewhere does not disturb it, and
the list may only shrink: a site not listed fails the rule, and a listed site that is gone fails
`test_the_debt_lists_only_what_is_left` until it is deleted. The owner's rule (2026-10-30): every
gap fixed, and tests so none comes back. A rule is final when its list is empty; the release waits
for every list to be.

- adapter_order: the adapter layers import in one direction, ecosystems < intel < rules, sources,
  images < detect. One rank let them import each other, and they formed a cycle.
- cycles: no module cycle, imports inside functions included. A lazy import that closes a cycle
  breaks no import, but the two modules still cannot change apart.
- detect_on_intel: a detector reads intelligence through intel.base's protocols, never a concrete
  intel module, so a detector is tested and changed without the store behind it.
- ecosystem_names: an ecosystem's name is compared only where its facts live (ecosystems, sources,
  images, intel.registries' clients). Elsewhere a new ecosystem would mean editing an if-chain.
- duplicate_classes: one piece of logic is written once; a class body with methods repeated in
  two places is one change made twice. Classes of fields alone are types, not logic, and are left.
- class_methods: at most 25 methods per class; a class past that does several jobs.
- incohesive_classes: a class of 8 or more instance methods of which no two share state is a bag of
  functions, not an object.
- isinstance_chains: dispatch on a type by a table keyed by it, not by three or more isinstance
  branches, so a new type is a new entry.

Rules that already hold have their own tests, unlisted: inner layers construct no adapter, no
override refuses its base's method, no unannotated mutable module-level store.
"""

from __future__ import annotations

import ast
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import ClassVar

from support import ROOT

PACKAGE = ROOT / "src" / "cordon_scanner"
DEBT = ROOT / "tests" / "unit" / "repository" / "architecture_debt.json"


class Modules:
    """Every module of the package, parsed once."""

    _trees: ClassVar[dict[str, ast.Module]] = {}

    @classmethod
    def trees(cls) -> dict[str, ast.Module]:
        if not cls._trees:
            for path in sorted(PACKAGE.rglob("*.py")):
                parts = list(path.relative_to(PACKAGE).with_suffix("").parts)
                if parts[-1] == "__init__":
                    parts.pop()
                cls._trees[".".join(["cordon_scanner", *parts])] = ast.parse(
                    path.read_text(encoding="utf-8")
                )
        return cls._trees

    @staticmethod
    def layer(module: str) -> str:
        parts = module.split(".")
        return parts[1] if len(parts) > 1 else ""

    @classmethod
    def resolve(cls, dotted: str) -> str | None:
        parts = dotted.split(".")
        while parts:
            if ".".join(parts) in cls.trees():
                return ".".join(parts)
            parts.pop()
        return None

    @staticmethod
    def guarded(tree: ast.Module) -> set[int]:
        """The ids of nodes under `if TYPE_CHECKING:`: annotations only, never run."""
        return {
            id(child)
            for node in ast.walk(tree)
            if isinstance(node, ast.If) and "TYPE_CHECKING" in ast.unparse(node.test)
            for child in ast.walk(node)
        }

    @classmethod
    def imports(cls, module: str) -> set[str]:
        """Every package module `module` imports, inside functions too."""
        tree = cls.trees()[module]
        is_package = (PACKAGE / Path(*module.split(".")[1:]) / "__init__.py").exists()
        package = module if is_package else module.rpartition(".")[0]
        guarded = Modules.guarded(tree)
        out = set()
        for node in ast.walk(tree):
            if id(node) in guarded:
                continue
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    anchor = package.split(".")[: len(package.split(".")) - node.level + 1]
                    base = ".".join([*anchor, base] if base else anchor)
                names = [base, *(f"{base}.{a.name}" for a in node.names)]
            for name in names:
                target = cls.resolve(name) if name.startswith("cordon_scanner") else None
                if target and target != module:
                    out.add(target)
        return out

    @staticmethod
    def scoped(tree: ast.Module):
        """`(qualified name, node)` for every class and function, nested ones included."""
        todo: list[tuple[ast.AST, str]] = [(tree, "")]
        while todo:
            node, prefix = todo.pop()
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    name = f"{prefix}{child.name}"
                    yield name, child
                    todo.append((child, f"{name}."))
                else:
                    todo.append((child, prefix))


class Rules:
    """Each rule's sites in the code as it is: {key: count}."""

    ADAPTER_RANK: ClassVar[dict[str, int]] = {
        "ecosystems": 0,
        "intel": 1,
        "rules": 2,
        "sources": 2,
        "images": 2,
        "detect": 3,
    }
    NAMES_HOME: ClassVar[tuple[str, ...]] = (
        "cordon_scanner.ecosystems",
        "cordon_scanner.sources",
        "cordon_scanner.images",
        "cordon_scanner.intel.registries",
    )
    ECOSYSTEM_NAMES: ClassVar[frozenset[str]] = frozenset(
        {
            "npm",
            "pypi",
            "PyPI",
            "cargo",
            "crates.io",
            "maven",
            "gradle",
            "nuget",
            "go",
            "gomod",
            "golang",
            "rubygems",
            "gem",
            "composer",
            "packagist",
            "hex",
            "pub",
            "cocoapods",
            "swift",
            "conda",
            "opam",
            "nix",
            "homebrew",
            "terraform",
            "helm",
            "actions",
            "ansible",
            "vscode",
        }
    )
    MAX_METHODS: ClassVar[int] = 25

    @staticmethod
    def adapter_order() -> dict[str, int]:
        out = {}
        for module in Modules.trees():
            mine = Rules.ADAPTER_RANK.get(Modules.layer(module))
            if mine is None:
                continue
            for target in Modules.imports(module):
                theirs = Rules.ADAPTER_RANK.get(Modules.layer(target))
                if theirs is not None and theirs > mine:
                    out[f"{module} -> {target}"] = 1
        return out

    @staticmethod
    def cycles() -> dict[str, int]:
        """Every import edge that lies inside a cycle (Tarjan's components, iteratively)."""
        graph = {m: Modules.imports(m) for m in Modules.trees()}
        index: dict[str, int] = {}
        low: dict[str, int] = {}
        stack: list[str] = []
        on: set[str] = set()
        component_of: dict[str, int] = {}
        counter = 0
        for start in sorted(graph):
            if start in index:
                continue
            index[start] = low[start] = counter
            counter += 1
            stack.append(start)
            on.add(start)
            work = [(start, iter(sorted(graph[start])))]
            while work:
                node, children = work[-1]
                for child in children:
                    if child not in index:
                        index[child] = low[child] = counter
                        counter += 1
                        stack.append(child)
                        on.add(child)
                        work.append((child, iter(sorted(graph[child]))))
                        break
                    if child in on:
                        low[node] = min(low[node], index[child])
                else:
                    work.pop()
                    if work:
                        low[work[-1][0]] = min(low[work[-1][0]], low[node])
                    if low[node] == index[node]:
                        while True:
                            member = stack.pop()
                            on.discard(member)
                            component_of[member] = index[node]
                            if member == node:
                                break
        return {
            f"{a} -> {b}": 1
            for a, targets in graph.items()
            for b in targets
            if component_of[a] == component_of[b]
        }

    @staticmethod
    def detect_on_intel() -> dict[str, int]:
        return {
            f"{module} -> {target}": 1
            for module in Modules.trees()
            if Modules.layer(module) == "detect"
            for target in Modules.imports(module)
            if Modules.layer(target) == "intel" and target not in ("cordon_scanner.intel.base",)
        }

    @staticmethod
    def ecosystem_names() -> dict[str, int]:
        out: dict[str, int] = defaultdict(int)
        for module, tree in Modules.trees().items():
            if module.startswith(Rules.NAMES_HOME):
                continue
            owner = {id(n): name for name, scope in Modules.scoped(tree) for n in ast.walk(scope)}
            for node in ast.walk(tree):
                if not isinstance(node, ast.Compare):
                    continue
                values = set()
                for operand in [node.left, *node.comparators]:
                    elements = (
                        operand.elts
                        if isinstance(operand, (ast.Tuple, ast.Set, ast.List))
                        else [operand]
                    )
                    values |= {
                        e.value
                        for e in elements
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)
                    }
                if values & Rules.ECOSYSTEM_NAMES:
                    out[f"{module}:{owner.get(id(node), '<module>')}"] += 1
        return dict(out)

    @staticmethod
    def duplicate_classes() -> dict[str, int]:
        """`Name#hash` -> how many modules write that body (2 or more)."""
        bodies: dict[str, set[str]] = defaultdict(set)
        for module, tree in Modules.trees().items():
            for _, node in Modules.scoped(tree):
                if isinstance(node, ast.ClassDef):
                    body = [
                        s
                        for s in node.body
                        if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
                    ]
                    text = "\n".join(ast.dump(s) for s in body)
                    if len(text) < 80 or not any(
                        isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) for s in body
                    ):
                        # Fields alone are a shape, not logic: two node types or two records with
                        # the same fields are two types, and merging them would lose one.
                        continue
                    digest = hashlib.sha256(text.encode()).hexdigest()[:12]
                    bodies[f"{digest}"].add(f"{module}.{node.name}")
        return {
            ",".join(sorted(members)): len(members)
            for members in bodies.values()
            if len(members) > 1
        }

    @staticmethod
    def methods_of(node: ast.ClassDef) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        return [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    @staticmethod
    def class_methods() -> dict[str, int]:
        return {
            f"{module}:{name}": len(Rules.methods_of(node))
            for module, tree in Modules.trees().items()
            for name, node in Modules.scoped(tree)
            if isinstance(node, ast.ClassDef) and len(Rules.methods_of(node)) > Rules.MAX_METHODS
        }

    @staticmethod
    def incohesive_classes() -> dict[str, int]:
        out = {}
        for module, tree in Modules.trees().items():
            for name, node in Modules.scoped(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                if any(ast.unparse(b).endswith(("Protocol", "ABC")) for b in node.bases):
                    continue
                instance = [
                    m
                    for m in Rules.methods_of(node)
                    if not any(
                        ast.unparse(d) in ("staticmethod", "classmethod") for d in m.decorator_list
                    )
                ]
                if len(instance) < 8:
                    continue
                used = [
                    {
                        n.attr
                        for n in ast.walk(m)
                        if isinstance(n, ast.Attribute)
                        and isinstance(n.value, ast.Name)
                        and n.value.id == "self"
                    }
                    | {
                        n.func.attr
                        for n in ast.walk(m)
                        if isinstance(n, ast.Call)
                        and isinstance(n.func, ast.Attribute)
                        and isinstance(n.func.value, ast.Name)
                        and n.func.value.id == "self"
                    }
                    for m in instance
                ]
                if not any(a & b for i, a in enumerate(used) for b in used[i + 1 :]):
                    out[f"{module}:{name}"] = len(instance)
        return out

    @staticmethod
    def isinstance_chains() -> dict[str, int]:
        out: dict[str, int] = {}
        for module, tree in Modules.trees().items():
            owner = {id(n): name for name, scope in Modules.scoped(tree) for n in ast.walk(scope)}
            inner: set[int] = set()
            for node in ast.walk(tree):
                if not isinstance(node, ast.If) or id(node) in inner:
                    continue
                chain, current = 0, node
                while isinstance(current, ast.If) and "isinstance(" in ast.unparse(current.test):
                    chain += 1
                    inner.add(id(current))
                    current = current.orelse[0] if len(current.orelse) == 1 else None
                if chain >= 3:
                    key = f"{module}:{owner.get(id(node), '<module>')}"
                    out[key] = max(out.get(key, 0), chain)
        return out

    ALL: ClassVar[tuple[str, ...]] = (
        "adapter_order",
        "cycles",
        "detect_on_intel",
        "ecosystem_names",
        "duplicate_classes",
        "class_methods",
        "incohesive_classes",
        "isinstance_chains",
    )

    @staticmethod
    def measure(rule: str) -> dict[str, int]:
        return getattr(Rules, rule)()


class Debt:
    @staticmethod
    def load() -> dict[str, dict[str, int]]:
        data = json.loads(DEBT.read_text(encoding="utf-8"))
        return {rule: data.get(rule, {}) for rule in Rules.ALL}


class TestDesignRules:
    def test_no_new_site_breaks_a_rule(self) -> None:
        debt = Debt.load()
        problems = []
        for rule in Rules.ALL:
            for key, count in sorted(Rules.measure(rule).items()):
                allowed = debt[rule].get(key)
                if allowed is None:
                    problems.append(f"{rule}: {key}")
                elif count > allowed:
                    problems.append(f"{rule}: {key} ({count}, listed {allowed})")
        assert not problems, (
            "these break a design rule (see this module's docstring for each rule's reason):\n"
            + "\n".join(problems)
        )

    def test_the_debt_lists_only_what_is_left(self) -> None:
        debt = Debt.load()
        stale = []
        for rule in Rules.ALL:
            now = Rules.measure(rule)
            for key, allowed in sorted(debt[rule].items()):
                if key not in now:
                    stale.append(f"{rule}: {key} is fixed; delete it from architecture_debt.json")
                elif now[key] < allowed:
                    stale.append(
                        f"{rule}: {key} is down to {now[key]}; lower its entry from {allowed}"
                    )
        assert not stale, "\n".join(stale)

    def test_inner_layers_construct_no_adapter(self) -> None:
        adapters = set()
        bases = {
            "Detector",
            "BaseEcosystem",
            "Ecosystem",
            "FileSource",
            "WorkingTreeSource",
            "Reporter",
            "Notifier",
        }
        for tree in Modules.trees().values():
            for _, node in Modules.scoped(tree):
                if isinstance(node, ast.ClassDef) and any(
                    ast.unparse(b).rsplit(".", 1)[-1] in bases for b in node.bases
                ):
                    adapters.add(node.name)
        found = [
            f"{module}:{node.lineno} {ast.unparse(node.func)}"
            for module, tree in Modules.trees().items()
            if Modules.layer(module) in ("foundation", "analysis", "decide", "engine")
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and ast.unparse(node.func).rsplit(".", 1)[-1] in adapters
        ]
        assert not found, (
            "an inner layer builds an adapter; take it from the registry:\n" + "\n".join(found)
        )

    def test_no_unannotated_mutable_module_store(self) -> None:
        found = []
        mutable_calls = {"dict", "list", "set", "defaultdict", "OrderedDict", "Counter", "deque"}
        for module, tree in Modules.trees().items():
            for statement in tree.body:
                if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                    target = statement.targets[0]
                    value = statement.value
                elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
                    target, value = statement.target, statement.value
                else:
                    continue
                name = ast.unparse(target)
                mutable = isinstance(
                    value, (ast.Dict, ast.List, ast.Set, ast.DictComp, ast.ListComp, ast.SetComp)
                ) or (
                    isinstance(value, ast.Call)
                    and ast.unparse(value.func).rsplit(".", 1)[-1] in mutable_calls
                )
                if mutable and name != "__all__" and not name.lstrip("_").isupper():
                    found.append(f"{module}:{statement.lineno} {name}")
        assert not found, "a mutable module-level store not named as a table:\n" + "\n".join(found)

    def test_only_the_outer_layers_use_the_front_door(self) -> None:
        """`cordon_scanner.Scanner` is for callers: the command line, the MCP server, the cloud
        runner. A module inside the engine or below it that builds a scan through it reaches up past
        its own layer; it uses engine.assembly, where a scan is put together."""
        outer = {"cli", "mcp", "cloud", "judge", "model", "notify", "report", "__main__"}
        found = sorted(
            module
            for module in Modules.trees()
            if Modules.layer(module)
            and Modules.layer(module) not in outer
            and "cordon_scanner" in Modules.imports(module)
        )
        assert not found, "imports the package's front door from inside:\n" + "\n".join(found)

    def test_no_override_refuses_its_base(self) -> None:
        classes: dict[str, list[ast.ClassDef]] = defaultdict(list)
        for tree in Modules.trees().values():
            for _, node in Modules.scoped(tree):
                if isinstance(node, ast.ClassDef):
                    classes[node.name].append(node)
        found = []
        for module, tree in Modules.trees().items():
            for name, node in Modules.scoped(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                for base in node.bases:
                    for parent in classes.get(ast.unparse(base).rsplit(".", 1)[-1], []):
                        inherited = {m.name: m for m in Rules.methods_of(parent)}
                        for method in Rules.methods_of(node):
                            original = inherited.get(method.name)
                            if original is None or method.name.startswith("__"):
                                continue
                            if "NotImplementedError" in ast.unparse(
                                method
                            ) and "NotImplementedError" not in ast.unparse(original):
                                found.append(f"{module}:{name}.{method.name}")
        assert not found, "an override refuses what its base does:\n" + "\n".join(found)
