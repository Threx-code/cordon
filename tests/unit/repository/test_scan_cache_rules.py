"""No cache keeps a scan's files past the scan by accident.

A process-wide memo whose arguments are a file's content held the last few files of every scan, at any
size, in a process that scans unit after unit; so such a cache registers with
`foundation.collector.ScanCaches`, which `Engine.scan` empties as it returns. And a store keyed by an
object's identity is safe only while its entry keeps the object and checks it with `is`: an identity
is reused once its object is freed. Read from the package's source:

A. a `functools.lru_cache` or `functools.cache` with a `text`, `raw`, `source`, `data` or `content`
   parameter is registered, or listed in PROCESS_WIDE with the reason it may outlive a scan;
B. no class-level store is keyed by a bare `id(...)`: identity goes through `ScanCaches.identity`;
C. a function that keys by `ScanCaches.identity` checks the held object with `is`, and its module
   registers a store.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import ClassVar

from cordon_scanner.foundation.paths import PackagePaths


class CacheRules:
    CONTENT: ClassVar[frozenset[str]] = frozenset({"text", "raw", "source", "data", "content"})
    #: A content-keyed cache allowed to outlive a scan, with the reason.
    PROCESS_WIDE: ClassVar[dict[str, str]] = {
        "intel/registries/registry_client.py:_cached_facts": (
            "a package's registry facts by its name, version and registry URL (`source` is the URL, "
            "not a file): the same package recurs across scans, and each miss is a network lookup"
        ),
    }

    @staticmethod
    def _decorated_as_cache(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = ast.unparse(target)
            if name in ("functools.lru_cache", "lru_cache", "functools.cache", "cache"):
                return True
        return False

    @staticmethod
    def _registered(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        return any(ast.unparse(d) == "ScanCaches.register" for d in node.decorator_list)

    @staticmethod
    def _key_of(call_or_subscript: ast.AST) -> ast.AST | None:
        if isinstance(call_or_subscript, ast.Subscript):
            return call_or_subscript.slice
        if (
            isinstance(call_or_subscript, ast.Call)
            and isinstance(call_or_subscript.func, ast.Attribute)
            and call_or_subscript.func.attr in ("get", "setdefault", "pop")
            and call_or_subscript.args
        ):
            return call_or_subscript.args[0]
        return None

    @staticmethod
    def _store(call_or_subscript: ast.AST) -> ast.AST | None:
        if isinstance(call_or_subscript, ast.Subscript):
            return call_or_subscript.value
        if isinstance(call_or_subscript, ast.Call) and isinstance(
            call_or_subscript.func, ast.Attribute
        ):
            return call_or_subscript.func.value
        return None

    @staticmethod
    def _class_level(store: ast.AST, aliases: frozenset[str] = frozenset()) -> bool:
        """`SomeClass._name` or `cls._name`, or a local name bound to one (`cache = Class._cache`):
        a store that outlives the call."""
        if isinstance(store, ast.Name):
            return store.id in aliases
        if not isinstance(store, ast.Attribute):
            return False
        root = store.value
        return isinstance(root, ast.Name) and (root.id == "cls" or root.id[:1].isupper())

    @staticmethod
    def _aliases(function: ast.AST) -> frozenset[str]:
        """Local names a function binds to a class-level store."""
        return frozenset(
            target.id
            for node in ast.walk(function)
            if isinstance(node, ast.Assign) and CacheRules._class_level(node.value)
            for target in node.targets
            if isinstance(target, ast.Name)
        )

    @staticmethod
    def violations(root: Path) -> list[str]:
        found: list[str] = []
        for path in sorted(root.rglob("*.py")):
            relative = path.relative_to(root).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"))
            text = ast.unparse(tree)
            registers = "ScanCaches.register(" in text
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    params = {
                        a.arg
                        for a in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
                    }
                    label = f"{relative}:{node.name}"
                    if (
                        CacheRules._decorated_as_cache(node)
                        and params & CacheRules.CONTENT
                        and not CacheRules._registered(node)
                        and label not in CacheRules.PROCESS_WIDE
                    ):
                        found.append(
                            f"A {label}: caches by {sorted(params & CacheRules.CONTENT)}, unregistered"
                        )
                    body = ast.unparse(node)
                    if "ScanCaches.identity(" in body and (" is " not in body or not registers):
                        found.append(
                            f"C {label}: keys by identity without an `is` check or a registered store"
                        )
                    aliases = CacheRules._aliases(node)
                    for inner in ast.walk(node):
                        key = CacheRules._key_of(inner)
                        if key is None or not (
                            isinstance(key, ast.Call) and ast.unparse(key.func) == "id"
                        ):
                            continue
                        store = CacheRules._store(inner)
                        if store is not None and CacheRules._class_level(store, aliases):
                            found.append(f"B {label}: {ast.unparse(store)} keyed by a bare id()")
        return found


class TestScanCaches:
    def test_every_cache_of_a_files_content_is_emptied_after_a_scan(self) -> None:
        found = CacheRules.violations(PackagePaths.root())
        assert not found, "register with ScanCaches, or list it in PROCESS_WIDE with a reason"
