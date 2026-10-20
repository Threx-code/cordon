"""Which PHP file a Composer plugin runs when it is installed.

A package of `"type": "composer-plugin"` names its plugin class in `extra.class`, and Composer
instantiates that class and calls `activate()` during `composer install` and `composer update`,
on the machine of whoever pulled the package in, before any of the application's own code runs.
That is the definition of an install hook, and it is how a malicious Composer package executes:
no `scripts` entry is needed, because the plugin is the script.

The class name is resolved through the package's own PSR-4 autoload map, the way Composer resolves
it, to a file in the scanned tree. Nothing outside the tree is consulted, and a name that does not
resolve to a scanned file is simply not a hook.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any


class ComposerPluginHooks:
    """The plugin classes `composer.json` files in a scan declare, as scanned file paths."""

    MAX_CLASSES = 16

    @classmethod
    def paths(cls, units: Sequence[Any]) -> set[str]:
        by_path = {unit.path: unit for unit in units}
        hooks: set[str] = set()
        for unit in units:
            member = unit.path.rpartition("!")[2]
            if member.rpartition("/")[2] != "composer.json":
                continue
            document = cls._document(unit)
            if document is None or document.get("type") != "composer-plugin":
                continue
            container = unit.path[: len(unit.path) - len(member)]
            root = member.rpartition("/")[0]
            for candidate in cls.candidates(document, root):
                full = f"{container}{candidate}"
                if full in by_path:
                    hooks.add(full)
        return hooks

    @staticmethod
    def _document(unit: Any) -> dict[str, Any] | None:
        content = getattr(unit, "content", None)
        text = getattr(content, "text", None)
        if not isinstance(text, str):
            return None
        try:
            parsed = json.loads(text)
        except (ValueError, RecursionError):
            return None
        return parsed if isinstance(parsed, dict) else None

    @classmethod
    def candidates(cls, document: dict[str, Any], root: str) -> list[str]:
        """Every scanned-tree path the declared plugin classes may live at."""
        extra = document.get("extra")
        declared = extra.get("class") if isinstance(extra, dict) else None
        names = (
            [declared]
            if isinstance(declared, str)
            else declared
            if isinstance(declared, list)
            else []
        )
        classes = [
            n.strip().lstrip("\\")
            for n in names[: cls.MAX_CLASSES]
            if isinstance(n, str) and n.strip()
        ]
        autoload = document.get("autoload")
        psr4 = autoload.get("psr-4") if isinstance(autoload, dict) else None
        if not classes or not isinstance(psr4, dict):
            return []
        found: list[str] = []
        for name in classes:
            for prefix, directories in psr4.items():
                if not isinstance(prefix, str) or not name.startswith(prefix.lstrip("\\")):
                    continue
                rest = name[len(prefix.lstrip("\\")) :].replace("\\", "/")
                for directory in (
                    [directories]
                    if isinstance(directories, str)
                    else directories
                    if isinstance(directories, list)
                    else []
                ):
                    if not isinstance(directory, str):
                        continue
                    relative = "/".join(p for p in (root, directory.strip("/"), f"{rest}.php") if p)
                    if ".." in relative.split("/"):
                        continue
                    found.append(relative)
        return found
