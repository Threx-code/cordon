"""The core integrates; it does not rebuild. Delivery to a webhook or a chat may exist, outside the core.

The core is the decision and detection path: `decide`, `contracts`, `engine` and `detect`. None of them imports a notification, webhook,
identity-provider or authorisation-engine module (Cordon's own `notify` package, or a standard-library module that delivers mail or serves
requests), and none holds a module of that kind by name. The runtime dependencies of the package stay empty (`test_no_third_party.py` also
pins that, with the imports): nothing is bought in to do these jobs either.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from support import ROOT


class Imports:
    @staticmethod
    def of(path: Path) -> list[tuple[int, str]]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        found: list[tuple[int, str]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.extend((node.lineno, alias.name) for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.append((node.lineno, node.module))
        return found


class Core:
    PACKAGES = ("decide", "contracts", "engine", "detect")
    #: A module the core must not import: Cordon's own delivery, and the standard library's mail and server modules.
    BARRED = frozenset(
        {
            "cordon_scanner.notify",
            "smtplib",
            "poplib",
            "imaplib",
            "http.server",
            "socketserver",
            "xmlrpc.server",
            "wsgiref.simple_server",
        }
    )
    #: A module name that says it is one of the rebuilt things.
    NAMED = re.compile(
        r"(oauth|oidc|saml|ldap|webhook|smtp|slack|sso|casbin|authoriz|notif)", re.IGNORECASE
    )

    @classmethod
    def imported(cls, module: str) -> bool:
        return any(module == name or module.startswith(name + ".") for name in cls.BARRED)

    @classmethod
    def violations(cls, root: Path = ROOT / "src" / "cordon_scanner") -> list[str]:
        out: list[str] = []
        for package in cls.PACKAGES:
            for path in sorted((root / package).rglob("*.py")):
                relative = path.relative_to(root).as_posix()
                if cls.NAMED.search(path.stem):
                    out.append(f"{relative} is named like a rebuilt integration")
                out.extend(
                    f"{relative}:{line} imports {module}"
                    for line, module in Imports.of(path)
                    if cls.imported(module)
                )
        return out


class TestTheCoreIntegratesOnly:
    def test_the_four_core_packages_exist(self) -> None:
        for package in Core.PACKAGES:
            assert (ROOT / "src" / "cordon_scanner" / package).is_dir(), package

    def test_the_core_imports_no_delivery_server_identity_or_authorisation_module(self) -> None:
        assert Core.violations() == []

    def test_the_check_finds_an_import_and_a_name_where_they_are_written(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "decide").mkdir()
        (tmp_path / "decide" / "ok.py").write_text("import json\n", encoding="utf-8")
        (tmp_path / "decide" / "mailer.py").write_text(
            "def f():\n    import smtplib\n", encoding="utf-8"
        )
        (tmp_path / "decide" / "oauth_client.py").write_text(
            "from cordon_scanner.notify import channel\n", encoding="utf-8"
        )
        found = []
        for package in ("decide",):
            for path in sorted((tmp_path / package).rglob("*.py")):
                if Core.NAMED.search(path.stem):
                    found.append(f"{path.name} named")
                found += [
                    f"{path.name} imports {m}" for _, m in Imports.of(path) if Core.imported(m)
                ]
        assert found == [
            "mailer.py imports smtplib",
            "oauth_client.py named",
            "oauth_client.py imports cordon_scanner.notify",
        ]

    def test_a_longer_name_that_only_starts_like_a_barred_one_is_not_barred(self) -> None:
        assert not Core.imported("cordon_scanner.notifier_free") and not Core.imported(
            "http.client"
        )
        assert Core.imported("cordon_scanner.notify.channels.slack") and Core.imported(
            "http.server"
        )
