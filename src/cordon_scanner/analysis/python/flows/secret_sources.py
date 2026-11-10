"""Where a secret comes from (group A (a)): a wallet's key, a value named for one, a credential
store read from disk, and the receivers that take one in. Moved out of `DataFlows` whole (its
method and module limits)."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.pyfacts import PythonFacts
from cordon_scanner.analysis.python.pysyntax import PythonSyntax

if TYPE_CHECKING:
    pass


class SecretSources(AnalyzerCore):
    """The sources `DataFlows._secret_sent` reads."""

    def _secret_carrying(self, tree: ast.AST) -> tuple[dict[str, str], dict[str, str]]:
        """(name -> the credential it carries, name -> the host its URL literal names), for the
        tree: credentials read, then carried through `with … as`, receivers that take one in,
        assignment and item assignment, to a fixed point bounded at three rounds."""
        from cordon_scanner.analysis.shared.credential_homes import SecretFlow

        self.__dict__["_tree_for_wallets"] = tree
        self.__dict__.pop("_wallet_names", None)
        self.__dict__.pop("_path_names", None)
        carrying: dict[str, str] = {}
        urls: dict[str, str] = {}
        # `with open(<credential store>) as f:`: the handle carries the store (`f.read()`).
        for node in PythonSyntax.of(tree, ast.With, ast.AsyncWith):
            for item in node.items:
                key = self._credential_read(item.context_expr)
                if key is not None and isinstance(item.optional_vars, ast.Name):
                    carrying[item.optional_vars.id] = key
        for _ in range(3):
            for call in PythonSyntax.of(tree, ast.Call):
                self._carried_by_receiver(call, carrying)
            for node in PythonSyntax.of(tree, ast.Assign):
                targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
                # `found[name] = secret` fills `found`, which then carries it.
                targets += [
                    t.value.id
                    for t in node.targets
                    if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
                ]
                literal = PythonFacts.url_literal(node.value)
                if literal is not None:
                    assigned = SecretFlow.host_of(literal)
                    if assigned:
                        urls.update(dict.fromkeys(targets, assigned))
                self._carry_assignment(node, targets, carrying)
        return carrying, urls

    def _carry_assignment(
        self, node: ast.Assign, targets: list[str], carrying: dict[str, str]
    ) -> None:
        """The targets of an assignment whose value reads or carries a credential carry it."""
        receivers = {id(a.value) for a in PythonSyntax.within(node.value, ast.Attribute)}
        for part in PythonSyntax.nodes(node.value):
            if isinstance(part, ast.Name) and part.id in self.KEY_NAMES and id(part) in receivers:
                continue
            key = self._credential_read(part)
            if key is None and isinstance(part, ast.Name) and part.id in carrying:
                key = carrying[part.id]
            if key is not None:
                carrying.update(dict.fromkeys(targets, key))
                return

    #: A wallet object's secret, by attribute, and the calls and annotations that make a wallet.
    WALLET_SECRETS: ClassVar[dict[str, str]] = {
        "key": "WALLET_PRIVATE_KEY",
        "private_key": "WALLET_PRIVATE_KEY",
        "privateKey": "WALLET_PRIVATE_KEY",
        "_private_key": "WALLET_PRIVATE_KEY",
        "mnemonic": "WALLET_MNEMONIC",
    }
    #: Names that say they hold a wallet's key or seed. Not `secret_key` or `api_key`: those name a
    #: service credential, which goes to its own host.
    KEY_NAMES: ClassVar[dict[str, str]] = {
        "private_key": "WALLET_PRIVATE_KEY",
        "privateKey": "WALLET_PRIVATE_KEY",
        "priv_key": "WALLET_PRIVATE_KEY",
        "privkey": "WALLET_PRIVATE_KEY",
        "mnemonic": "WALLET_MNEMONIC",
        "seed_phrase": "WALLET_MNEMONIC",
        "seedPhrase": "WALLET_MNEMONIC",
    }
    WALLET_MAKERS: ClassVar[tuple[str, ...]] = (
        "Account.from_key",
        "Account.create",
        "Account.from_mnemonic",
        "account.from_key",
        "account.create",
        "account.from_mnemonic",
        "Keypair.from_secret_key",
        "Keypair.from_seed",
        "Keypair.generate",
    )

    def _wallets(self) -> set[str]:
        """Names holding a wallet in this file: assigned from a wallet maker
        (`web3.Account.from_key(k)`), or a parameter annotated as an account (`account:
        LocalAccount`). Kept per tree."""
        tree = self.__dict__.get("_tree_for_wallets")
        cached: set[str] | None = self.__dict__.get("_wallet_names")
        if cached is not None:
            return cached
        found: set[str] = set()
        if tree is not None:
            for node in PythonSyntax.of(tree, ast.Assign):
                if isinstance(node.value, ast.Call):
                    dotted = self._dotted(node.value.func) or ""
                    if dotted.endswith(self.WALLET_MAKERS):
                        found.update(t.id for t in node.targets if isinstance(t, ast.Name))
            for arg in PythonSyntax.of(tree, ast.arg):
                annotation = arg.annotation
                named = (
                    annotation.id
                    if isinstance(annotation, ast.Name)
                    else annotation.attr
                    if isinstance(annotation, ast.Attribute)
                    else ""
                )
                if named.endswith(("Account", "Keypair")):
                    found.add(arg.arg)
        self.__dict__["_wallet_names"] = found
        return found

    def _credential_read(self, node: ast.AST) -> str | None:
        from cordon_scanner.analysis.shared.credential_homes import SecretFlow

        if (
            isinstance(node, ast.Attribute)
            and node.attr in self.WALLET_SECRETS
            and isinstance(node.value, ast.Name)
            and node.value.id in self._wallets()
        ):
            return self.WALLET_SECRETS[node.attr]
        if isinstance(node, ast.Name) and node.id in self.KEY_NAMES:
            # A value named for a wallet's key (`def perm(private_key): requests.post(URL,
            # json={"k": private_key})`, trongridor 0.0.1): what it holds is never sent.
            return self.KEY_NAMES[node.id]
        if isinstance(node, ast.Call):
            opened = self._opened_path(node)
            if opened is not None and SecretFlow.store_of(self._path_parts(opened)):
                # The contents of a credential store read from disk (http_query 0.0.1).
                return "CREDENTIAL_FILE"
        name: ast.AST | None = None
        if isinstance(node, ast.Subscript) and self._dotted(node.value) in (
            "os.environ",
            "os.environb",
        ):
            name = node.slice
        elif isinstance(node, ast.Call):
            dotted = self._dotted(node.func)
            if (
                dotted in ("os.getenv", "os.environ.get", "os.environ.setdefault", "os.environ.pop")
                and node.args
            ):
                name = node.args[0]
        if isinstance(name, ast.Constant) and isinstance(name.value, str):
            return name.value if SecretFlow.home_of(name.value) else None
        return None

    def _carried_by_receiver(self, call: ast.Call, carrying: dict[str, str]) -> None:
        """A receiver that takes a secret in: a reader handed a credential store's path
        (`config.read(path)`, configparser; http_query 0.0.1), or a container filled with a
        carried value (`all_secrets.append(d)`)."""
        from cordon_scanner.analysis.python.flows.containers import Containers
        from cordon_scanner.analysis.shared.credential_homes import SecretFlow

        func = call.func
        if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)):
            return
        receiver = func.value.id
        if receiver in carrying or not call.args:
            return
        if func.attr in ("read", "read_file") and SecretFlow.store_of(
            self._path_parts(call.args[0])
        ):
            carrying[receiver] = "CREDENTIAL_FILE"
            return
        if func.attr in Containers.FILLS:
            for argument in call.args:
                for part in PythonSyntax.within(argument, ast.Name):
                    if part.id in carrying:
                        carrying[receiver] = carrying[part.id]
                        return

    def _opened_path(self, call: ast.Call) -> ast.AST | None:
        """The path a call opens or reads: `open(P)`, `io.open(P)`, `P.read_text()`,
        `P.read_bytes()`, `P.open()`; None for any other call."""
        dotted = self._dotted(call.func)
        if dotted in ("open", "io.open", "codecs.open") and call.args:
            return call.args[0]
        if isinstance(call.func, ast.Attribute) and call.func.attr in (
            "read_text",
            "read_bytes",
            "open",
        ):
            return call.func.value
        return None

    def _path_parts(self, path: ast.AST) -> list[str]:
        """The string pieces a path is built from: its literals, and the literals of the names it
        uses where each is assigned once in the file (`p = os.path.expanduser("~/.aws/credentials")`
        then `open(p)`)."""
        tree = self.__dict__.get("_tree_for_wallets")
        named: dict[str, list[str]] | None = self.__dict__.get("_path_names")
        if named is None:
            named = {}
            counts: dict[str, int] = {}
            for node in PythonSyntax.of(tree, ast.Assign) if tree is not None else ():
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        counts[target.id] = counts.get(target.id, 0) + 1
                        named[target.id] = [
                            c.value
                            for c in PythonSyntax.within(node.value, ast.Constant)
                            if isinstance(c.value, str)
                        ]
            named = {k: v for k, v in named.items() if counts.get(k) == 1}
            self.__dict__["_path_names"] = named
        parts = [
            c.value for c in PythonSyntax.within(path, ast.Constant) if isinstance(c.value, str)
        ]
        for name in PythonSyntax.within(path, ast.Name):
            parts += named.get(name.id, [])
        return parts


__all__ = ["SecretSources"]
