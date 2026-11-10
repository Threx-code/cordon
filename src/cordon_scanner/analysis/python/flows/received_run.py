"""A command a message, a socket or a service handed the program, run (group B: remote command to exec).

`ExecutionFlows._received_and_run` follows an HTTP response or a sized `recv` to `exec` or a
command string. A remote shell is written many other ways: a bot answers a chat message by running
its text, a client reads a websocket and runs what the server sent, a program reads its
instructions out of a spreadsheet, and the run is in a helper the handler reaches through
`asyncio.to_thread`. This adds those SOURCES and that HOP to the same flow; the sinks are the same
ones (`exec`/`eval`/`compile`, a command string, never an argument list naming a program).
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.python.execution_flows import ExecutionFlows
from cordon_scanner.analysis.python.pyfacts import PRIMITIVES
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from cordon_scanner.analysis.python.scoped_taint import ScopedTaint


class ReceivedRuns(ExecutionFlows):
    """`_received_message_run` and what it needs."""

    #: Calls that register a function as the one a message or command is handed to.
    _REGISTRARS: ClassVar[frozenset[str]] = frozenset(
        {
            "add_handler", "CommandHandler", "MessageHandler", "CallbackQueryHandler",
            "register_message_handler", "add_message_handler", "add_event_handler",
        }
    )  # fmt: skip
    #: Decorators that make a function the one a message is handed to.
    _HANDLER_DECORATORS: ClassVar[frozenset[str]] = frozenset(
        {
            "message_handler", "on_message", "callback_query_handler", "channel_post_handler",
            "command", "event", "listen", "message",
        }
    )  # fmt: skip
    #: A connection a server's frames are read from: what `.recv()` and `async for` read.
    _SOCKET_CLIENTS: ClassVar[frozenset[str]] = frozenset(
        {
            "websockets.connect", "websockets.client.connect", "websockets.legacy.client.connect",
            "websocket.create_connection", "websocket.WebSocket",
        }
    )  # fmt: skip
    #: Calls whose result is a batch of messages a service holds for the program.
    _POLLS: ClassVar[frozenset[str]] = frozenset({"getUpdates", "get_updates"})
    #: Wrappers that start a function on another thread: the function and the arguments it gets.
    _OFFLOADS: ClassVar[frozenset[str]] = frozenset({"to_thread", "run_in_executor", "submit"})
    #: Parameter types a chat library hands a handler: the message, update or callback it received.
    _MESSAGE_TYPES: ClassVar[frozenset[str]] = frozenset({"Message", "Update", "CallbackQuery"})
    #: Modules of the chat and messaging libraries. A decorator named `command` or a parameter named
    #: `message` is only a handler where the file talks to one of them: `@click.command()` and an
    #: `email.message.Message` are not a channel anyone sends commands over.
    _CHAT_LIBRARIES: ClassVar[frozenset[str]] = frozenset(
        {
            "telegram", "telebot", "aiogram", "pyrogram", "telethon", "discord", "disnake",
            "nextcord", "hikari", "slack_sdk", "slack_bolt", "slack", "slackclient", "twilio",
            "irc", "matrix_client", "nio", "vk_api", "vkbottle", "botbuilder", "whatsapp",
            "tweepy", "mattermostdriver", "zulip", "rocketchat_API", "line", "linebot",
            "pytgcalls", "pyTelegramBotAPI", "fbchat", "wechat", "itchat", "wxpy",
        }
    )  # fmt: skip
    #: Methods that return the command's text in another shape.
    _SAME_TEXT: ClassVar[frozenset[str]] = frozenset(
        {"split", "strip", "lower", "decode", "rstrip"}
    )

    def _received_message_run(self, tree: ast.AST) -> None:
        """What a message, a websocket frame or a service's reply carries, run as a command.

        Seeds: the parameters of a registered handler, a connection's frames, a polled batch, a
        spreadsheet read. The flow is `ScopedTaint`'s (every binding form, local returns, local
        calls); the sinks are `_received_and_run`'s. One hop more: a local function that runs one of
        its own parameters is a runner, and a call to it with a received value (also through
        `asyncio.to_thread(run, text)`) runs it."""
        from cordon_scanner.analysis.python.scoped_taint import ScopedTaint

        calls = PythonSyntax.of(tree, ast.Call)
        handlers = self._handlers(tree, calls)
        if not handlers and not any(
            self._source_call(c) or self._dotted(c.func) in self._SOCKET_CLIENTS for c in calls
        ):
            return
        tainted = ScopedTaint(tree)
        for function in handlers:
            params = {a.arg for a in function.args.args + function.args.kwonlyargs} - {
                "self",
                "cls",
            }
            tainted.mark(n for n in PythonSyntax.within(function, ast.Name) if n.id in params)
        sockets = self._socket_names(tainted)

        def received(node: ast.AST) -> bool:
            return self._received_by(tainted, node) or self._message_source(tainted, node, sockets)

        tainted.spread(received)
        runners = {**self._imported_runners, **self._runners(tree)}
        for node in calls:
            resolved = self._resolve_callee(node)
            if resolved is None:
                continue
            command = resolved[1].args[0] if resolved[1].args else None
            if command is not None and received(command):
                self._run_of(tainted, tree, node, resolved[0], command)
            for name, args in self._reached(node):
                if name in runners and any(
                    i in runners[name] for i, a in enumerate(args) if received(a)
                ):
                    self._record(
                        Capability.FETCH_EXEC,
                        node,
                        f"received run: {name} runs a received command at={self._when(tainted, tree, node)}",
                    )

    def _run_of(
        self, tainted: ScopedTaint, tree: ast.AST, node: ast.Call, callee: str, command: ast.AST
    ) -> None:
        capability = PRIMITIVES.get(callee)
        if capability is Capability.EXECUTE or (
            capability is Capability.SPAWN and not tainted.is_argument_list(command)
        ):
            self._record(
                Capability.FETCH_EXEC,
                node,
                f"received run: {callee} at={self._when(tainted, tree, node)}",
            )

    @staticmethod
    def _when(tainted: ScopedTaint, tree: ast.AST, node: ast.AST) -> str:
        """`load` at the top of the module, `call` inside a function."""
        return "load" if tainted.scope_of(node) is tree else "call"

    def _handlers(
        self, tree: ast.AST, calls: list[ast.Call]
    ) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        """Functions a message or command is handed to: registered by a call, or decorated."""
        functions = PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef)
        by_name = {f.name: f for f in functions}
        found: dict[int, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        chat = self._talks_to_a_chat_library(tree)
        for function in functions if chat else ():
            for decorator in function.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if isinstance(target, ast.Attribute) and target.attr in self._HANDLER_DECORATORS:
                    found[id(function)] = function
        for function in functions if chat else ():
            if self._takes_a_message(function):
                found[id(function)] = function
        for call in calls:
            name = (
                call.func.attr
                if isinstance(call.func, ast.Attribute)
                else getattr(call.func, "id", "")
            )
            if name in self._REGISTRARS:
                for arg in [*call.args, *(k.value for k in call.keywords)]:
                    if isinstance(arg, ast.Name) and arg.id in by_name:
                        found[id(by_name[arg.id])] = by_name[arg.id]
        return list(found.values())

    def _talks_to_a_chat_library(self, tree: ast.AST) -> bool:
        """Whether the file imports a chat or messaging library (`_CHAT_LIBRARIES`)."""
        for node in PythonSyntax.of(tree, ast.Import, ast.ImportFrom):
            modules = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if not node.level
                else []
            )
            if any(m.split(".")[0] in self._CHAT_LIBRARIES for m in modules):
                return True
        return False

    def _takes_a_message(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """The signature of a chat handler: `(update, context)`, a parameter typed as the library's
        message, or `handle_*`/`on_*` taking `message`. The registration may be in another module."""
        args = [a for a in function.args.args if a.arg not in ("self", "cls")]
        if [a.arg for a in args[:2]] == ["update", "context"]:
            return True
        for a in args:
            note = (
                a.annotation.attr
                if isinstance(a.annotation, ast.Attribute)
                else getattr(a.annotation, "id", "")
            )
            if note in self._MESSAGE_TYPES:
                return True
        return function.name.startswith(("handle_", "on_")) and any(
            a.arg in ("message", "msg") for a in args
        )

    def _source_call(self, call: ast.Call) -> bool:
        """A call whose result is what a service or a peer sent."""
        func = call.func
        if not isinstance(func, ast.Attribute):
            return False
        if func.attr in self._POLLS:
            return True
        if func.attr == "execute":
            links: set[str] = set()
            link: ast.AST = func
            while isinstance(link, ast.Attribute | ast.Call):
                links.add(link.attr if isinstance(link, ast.Attribute) else "")
                link = link.value if isinstance(link, ast.Attribute) else link.func
            return {"spreadsheets", "values"} <= links
        return func.attr == "recv" and not call.args

    def _socket_names(self, tainted: ScopedTaint) -> set[str]:
        """Names bound from a connection whose frames the program reads (`ws = await connect(...)`)."""
        names: set[str] = set()
        for _scope, targets, value in tainted._bindings:
            inner = value.value if isinstance(value, ast.Await) else value
            if isinstance(inner, ast.Call) and (self._dotted(inner.func) in self._SOCKET_CLIENTS):
                names.update(targets)
        return names

    def _message_source(self, tainted: ScopedTaint, node: ast.AST, sockets: set[str]) -> bool:
        """Whether this expression reads a frame, a polled batch or a spreadsheet's cells."""
        stack = [node]
        while stack:
            part = stack.pop()
            if isinstance(part, ast.Lambda | ast.FunctionDef | ast.AsyncFunctionDef) or self._wraps(
                part
            ):
                continue
            if (
                isinstance(part, ast.Call)
                and self._source_call(part)
                and not (
                    isinstance(part.func, ast.Attribute)
                    and part.func.attr == "recv"
                    and not self._reads_socket(part.func.value, sockets)
                )
            ):
                return True
            if (
                isinstance(part, ast.Name)
                and part.id in sockets
                and isinstance(
                    self._parent_of(tainted, part), ast.comprehension | ast.For | ast.AsyncFor
                )
            ):
                return True
            stack.extend(ast.iter_child_nodes(part))
        return False

    @staticmethod
    def _reads_socket(receiver: ast.AST, sockets: set[str]) -> bool:
        return isinstance(receiver, ast.Name) and receiver.id in sockets

    @staticmethod
    def _parent_of(tainted: ScopedTaint, node: ast.AST) -> ast.AST | None:
        return tainted._parents.get(id(node))

    def _runners(self, tree: ast.AST) -> dict[str, set[int]]:
        """Local functions that run one of their own parameters, by the positions that are run."""
        found: dict[str, set[int]] = {}
        for function in PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef):
            params = [a.arg for a in function.args.args if a.arg not in ("self", "cls")]
            derived = {p: {p} for p in params}
            for assign in PythonSyntax.within(function, ast.Assign):
                names = {n.id for n in PythonSyntax.within(assign.value, ast.Name)}
                for held in derived.values():
                    if names & held:
                        held.update(t.id for t in assign.targets if isinstance(t, ast.Name))
            for call in PythonSyntax.within(function, ast.Call):
                resolved = self._resolve_callee(call)
                if resolved is None or not resolved[1].args:
                    continue
                capability = PRIMITIVES.get(resolved[0])
                command = resolved[1].args[0]
                for i, p in enumerate(params):
                    if self._runs(capability, command, derived[p], resolved[1]):
                        found.setdefault(function.name, set()).add(i)
        return found

    def _runs(
        self, capability: Capability | None, command: ast.AST, held: set[str], call: ast.Call
    ) -> bool:
        """`exec(p)`, `os.system(p)`, `check_output(p.split())`, `run(p, shell=True)`: p is the program."""
        while (
            isinstance(command, ast.Call)
            and isinstance(command.func, ast.Attribute)
            and (
                command.func.attr in self._SAME_TEXT or self._dotted(command.func) == "shlex.split"
            )
        ):
            command = (
                command.func.value if command.func.attr in self._SAME_TEXT else command.args[0]
            )
        if capability is Capability.EXECUTE:
            return isinstance(command, ast.Name) and command.id in held
        if capability is Capability.SPAWN:
            return isinstance(command, ast.Name) and command.id in held
        return False

    def _reached(self, call: ast.Call) -> list[tuple[str, list[ast.AST]]]:
        """(function, arguments it gets) for a call to a local function, direct or offloaded."""
        func = call.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        out: list[tuple[str, list[ast.AST]]] = []
        if isinstance(func, ast.Name):
            out.append((func.id, list(call.args)))
        elif (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in ("self", "cls")
        ):
            out.append((func.attr, list(call.args)))
        if name in self._OFFLOADS:
            skip = 2 if name == "run_in_executor" else 1
            target = call.args[skip - 1] if len(call.args) >= skip else None
            if isinstance(target, ast.Name | ast.Attribute):
                out.append(
                    (
                        target.id if isinstance(target, ast.Name) else target.attr,
                        list(call.args[skip:]),
                    )
                )
        if name == "Thread":
            target = next((k.value for k in call.keywords if k.arg == "target"), None)
            args = next((k.value for k in call.keywords if k.arg == "args"), None)
            if isinstance(target, ast.Name) and isinstance(args, ast.Tuple | ast.List):
                out.append((target.id, list(args.elts)))
        return out


__all__ = ["ReceivedRuns"]
