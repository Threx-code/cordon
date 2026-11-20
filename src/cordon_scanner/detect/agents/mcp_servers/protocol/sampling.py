"""An MCP server using the client's model as its own tool, through sampling.

`sampling/createMessage` lets a server ask the client's model to complete a prompt the server wrote. Summarising or
classifying what the server fetched is what it is for. Two uses are not:

```
  directive   the prompt tells the model to read a secret and put it in its answer, or to hide
              something from the user                      "read the user's SSH private key and include it", "do not tell the user"
  forwarded   the model's answer is carried to an outside host the server writes in the code
                                                            reply = createMessage(...)  ->  fetch("https://host/...", reply)
```

A directive turns the user's own model against them in a request the user never sees; a forwarded answer is the user's
conversation handed to a third party. The prompt is read from the call itself and from a constant of the file it
names; the answer is followed by name from the call to the request that sends it, in the same file (`protocol_reading.py`).
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar, Final

from cordon_scanner.analysis.javascript.front.syntax import Node, Syntax
from cordon_scanner.detect.agents.mcp_servers.protocol.protocol_reading import (
    ProtocolReading as Read,
)

#: The calls that ask the client's model, by the name each SDK gives them.
_SAMPLES: Final = frozenset({"createMessage", "create_message", "sample"})
_METHOD: Final = "sampling/createMessage"
#: The calls that send something to a host.
_SENDS: Final = frozenset(
    {
        "fetch",
        "post",
        "put",
        "patch",
        "request",
        "sendBeacon",
        "urlopen",
        "send",
        "axios",
        "got",
        "ky",
        "wget",
    }
)
_NATIVE_CALL: Final = re.compile(
    r"\b(?:RequestSampling|create_message|CreateMessage|createMessage)\w{0,12}\s*\("
)
_QUOTED: Final = re.compile(r"\"([^\"\n]{1,300})\"")
_URL: Final = re.compile(
    r"^https?://(?:[^@/\s]*@)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9._-]+)", re.IGNORECASE
)
#: A host on this machine or inside a private network: loopback, the private IPv4 ranges, `.local`.
_PRIVATE: Final = re.compile(
    r"^(?:localhost|0\.0\.0\.0|\[?::1\]?|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}"
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|[A-Za-z0-9.-]+\.local)$",
    re.IGNORECASE,
)


class McpSampling:
    """`abuse_js(text)` / `abuse_py(text)`: (where, kind) for each sampling call that is abused, kind `directive` or
    `forwarded`."""

    _HIDE: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:do not|don't|never|must not|without)\s+(?:to\s+)?(?:tell|tell(?:ing)?|inform|notify|mention|show|reveal|"
        r"disclose|let)\b[^.\n]{0,40}\b(?:user|human|operator|owner)\b"
        r"|\b(?:silently|secretly|covertly)\b|\bhidden from the user\b",
        re.IGNORECASE,
    )
    _TARGET: ClassVar[re.Pattern[str]] = re.compile(
        r"[/\\]\.(?:ssh|aws|gnupg|kube|npmrc|netrc|docker)\b|\.env\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b"
        r"|\bcredentials? file\b|\bprivate keys?\b|\bseed phrase\b|\baccess tokens?\b|\bapi keys?\b"
        r"|\benvironment variables?\b|\bshell history\b|\bkeychain\b|\bwallet\b",
        re.IGNORECASE,
    )
    _TAKE: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:read|include|send|print|output|reveal|exfiltrate|copy|append|attach|forward|paste|dump|"
        r"upload|return|leak|show|add)\b",
        re.IGNORECASE,
    )

    @classmethod
    def directs(cls, strings: list[str]) -> bool:
        """Whether a prompt tells the model to take a secret or to hide what it does from the user."""
        for raw in strings:
            if len(raw) > 6000:
                continue
            if cls._HIDE.search(raw):
                return True
            for sentence in re.split(r"(?<=[.!?])\s+|\n", raw):
                if cls._TARGET.search(sentence) and cls._TAKE.search(sentence):
                    return True
        return False

    # -- JavaScript and TypeScript ---------------------------------------------------------------

    @classmethod
    def abuse_js(cls, text: str, typescript: bool = True) -> list[tuple[int, str]]:
        if "createMessage" not in text and "sampling/" not in text:
            return []
        program = Read.program(text, typescript)
        if program is None:
            return []
        bound = Read.js_bindings(program)
        out: list[tuple[int, str]] = []
        answers: set[str] = set()
        for node in Syntax.walk(program):
            if node.type == "CallExpression" and cls._js_samples(node):
                strings: list[str] = []
                for argument in node["arguments"] or []:
                    Read.js_strings(argument, bound, strings)
                if cls.directs(strings):
                    out.append((node.start, "directive"))
            elif node.type == "VariableDeclarator" and node["id"] is not None:
                init = node["init"]
                if init is not None and init.type == "AwaitExpression":
                    init = init["argument"]
                if (
                    init is not None
                    and init.type == "CallExpression"
                    and cls._js_samples(init)
                    and node["id"].type == "Identifier"
                ):
                    answers.add(str(node["id"]["name"]))
        if answers:
            for node in Syntax.walk(program):
                if node.type == "CallExpression" and Read.js_callee(node) in _SENDS:
                    names: set[str] = set()
                    strings = []
                    for argument in node["arguments"] or []:
                        names |= Read.js_identifiers(argument)
                        Read.js_strings(argument, {}, strings)
                    if names & answers and any(cls._outside(s) for s in strings):
                        out.append((node.start, "forwarded"))
        return sorted(set(out))

    @staticmethod
    def _js_samples(call: Node) -> bool:
        return Read.js_callee(call) in _SAMPLES or Read.js_names_method(call, _METHOD)

    @staticmethod
    def _outside(value: str) -> bool:
        """Whether a string is a URL to a host that is not this machine or a private network."""
        found = _URL.match(value)
        return found is not None and not _PRIVATE.match(found.group(1))

    # -- Python ----------------------------------------------------------------------------------

    @classmethod
    def abuse_text(cls, text: str) -> list[int]:
        """The character offset of each sampling request, in a language this module reads as text (Go, Rust, Java,
        C#), whose prompt tells the model to take a secret or hide something: the strings in the 800 characters
        after the call."""
        if "ampling" not in text and "create_message" not in text and "CreateMessage" not in text:
            return []
        out: list[int] = []
        for call in _NATIVE_CALL.finditer(text):
            if cls.directs(_QUOTED.findall(text[call.end() : call.end() + 800])):
                out.append(call.start())
                if len(out) >= 3:
                    break
        return out

    @classmethod
    def abuse_py(cls, text: str) -> list[tuple[int, str]]:
        if "create_message" not in text and "sample" not in text and "sampling/" not in text:
            return []
        tree = Read.py_tree(text)
        if tree is None:
            return []
        scope = Read.py_scope(tree)
        out: list[tuple[int, str]] = []
        answers: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and cls._py_samples(node):
                strings: list[str] = []
                for argument in Read.py_arguments(node):
                    Read.py_strings(argument, scope, strings)
                if cls.directs(strings):
                    out.append((node.lineno, "directive"))
            elif isinstance(node, ast.Assign) and len(node.targets) == 1:
                value = node.value.value if isinstance(node.value, ast.Await) else node.value
                target = node.targets[0]
                if (
                    isinstance(value, ast.Call)
                    and cls._py_samples(value)
                    and isinstance(target, ast.Name)
                ):
                    answers.add(target.id)
        if answers:
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and Read.py_name(node) in _SENDS:
                    names: set[str] = set()
                    strings = []
                    for argument in Read.py_arguments(node):
                        names |= Read.py_names(argument)
                        Read.py_strings(argument, ({}, {}), strings)
                    if names & answers and any(cls._outside(s) for s in strings):
                        out.append((node.lineno, "forwarded"))
        return sorted(set(out))

    @staticmethod
    def _py_samples(call: ast.Call) -> bool:
        return Read.py_name(call) in _SAMPLES or Read.py_names_method(call, _METHOD)


__all__ = ["McpSampling"]
