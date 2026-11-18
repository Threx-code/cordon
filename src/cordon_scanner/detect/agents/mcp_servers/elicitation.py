"""An MCP server asking the user for a credential through the protocol's own prompt.

`elicitation/create` lets a server put a question to the user and read the answer back. The protocol is explicit that a
server must not use it to ask for sensitive information: the host shows the prompt as part of the client, so a user
reads "enter your password" or "paste your seed phrase" as the client's request and answers it. A server that asks is
phishing through a dialogue the user has every reason to trust.

```
  server.elicitInput({ message, requestedSchema })      ctx.elicit(message, schema)
  request({ method: "elicitation/create", params })     create_elicitation(...)
        │
        └── the message, the schema's field names, titles and descriptions  ──►  a credential word?
              password · passphrase · API key · access or private key · token of a named service ·
              seed or recovery phrase · card number · security code · one-time code · "your credentials"
```

Only what the call itself says is read (`protocol_reading.py`). A credential word anywhere else in a server is another
rule's business; a question about a city, a name or a confirmation is what the prompt is for.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar, Final

from cordon_scanner.analysis.javascript.front.syntax import Syntax
from cordon_scanner.detect.agents.mcp_servers.protocol_reading import ProtocolReading as Read

#: The calls that put a question to the user, by the name each SDK gives them.
_ASKS: Final = frozenset(
    {"elicitInput", "elicit", "createElicitation", "create_elicitation", "elicit_input"}
)
_METHOD: Final = "elicitation/create"
_CAMEL: Final = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NATIVE_CALL: Final = re.compile(
    r"\b(?:RequestElicitation|CreateElicitation|create_elicitation|ElicitInput|elicit_input|Elicit)\w{0,12}\s*\("
)
_QUOTED: Final = re.compile(r"\"([^\"\n]{1,300})\"")


class McpElicitation:
    """`credential_requests_js(text)` / `credential_requests_py(text)`: where a server asks for a credential."""

    #: A credential, named. Applied to a string with `_` and `-` read as spaces and camelCase split, lower-cased.
    CREDENTIAL: ClassVar[re.Pattern[str]] = re.compile(
        r"\bpass ?words?\b|\bpasswd\b|\bpass ?phrases?\b|\byour pin\b|\bpin (?:code|number)\b"
        r"|\bsecret(?: key| code| phrase)?\b"
        r"|\b(?:api|access|auth|authentication|bearer|refresh|session|private|signing|personal access"
        r"|service account|oauth|jwt|bot|master) (?:key|token|secret)\b"
        r"|\b(?:github|gitlab|slack|npm|pypi|openai|anthropic|aws|azure|stripe|discord|telegram) "
        r"(?:token|key|secret|password)\b"
        r"|\bseed (?:phrase|words?)\b|\bmnemonic\b|\brecovery (?:phrase|words?|code|key)\b"
        r"|\bwallet (?:key|password|seed)\b|\bcvv\b|\bcvc\b|\bcard number\b|\bcredit card\b"
        r"|\bssn\b|\bsocial security\b|\bone time (?:code|password|passcode)\b|\botp\b|\b2fa\b"
        r"|\btwo factor (?:code|token)\b|\bverification code\b|\bsecurity (?:answer|code)\b"
        r"|\b(?:enter|type|paste|provide|input|give|share|send|supply)\b[^.?!\n]{0,40}\bcredentials?\b"
    )

    @classmethod
    def asks_for_credential(cls, strings: list[str]) -> bool:
        """Whether any of the strings names a credential."""
        for raw in strings:
            if len(raw) > 2000:
                continue
            spaced = _CAMEL.sub(" ", raw.replace("_", " ").replace("-", " ")).lower()
            if cls.CREDENTIAL.search(spaced):
                return True
        return False

    @classmethod
    def credential_requests_js(cls, text: str, typescript: bool = True) -> list[int]:
        """The character offset of each elicitation whose message or schema asks for a credential."""
        if "elicit" not in text:
            return []
        program = Read.program(text, typescript)
        if program is None:
            return []
        bound = Read.js_bindings(program)
        out: list[int] = []
        for node in Syntax.walk(program):
            if node.type != "CallExpression":
                continue
            if Read.js_callee(node) not in _ASKS and not Read.js_names_method(node, _METHOD):
                continue
            strings: list[str] = []
            for argument in node["arguments"] or []:
                Read.js_strings(argument, bound, strings)
            if cls.asks_for_credential(strings):
                out.append(node.start)
        return out

    @classmethod
    def credential_requests_text(cls, text: str) -> list[int]:
        """The character offset of each elicitation, in a language this module reads as text (Go, Rust, Java, C#),
        whose message names a credential: the strings in the 600 characters after the call."""
        if "licit" not in text:
            return []
        out: list[int] = []
        for call in _NATIVE_CALL.finditer(text):
            strings = _QUOTED.findall(text[call.end() : call.end() + 600])
            if cls.asks_for_credential(strings):
                out.append(call.start())
                if len(out) >= 3:
                    break
        return out

    @classmethod
    def credential_requests_py(cls, text: str) -> list[int]:
        """The line of each elicitation whose message or schema asks for a credential."""
        if "elicit" not in text:
            return []
        tree = Read.py_tree(text)
        if tree is None:
            return []
        scope = Read.py_scope(tree)
        out: list[int] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if Read.py_name(node) not in _ASKS and not Read.py_names_method(node, _METHOD):
                continue
            strings: list[str] = []
            for argument in Read.py_arguments(node):
                Read.py_strings(argument, scope, strings)
            if cls.asks_for_credential(strings):
                out.append(node.lineno)
        return out


__all__ = ["McpElicitation"]
