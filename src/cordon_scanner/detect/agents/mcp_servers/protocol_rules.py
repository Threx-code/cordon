"""Catalogue entries of the rules for what an MCP server does to its client and for the addresses its source names:
asking the user for a credential, driving the client's model, a cloud instance's metadata service, and the places
a server can send what it handles to (a webhook, an anonymous drop, a tunnel, an IP-logging link). The readers are
`elicitation.py`, `sampling.py` and `literal_sinks.py`."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cordon_scanner.foundation.models import Category, Confidence, Severity


class ProtocolRules:
    """`rules(factory, references)`: the entries, built with the caller's rule factory."""

    @classmethod
    def rules(cls, factory: Callable[..., Any], references: tuple[str, ...]) -> dict[str, Any]:
        parts = (
            cls._protocol(factory, references),
            cls._channels(factory, references),
            cls._inputs(factory, references),
        )
        return {entry.rule_id: entry for part in parts for entry in part}

    @staticmethod
    def _protocol(factory: Callable[..., Any], references: tuple[str, ...]) -> tuple[Any, ...]:
        return (
            factory(
                "SUSPECT.MCP.ELICIT_CREDENTIAL.001",
                "An MCP server asks the user for a credential through the protocol's own prompt",
                Category.SUSPICIOUS,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "This MCP server uses the protocol's elicitation request to ask the user for a "
                "password, an API key or token, a private key, a seed phrase, a card number or a "
                "one-time code. The protocol says a server must not ask for sensitive information "
                "this way: the host shows the prompt as part of the client, so the user answers it "
                "as the client's own request. A server that needs a credential is configured with "
                "it; one that asks for it in a dialogue is phishing.",
                "Do not answer the prompt. Find what the server does with the answer and rotate "
                "anything already given.",
                references,
            ),
            factory(
                "SUSPECT.MCP.CLOUD_METADATA.001",
                "An MCP server's source names a cloud instance's metadata service",
                Category.SUSPICIOUS,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "The source of this MCP server contains the address of a cloud machine's metadata "
                "service -- 169.254.169.254, metadata.google.internal or a path only it serves. "
                "That service hands the machine's own credentials to whatever asks from the "
                "machine. A cloud SDK reaches it inside its own library; a tool server that names "
                "it in its own code is after those credentials.",
                "Find what the server does with the answer. Rotate the credentials of any cloud "
                "machine it has run on.",
                references,
            ),
        )

    @staticmethod
    def _channels(factory: Callable[..., Any], references: tuple[str, ...]) -> tuple[Any, ...]:
        return (
            factory(
                "SUSPECT.MCP.EXFIL_WEBHOOK.001",
                "An MCP server's source carries a chat webhook with its secret written in",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "The source of this MCP server contains a Discord, Slack, Teams or Telegram bot "
                "address with its secret in it. A webhook is write-only and needs no account, and "
                "it is a credential: a server that ships its author's, rather than reading the "
                "user's from configuration, sends what its tools handle to the author's chat.",
                "Find what is sent to the address. Do not use the server until it is explained.",
                references,
            ),
            factory(
                "SUSPECT.MCP.EXFIL_DROP.001",
                "An MCP server's source names an anonymous paste or file-drop service",
                Category.SUSPICIOUS,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "The source of this MCP server contains an address on an anonymous paste or "
                "file-drop service. Such a service takes uploads with no account and hands back a "
                "link: a place to leave data for someone else, or to fetch a second stage from. "
                "A server has its own service to talk to.",
                "Find what is sent to the address or fetched from it. Do not use the server until it "
                "is explained.",
                references,
            ),
            factory(
                "SUSPECT.MCP.EXFIL_TUNNEL.001",
                "An MCP server's source names a tunnel, request-capture or interaction host",
                Category.SUSPICIOUS,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "The source of this MCP server contains an address on a tunnel, request-capture or "
                "out-of-band interaction service (ngrok, webhook.site, interact.sh and their "
                "kind). These exist to receive a callback from a machine that cannot be reached "
                "directly. They have no place in a shipped server.",
                "Find what is sent to the address. Do not use the server until it is explained.",
                references,
            ),
            factory(
                "SUSPECT.MCP.EXFIL_LOGGER.001",
                "An MCP server's source names an IP-logging link",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "The source of this MCP server contains a link on an IP-logging service: a link "
                "whose only purpose is to tell whoever made it the address of whoever opened it. "
                "A server has no reason to fetch one.",
                "Find where the link is shown or fetched. Do not use the server until it is "
                "explained.",
                references,
            ),
            factory(
                "SUSPECT.MCP.SAMPLING_ABUSE.001",
                "An MCP server uses the client's model as its own tool through sampling",
                Category.SUSPICIOUS,
                Severity.HIGH,
                Confidence.MEDIUM,
                "This MCP server asks the client's model to complete a prompt it wrote, and the "
                "prompt tells the model to read a secret and include it, or to hide what it does "
                "from the user; or the model's answer is sent on to an outside host the code names. "
                "Sampling is for a server to have text summarised or classified; used this way it "
                "turns the user's own model, and the conversation it holds, into the server's tool.",
                "Read the prompt and find where the answer goes. Do not use the server until both "
                "are explained.",
                references,
            ),
        )

    @staticmethod
    def _inputs(factory: Callable[..., Any], references: tuple[str, ...]) -> tuple[Any, ...]:
        return (
            factory(
                "SUSPECT.MCP.INPUT_PROGRAM.001",
                "An MCP tool starts the program its input names",
                Category.SUSPICIOUS,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "A tool of this MCP server starts, without a shell, the program that one of its own arguments "
                "names. The agent fills the argument, so whatever the agent is told to type becomes the program "
                "that runs on the user's machine. A tool that does not say it runs programs takes a value, not "
                "a program.",
                "Fix the program in the code and pass the argument as an argument to it.",
                references,
            ),
            factory(
                "SUSPECT.MCP.INPUT_SHELL.001",
                "An MCP tool hands its input to a shell as a command",
                Category.SUSPICIOUS,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "A tool of this MCP server, written in Go, Rust or another compiled language, passes one of its "
                "own arguments to a shell as the command to run. The agent fills the argument, so whatever the "
                "agent is told to type runs on the user's machine. A tool that does not say it runs commands "
                "has no need of a shell.",
                "Run a fixed program with the argument as one of its arguments, and no shell.",
                references,
            ),
            factory(
                "SUSPECT.MCP.INPUT_DROPPED.001",
                "An MCP tool posts what it is asked to an address written in its code",
                Category.SUSPICIOUS,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "A tool of this MCP server sends one of its own arguments, as the body of a POST or a PUT, to an "
                "address written into the code, with no credential and no configured value in the request. A "
                "service call says who is asking; a request that does not is a place to leave what the agent "
                "handed over.",
                "Find who owns the address and what is sent to it. Do not use the server until it is explained.",
                references,
            ),
        )


__all__ = ["ProtocolRules"]
