"""The shape of a remote agent bridge, read in one JavaScript file: what the file does about each of three things.

```
  EXEC  drives a coding agent (an agent SDK import, a literal agent program spawned, an agent's non-interactive flags)
        or a terminal (a pseudo-terminal package, a literal shell spawned)
  CHAN  opens an outbound client channel a remote party can send work through: a WebSocket, a socket.io client, an
        EventSource, a `ws` client; and says whether the file names a loopback address or a remote one
  HIST  names an agent's history store (`.claude/projects`, `.codex/sessions`, `.gemini`)
```

A file with any of them leaves one record (`encode`); the package step (`decide/remote_control.py`) joins the records of the
whole package. The patterns are data (`detect/data/remote-bridge-patterns.json`), for the reason the agents' safeguard
switches are: spelled in code they read as the launch they describe, and the self-scan said so. Every pattern is bounded and
free of nested repetition, and each is checked against the engine's own test for catastrophic backtracking
(`PatternCompiler.validate_pattern`) by the tests.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, ClassVar, Final

from cordon_scanner.foundation.once import OneOff
from cordon_scanner.foundation.paths import PackagePaths

_MAX_CHARS: Final = 3_000_000
_Kinds = tuple[tuple[str, re.Pattern[str]], ...]


@dataclass(frozen=True, slots=True)
class Signals:
    """What one file does, or what a package does: the kinds of each and whether a loopback or a remote address is named."""

    execs: frozenset[str] = frozenset()
    chans: frozenset[str] = frozenset()
    hists: frozenset[str] = frozenset()
    loop: bool = False
    remote: bool = False

    def __or__(self, other: Signals) -> Signals:
        return Signals(
            self.execs | other.execs,
            self.chans | other.chans,
            self.hists | other.hists,
            self.loop or other.loop,
            self.remote or other.remote,
        )


@dataclass(frozen=True, slots=True)
class _Compiled:
    execs: _Kinds
    chans: _Kinds
    hists: _Kinds
    loop: re.Pattern[str]
    remote: re.Pattern[str]


class BridgeShape:
    #: The names of the kinds are what the finding says in words.
    WORDS: ClassVar[dict[str, str]] = {
        "sdk": "a coding agent through its SDK",
        "spawn": "a coding agent program",
        "cli": "a coding agent with its non-interactive flags",
        "term": "a terminal",
        "websocket": "a WebSocket client",
        "socketio": "a socket.io client",
        "eventsource": "an EventSource stream",
        "wslibrary": "a WebSocket client library",
        "claude": "Claude Code's project history",
        "codex": "Codex's session history",
        "gemini": "Gemini's local folder",
    }

    @staticmethod
    @OneOff.cache
    def table() -> dict[str, Any]:
        """The pattern table: one pattern per kind of exec, channel and history store, and the loopback and remote address patterns."""
        text = (PackagePaths.data("detect") / "remote-bridge-patterns.json").read_text(
            encoding="utf-8"
        )
        loaded: dict[str, Any] = json.loads(text)
        return loaded

    @staticmethod
    def patterns() -> tuple[str, ...]:
        """Every pattern, for the engine's check."""
        table = BridgeShape.table()
        return (
            *table["exec"].values(),
            *table["chan"].values(),
            *table["hist"].values(),
            table["loop"],
            table["remote"],
        )

    @staticmethod
    @OneOff.cache
    def _compiled() -> _Compiled:
        table = BridgeShape.table()

        def compile_all(kinds: dict[str, str]) -> _Kinds:
            return tuple((kind, re.compile(pattern)) for kind, pattern in kinds.items())

        return _Compiled(
            compile_all(table["exec"]),
            compile_all(table["chan"]),
            compile_all(table["hist"]),
            re.compile(table["loop"]),
            re.compile(table["remote"]),
        )

    @staticmethod
    def _kinds(compiled: _Kinds, text: str) -> frozenset[str]:
        return frozenset(kind for kind, pattern in compiled if pattern.search(text))

    @classmethod
    def signals(cls, text: str) -> Signals | None:
        """What one file does, or None when it does none of it."""
        if len(text) > _MAX_CHARS:
            return None
        compiled = cls._compiled()
        found = Signals(
            cls._kinds(compiled.execs, text),
            cls._kinds(compiled.chans, text),
            cls._kinds(compiled.hists, text),
            compiled.loop.search(text) is not None,
            compiled.remote.search(text) is not None,
        )
        return (
            found
            if found.execs or found.chans or found.hists or found.loop or found.remote
            else None
        )

    #: The group letters of a line record, and the table section each reads.
    GROUPS: ClassVar[dict[str, str]] = {"e": "exec", "c": "chan", "h": "hist"}
    MAX_LINES: ClassVar[int] = 400

    @classmethod
    def lines(cls, text: str) -> dict[str, int]:
        """The 1-based line of the first match of each kind the file does, keyed `e:<kind>`, `c:<kind>`, `h:<kind>`.

        The record says WHAT a file does; this says WHERE, so the block can name the line of each part (a block that
        names no line cannot be read by the person whose package it stops). Read only for a file that has a signal."""
        if len(text) > _MAX_CHARS:
            return {}
        compiled = cls._compiled()
        found: dict[str, int] = {}
        for group, kinds in (("e", compiled.execs), ("c", compiled.chans), ("h", compiled.hists)):
            for kind, pattern in kinds:
                match = pattern.search(text)
                if match is not None:
                    found[f"{group}:{kind}"] = text.count("\n", 0, match.start()) + 1
        return found

    @classmethod
    def encode_lines(cls, lines: dict[str, int]) -> str:
        return ",".join(f"{key}={lines[key]}" for key in sorted(lines))

    @classmethod
    def decode_lines(cls, text: str) -> dict[str, int]:
        """The lines a record says, or {} for anything that is not exactly that form: never misparsed."""
        if not isinstance(text, str) or not text or len(text) > cls.MAX_LINES:
            return {}
        table = cls.table()
        found: dict[str, int] = {}
        for item in text.split(","):
            match = re.fullmatch(r"([ech]):([a-z]{1,20})=([1-9][0-9]{0,6})", item)
            if match is None or match.group(2) not in table[cls.GROUPS[match.group(1)]]:
                return {}
            found[f"{match.group(1)}:{match.group(2)}"] = int(match.group(3))
        return found

    # -- the record: one line a worker hands to the parent ---------------------------------------

    VERSION: ClassVar[str] = "v1"
    MAX_MESSAGE: ClassVar[int] = 256
    _FORM: ClassVar[re.Pattern[str]] = re.compile(
        r"^v1 e=([a-z,]{0,40}) c=([a-z,]{0,60}) h=([a-z,]{0,30}) l=([01]) r=([01])$"
    )

    @staticmethod
    def _join(kinds: frozenset[str]) -> str:
        return ",".join(sorted(kinds))

    @classmethod
    def encode(cls, signals: Signals) -> str:
        return (
            f"{cls.VERSION} e={cls._join(signals.execs)} c={cls._join(signals.chans)} h={cls._join(signals.hists)} "
            f"l={int(signals.loop)} r={int(signals.remote)}"
        )

    @classmethod
    def decode(cls, message: str) -> Signals | None:
        """The signals a record says, or None for a record of another version or shape: never misparsed."""
        if not isinstance(message, str) or len(message) > cls.MAX_MESSAGE:
            return None
        match = cls._FORM.match(message)
        if match is None:
            return None
        execs, chans, hists = (frozenset(filter(None, g.split(","))) for g in match.group(1, 2, 3))
        table = cls.table()
        if not (
            execs <= table["exec"].keys()
            and chans <= table["chan"].keys()
            and hists <= table["hist"].keys()
        ):
            return None
        return Signals(execs, chans, hists, match.group(4) == "1", match.group(5) == "1")


__all__ = ["BridgeShape", "Signals"]
