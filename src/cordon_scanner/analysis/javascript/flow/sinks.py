"""Where data leaves a JavaScript file: the calls that send, write, spawn or look up a name, the
decoders, and the host and kind of the destination a URL names."""

from __future__ import annotations

import re

from cordon_scanner.analysis.javascript.flow.bindings import Bindings
from cordon_scanner.analysis.javascript.flow.vocabulary import (
    _BOT_SEND,
    _CONNECTION_MODULES,
    _CONNECTION_OPEN,
    _CONNECTION_SEND,
    _DECODE_ENCODINGS,
    _DECODERS,
    _DNS_CALL,
    _DNS_MODULES,
    _LOOPBACK,
    _PROCESS_CALL,
    _PROCESS_MODULES,
    _RAW_IP,
    _RAW_SOCKET_MODULES,
    _REQUEST_METHODS,
    _REQUEST_MODULES,
    _URL,
    _VM_RUN,
)


class Sinks(Bindings):
    """The sinks layer of `js_flow._Analysis`: what kind of sink a call is, and where it sends."""

    # -- sinks -----------------------------------------------------------------------------------

    def _is_decode(self, k: int) -> bool:
        """Whether the call at name token `k` decodes a value -- `atob(x)`, `Buffer.from(x,
        "base64"|"hex")`, or a zlib/brotli decompressor -- so its result is bytes a server or a
        blob chose. Running that result is the decoded-content dropper the REMOTE_CODE/DECODE rules
        read; `.toString("base64")` is the opposite act and is not one."""
        parts = self._chain(k)[0]
        last = parts[-1]
        if last == "atob" or last in _DECODERS:
            return True
        if last == "from" and len(parts) >= 2 and parts[-2] == "Buffer":
            args = self._args(k + 1)
            if len(args) >= 2:
                enc = self._folded(args[1][0], args[1][1])
                return enc is not None and enc.lower() in _DECODE_ENCODINGS
        return False

    def _sink_kind(self, k: int, scope: int) -> str | None:
        """The kind of sink a call at name token `k` is, if any."""
        parts, _ = self._chain(k)
        root, last = parts[0], parts[-1]
        if root == "vm" and (last in _VM_RUN or (last == "Script" and self.is_name(k - 3, "new"))):
            return "execute"
        if len(parts) == 1:
            if last == "eval" or (last == "Function" and not self.is_p(k - 1, ".")):
                return "execute"
            if last == "require" and not self.is_p(k - 1, "."):
                # `require(p)` runs p's top level: a response written to disk and required back is
                # run. `execute` reaches only the REMOTE_CODE rule, so a plain `require("pkg")`
                # (a literal, no response taint) raises nothing.
                return "execute"
            if last in ("fetch", "$fetch") or root in _REQUEST_MODULES:
                return "request"
            if self.is_name(k - 1, "new") and last in ("WebSocket", "EventSource"):
                return "request"
            if root.startswith("child_process.") or root in _PROCESS_MODULES:
                return "process"
        if root in _REQUEST_MODULES and (
            len(parts) == 1 or last in _REQUEST_METHODS or last == "create"
        ):
            return "request"
        if root in _CONNECTION_MODULES and last in _CONNECTION_OPEN:
            # What opening an HTTP request sends (its URL, path, headers) is a request; only a
            # socket below HTTP to another machine is a channel of the payload's own.
            return "connection" if self._raw_open(k) else "request"
        if root in _DNS_MODULES and last in _DNS_CALL:
            return "dns"
        if root in _PROCESS_MODULES and last in _PROCESS_CALL:
            return "process"
        if (
            len(parts) == 2
            and last in _CONNECTION_SEND
            and self.resolve(root, scope) in self.connections
        ):
            return "connection" if self.resolve(root, scope) in self.raw_connections else "request"
        if (
            len(parts) == 1
            and last in _CONNECTION_SEND
            and self.is_p(k - 1, ".")
            and self.is_p(k - 2, ")")
            and self.match[k - 2] > 0
            and self.is_name(self.match[k - 2] - 1)
            and self._opens(self.match[k - 2] - 1)
        ):
            # `https.request(opts).end(body)`: sent on the request just opened; on a raw socket
            # (`net.connect(...).write(x)`), sent down the socket.
            return self._sink_kind(self.match[k - 2] - 1, scope)
        if parts[:2] == ["navigator", "sendBeacon"] or (
            root in ("$", "jQuery") and last in ("ajax", "post", "get")
        ):
            return "request"
        if len(parts) >= 2 and last in _BOT_SEND and self.resolve(root, scope) in self.bot_clients:
            # `bot.telegram.sendDocument(chat, file)`, `hook.send(x)`, `mail.sendMail(x)`.
            return "request"
        if len(parts) >= 2 and parts[-2] in ("http", "https") and last in ("request", "get"):
            return "request"
        return None

    def _opens(self, k: int) -> bool:
        """Whether the call at name token `k` opens a connection: an HTTP request or a socket."""
        parts = self._chain(k)[0]
        return (parts[0] in _CONNECTION_MODULES and parts[-1] in _CONNECTION_OPEN) or (
            len(parts) >= 2 and parts[-2] in ("http", "https") and parts[-1] in ("request", "get")
        )

    def _raw_open(self, k: int) -> bool:
        """Whether the call at name token `k` opens a raw socket to another machine."""
        parts = self._chain(k)[0]
        if parts[0] not in _RAW_SOCKET_MODULES:
            return False
        close = self.match[k + 1] if self.is_p(k + 1, "(") else -1
        return not any(
            self.t[i].kind == "str" and _LOOPBACK.match(str(self.t[i].value))
            for i in range(k + 2, close)
        )

    @staticmethod
    def classify(url: str) -> tuple[str | None, str]:
        """(host, kind) of a URL: `drop` for a webhook, paste, tunnel or out-of-band interaction
        service (`analysis/shared/destinations.py`, the same lists the manifest and egress rules use), `ip` for a
        bare address, `fixed` for any other host the file names; (None, "unknown") when the
        string is not a URL at all."""
        from cordon_scanner.analysis.shared.destinations import ALL_HOSTS, INTERACTION_HOSTS

        m = _URL.match(url.strip())
        if m is None:
            return (None, "unknown")
        host, path = m.group(1).lower(), m.group(2) or ""
        if _RAW_IP.match(url.strip()):
            # This machine or its own network is not somewhere data leaves to.
            private = re.match(
                r"(?:127|10|0)\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.", host
            )
            return (host, "fixed" if private else "ip")
        for known in ALL_HOSTS | INTERACTION_HOSTS:
            domain, _, prefix = known.partition("/")
            if (host == domain or host.endswith("." + domain)) and (
                not prefix or path.lstrip("/").startswith(prefix)
            ):
                return (host, "drop")
        return (host, "fixed")

    def _destination(self, a: int, b: int) -> tuple[str | None, str]:
        for k in range(a, b):
            tok = self.t[k]
            if tok.kind == "str":
                host, kind = Sinks.classify(str(tok.value))
                if host is not None:
                    return (host, kind)
        return (None, "unknown")
