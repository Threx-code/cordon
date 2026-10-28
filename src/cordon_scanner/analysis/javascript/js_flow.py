"""Where a JavaScript file's sensitive values go: sources to sinks, through bindings and functions.

The capability rules see what a file CAN do: read `~/.ssh`, reach the network. A line window ties
the two together when they sit close, and an attacker who knows that puts them apart -- read the
key in one function, encode it in a second, send it from a third, two thousand lines down. What
does not change, however the code is arranged, is that the value flows. This module follows it.

The analysis is static and bounded: tokens from `JsEval.tokens` (a linear scan), no parser
dependency, no evaluation of package code. It is deliberately approximate where approximation is
safe and narrow where it is not:

* **Scopes.** Every function literal (declaration, expression, arrow, method shorthand) is a scope;
  a name resolves to the innermost scope that declares it, else to the file.
* **Bindings.** `const|let|var` declarations (destructuring included), assignments to a name or to
  a member of one (`payload.data = x` taints `payload`), and the mutating calls that store into a
  receiver (`.push`, `.set`, `.append`, `Object.assign`).
* **Functions.** Each has a summary: which parameters reach its return value and which reach a
  sink. A call applies the summary to its arguments; summaries are iterated to a fixpoint, so a
  value passed through three helpers is followed through all three.
* **Callbacks.** A function literal passed to a call receives the taint of the call's receiver and
  other arguments as its parameters: `read(p).then(d => send(d))`, `fs.readFile(p, (e, d) => ...)`.
* **Sources** are kinds of value, not names: a file under a credential path, the whole
  environment, the machine's identity, browser storage, the clipboard, key material read from a
  wallet object or handed to a function as `privateKey`/`mnemonic`.
* **Sinks** are where data leaves: request calls (resolved through `require`/`import` aliases),
  `.write`/`.send` on a connection the file opened, DNS lookups, and process spawns.

What it reports is a `Flow`: the source kinds, the sink, the destination host when the file names
one, and the line of the sink. Judgement -- which flows are an attack -- is left to the rules that
consume them, so this module stays a fact-finder.
"""

from __future__ import annotations

import re
from contextlib import suppress
from typing import ClassVar

from cordon_scanner.analysis.javascript.flow.taint import Taint
from cordon_scanner.analysis.javascript.flow.vocabulary import (
    _ARCHIVE_ADD_PATH,
    _ARCHIVE_CLASSES,
    _ARCHIVE_MODULES,
    _ARGV_CALLS,
    _CLOSE,
    _CONNECTION_OPEN,
    _DESTINATION_KEYS,
    _DNS_MODULES,
    _FS_WRITE,
    _HOST_OBJECTS,
    _KEYWORDS,
    _OPEN,
    _OPENER,
    _RAW_SOCKET_MODULES,
    _RUNS_ITS_ARGUMENT,
    _SECRET_PATH,
    _STORE_METHODS,
    _WALLET_PARAM,
    MAX_BYTES,
    MAX_PARAMETER_LABELS,
    MAX_ROUNDS,
    Flow,
    Label,
    Request,
    _OverBudget,
)
from cordon_scanner.analysis.shared.content_memo import ContentMemo


class JsFlow:
    """`flows(text)`: the source-to-sink flows in one JavaScript file."""

    SOURCES: ClassVar[tuple[str, ...]] = (
        "secret_file",
        "home_file",
        "network_response",
        "decoded",
        "environment",
        "identity",
        "browser",
        "clipboard",
        "wallet_key",
    )

    #: A string naming a credential store, as the file-read sources read it (`_SECRET_PATH`).
    SECRET_PATH: ClassVar[re.Pattern[str]] = _SECRET_PATH

    @staticmethod
    def classify(url: str) -> tuple[str | None, str]:
        """(host, kind) of a URL: `drop`, `ip`, `fixed`, or (None, "unknown") for no URL. Shared
        with the Python flow facts (`PythonFlowFacts`), so both languages class a host alike."""
        return _Analysis.classify(url)

    @staticmethod
    def read_of(labels: set[Label]) -> set[Label]:
        """What reading a file at a path carrying `labels` yields: a credential store's path gives its
        contents; a parameter's path gives a read deferred to the call site."""
        return Taint.read_of(labels)

    @classmethod
    def flows(cls, text: str) -> list[Flow]:
        if len(text) > MAX_BYTES:
            return []
        return JsFlow.MEMO.get("flows", text, lambda: JsFlow._flows(text))

    #: Each distinct text's flows, worked out once per process (`analysis.shared.content_memo`).
    MEMO: ClassVar[ContentMemo] = ContentMemo()

    @staticmethod
    def _flows(text: str) -> list[Flow]:
        try:
            return _Analysis(text).run()
        except RecursionError:
            return []

    @classmethod
    def requests(cls, text: str) -> list[Request]:
        """Every request the file makes, classed by the URL reaching it. A file whose every
        request is a registry tarball (or a redirect one gave) installs packages from the
        registry; one `other` request means it fetches from somewhere else too. Which packages
        the tarballs are is for the caller to check against the manifest (`Request.parts`)."""
        if len(text) > MAX_BYTES:
            return []
        try:
            analysis = _Analysis(text)
            analysis.run()
            return analysis.requests()
        except (RecursionError, _OverBudget):
            return []

    @classmethod
    def deferred_spans(cls, text: str) -> list[tuple[int, int]] | None:
        """Character spans of the function bodies nothing at the file's top level reaches.

        What runs when a file is loaded is its top level and every function that reaches: one
        invoked where it stands (`(function(){ ... })()`, `!function(){ ... }()`, `.call`), one
        handed to a call (`setTimeout(() => ...)`, `.then(...)`, `process.on(..., fn)`, since the
        runtime calls it without the user asking), one that reached code calls or passes by name,
        and the methods the language calls on its own (`constructor`, `then`, `toString`). What is
        left is behind an export: it runs when the package's user calls it (review 98, 19 step 2).

        Every approximation keeps code reached: names resolve by spelling, not scope, so a call to
        any function of that name reaches every function of that name. None when the file is past
        the analysis limit or did not tokenise; the caller then knows nothing was ruled out.
        """
        if len(text) > MAX_BYTES:
            return None
        try:
            return _Analysis(text).deferred()
        except RecursionError:
            return None

    @classmethod
    def safe_spawn_lines(cls, text: str) -> frozenset[int]:
        """Lines of process calls the analysis RESOLVED as a process sink and found no source
        reaches -- the command and its arguments are literals or local constants, nothing decoded,
        fetched or otherwise tracked flows in. For the decode-run composites to drop a spawn that
        cannot be running decoded content. A call it could not resolve as a process sink is absent,
        so a dynamic command keeps its pairing; empty when the file is too large or did not parse,
        so the caller drops nothing (fail-closed)."""
        if len(text) > MAX_BYTES:
            return frozenset()
        try:
            analysis = _Analysis(text)
            analysis.run()
            return analysis.clean_spawns()
        except (RecursionError, _OverBudget):
            return frozenset()


class _Analysis(Taint):
    # -- bindings --------------------------------------------------------------------------------

    # -- taint ------------------------------------------------------------------------------------

    # -- the fixpoint ----------------------------------------------------------------------------

    #: Methods the language calls without a call written: `new X()` runs `constructor`, `await x`
    #: runs `then`, string conversion runs `toString`, `valueOf`, `toJSON`. (Accessors, run by
    #: reading a property, are told by the `get`/`set` before them, not by a name.)
    _IMPLICIT: ClassVar[frozenset[str]] = frozenset(
        {"constructor", "then", "toString", "valueOf", "toJSON", "toPrimitive"}
    )
    #: Rounds of the reach fixpoint; past it everything is taken as reached.
    _REACH_ROUNDS: ClassVar[int] = 64

    def deferred(self) -> list[tuple[int, int]]:
        """See `JsFlow.deferred_spans`."""
        self._find_functions()
        self._scopes()
        self._classes()
        t, n = self.t, self.n
        if not self.fns:
            return []
        head = {fid: tok for tok, fid in self.fn_at_token.items()}
        # The bracket each token sits directly inside, to tell an argument list from a group.
        opener = [-1] * n
        stack: list[int] = []
        for i, tok in enumerate(t):
            opener[i] = stack[-1] if stack else -1
            if tok.kind == "punct" and tok.value in _OPEN and self.match[i] > 0:
                stack.append(i)
            elif tok.kind == "punct" and tok.value in _CLOSE and stack and self.match[i] >= 0:
                stack.pop()

        def in_call_args(i: int) -> bool:
            o = opener[i] if 0 <= i < n else -1
            if o < 0 or not self.is_p(o, "("):
                return False
            before = o - 1
            return before >= 0 and (
                (t[before].kind == "name" and t[before].value not in _KEYWORDS - {"super"})
                or self.is_p(before, ")")
                or self.is_p(before, "]")
            )

        names: dict[int, str] = {}
        own_name_token: dict[int, int] = {}
        at_once: set[int] = set()
        for fn in self.fns:
            h = head.get(fn.fid)
            if h is None:
                at_once.add(fn.fid)
                continue
            if fn.name:
                names[fn.fid] = fn.name
                own_name_token[fn.fid] = h + 1 if self.is_name(h, "function") else h
            else:
                p = h - 1
                if (self.is_p(p, "=") or self.is_p(p, ":")) and (
                    self.is_name(p - 1) or (p - 1 >= 0 and t[p - 1].kind == "str")
                ):
                    names[fn.fid] = str(t[p - 1].value)
                    own_name_token[fn.fid] = p - 1
            after = fn.end if fn.expression_body else fn.end + 1
            while self.is_p(after, ")"):
                after += 1
            first = h - 1 if self.is_name(h - 1, "async") else h
            if (
                self.is_p(after, "(")
                or (
                    self.is_p(after, ".")
                    and self.is_name(after + 1)
                    and t[after + 1].value in ("call", "apply")
                )
                or in_call_args(first)
                or names.get(fn.fid) in _Analysis._IMPLICIT
                or self.is_name(h - 1, "get")
                or self.is_name(h - 1, "set")
            ):
                at_once.add(fn.fid)
        # Every name a scope calls or hands on: `f(`, `f.call(`, or `f` as a call's argument.
        own = set(own_name_token.values())
        uses: dict[int, set[str]] = {}
        for k in range(n):
            if t[k].kind != "name" or k in own:
                continue
            if (
                self.is_p(k + 1, "(")
                or (
                    self.is_p(k + 1, ".")
                    and self.is_name(k + 2)
                    and t[k + 2].value in ("call", "apply", "bind")
                )
                or ((self.is_p(k - 1, "(") or self.is_p(k - 1, ",")) and in_call_args(k))
            ):
                uses.setdefault(self.scope_of(k), set()).add(t[k].value)
        reached = {0}
        called = set(uses.get(0, ()))
        for _ in range(_Analysis._REACH_ROUNDS):
            grown = False
            for fn in self.fns:
                if fn.fid in reached or self.parent.get(fn.fid, 0) not in reached:
                    continue
                if fn.fid in at_once or names.get(fn.fid) in called:
                    reached.add(fn.fid)
                    called |= uses.get(fn.fid, set())
                    grown = True
            if not grown:
                break
        else:
            return []
        spans: list[tuple[int, int]] = []
        for fn in self.fns:
            if fn.fid in reached or fn.start >= n:
                continue
            spans.append((t[fn.start].start, t[min(max(fn.end - 1, fn.start), n - 1)].end))
        return sorted(spans)

    def run(self) -> list[Flow]:
        self._find_functions()
        self._scopes()
        self._classes()
        self._modules()
        self._facts()
        bindings = self._bindings()
        for targets, s, e in bindings:
            for target in targets:
                self.bound.setdefault(target, []).append((s, e))
        for fn in self.fns:
            if fn.name:
                self.fn_by_name.setdefault(
                    self.resolve(fn.name, self.parent.get(fn.fid, 0)), fn.fid
                )
                owner = self.this_of(fn.fid) if fn.method else (0, "")
                if owner[0] < 0:
                    self.fn_by_name.setdefault((owner[0], fn.name), fn.fid)
        self._promises()
        for targets, s, e in bindings:
            if e - s >= 1 and len(targets) == 1:
                if self.is_name(s, "new") and str(self.t[s + 1].value) in self.class_by_name:
                    # `const r = new Runner()`: which class's fields `r.set(x)` stores into.
                    self.instance_of[targets[0]] = self.class_by_name[str(self.t[s + 1].value)]
                fid = self.fn_at_token.get(s) or (
                    self.fn_at_token.get(s + 1) if self.is_name(s, "async") else None
                )
                if fid is not None:
                    self.fn_by_name.setdefault(targets[0], fid)
                    self.fns[fid - 1].name = self.fns[fid - 1].name or targets[0][1]
                if self._opens_connection(s, e):
                    self.connections.add(targets[0])
                if self._opens_raw(s, e):
                    self.raw_connections.add(targets[0])
                bot = self._opens_bot(s, e)
                if bot is not None:
                    self.bot_clients[targets[0]] = bot
                if self._opens_archive(s, e):
                    self.archives.add(targets[0])
        calls = [
            k
            for k in range(self.n - 1)
            if self.t[k].kind == "name" and self.is_p(k + 1, "(") and self.match[k + 1] > 0
        ]
        returns = [k for k in range(self.n) if self.is_name(k, "return")]
        with suppress(_OverBudget):
            self._rounds(bindings, calls, returns)
        return sorted(self.flows.values(), key=lambda f: f.line)

    def _rounds(
        self,
        bindings: list[tuple[list[tuple[int, str]], int, int]],
        calls: list[int],
        returns: list[int],
    ) -> None:
        for _ in range(MAX_ROUNDS):
            changed = False
            for targets, s, e in bindings:
                scope = self.scope_of(s)
                value = self.taint(s, e, scope)
                if not value:
                    continue
                for target in targets:
                    changed |= self._grow(self.vars.setdefault(target, set()), value)
            for fn in self.fns:
                if fn.expression_body:
                    value = self.taint(fn.start, fn.end, fn.fid)
                    changed |= self._grow(fn.ret, value)
            for k in returns:
                scope = self.scope_of(k)
                if not scope:
                    continue
                fn = self.fns[scope - 1]
                value = self.taint(k + 1, self.expr_end(k + 1), scope)
                changed |= self._grow(fn.ret, value)
            for k in calls:
                changed |= self._call(k)
            if not changed:
                break

    def _grow(self, have: set[Label], value: set[Label]) -> bool:
        """Add `value` to a binding's labels. Source kinds are always kept; parameter labels are
        capped per binding, so a bundle of thousands of functions cannot make every value carry
        every parameter (the summaries lose a hop of precision there, never a source)."""
        if not value or value <= have:
            return False
        before = len(have)
        symbolic = sum(1 for x in have if isinstance(x, tuple))
        for x in value:
            if x in have:
                continue
            if isinstance(x, tuple):
                if symbolic >= MAX_PARAMETER_LABELS:
                    continue
                symbolic += 1
            have.add(x)
        if len(have) == before:
            return False
        self.version += 1
        self.work += 1
        if self.work > self.budget:
            raise _OverBudget
        return True

    def _opens_raw(self, s: int, e: int) -> bool:
        """Whether the value bound from [s, e) is a raw socket: `net.connect(...)`,
        `tls.connect(...)`, `dgram.createSocket(...)`, `new net.Socket()`."""
        for k in range(s, min(e, s + 40)):
            if self.t[k].kind == "name" and self.is_p(k + 1, "("):
                parts = self._chain(k)[0]
                if parts[-1] == "Socket" and parts[0] in _RAW_SOCKET_MODULES:
                    return True
                if parts[-1] in _CONNECTION_OPEN and self._raw_open(k):
                    return True
        return False

    def _opens_connection(self, s: int, e: int) -> bool:
        if self._opens_raw(s, e):
            return True
        for k in range(s, min(e, s + 40)):
            if self.t[k].kind == "name" and self.is_p(k + 1, "(") and self._opens(k):
                return True
            if (
                self.is_name(k, "new")
                and self.is_name(k + 1)
                and str(self.t[k + 1].value) in ("WebSocket", "XMLHttpRequest")
            ):
                return True
        return False

    def _call(self, k: int) -> bool:
        """Apply one call: stores into its receiver, callbacks, summaries and sinks."""
        self.work += 1
        if self.work > self.budget:
            raise _OverBudget
        changed = False
        scope = self.scope_of(k)
        open_i = k + 1
        args = self._args(open_i)
        name = str(self.t[k].value)
        parts, first = self._chain(k)
        # Storing into a receiver: `list.push(secret)`, `form.append("k", secret)`, Object.assign.
        if len(parts) >= 2 and (name in _STORE_METHODS or parts[-2:] == ["Object", "assign"]):
            if parts[-2:] == ["Object", "assign"] and args:
                base = self._assign_base(args[0][1] - 1)
                rest = args[1:]
            else:
                # Not a module, nor the runtime's own objects: `Buffer.concat(chunks)` stores nothing.
                base = (
                    parts[0]
                    if parts[0] not in self.aliases and parts[0] not in _HOST_OBJECTS
                    else None
                )
                rest = args
            if base:
                value = set().union(*(self.taint(s, e, scope) for s, e in rest)) if rest else set()
                receiver = self.resolve(base, scope)
                changed |= self._grow(self.vars.setdefault(receiver, set()), value)
        # An archive accumulating local files: `zip.addLocalFile(secretPath)`, `zip.directory(p)`,
        # `zip.file(name, fs.readFileSync(p))`. The archive carries what a read of the file gives
        # (home_file/secret_file), and is read where the archive is sent -- its `.toBuffer()` /
        # `.generateAsync()` carries the archive's taint through the `zip` reference already.
        if len(parts) == 2 and args and self.resolve(parts[0], scope) in self.archives:
            av = self.resolve(parts[0], scope)
            if name == "file" and len(args) >= 2:  # jszip.file(name, content): the content
                changed |= self._grow(self.vars.setdefault(av, set()), self.taint(*args[1], scope))
            elif name in _ARCHIVE_ADD_PATH:  # the archiver reads the path: its contents go in
                added = set().union(*(JsFlow.read_of(self.taint(s, e, scope)) for s, e in args))
                changed |= self._grow(self.vars.setdefault(av, set()), added)
        # A response -- or a decoded blob -- written to a file to be run from disk: the file now
        # holds code something chose, so the path it was written to carries that label. Running the
        # path (`exec(p)`, `require(p)`) is the dropper the REMOTE_CODE/DECODE rules read; neither
        # label reaches a send-sink, so the path is only ever judged where it runs. A verified
        # own-release download is lowered in grading (review 98 round 2 B).
        if name in _FS_WRITE and len(args) >= 2:
            carried = self.taint(*args[1], scope) & {"network_response", "decoded"}
            s0, e0 = args[0]
            if carried and e0 - s0 == 1 and self.t[s0].kind == "name":
                written = self.resolve(str(self.t[s0].value), scope)
                changed |= self._grow(self.vars.setdefault(written, set()), carried)
        # Callbacks get what the call works on: its receiver and its other arguments.
        candidates = [
            (i, self.fn_at_token.get(s) or self.fn_at_token.get(s + 1))
            for i, (s, _) in enumerate(args)
        ]
        callbacks = [(i, fid) for i, fid in candidates if fid]
        if callbacks:
            given: set[Label] = set()
            if self.is_p(first - 1, ".") and self.is_p(first - 2, ")"):
                # `request(...).then(cb)`: the receiver is the call before the dot.
                given |= self._receiver_taint(first - 1, k, scope)
            elif (first > 0 and self.is_p(first - 1, ")")) or len(parts) >= 2:
                given |= self._receiver_taint(first, k, scope)
            for i, (s, e) in enumerate(args):
                if i not in {c for c, _ in callbacks}:
                    given |= self.taint(s, e, scope)
            if (
                any(p in ("readFile", "readFileSync") for p in parts[-1:])
                and "secret_path" in given
            ):
                given.add("secret_file")
            if self._sink_kind(k, scope) in ("request", "connection") or (
                parts[0] in _DNS_MODULES and parts[-1] in ("resolveTxt", "resolveAny")
            ):
                # `https.get(url, res => ...)`: the callback is handed the server's answer; a TXT
                # record is one too, the channel a payload is fetched in chunks over.
                given.add("network_response")
            elif self._identity_command(k):
                # `exec("whoami", (e, out) => ...)`: the callback is handed who this machine is.
                given.add("identity")
            for _, fid in callbacks:
                fn = self.fns[fid - 1]
                for p in fn.params:
                    changed |= self._grow(self.vars.setdefault((fid, p), set()), given)
        # A known function: its sinks apply to the arguments given here.
        if len(parts) == 2 and parts[0] == "this":
            target = self.method_of(name, scope)
        elif len(parts) == 2 and self._static_call(k) is not None:
            target = self._static_call(k)
        elif len(parts) == 1:
            target = self.fn_by_name.get(self.resolve(name, scope))
        else:
            target = None
        if target is not None:
            fn = self.fns[target - 1]
            for (how, idx), sinks in list(fn.sinks.items()):
                if idx >= len(args):
                    continue
                value = self.taint(args[idx][0], args[idx][1], scope)
                if how == "R":
                    value = JsFlow.read_of(value)
                for sink, host, dest, line in sinks:
                    changed |= self._record(value, sink, host, dest, line, scope)
        if len(parts) == 1 and args:
            settles = self.resolvers.get(self.resolve(name, scope))
            if settles is not None:
                # `resolve(Buffer.concat(chunks))` in a promise's executor: the promise's value.
                value = self.taint(args[0][0], args[0][1], scope)
                changed |= self._grow(self.vars.setdefault(settles, set()), value)
            elif self.is_name(k - 1, "new") and name in self.class_by_name:
                c = self.class_by_name[name]
                changed |= self._store_fields(
                    c, self.fn_by_name.get((-c, "constructor")), args, scope
                )
        elif len(parts) == 2 and args:
            # `r.set(t)` on `r = new Runner()`, or `this.set(t)` inside Runner: Runner's `set`
            # takes `t` into its fields. Only a receiver whose class is known: a method name
            # alone (`send`, `write`) is in every class of a bundle.
            owner = (
                -self.this_of(scope)[0]
                if parts[0] == "this"
                else self.instance_of.get(self.resolve(parts[0], scope), 0)
            )
            if owner > 0:
                method = self.fn_by_name.get((-owner, name))
                changed |= self._store_fields(owner, method, args, scope)
        # A sink.
        kind = self._sink_kind(k, scope)
        if kind == "process" and args and self._opener(*args[0], scope):
            # The desktop opening what it is given -- a sign-in link the server sent, in the
            # browser -- runs none of it: an `open` sink, which only the send rules read.
            kind = "open"
        if kind is not None and args:
            # Opening a connection sends its options (host, path, headers); the body follows
            # through `.write`/`.end` on the bound name.
            value = self._sent(k, kind, args, scope)
            host, dest = self._destination(open_i, self.match[open_i])
            bot = self.bot_clients.get(self.resolve(parts[0], scope)) if len(parts) >= 2 else None
            if bot is not None and kind == "request" and dest == "unknown":
                host, dest = bot  # the bot API the client speaks to
            if dest == "unknown":
                host, dest = self._bound_destination(scope)
            changed |= self._record(value, kind, host, dest, self.line(k), scope)
        return changed

    def _opens_bot(self, s: int, e: int) -> tuple[str | None, str] | None:
        """(host, kind) of the messaging client bound from [s, e), if it is one: a Telegram bot
        (`new Telegraf(token)`, `new TelegramBot(token)`) or a Discord webhook client, whose sends
        go to a drop point's API; a mail transport (`nodemailer.createTransport(..)`), whose
        server is the caller's."""
        for k in range(s, min(e, s + 12)):
            if self.t[k].kind != "name" or not self.is_p(k + 1, "("):
                continue
            name = str(self.t[k].value)
            if self.is_name(k - 1, "new") or self.is_p(k - 1, "."):
                if name in ("Telegraf", "TelegramBot"):
                    return ("api.telegram.org", "drop")
                if name == "WebhookClient":
                    return ("discord.com", "drop")
            if name == "createTransport" or name == "createTransporter":
                return (None, "unknown")
        return None

    def _opens_archive(self, s: int, e: int) -> bool:
        """Whether [s, e) binds an archive being built: `new JSZip()`, `new AdmZip()`, or a
        factory call `archiver("zip")`. The files added to it accumulate on the bound name, and
        its `.toBuffer()`/`.generateAsync()` carries them where the archive is sent."""
        for k in range(s, min(e, s + 12)):
            if self.t[k].kind != "name":
                continue
            name = str(self.t[k].value)
            module = self.aliases.get(name, "").split(".")[0]
            if self.is_name(k - 1, "new") and (
                name in _ARCHIVE_CLASSES or module in _ARCHIVE_MODULES
            ):
                return True
            if self.is_p(k + 1, "(") and (name in _ARCHIVE_MODULES or module in _ARCHIVE_MODULES):
                return True  # `archiver("zip")`, or an aliased require called directly
        return False

    def _sent(self, k: int, kind: str, args: list[tuple[int, int]], scope: int) -> set[Label]:
        """What the sink at name token `k` sends: its arguments' labels, less the machine's own
        identity where that is only where the call goes -- a socket bound to the host's own
        name, a printer scan over its interfaces, NAT-PMP to its gateway, a router's own API
        (review 98 P1 A/B: five benign tools). The destination is a `host`/`hostname`/
        `localAddress`/`port` option, a socket's `(port, host)`, a datagram's port and address,
        or a lookup's name, and only when it is the value as it stands: a beacon puts the
        identity in a path, a body or a name's labels (`id + ".x.invalid"`), which stay."""
        parts = self._chain(k)[0]
        root, last = parts[0], parts[-1]
        if kind == "dns":
            where = {0}
        elif root in _RAW_SOCKET_MODULES and last in _CONNECTION_OPEN:
            where = {0, 1}
        elif len(parts) == 2 and last == "send" and self.resolve(root, scope) in self.connections:
            where = set(range(1, len(args)))
        else:
            where = set()
        out: set[Label] = set()
        for i, (s, e) in enumerate(args):
            if i in where and self._as_it_stands(s, e, scope):
                out |= self.taint(s, e, scope) - {"identity"}
            elif self.is_p(s, "{") and self.match[s] == e - 1:
                for a, b in self._split_args(s):
                    if (
                        self.t[a].kind in ("name", "str")
                        and str(self.t[a].value) in _DESTINATION_KEYS
                        and (b == a + 1 or self.is_p(a + 1, ":"))
                        and self._as_it_stands(min(a + 2, b - 1), b, scope)
                    ):
                        out |= self.taint(a, b, scope) - {"identity"}
                    else:
                        out |= self.taint(a, b, scope)
            else:
                out |= self.taint(s, e, scope)
        if kind == "process" and self._argv_only(last, args):
            # A fixed program given what a server sent as its arguments, with no shell: the
            # reply is data to that program (a version to install, a file to convert), not code
            # run. Anything else the arguments carry -- a secret handed to curl -- stays.
            out -= {"network_response", "decoded"}
        return out

    def _argv_only(self, call: str, args: list[tuple[int, int]]) -> bool:
        """Whether a process call runs a literal, non-interpreter program with an argument list and
        no shell: `spawn("ffmpeg", [...])`, not `exec(cmd)`, `spawn(path)`, `spawn("node", ["-e",
        x])` or `spawn("npx", [pkg])`, which run what they are given."""
        if call not in _ARGV_CALLS or len(args) < 2:
            return False
        s, e = args[0]
        if e != s + 1 or self.t[s].kind != "str":
            return False
        program = str(self.t[s].value).strip()
        if not program or _RUNS_ITS_ARGUMENT.search(program):
            return False
        options = args[2:] if call.startswith("spawn") else args[2:3]
        return not any(
            self.t[k].kind in ("name", "str") and str(self.t[k].value) == "shell"
            for a, b in options
            for k in range(a, b)
        )

    def _opener(self, a: int, b: int, scope: int, follow: bool = True) -> bool:
        """Whether the command [a, b) only opens its operand in the desktop's handler: `open`,
        `xdg-open`, `start ""`, `rundll32 url.dll,FileProtocolHandler`, in every branch of a
        platform choice (`darwin ? \\`open "${u}"\\` : ...`), written in place or bound to the
        name passed. Operands compared against (`=== "darwin"`) are not commands. `open -a App`
        runs the app, so it is not one."""
        if follow and b == a + 1 and self.is_name(a):
            rhs = self.bound.get(self.resolve(str(self.t[a].value), scope))
            return bool(rhs) and all(
                self._opener(s, e, self.scope_of(s), follow=False) for s, e in rhs or ()
            )
        heads: list[str] = []
        for i in range(a, b):
            tok = self.t[i]
            if tok.kind != "str":
                continue
            before, after = (
                self.t[i - 1] if i > 0 else None,
                self.t[i + 1] if i + 1 < self.n else None,
            )
            if any(
                x is not None and x.kind == "punct" and x.value in ("===", "!==", "==", "!=")
                for x in (before, after)
            ):
                continue
            if i == a or (
                before is not None and before.kind == "punct" and before.value in ("(", "?", ":")
            ):
                heads.append(str(tok.value))
        return bool(heads) and all(_OPENER.match(h) for h in heads)

    def requests(self) -> list[Request]:
        """See `JsFlow.requests`."""
        from cordon_scanner.analysis.javascript.js_values import JsValues

        out: list[Request] = []
        parts = tuple(sorted(self.registry_parts))
        values: JsValues | None = None
        for k in range(self.n - 1):
            if not self._called(k):
                continue
            scope = self.scope_of(k)
            if self._sink_kind(k, scope) != "request":
                continue
            args = self._args(k + 1)
            kind = self._url_kind(args[0], scope, k, 0) if args else "other"
            urls: frozenset[str] | None = None
            if kind == "other" and args:
                values = values or JsValues(self)
                urls = values.strings(*args[0], scope)
            out.append(
                Request(
                    self.line(k),
                    kind,
                    parts if kind == "registry" else (),
                    tuple(sorted(urls)) if urls else (),
                )
            )
        return out

    def clean_spawns(self) -> frozenset[int]:
        """See `JsFlow.safe_spawn_lines`. Read after `run`, over the final taint: a process sink
        whose command position carries no label at all -- so its command and arguments are
        literals or local constants, with nothing decoded, fetched or deferred to a call site
        flowing into them."""
        out: set[int] = set()
        for k in range(self.n - 1):
            if not self._called(k):
                continue
            scope = self.scope_of(k)
            if self._sink_kind(k, scope) != "process":
                continue
            args = self._args(k + 1)
            if not args or self._opener(*args[0], scope):
                continue
            if not self._sent(k, "process", args, scope):
                out.add(self.line(k))
        return frozenset(out)

    def _called(self, k: int) -> bool:
        """Whether name token `k` is called here, not declared (`function fetch(url) {`, a
        method's head)."""
        return (
            self.t[k].kind == "name"
            and self.is_p(k + 1, "(")
            and self.match[k + 1] > 0
            and not self.is_name(k - 1, "function")
            and k not in self.fn_at_token
        )

    def _call_sites(self, fid: int) -> list[int]:
        """The name tokens calling the named function `fid` in the file."""
        fn = self.fns[fid - 1]
        return [
            j
            for j in range(self.n - 1)
            if fn.name
            and str(self.t[j].value) == fn.name
            and self._called(j)
            and self.fn_by_name.get(self.resolve(fn.name, self.scope_of(j))) == fid
        ]

    def _named_params(
        self, taint: set[Label], resolving: frozenset[tuple[str, int, int]]
    ) -> set[tuple[str, int, int]]:
        """The parameters of named functions in `taint`, less those being resolved: what the
        function's callers pass. A callback's (`res` in `https.get(u, res => ...)`) are the
        library's to fill."""
        return {
            (x[0], x[1], x[2])
            for x in taint
            if isinstance(x, tuple)
            and x[0] == "P"
            and self.fns[x[1] - 1].name
            and (x[0], x[1], x[2]) not in resolving
        }

    def _chosen_here(
        self,
        params: set[tuple[str, int, int]],
        depth: int,
        resolving: frozenset[tuple[str, int, int]],
    ) -> bool:
        """Whether every caller in the file passes these parameters a value no response chose:
        a literal, a lookup table, the package's own metadata. No caller seen is not."""
        if depth >= 3:
            return False
        for p in params:
            _, fid, idx = p
            sites = self._call_sites(fid)
            if not sites:
                return False
            for j in sites:
                a = self._args(j + 1)
                if idx >= len(a):
                    continue
                taint = self.taint(a[idx][0], a[idx][1], self.scope_of(j))
                if "network_response" in taint:
                    return False
                inner = self._named_params(taint, resolving | {p})
                if inner and not self._chosen_here(inner, depth + 1, resolving | {p}):
                    return False
        return True

    def _url_kind(
        self,
        arg: tuple[int, int],
        scope: int,
        call: int,
        depth: int,
        resolving: frozenset[tuple[str, int, int]] = frozenset(),
    ) -> str:
        """`registry`, `redirect` or `other` for the URL argument `arg` of the request at `call`:
        a helper's parameter is what every call of the helper in the file passes it, and a
        helper nothing in the file calls is `other` (its callers are not seen). A parameter
        already being resolved (a helper following its own redirect) adds nothing."""
        taint = self.taint(arg[0], arg[1], scope)
        concrete = {x for x in taint if isinstance(x, str)}
        params = self._named_params(taint, resolving)
        if "registry_url" in concrete:
            # Only the template and what fills it -- the package's own name and version, from its
            # callers in the file: a package name a response chose is not the manifest's.
            if concrete != {"registry_url"}:
                return "other"
            return "registry" if self._chosen_here(params, depth, resolving) else "other"
        if concrete - {"network_response"} or depth >= 3:
            return "other"
        if not params:
            # `fetch(res.headers.location)`: a redirect; nothing at all is a literal URL's call.
            return "redirect" if concrete else "other"
        kinds: set[str] = {"redirect"} if concrete else set()
        for _, fid, idx in params:
            sites = [j for j in self._call_sites(fid) if j != call]
            if not sites:
                return "other"
            for j in sites:
                a = self._args(j + 1)
                kinds.add(
                    self._url_kind(a[idx], self.scope_of(j), j, depth + 1, resolving | params)
                    if idx < len(a)
                    else "other"
                )
        if "other" in kinds:
            return "other"
        return "registry" if "registry" in kinds else "redirect"

    #: Calls that pick out a value without joining anything to it (`_as_it_stands`).
    _PICKS: ClassVar[frozenset[str]] = frozenset(
        {"keys", "values", "entries", "find", "filter", "flat", "at"}
    )

    def _as_it_stands(
        self, a: int, b: int, scope: int, seen: frozenset[tuple[int, str]] = frozenset()
    ) -> bool:
        """Whether the expression [a, b) is the machine's identity as it was read: names, member
        reads and `os`'s own reads, each variable in it bound only that way. Nothing joined to it
        -- no string, `+`, template, `.join` -- and no function it passed through, which may
        join: a beacon builds its name first (`const h = os.hostname() + ".x.invalid"`) and
        hands it over bare. A parameter is not one either: what a caller passed is not seen."""
        if b - a > 64 or len(seen) > 8:
            return False
        i = a - 1
        while i + 1 < b:
            i += 1
            tok = self.t[i]
            if (
                self.is_name(i, "require")
                and self.is_p(i + 1, "(")
                and i + 3 < b
                and self.t[i + 2].kind == "str"
                and self.t[i + 2].value in ("os", "node:os")
                and self.is_p(i + 3, ")")
            ):
                i += 3  # `require("os").hostname()`: the module itself, as an alias of it is
                continue
            if tok.kind == "str" or (tok.kind == "punct" and tok.value in ("+", "+=", "`")):
                return False
            if tok.kind != "name":
                continue
            v = str(tok.value)
            identity = self.fact[i] == ("src", "identity")
            if self.is_p(i - 1, ".") or self.is_p(i - 1, "?."):
                if self.is_p(i + 1, "(") and not identity and v not in self._PICKS:
                    return False
                continue
            if (
                identity
                or v in self.aliases
                or (v in ("Object", "Array") and self.is_p(i + 1, "."))
            ):
                continue
            if self.is_p(i + 1, "(") or v in _KEYWORDS:
                return False
            ref = self.resolve(v, scope)
            if ref in seen:
                continue
            rhs = self.bound.get(ref)
            if not rhs or not all(
                self._as_it_stands(s, e, self.scope_of(s), seen | {ref}) for s, e in rhs
            ):
                return False
        return True

    def _promises(self) -> None:
        """`resolvers`: an executor's first parameter -> the promise it settles."""
        self.resolvers: dict[tuple[int, str], tuple[int, str]] = {}
        for k in range(1, self.n - 2):
            if self.is_name(k, "Promise") and self.is_name(k - 1, "new") and self.is_p(k + 1, "("):
                s = k + 2
                fid = self.fn_at_token.get(s) or (
                    self.fn_at_token.get(s + 1) if self.is_name(s, "async") else None
                )
                if fid is not None and self.fns[fid - 1].params:
                    self.resolvers[(fid, self.fns[fid - 1].params[0])] = _Analysis.promise_key(k)

    def _store_fields(
        self, c: int, method: int | None, args: list[tuple[int, int]], scope: int
    ) -> bool:
        """`new C(a, b)` or `obj.m(a, b)`: the fields C's constructor (or method `m`) set from its
        parameters get `a` and `b`. One instance per class, as one `this` per class is."""
        instance = self.vars.get((-c, "this"))
        if method is None or not instance:
            return False
        value: set[Label] = set()
        for label in list(instance):
            if isinstance(label, tuple) and label[1] == method and label[2] < len(args):
                s, e = args[label[2]]
                got = self.taint(s, e, scope)
                value |= JsFlow.read_of(got) if label[0] == "R" else got
        return self._grow(instance, value)

    def _receiver_taint(self, first: int, k: int, scope: int) -> set[Label]:
        """The taint of what a method is called on: `read(p)` in `read(p).then(...)`, `x` in `x.on(...)`."""
        end = first  # tokens before the dotted callee
        parts_end = k - 1  # the `.` before the method
        start = first
        # Back over the whole call chain: `fetch(u).then(r => r.text())` is the receiver of a
        # second `.then`, and what the server sent flows down it.
        while self.is_p(start - 1, ")") and self.match[start - 1] >= 0:
            start = self.match[start - 1]
            if not self.is_name(start - 1):
                break
            _, start = self._chain(start - 1)
            if not (self.is_p(start - 1, ".") and self.is_p(start - 2, ")")):
                break
            start -= 1
        del end
        return self.taint(start, max(parts_end, start), scope)

    def _bound_destination(self, scope: int) -> tuple[str | None, str]:
        """A request whose URL is a name bound in the file (see `_scan_destination`)."""
        if self._file_destination is None:
            self._file_destination = self._scan_destination()
        return self._file_destination

    def _scan_destination(self) -> tuple[str | None, str]:
        """Only when every URL the file names is a drop point or a bare address: a request whose
        URL is a variable then goes to one of them, whichever. A file that also names an ordinary
        host may be sending to that one, and the destination stays unknown."""
        found: tuple[str | None, str] = (None, "unknown")
        for tok in self.t:
            if tok.kind != "str":
                continue
            host, kind = _Analysis.classify(str(tok.value))
            if host is None:
                continue
            if kind == "fixed":
                return (None, "unknown")
            found = (host, kind)
        return found

    def _record(
        self, value: set[Label], sink: str, host: str | None, dest: str, line: int, scope: int
    ) -> bool:
        changed = False
        concrete = frozenset(x for x in value if isinstance(x, str) and x in JsFlow.SOURCES)
        if concrete:
            key = (line, sink)
            prev = self.flows.get(key)
            merged = concrete | (prev.sources if prev else frozenset())
            if prev is None or merged != prev.sources:
                self.flows[key] = Flow(merged, sink, host, dest, line)
                changed = True
        # A parameter of the enclosing function reaching the sink: that function's summary.
        for x in value:
            if isinstance(x, tuple):
                fn = self.fns[x[1] - 1]
                entry = (sink, host, dest, line)
                have = fn.sinks.setdefault((x[0], x[2]), set())
                if entry not in have:
                    have.add(entry)
                    changed = True
                # A key handed to a function as `privateKey` and sent: the parameter is the source.
                if x[0] == "P" and x[2] < len(fn.params) and _WALLET_PARAM.match(fn.params[x[2]]):
                    key = (line, sink)
                    prev = self.flows.get(key)
                    merged = frozenset({"wallet_key"}) | (prev.sources if prev else frozenset())
                    if prev is None or merged != prev.sources:
                        self.flows[key] = Flow(merged, sink, host, dest, line)
                        changed = True
        return changed
