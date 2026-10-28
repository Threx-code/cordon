"""What one JavaScript call does to the values in a file: what it stores and where, what its
callbacks are handed, what a function the file defines does with its arguments, and the flow a
sink records."""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.analysis.javascript.flow.sinks import Sinks
from cordon_scanner.analysis.javascript.flow.taint import Taint
from cordon_scanner.analysis.javascript.flow.vocabulary import (
    _ARCHIVE_ADD_PATH,
    _ARGV_CALLS,
    _CONNECTION_OPEN,
    _DESTINATION_KEYS,
    _DNS_MODULES,
    _FS_WRITE,
    _HOST_OBJECTS,
    _KEYWORDS,
    _OPENER,
    _RAW_SOCKET_MODULES,
    _RUNS_ITS_ARGUMENT,
    _STORE_METHODS,
    _WALLET_PARAM,
    MAX_PARAMETER_LABELS,
    SOURCES,
    Flow,
    Label,
    _OverBudget,
)


class Calls(Taint):
    """The calls layer of `js_flow._Analysis`: one call applied to the bindings, and the flows its
    sinks record. The fixpoint above applies every call until nothing grows."""

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
        changed |= self._apply_stores(parts, name, args, scope)
        changed |= self._feed_callbacks(k, parts, first, args, scope)
        changed |= self._apply_known(k, parts, name, args, scope)
        changed |= self._apply_sink(k, parts, open_i, args, scope)
        return changed

    def _apply_stores(
        self, parts: list[str], name: str, args: list[tuple[int, int]], scope: int
    ) -> bool:
        """Values a call stores: into its receiver, into an archive being built, or into a file written
        to be run."""
        changed = False
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
                added = set().union(*(Taint.read_of(self.taint(s, e, scope)) for s, e in args))
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
        return changed

    def _feed_callbacks(
        self, k: int, parts: list[str], first: int, args: list[tuple[int, int]], scope: int
    ) -> bool:
        """What the function literals passed to call `k` are handed: its receiver and other arguments,
        and a server's answer or this machine's identity where the call fetches one."""
        changed = False
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
        return changed

    def _apply_known(
        self, k: int, parts: list[str], name: str, args: list[tuple[int, int]], scope: int
    ) -> bool:
        """A call to a function this file defines: its sinks applied to these arguments, a promise's
        resolver, and the fields a constructor or method stores."""
        changed = False
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
                    value = Taint.read_of(value)
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
        return changed

    def _apply_sink(
        self, k: int, parts: list[str], open_i: int, args: list[tuple[int, int]], scope: int
    ) -> bool:
        """Call `k` as a sink: what it sends, recorded with where it goes."""
        changed = False
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
                value |= Taint.read_of(got) if label[0] == "R" else got
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
            host, kind = Sinks.classify(str(tok.value))
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
        concrete = frozenset(x for x in value if isinstance(x, str) and x in SOURCES)
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
                    self.resolvers[(fid, self.fns[fid - 1].params[0])] = Taint.promise_key(k)
