"""What one JavaScript call does to the values in a file: what it stores and where, what its
callbacks are handed, what a function the file defines does with its arguments, and the flow a
sink records."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

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
    _STORE_METHODS,
    _WALLET_PARAM,
    DATA_ARGS,
    MAX_PARAMETER_LABELS,
    SOURCES,
    Flow,
    Label,
    ProgramNames,
    _OverBudget,
)

if TYPE_CHECKING:
    from collections.abc import Callable

#: A parameter's label wrapped as (_DATA, label) on its way from a DATA_ARGS spawn to `_record`:
#: the summary keeps it in `_Fn.data_sinks` (note 69). It never enters a binding.
_DATA = "D"


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
            for data, summary in ((False, fn.sinks), (True, fn.data_sinks)):
                for (how, idx), sinks in list(summary.items()):
                    if how == "Q":
                        # A parameter's field reaching a sink: this call's argument's field
                        # (item 59).
                        position, field = idx
                        if position >= len(args):
                            continue
                        value = self.arg_field(args[position], field, scope)
                    elif idx >= len(args):
                        continue
                    else:
                        value = self.taint(args[idx][0], args[idx][1], scope)
                        if how == "R":
                            value = Taint.read_of(value)
                    if data:
                        # A DATA_ARGS spawn's data argument (note 69): as written in place.
                        value = {(_DATA, x) if self._deferred(x) else x for x in value}
                        value -= self._CODE_LABELS
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
        if kind == "process" and args and self._opens_a_link(parts[-1], args, scope):
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
        local = bool(args) and DATA_ARGS.get(self._program(*args[0], scope) or "") == "local"
        if (
            kind == "process"
            and not local  # a `local` row's arguments stay a sink: a reply at the call site is a flow
            and self._fixed_program(last, args, scope, self._may_carry_code)
        ):
            # A DATA_ARGS program given what a server sent only where its rule says it is data,
            # with no shell and nothing in its options (note 44): the reply is a pid, an archive, a
            # URL to fetch, not code run. Anything else the arguments carry -- a secret handed to
            # curl -- stays. A parameter's label is marked data, so the call site applies its
            # argument the same way (note 69).
            out -= self._CODE_LABELS
            out = {(_DATA, x) if self._deferred(x) else x for x in out}
        return out

    #: What a spawn's argument may carry for the reply to be code run: `_fixed_program`'s question.
    _CODE_LABELS: ClassVar[frozenset[str]] = frozenset({"network_response", "decoded"})

    def _carries_code(self, a: int, b: int, scope: int) -> bool:
        """Whether [a, b) carries what a server sent or a blob decoded."""
        return bool(self.taint(a, b, scope) & self._CODE_LABELS)

    def _may_carry_code(self, a: int, b: int, scope: int) -> bool:
        """Whether [a, b) carries what a server sent or a blob decoded, or a parameter's value,
        which a call site may fill with either (note 69)."""
        labels = self.taint(a, b, scope)
        return bool(labels & self._CODE_LABELS) or any(self._deferred(x) for x in labels)

    @staticmethod
    def _deferred(label: Label) -> bool:
        """A parameter's value, or a file read at its path: resolved at each call site."""
        return isinstance(label, tuple) and label[0] in ("P", "Q", "R")

    def _not_literal(self, a: int, b: int, scope: int) -> bool:
        """Whether [a, b) is anything but string literals: the co-occurrence composites' question,
        which have no taint, so every value not written out counts as one a reply may set."""
        for i in range(a, b):
            tok = self.t[i]
            if tok.kind in ("str", "punct", "num"):
                continue
            key = self.is_p(i + 1, ":") and (self.is_p(i - 1, "{") or self.is_p(i - 1, ","))
            if tok.kind == "name" and (key or tok.value in self._WRITTEN_OUT):
                continue  # an object's key (`{ stdio: "ignore" }`), `true`, `null`
            return True
        return False

    #: Names that are values written out, not a variable a reply may set.
    _WRITTEN_OUT: ClassVar[frozenset[str]] = frozenset({"true", "false", "null", "undefined"})

    def _program(self, a: int, b: int, scope: int) -> str | None:
        """The program a spawn's first argument names, as DATA_ARGS keys it: a literal, or a name
        bound only to one literal; None for anything else (a property, a parameter, a call)."""
        if b == a + 1 and self.is_name(a):
            rhs = self.bound.get(self.resolve(str(self.t[a].value), scope)) or []
            spans = {(s, e) for s, e in rhs}
            if len(spans) != 1:
                return None
            a, b = next(iter(spans))
        if b != a + 1 or self.t[a].kind != "str":
            return None
        return ProgramNames.of(str(self.t[a].value)) or None

    def _fixed_program(
        self,
        call: str,
        args: list[tuple[int, int]],
        scope: int,
        tainted: Callable[[int, int, int], bool],
    ) -> bool:
        """Whether an argv-form spawn runs a DATA_ARGS program whose every `tainted` argument meets
        the program's rule, with no shell and nothing tainted in its options (note 44). `spawn(
        "taskkill", ["/PID", v])` and `spawn("tar", ["x", "--", f])` are; `spawn("git", [v])`,
        `spawn("tar", ["x", v])`, `spawn("x.cmd", [v])`, `spawn(p, [v], {env: {X: v}})` are not."""
        if call not in _ARGV_CALLS or len(args) < 2:
            return False
        program = self._program(*args[0], scope)
        rule = DATA_ARGS.get(program or "")
        if rule is None:
            return False
        if rule == "local":
            # For the composites' marking only (`fixed_spawns`; `_sent` keeps a `local` row's
            # arguments a sink, so a reply handed to a helper is a flow at its call site): fixed
            # while nothing a server sent or a blob decoded reaches any argument or option (note 78).
            return not any(
                self._carries_code(a, b, scope)
                or any(
                    self.t[k].kind in ("name", "str") and str(self.t[k].value) == "shell"
                    for k in range(a, b)
                )
                for a, b in args[1:]
            )
        options = args[2:] if call.startswith("spawn") else args[2:3]
        for a, b in options:
            if any(
                self.t[k].kind in ("name", "str") and str(self.t[k].value) == "shell"
                for k in range(a, b)
            ) or tainted(a, b, scope):
                return False
        s, e = args[1]
        if not (self.is_p(s, "[") and self.match[s] == e - 1):
            # Not written as a list: where a tainted part sits is unknown.
            return rule == "any" or not tainted(s, e, scope)
        dashes: int | None = None
        for index, (a, b) in enumerate(self._split_args(s)):
            if (
                dashes is None
                and b == a + 1
                and self.t[a].kind == "str"
                and self.t[a].value == "--"
            ):
                dashes = index
            if not tainted(a, b, scope):
                continue
            if rule == "after --" and dashes is None:
                return False
            if rule == "link" and not self._starts_a_link(a, b):
                return False
        return True

    def _starts_a_link(self, a: int, b: int) -> bool:
        """Whether [a, b) begins with a literal http(s)://, a template's group included."""
        while a < b and self.is_p(a, "("):
            a += 1
        return (
            a < b and self.t[a].kind == "str" and ProgramNames.starts_a_link(str(self.t[a].value))
        )

    def _opens_a_link(self, call: str, args: list[tuple[int, int]], scope: int) -> bool:
        """Whether a process call only opens a link in the desktop's handler: a command string
        whose every branch is an opener followed by a literal http(s):// (`_opener`), or an argv
        opener on DATA_ARGS whose every non-literal argument starts with one."""
        return self._opener(*args[0], scope) or (
            DATA_ARGS.get(self._program(*args[0], scope) or "") == "link"
            and self._fixed_program(call, args, scope, self._not_literal)
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
        # Each opener must be handed a link the code itself starts (note 44): what a reply names,
        # opened, may be `file:`, an app or a scheme's handler.
        return bool(heads) and all(
            (opener := _OPENER.match(h)) is not None
            and ProgramNames.starts_a_link(h[opener.end() :])
            for h in heads
        )

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
        if method is None:
            return False
        changed = False
        # The instance itself and each field the class stores into (item 59): each gets what its
        # own parameter labels stand for here, so `this.command = command` fills this.command only.
        for key in ((-c, "this"), *self.fields.get((-c, "this"), ())):
            held = self.vars.get(key)
            if not held:
                continue
            value: set[Label] = set()
            for label in list(held):
                if not (
                    isinstance(label, tuple)
                    and label[0] in ("P", "R", "Q")
                    and label[1] == method
                    and label[2] < len(args)
                ):
                    continue
                if label[0] == "Q":
                    value |= self.arg_field(args[label[2]], label[3], scope)
                    continue
                s, e = args[label[2]]
                got = self.taint(s, e, scope)
                value |= Taint.read_of(got) if label[0] == "R" else got
            changed |= self._grow(held, value)
        return changed

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
            if isinstance(x, tuple) and x[0] == "C":
                # A local module call's result reaching the sink (item 60): the parent resolves it.
                entry = (sink, host, dest, line)
                have_c = self.c_sinks.setdefault(int(x[1]), set())
                if entry not in have_c:
                    have_c.add(entry)
                    changed = True
                continue
            if isinstance(x, tuple):
                data = x[0] == _DATA
                if data:
                    x = x[1]
                fn = self.fns[x[1] - 1]
                entry = (sink, host, dest, line)
                slot = (x[0], (x[2], x[3])) if x[0] == "Q" else (x[0], x[2])
                have = (fn.data_sinks if data else fn.sinks).setdefault(slot, set())
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
