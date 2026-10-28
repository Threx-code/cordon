"""What a JavaScript value carries: the facts each token contributes (a source, a path, a decode),
and the taint of a token range, compiled once and read through bindings and calls."""

from __future__ import annotations

from cordon_scanner.analysis.javascript.flow.sinks import Sinks
from cordon_scanner.analysis.javascript.flow.vocabulary import (
    _BROWSER,
    _FS_READ,
    _IDENTITY,
    _IDENTITY_COMMAND,
    _KEYWORDS,
    _REGISTRY_URL,
    _SECRET_PATH,
    _WALLET_MEMBER,
    Label,
    _OverBudget,
)


class Taint(Sinks):
    """The taint layer of `js_flow._Analysis`: each token's fact, and the labels a range of tokens
    carries."""

    def _facts(self) -> None:
        """What each token contributes to a value, decided once: the rounds only look these up."""
        t = self.t
        self.fact: list[tuple[str, object] | None] = [None] * self.n
        for k in range(self.n):
            tok = t[k]
            if tok.kind == "str":
                self.fact[k] = self._string_fact(k)
            elif tok.kind == "name":
                v = str(tok.value)
                if self.is_p(k - 1, ".") or self.is_p(k - 1, "?."):
                    self.fact[k] = self._member_fact(k, v)
                elif v in _BROWSER and v != "cookie" and self.is_p(k + 1, "."):
                    self.fact[k] = ("src", "browser")
                elif (
                    v in self.aliases
                    and self.is_p(k + 1, "(")
                    and self.match[k + 1] > 0
                    and self._bound_source(k)
                ):
                    # `const {hostname} = require("os")`, `import {readFileSync} from "fs"`: the
                    # member called by the name it was bound to.
                    self.fact[k] = self._bound_source(k)
                elif v == "this" and self.is_p(k + 1, "."):
                    self.fact[k] = ("ref", "this")  # `this.key = v` taints the instance
                elif v not in _KEYWORDS and not (
                    self.is_p(k + 1, ":") and (self.is_p(k - 1, "{") or self.is_p(k - 1, ","))
                ):
                    if (
                        self.is_p(k + 1, "(")
                        and self.match[k + 1] > 0
                        and self._sink_kind(k, self.scope_of(k)) == "request"
                    ):
                        # What a request returns is what the server chose to send.
                        self.fact[k] = ("src", "network_response")
                    elif self.is_p(k + 1, "(") and self.match[k + 1] > 0 and self._is_decode(k):
                        # `atob(x)`, a destructured `gunzipSync(x)`: the decoded bytes.
                        self.fact[k] = ("src", "decoded")
                    elif self.is_p(k + 1, "(") and self.match[k + 1] > 0:
                        self.fact[k] = ("call", v)
                    else:
                        self.fact[k] = ("ref", v)
        self._spelled_identity()

    def _string_fact(self, k: int) -> tuple[str, object] | None:
        """The fact string literal `k` contributes: a seeded label, a credential or home path, or a
        registry tarball URL."""
        tok = self.t[k]
        if self.seed is not None and (label := self.seed(str(tok.value))) is not None:
            return ("src", label)
        if _SECRET_PATH.search(str(tok.value)):
            return ("src", "secret_path")
        if str(tok.value).startswith(("~/", "~\\")) or str(tok.value) in (
            "~",
            "HOME",
            "USERPROFILE",
        ):
            return ("src", "home_path")
        if _REGISTRY_URL.match(str(tok.value)) and self._registry_template(k):
            # Not a source a rule reads: what tells a registry install's request apart.
            return ("src", "registry_url")
        return None

    def _member_fact(self, k: int, v: str) -> tuple[str, object] | None:
        """The fact member name `k` (`v`, after `.` or `?.`) contributes: a source it reads, a file
        read, a decode, or a call to a method of its own class."""
        t = self.t
        if (
            self.is_p(k + 1, "(")
            and self.match[k + 1] > 0
            and self._sink_kind(k, self.scope_of(k)) == "request"
        ):
            return ("src", "network_response")  # `axios.get(...)`'s value
        if _WALLET_MEMBER.match(v):
            return ("src", "wallet_key")
        if v in _BROWSER and k >= 2 and str(t[k - 2].value) in ("document", "window", "globalThis"):
            return ("src", "browser")
        if (
            v == "env"
            and self.is_name(k - 2, "process")
            and not (self.is_p(k + 1, ".") or self.is_p(k + 1, "[") or self.is_p(k + 1, "?."))
        ):
            if not (self.is_p(k - 4, "(") and self.is_name(k - 5, "keys")):
                return ("src", "environment")
            return None  # `Object.keys(process.env)`: the names, not the values
        if v in _IDENTITY and self.is_p(k + 1, "(") and self._chain(k)[0][0] == "os":
            return ("src", "identity")
        if v == "homedir" and self.is_p(k + 1, "(") and self._chain(k)[0][0] == "os":
            # Not a source: a path. Reading a file under it is (see `Taint.read_of`).
            return ("src", "home_path")
        if v in ("HOME", "USERPROFILE") and self.is_name(k - 2, "env"):
            return ("src", "home_path")
        if (
            v in _FS_READ
            and self.is_p(k + 1, "(")
            and self.match[k + 1] > 0
            and not self._opened_to_write(k)
        ):
            return ("read", self.match[k + 1])
        if (
            v in ("readText", "read")
            and k >= 2
            and str(t[k - 2].value) in ("clipboard", "clipboardy")
        ):
            return ("src", "clipboard")
        if self.is_p(k + 1, "(") and self.match[k + 1] > 0 and self._is_decode(k):
            # `Buffer.from(x, "base64")`, `zlib.gunzipSync(x)`: the decoded bytes.
            return ("src", "decoded")
        if (
            (self.is_name(k - 2, "this") or self._on_class(k))
            and self.is_p(k + 1, "(")
            and self.match[k + 1] > 0
        ):
            # A method of the same class, or a static one called on its class
            # (`WorkerHost.start(p)`).
            return ("call", v)
        return None

    def _spelled_identity(self) -> None:
        """The machine's identity read in spellings `_facts` does not see one token at a time:
        what an identity command prints (`execSync("whoami")`, `exec("uname -a", cb)`), and
        `os`'s own reads behind a computed name (`os["host" + "name"]()`) -- review 98 P3: four
        study-half misses send `whoami`/`uname` output through a helper, three call
        `os["S" + "S"]()`."""
        for k in range(self.n - 1):
            if self.t[k].kind != "name" or not self.is_p(k + 1, "(") or self.match[k + 1] <= 0:
                if (
                    self.t[k].kind == "name"
                    and self.is_p(k + 1, "[")
                    and self.match[k + 1] > 0
                    and (
                        str(self.t[k].value) == "os"
                        or self.aliases.get(str(self.t[k].value)) == "os"
                    )
                    and self.is_p(self.match[k + 1] + 1, "(")
                ):
                    name = self._folded(k + 2, self.match[k + 1])
                    if name in _IDENTITY:
                        self.fact[self.match[k + 1]] = ("src", "identity")
                    elif name == "homedir":
                        self.fact[self.match[k + 1]] = ("src", "home_path")
                continue
            if self._identity_command(k):
                self.fact[k] = ("src", "identity")

    def _identity_command(self, k: int) -> bool:
        """Whether the process call at name token `k` runs a command that prints who and where
        this machine is, given as a literal (`execSync("whoami")`, `exec("uname -a", cb)`)."""
        if self._sink_kind(k, self.scope_of(k)) != "process":
            return False
        args = self._args(k + 1)
        if not args:
            return False
        command = self._folded(args[0][0], args[0][1])
        return command is not None and bool(_IDENTITY_COMMAND.match(command))

    def _bound_source(self, k: int) -> tuple[str, object] | None:
        """What a call by a bound member name at `k` contributes, as `_facts` gives it for the
        same member called on its module."""
        module, _, member = self.aliases[str(self.t[k].value)].partition(".")
        if module == "os" and member in _IDENTITY:
            return ("src", "identity")
        if module == "os" and member == "homedir":
            return ("src", "home_path")
        if module in ("fs", "fs/promises") and member in _FS_READ and not self._opened_to_write(k):
            return ("read", self.match[k + 1])
        return None

    def _opened_to_write(self, k: int) -> bool:
        """`openSync(log, "a")`: a descriptor to write a log through is no read of the file. Only
        `openSync` takes a mode; a read is one without it or with an `r` mode."""
        if str(self.t[k].value) != "openSync" and not str(
            self.aliases.get(str(self.t[k].value), "")
        ).endswith(".openSync"):
            return False
        args = self._split_args(k + 1)
        if len(args) < 2:
            return False
        mode = self.t[args[1][0]]
        return mode.kind == "str" and not str(mode.value).startswith("r")

    def _compile(
        self, a: int, b: int, scope: int
    ) -> tuple[
        frozenset[Label],
        tuple[tuple[int, str], ...],
        tuple[tuple[int, int], ...],
        tuple[tuple[int, int], ...],
    ]:
        """A range reduced once to what its value depends on: constant labels, the names it reads,
        the known functions it calls (token, function id) and the files it reads (token, close)."""
        key = (a, b, scope)
        got = self._compiled.get(key)
        if got is not None:
            return got
        labels: set[Label] = set()
        refs: list[tuple[int, str]] = []
        calls: list[tuple[int, int]] = []
        reads: list[tuple[int, int]] = []
        fact, fn_at = self.fact, self.fn_at_token
        k = a
        while k < b:
            fid = fn_at.get(k)
            if fid is not None:
                k = max(k + 1, self.fns[fid - 1].end)  # a function literal's value carries nothing
                continue
            f = fact[k]
            if f is not None:
                what, v = f
                if what == "src":
                    labels.add(v)
                elif what == "read":
                    reads.append((k, int(v)))  # type: ignore[call-overload]
                    k = int(v)  # type: ignore[call-overload]
                elif what == "call" and v == "Promise" and self.is_name(k - 1, "new"):
                    refs.append(Taint.promise_key(k))  # what its executor resolves it with
                    k = max(k, self.match[k + 1])
                else:
                    resolved = self.resolve(str(v), scope)
                    if what != "call":
                        target = None
                    elif self.is_p(k - 1, ".") and self.is_name(k - 2, "this"):
                        target = self.method_of(str(v), scope)
                    elif self._static_call(k) is not None:
                        target = self._static_call(k)
                    else:
                        target = self.fn_by_name.get(resolved)
                    if target is not None:
                        calls.append((k, target))
                        k = self.match[k + 1]
                    else:
                        refs.append(resolved)
            k += 1
        self.work += (b - a) // 64
        if self.work > self.budget:
            raise _OverBudget
        got = (frozenset(labels), tuple(dict.fromkeys(refs)), tuple(calls), tuple(reads))
        self._compiled[key] = got
        return got

    @staticmethod
    def read_of(labels: set[Label]) -> set[Label]:
        """What reading a file at a path carrying `labels` yields: a credential store's path gives its
        contents; a parameter's path gives a read deferred to the call site."""
        out: set[Label] = set()
        for x in labels:
            if x == "secret_path":
                out.add("secret_file")
            elif x == "home_path":
                out.add("home_file")
            elif isinstance(x, tuple) and x[0] == "P":
                out.add(("R", x[1], x[2]))
        return out

    def taint(self, a: int, b: int, scope: int) -> set[Label]:
        """The labels an expression spanning tokens [a, b) carries."""
        key = (a, b, scope)
        hit = self._cache.get(key)
        if hit is not None and hit[0] == self.version:
            return hit[1]
        labels, refs, calls, reads = self._compile(a, b, scope)
        self.work += 1 + len(refs) // 8
        if self.work > self.budget:
            raise _OverBudget
        out: set[Label] = set(labels)
        for ref in refs:
            got = self.vars.get(ref)
            if got:
                out |= got
        for k, target in calls:
            out |= self._call_return(k, target, scope)
        for k, close in reads:
            out |= Taint.read_of(self.taint(k + 2, close, scope))
        self._cache[key] = (self.version, out)
        return out

    def _call_return(self, k: int, target: int, scope: int) -> set[Label]:
        """What calling the known function `target` at token `k` returns: its summary applied to the
        arguments. (An unknown function's arguments are read where they stand: what it returns is
        not known, what it was given usually is.)"""
        args = self._args(k + 1)
        fn = self.fns[target - 1]
        out: set[Label] = set()
        for label in fn.ret:
            if isinstance(label, tuple) and label[1] == fn.fid:
                if label[2] < len(args):
                    s, e = args[label[2]]
                    value = self.taint(s, e, scope)
                    out |= Taint.read_of(value) if label[0] == "R" else value
            else:
                out.add(label)
        return out

    def _registry_template(self, k: int) -> bool:
        """Whether the registry host at string `k` begins a package tarball URL: `/-/` and `.tgz`
        further along the same template or concatenation. Its literal parts are kept
        (`registry_parts`)."""
        end = self.match[k - 1] if self.is_p(k - 1, "(") and self.match[k - 1] > k else -1
        if end < 0:
            end = self.expr_end(k)
        parts = [
            str(self.t[i].value) for i in range(k, min(end, k + 60)) if self.t[i].kind == "str"
        ]
        if any("/-/" in p for p in parts) and any(".tgz" in p for p in parts):
            self.registry_parts.update(parts)
            return True
        return False

    @staticmethod
    def promise_key(k: int) -> tuple[int, str]:
        """The value of the `new Promise(...)` at token `k`, as a name no scope declares."""
        return (-1_000_000 - k, "Promise")
