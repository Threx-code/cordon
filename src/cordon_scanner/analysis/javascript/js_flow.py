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

import bisect
import re
from contextlib import suppress
from dataclasses import dataclass, field
from typing import ClassVar, Final

from cordon_scanner.analysis.javascript.js_eval import JsEval, Tok

#: Files above this are not analysed: bundles of that size are third-party code concatenated, and
#: the analysis is linear but not free.
MAX_BYTES: Final = 1_500_000
#: Fixpoint rounds over the bindings and summaries. Each round follows one more hop; real chains
#: are a handful deep, and the bound keeps a pathological file linear.
MAX_ROUNDS: Final = 8
#: Parameter labels one binding may carry (see `_Analysis._grow`).
MAX_PARAMETER_LABELS: Final = 24

_KEYWORDS: Final = frozenset(
    [
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "default",
        "delete",
        "do",
        "else",
        "export",
        "extends",
        "finally",
        "for",
        "function",
        "if",
        "import",
        "in",
        "instanceof",
        "let",
        "new",
        "return",
        "super",
        "switch",
        "this",
        "throw",
        "try",
        "typeof",
        "var",
        "void",
        "while",
        "with",
        "yield",
        "async",
        "await",
        "of",
        "static",
        "get",
        "set",
        "null",
        "true",
        "false",
        "undefined",
        "from",
        "as",
    ]
)
_DECLARE: Final = frozenset({"const", "let", "var"})
_OPEN: Final = {"(": ")", "[": "]", "{": "}"}
_CLOSE: Final = frozenset(_OPEN.values())

# -- sources ------------------------------------------------------------------------------------

#: A string naming a credential store: a path component or file only secrets live in.
_SECRET_PATH: Final = re.compile(
    r"\.ssh\b|id_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws[/\\\\]|\.aws$|aws[/\\\\]credentials|\.npmrc\b"
    r"|\.pypirc\b|\.git-credentials\b|\.netrc\b|\.docker[/\\\\]config\.json|\.kube[/\\\\]config"
    r"|\.config[/\\\\]gcloud|application_default_credentials|Login Data|Local State|Cookies$"
    r"|Local Storage[/\\\\]leveldb|\bleveldb\b|wallet\.dat|\bkeystore\b|Exodus|Electrum|atomic[/\\\\]"
    r"|solana[/\\\\]id\.json|\.config[/\\\\]solana|nkbihfbeogaeaoehlefnkodbefgpgknn|Keychains?\b"
    r"|\.bash_history|\.zsh_history|/etc/passwd|/etc/shadow|\.gnupg|\.password-store|keychain-db"
    r"|Telegram Desktop|tdata\b|discord[/\\\\]Local Storage|\.config[/\\\\]gh[/\\\\]hosts",
    re.I,
)
_FS_READ: Final = frozenset(
    {"readFileSync", "readFile", "createReadStream", "readdirSync", "readdir", "openSync"}
)
#: Who and where this machine is. Not `homedir` (it builds paths) nor `platform`/`arch` (every
#: installer that picks a binary reads them).
_IDENTITY: Final = frozenset({"hostname", "userInfo", "networkInterfaces"})
_WALLET_MEMBER: Final = re.compile(
    r"^(?:privateKey|private_key|secretKey|secret_key|mnemonic|mnemonicPhrase|seedPhrase|seed_phrase"
    r"|_privateKey|_signingKey|signingKey|exportPrivateKey|keystore)$"
)
_WALLET_PARAM: Final = re.compile(
    r"^(?:privateKey|private_key|privKey|privkey|pk|secretKey|secret_key|sk|mnemonic|mnemonicPhrase"
    r"|seed|seedPhrase|seed_phrase|phrase|recoveryPhrase|wif)$",
    re.I,
)
_BROWSER: Final = frozenset({"cookie", "localStorage", "sessionStorage"})

# -- sinks --------------------------------------------------------------------------------------

#: Modules whose default export or members send a request.
_REQUEST_MODULES: Final = frozenset(
    {
        "axios",
        "node-fetch",
        "got",
        "request",
        "superagent",
        "needle",
        "undici",
        "cross-fetch",
        "isomorphic-fetch",
        "ky",
        "phin",
        "centra",
        "bent",
        "make-fetch-happen",
        "ofetch",
    }
)
_CONNECTION_MODULES: Final = frozenset({"http", "https", "http2", "net", "tls", "dgram"})
_DNS_MODULES: Final = frozenset({"dns", "dns/promises"})
_PROCESS_MODULES: Final = frozenset({"child_process"})
_REQUEST_METHODS: Final = frozenset(
    {"get", "post", "put", "patch", "delete", "request", "head", "fetch", "send", "options"}
)
_CONNECTION_OPEN: Final = frozenset(
    {"request", "get", "connect", "createConnection", "createSocket"}
)
_CONNECTION_SEND: Final = frozenset({"write", "end", "send"})
_PROCESS_CALL: Final = frozenset(
    {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
)
_DNS_CALL: Final = frozenset(
    {"lookup", "resolve", "resolve4", "resolve6", "resolveTxt", "resolveAny", "resolveCname"}
)
_STORE_METHODS: Final = frozenset({"push", "unshift", "set", "append", "add", "concat"})
_VM_RUN: Final = frozenset(
    {"runInContext", "runInNewContext", "runInThisContext", "compileFunction"}
)

_RAW_IP: Final = re.compile(
    r"^(?:https?|wss?)://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/|$)"
)
_URL: Final = re.compile(
    r"^(?:https?|wss?)://(?:[^@/\s]{1,200}@)?([^/:?#\s]+)(?::\d+)?([^?#\s]*)", re.I
)


@dataclass(frozen=True)
class Flow:
    """One source kind's value reaching a sink."""

    sources: frozenset[str]
    sink: str  # request | connection | dns | process
    host: str | None
    destination: str  # drop | ip | fixed | unknown
    line: int


@dataclass
class _Fn:
    fid: int
    params: list[str]
    start: int  # first token of the body (or of the expression body)
    end: int  # one past its last token
    expression_body: bool
    name: str | None = None
    ret: set[object] = field(default_factory=set)
    #: ("P" | "R", parameter index) -> sinks it reaches: the parameter itself, or a file read at it.
    sinks: dict[tuple[str, int], set[tuple[str, str | None, str, int]]] = field(
        default_factory=dict
    )


class _OverBudget(Exception):
    """The file's analysis used its work budget; what was found so far stands."""


Label = (
    object  # a source kind (str), a parameter ("P", fid, i), or a file read at one ("R", fid, i)
)


class JsFlow:
    """`flows(text)`: the source-to-sink flows in one JavaScript file."""

    SOURCES: ClassVar[tuple[str, ...]] = (
        "secret_file",
        "home_file",
        "network_response",
        "environment",
        "identity",
        "browser",
        "clipboard",
        "wallet_key",
    )

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

    @classmethod
    def flows(cls, text: str) -> list[Flow]:
        if len(text) > MAX_BYTES:
            return []
        try:
            return _Analysis(text).run()
        except RecursionError:
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


class _Analysis:
    def __init__(self, text: str) -> None:
        self.text = text
        self.t: list[Tok] = JsEval.tokens(text)
        self.n = len(self.t)
        self.newlines = [i for i, c in enumerate(text) if c == "\n"]
        self.match = self._brackets()
        self.fns: list[_Fn] = []
        self.scope_at: list[int] = []
        self.declared: dict[int, set[str]] = {}
        self.parent: dict[int, int] = {}
        self.vars: dict[tuple[int, str], set[Label]] = {}
        self.aliases: dict[str, str] = {}  # local name -> "module" or "module.member"
        self.connections: set[tuple[int, str]] = set()  # names bound to an open connection
        self.flows: dict[tuple[int, str], Flow] = {}
        self.fn_by_name: dict[tuple[int, str], int] = {}
        self.fn_at_token: dict[int, int] = {}
        #: Range taints are cached until any binding or return value grows.
        self.version = 0
        #: Work done (label growth and range evaluations), bounded so no file can run long.
        self.work = 0
        self.budget = 8 * self.n + 100_000
        self._args_cache: dict[int, list[tuple[int, int]]] = {}
        self._file_destination: tuple[str | None, str] | None = None
        self._cache: dict[tuple[int, int, int], tuple[int, set[Label]]] = {}
        self._compiled: dict[
            tuple[int, int, int],
            tuple[
                frozenset[Label],
                tuple[tuple[int, str], ...],
                tuple[tuple[int, int], ...],
                tuple[tuple[int, int], ...],
            ],
        ] = {}

    # -- structure -------------------------------------------------------------------------------

    def _brackets(self) -> list[int]:
        match = [-1] * self.n
        stack: list[int] = []
        for i, tok in enumerate(self.t):
            if tok.kind != "punct":
                continue
            if tok.value in _OPEN:
                stack.append(i)
            elif tok.value in _CLOSE and stack:
                j = stack.pop()
                match[i], match[j] = j, i
        return match

    def line(self, i: int) -> int:
        return bisect.bisect_right(self.newlines, self.t[min(i, self.n - 1)].start) + 1

    def is_p(self, i: int, value: str) -> bool:
        return 0 <= i < self.n and self.t[i].kind == "punct" and self.t[i].value == value

    def is_name(self, i: int, value: str | None = None) -> bool:
        return (
            0 <= i < self.n
            and self.t[i].kind == "name"
            and (value is None or self.t[i].value == value)
        )

    def _new_line_between(self, i: int, j: int) -> bool:
        return "\n" in self.text[self.t[i].end : self.t[j].start]

    def expr_end(self, j: int) -> int:
        """One past the last token of the expression starting at `j` (statement-level)."""
        k = j
        while k < self.n:
            tok = self.t[k]
            if tok.kind == "punct":
                if tok.value in _OPEN:
                    close = self.match[k]
                    if close < 0:
                        return k  # unbalanced: the expression is not known to go further
                    k = close + 1
                    continue
                if tok.value in (";", ",") or tok.value in _CLOSE:
                    return k
            if k > j and self._asi(k):
                return k
            k += 1
        return k

    def _asi(self, k: int) -> bool:
        """A line break that ends the previous statement (automatic semicolon insertion)."""
        prev, tok = self.t[k - 1], self.t[k]
        if not self._new_line_between(k - 1, k):
            return False
        ends = prev.kind in ("name", "str", "num") or (
            prev.kind == "punct" and prev.value in (")", "]", "}", "++", "--")
        )
        if not ends or (
            prev.kind == "name"
            and prev.value in _KEYWORDS - {"this", "null", "true", "false", "undefined"}
        ):
            return False
        if tok.kind == "punct":
            return tok.value in ("++", "--", "!", "~")
        return tok.kind in ("name", "str", "num") and tok.value not in ("in", "of", "instanceof")

    def _params(self, open_i: int) -> list[str]:
        close = self.match[open_i]
        names: list[str] = []
        depth = 0
        k = open_i + 1
        while k < close:
            tok = self.t[k]
            if tok.kind == "punct" and tok.value in _OPEN:
                depth += 1
            elif tok.kind == "punct" and tok.value in _CLOSE:
                depth -= 1
            elif tok.kind == "punct" and tok.value == "=" and depth == 0:
                k = self.expr_end(k + 1)
                continue
            elif tok.kind == "name" and tok.value not in _KEYWORDS and not self.is_p(k + 1, ":"):
                names.append(tok.value)
            k += 1
        return names

    def _find_functions(self) -> None:
        t, n = self.t, self.n
        for i in range(n):
            tok = t[i]
            fn: _Fn | None = None
            if tok.kind == "name" and tok.value == "function":
                k = i + 1
                if self.is_p(k, "*"):
                    k += 1
                name = None
                if self.is_name(k):
                    name, k = t[k].value, k + 1
                if self.is_p(k, "(") and self.match[k] > 0 and self.is_p(self.match[k] + 1, "{"):
                    body = self.match[k] + 1
                    if self.match[body] > 0:
                        fn = _Fn(
                            len(self.fns) + 1,
                            self._params(k),
                            body + 1,
                            self.match[body],
                            False,
                            name,
                        )
                        self.fn_at_token[i] = fn.fid
            elif tok.kind == "punct" and tok.value == "=>":
                p = i - 1
                if self.is_p(p, ")") and self.match[p] >= 0:
                    params = self._params(self.match[p])
                    head = self.match[p]
                elif self.is_name(p):
                    params, head = [t[p].value], p
                else:
                    continue
                if self.is_name(head - 1, "async"):
                    head -= 1
                if self.is_p(i + 1, "{") and self.match[i + 1] > 0:
                    fn = _Fn(len(self.fns) + 1, params, i + 2, self.match[i + 1], False)
                else:
                    fn = _Fn(len(self.fns) + 1, params, i + 1, self.expr_end(i + 1), True)
                self.fn_at_token[head] = fn.fid
            elif (
                tok.kind == "name"
                and tok.value not in _KEYWORDS
                and self.is_p(i + 1, "(")
                and self.match[i + 1] > 0
                and self.is_p(self.match[i + 1] + 1, "{")
                and (
                    i == 0
                    or (t[i - 1].kind == "punct" and t[i - 1].value in ("{", "}", ",", ";", "*"))
                    or self.is_name(i - 1, "async")
                    or self.is_name(i - 1, "static")
                    or self.is_name(i - 1, "get")
                    or self.is_name(i - 1, "set")
                )
            ):
                body = self.match[i + 1] + 1
                if self.match[body] > 0:
                    fn = _Fn(
                        len(self.fns) + 1,
                        self._params(i + 1),
                        body + 1,
                        self.match[body],
                        False,
                        tok.value,
                    )
                    self.fn_at_token[i] = fn.fid
            if fn is not None:
                self.fns.append(fn)

    def _scopes(self) -> None:
        self.scope_at = [0] * self.n
        for fn in sorted(self.fns, key=lambda f: f.start - f.end):  # widest first
            outer = self.scope_at[fn.start] if fn.start < self.n else 0
            self.parent[fn.fid] = outer
            for k in range(fn.start, min(fn.end, self.n)):
                self.scope_at[k] = fn.fid
        self.declared = {0: set()}
        for fn in self.fns:
            self.declared.setdefault(fn.fid, set()).update(fn.params)
            for idx, p in enumerate(fn.params):
                self.vars[(fn.fid, p)] = {("P", fn.fid, idx)}

    def scope_of(self, i: int) -> int:
        return self.scope_at[i] if 0 <= i < self.n else 0

    def resolve(self, name: str, scope: int) -> tuple[int, str]:
        s = scope
        seen = 0
        while s and seen < 200:
            if name in self.declared.get(s, ()):
                return (s, name)
            s = self.parent.get(s, 0)
            seen += 1
        return (0, name)

    # -- bindings --------------------------------------------------------------------------------

    def _bindings(self) -> list[tuple[list[tuple[int, str]], int, int]]:
        """(targets, rhs_start, rhs_end): every binding site, with the names it writes."""
        t, out = self.t, []
        for i in range(self.n):
            tok = t[i]
            if tok.kind == "name" and tok.value in _DECLARE:
                k = i + 1
                while k < self.n:
                    scope = self.scope_of(k)
                    if self.is_name(k) and t[k].value not in _KEYWORDS:
                        targets = [t[k].value]
                        k += 1
                    elif self.is_p(k, "{") or self.is_p(k, "["):
                        close = self.match[k]
                        if close < 0:
                            break
                        targets = [
                            t[m].value
                            for m in range(k + 1, close)
                            if t[m].kind == "name"
                            and t[m].value not in _KEYWORDS
                            and not self.is_p(m + 1, ":")
                        ]
                        k = close + 1
                    else:
                        break
                    self.declared.setdefault(scope, set()).update(targets)
                    if self.is_p(k, "=") or (self.is_name(k, "of") or self.is_name(k, "in")):
                        end = self.expr_end(k + 1)
                        out.append(([(scope, x) for x in targets], k + 1, end))
                        k = end
                    if self.is_p(k, ","):
                        k += 1
                        continue
                    break
            elif tok.kind == "punct" and tok.value in ("=", "+=", "||=", "??="):
                if i == 0 or t[i - 1].kind not in ("name", "punct"):
                    continue
                base = self._assign_base(i - 1)
                if base is None:
                    continue
                scope = self.scope_of(i)
                out.append(([self.resolve(base, scope)], i + 1, self.expr_end(i + 1)))
            elif tok.kind == "name" and tok.value == "function" and self.is_name(i + 1):
                self.declared.setdefault(self.scope_of(i), set()).add(t[i + 1].value)
        return out

    def _assign_base(self, k: int) -> str | None:
        """The name at the root of an assignment target ending at token `k`: `a`, `a.b.c`, `a[x]`."""
        while k >= 0:
            tok = self.t[k]
            if tok.kind == "punct" and tok.value == "]" and self.match[k] >= 0:
                k = self.match[k] - 1
                continue
            if tok.kind == "name":
                if self.is_p(k - 1, "."):
                    k -= 2
                    continue
                return None if tok.value in _KEYWORDS and tok.value != "this" else tok.value
            return None
        return None

    def _modules(self) -> None:
        """`const h = require("https")`, `import axios from "axios"`, `const {request} = require(...)`."""
        t = self.t
        for i in range(self.n):
            if (
                self.is_name(i, "require")
                and self.is_p(i + 1, "(")
                and i + 2 < self.n
                and t[i + 2].kind == "str"
            ):
                module = str(t[i + 2].value).removeprefix("node:")
                k = i - 1
                member = None
                if self.is_p(i + 4, ".") and self.is_name(i + 5):
                    member = t[i + 5].value
                if self.is_p(k, "="):
                    k -= 1
                    if self.is_name(k):
                        self.aliases[t[k].value] = module + (f".{member}" if member else "")
                    elif self.is_p(k, "}") and self.match[k] >= 0:
                        self._destructured(self.match[k], k, module)
            elif self.is_name(i, "import") and not self.is_p(i + 1, "("):
                k = i + 1
                end = min(self.n, i + 200)
                while k < end and not self.is_name(k, "from"):
                    k += 1
                if k + 1 < self.n and t[k + 1].kind == "str":
                    module = str(t[k + 1].value).removeprefix("node:")
                    j = i + 1
                    if self.is_name(j) and t[j].value not in _KEYWORDS:
                        self.aliases[t[j].value] = module
                    for m in range(i + 1, k):
                        if self.is_name(m, "as") and self.is_name(m + 1):
                            prev = t[m - 1]
                            self.aliases[t[m + 1].value] = (
                                module
                                if prev.kind == "punct" and prev.value == "*"
                                else f"{module}.{prev.value}"
                            )
                    for m in range(i + 1, k):
                        if self.is_p(m, "{") and self.match[m] > 0:
                            self._destructured(m, self.match[m], module)

    def _destructured(self, open_i: int, close_i: int, module: str) -> None:
        t = self.t
        for m in range(open_i + 1, close_i):
            if t[m].kind != "name" or t[m].value in _KEYWORDS:
                continue
            if (self.is_p(m + 1, ":") or self.is_name(m + 1, "as")) and self.is_name(m + 2):
                self.aliases[t[m + 2].value] = f"{module}.{t[m].value}"
            elif not self.is_p(m - 1, ":") and not self.is_name(m - 1, "as"):
                self.aliases[t[m].value] = f"{module}.{t[m].value}"

    def _chain(self, i: int) -> tuple[list[str], int]:
        """The dotted callee ending at token `i` (`a.b.c` -> ["a","b","c"]) and its first token."""
        parts = [str(self.t[i].value)]
        k = i
        while self.is_p(k - 1, ".") and self.is_name(k - 2):
            parts.append(str(self.t[k - 2].value))
            k -= 2
        if self.is_p(k - 1, "?.") and self.is_name(k - 2):
            parts.append(str(self.t[k - 2].value))
            k -= 2
        # `require("axios").post(...)`: the module itself, inline.
        if (
            self.is_p(k - 1, ".")
            and self.is_p(k - 2, ")")
            and self.match[k - 2] >= 3
            and self.is_name(self.match[k - 2] - 1, "require")
            and self.t[self.match[k - 2] + 1].kind == "str"
        ):
            parts.append(str(self.t[self.match[k - 2] + 1].value).removeprefix("node:"))
            k = self.match[k - 2] - 1
        parts.reverse()
        if parts and parts[0] in self.aliases:
            parts = (
                self.aliases[parts[0]].split(".", 1)[:1]
                + (
                    self.aliases[parts[0]].split(".", 1)[1:]
                    if "." in self.aliases[parts[0]]
                    else []
                )
                + parts[1:]
            )
        return parts, k

    # -- taint ------------------------------------------------------------------------------------

    def _facts(self) -> None:
        """What each token contributes to a value, decided once: the rounds only look these up."""
        t = self.t
        self.fact: list[tuple[str, object] | None] = [None] * self.n
        for k in range(self.n):
            tok = t[k]
            if tok.kind == "str":
                if _SECRET_PATH.search(str(tok.value)):
                    self.fact[k] = ("src", "secret_path")
                elif str(tok.value).startswith(("~/", "~\\")) or str(tok.value) in (
                    "~",
                    "HOME",
                    "USERPROFILE",
                ):
                    self.fact[k] = ("src", "home_path")
            elif tok.kind == "name":
                v = str(tok.value)
                if self.is_p(k - 1, ".") or self.is_p(k - 1, "?."):
                    if (
                        self.is_p(k + 1, "(")
                        and self.match[k + 1] > 0
                        and self._sink_kind(k, self.scope_of(k)) == "request"
                    ):
                        self.fact[k] = ("src", "network_response")  # `axios.get(...)`'s value
                    elif _WALLET_MEMBER.match(v):
                        self.fact[k] = ("src", "wallet_key")
                    elif (
                        v in _BROWSER
                        and k >= 2
                        and str(t[k - 2].value) in ("document", "window", "globalThis")
                    ):
                        self.fact[k] = ("src", "browser")
                    elif (
                        v == "env"
                        and self.is_name(k - 2, "process")
                        and not (
                            self.is_p(k + 1, ".") or self.is_p(k + 1, "[") or self.is_p(k + 1, "?.")
                        )
                    ):
                        if not (self.is_p(k - 4, "(") and self.is_name(k - 5, "keys")):
                            self.fact[k] = ("src", "environment")
                    elif v in _IDENTITY and self.is_p(k + 1, "(") and self._chain(k)[0][0] == "os":
                        self.fact[k] = ("src", "identity")
                    elif v == "homedir" and self.is_p(k + 1, "(") and self._chain(k)[0][0] == "os":
                        # Not a source: a path. Reading a file under it is (see `JsFlow.read_of`).
                        self.fact[k] = ("src", "home_path")
                    elif v in ("HOME", "USERPROFILE") and self.is_name(k - 2, "env"):
                        self.fact[k] = ("src", "home_path")
                    elif v in _FS_READ and self.is_p(k + 1, "(") and self.match[k + 1] > 0:
                        self.fact[k] = ("read", self.match[k + 1])
                    elif (
                        v in ("readText", "read")
                        and k >= 2
                        and str(t[k - 2].value) in ("clipboard", "clipboardy")
                    ):
                        self.fact[k] = ("src", "clipboard")
                elif v in _BROWSER and v != "cookie" and self.is_p(k + 1, "."):
                    self.fact[k] = ("src", "browser")
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
                    elif self.is_p(k + 1, "(") and self.match[k + 1] > 0:
                        self.fact[k] = ("call", v)
                    else:
                        self.fact[k] = ("ref", v)

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
                else:
                    resolved = self.resolve(str(v), scope)
                    target = self.fn_by_name.get(resolved) if what == "call" else None
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
            out |= JsFlow.read_of(self.taint(k + 2, close, scope))
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
                    out |= JsFlow.read_of(value) if label[0] == "R" else value
            else:
                out.add(label)
        return out

    def _args(self, open_i: int) -> list[tuple[int, int]]:
        got = self._args_cache.get(open_i)
        if got is None:
            got = self._args_cache[open_i] = self._split_args(open_i)
        return got

    def _split_args(self, open_i: int) -> list[tuple[int, int]]:
        close = self.match[open_i]
        if close < 0:
            return []
        out, k = [], open_i + 1
        start = k
        while k < close:
            if self.t[k].kind == "punct" and self.t[k].value in _OPEN and self.match[k] > 0:
                k = self.match[k] + 1
                continue
            if self.is_p(k, ","):
                out.append((start, k))
                start = k + 1
            k += 1
        if start < close:
            out.append((start, close))
        return out

    # -- sinks -----------------------------------------------------------------------------------

    def _sink_kind(self, k: int, scope: int) -> str | None:
        """The kind of sink a call at name token `k` is, if any."""
        parts, _ = self._chain(k)
        root, last = parts[0], parts[-1]
        if root == "vm" and (last in _VM_RUN or (last == "Script" and self.is_name(k - 3, "new"))):
            return "execute"
        if len(parts) == 1:
            if last == "eval" or (last == "Function" and not self.is_p(k - 1, ".")):
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
            return "connection"
        if root in _DNS_MODULES and last in _DNS_CALL:
            return "dns"
        if root in _PROCESS_MODULES and last in _PROCESS_CALL:
            return "process"
        if (
            len(parts) == 2
            and last in _CONNECTION_SEND
            and self.resolve(root, scope) in self.connections
        ):
            return "request"
        if parts[:2] == ["navigator", "sendBeacon"] or (
            root in ("$", "jQuery") and last in ("ajax", "post", "get")
        ):
            return "request"
        if len(parts) >= 2 and parts[-2] in ("http", "https") and last in ("request", "get"):
            return "connection"
        return None

    @staticmethod
    def classify(url: str) -> tuple[str | None, str]:
        """(host, kind) of a URL: `drop` for a webhook, paste, tunnel or out-of-band interaction
        service (`intel/hosts.py`, the same lists the manifest and egress rules use), `ip` for a
        bare address, `fixed` for any other host the file names; (None, "unknown") when the
        string is not a URL at all."""
        from cordon_scanner.intel.malware.hosts import ALL_HOSTS, INTERACTION_HOSTS

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
                host, kind = _Analysis.classify(str(tok.value))
                if host is not None:
                    return (host, kind)
        return (None, "unknown")

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
        self._modules()
        self._facts()
        bindings = self._bindings()
        for fn in self.fns:
            if fn.name:
                self.fn_by_name.setdefault(
                    self.resolve(fn.name, self.parent.get(fn.fid, 0)), fn.fid
                )
        for targets, s, e in bindings:
            if e - s >= 1 and len(targets) == 1:
                fid = self.fn_at_token.get(s) or (
                    self.fn_at_token.get(s + 1) if self.is_name(s, "async") else None
                )
                if fid is not None:
                    self.fn_by_name.setdefault(targets[0], fid)
                    self.fns[fid - 1].name = self.fns[fid - 1].name or targets[0][1]
                if self._opens_connection(s, e):
                    self.connections.add(targets[0])
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

    def _opens_connection(self, s: int, e: int) -> bool:
        for k in range(s, min(e, s + 40)):
            if self.t[k].kind == "name" and self.is_p(k + 1, "("):
                kind = self._sink_kind(k, self.scope_of(k))
                if kind == "connection":
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
                base = parts[0] if parts[0] not in self.aliases else None
                rest = args
            if base:
                value = set().union(*(self.taint(s, e, scope) for s, e in rest)) if rest else set()
                target = self.resolve(base, scope)
                changed |= self._grow(self.vars.setdefault(target, set()), value)
        # Callbacks get what the call works on: its receiver and its other arguments.
        callbacks = [
            (i, self.fn_at_token.get(s) or self.fn_at_token.get(s + 1))
            for i, (s, _) in enumerate(args)
        ]
        callbacks = [(i, fid) for i, fid in callbacks if fid]
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
            if self._sink_kind(k, scope) in ("request", "connection"):
                # `https.get(url, res => ...)`: the callback is handed the server's answer.
                given.add("network_response")
            for _, fid in callbacks:
                fn = self.fns[fid - 1]
                for p in fn.params:
                    changed |= self._grow(self.vars.setdefault((fid, p), set()), given)
        # A known function: its sinks apply to the arguments given here.
        target = self.fn_by_name.get(self.resolve(name, scope)) if len(parts) == 1 else None
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
        # A sink.
        kind = self._sink_kind(k, scope)
        if kind is not None and args:
            value = set().union(*(self.taint(s, e, scope) for s, e in args))
            if kind == "connection":
                # Opening a connection sends its options (host, path, headers); the body follows
                # through `.write`/`.end` on the bound name.
                pass
            host, dest = self._destination(open_i, self.match[open_i])
            if dest == "unknown":
                host, dest = self._bound_destination(scope)
            changed |= self._record(value, kind, host, dest, self.line(k), scope)
        return changed

    def _receiver_taint(self, first: int, k: int, scope: int) -> set[Label]:
        """The taint of what a method is called on: `read(p)` in `read(p).then(...)`, `x` in `x.on(...)`."""
        end = first  # tokens before the dotted callee
        parts_end = k - 1  # the `.` before the method
        start = first
        if self.is_p(start - 1, ")") and self.match[start - 1] >= 0:
            start = self.match[start - 1]
            if self.is_name(start - 1):
                _, start = self._chain(start - 1)
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
