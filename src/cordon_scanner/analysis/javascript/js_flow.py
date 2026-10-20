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
#: Sockets below HTTP: what is written to one goes out as it is, to whatever listens -- the
#: `connection` sink the raw-channel rules read, where an HTTP request is a `request`.
_RAW_SOCKET_MODULES: Final = frozenset({"net", "tls", "dgram"})
#: A host on this machine, as a socket's own argument: `net.createConnection(port, "127.0.0.1")`
#: (a browser's DevTools port) reaches nothing outside it.
_LOOPBACK: Final = re.compile(r"(?:localhost|127(?:\.\d{1,3}){3}|::1|\[::1\])\Z", re.I)
#: The runtime's own objects: a member stored into one is not a value the file built
#: (`_Analysis._assign_base`). `window`, `globalThis` and `module` are not among them -- a file
#: keeps its own values there.
_HOST_OBJECTS: Final = frozenset(
    {"process", "console", "Math", "JSON", "Reflect", "Symbol", "Promise", "Number", "String"}
    | {"Boolean", "Date", "Error", "Buffer", "Intl"}
)
#: A command that hands its operand to the desktop's handler for it -- a URL to the browser
#: (`_Analysis._opener`). `open -a <browser>` too, but not with a terminal or a script runner
#: named: `open -a Terminal x.command` runs it.
_OPENER: Final = re.compile(
    r"\s*(?:open(?!\s+-[ab]\s+\"?(?:Terminal|iTerm|Script\s?Editor|Automator|Warp|Alacritty"
    r"|kitty|Hyper|Ghostty|osascript)\b)|xdg-open|gio\s+open|wslview|sensible-browser|x-www-browser"
    r'|start\s+""|cmd(?:\.exe)?\s+/c\s+start\s+""|rundll32(?:\.exe)?\s+url\.dll,FileProtocolHandler'
    r"|explorer(?:\.exe)?)(?:\s|\"|$)",
    re.I,
)
#: Keywords only in context, ordinary names as a method's own name (`_Analysis._find_functions`).
_CONTEXTUAL: Final = frozenset({"get", "set", "of", "from", "as", "async", "static"})
#: The public npm registries' own hosts, at the start of a URL (`_Analysis._registry_template`).
_REGISTRY_URL: Final = re.compile(
    r"https?://(?:registry\.npmjs\.org|registry\.yarnpkg\.com|registry\.npmmirror\.com)/"
)
#: What a messaging client sends with (`_Analysis._opens_bot`): a message, a file, a mail.
_BOT_SEND: Final = frozenset(
    {"sendMessage", "sendDocument", "sendPhoto", "sendAudio", "sendVideo", "sendMediaGroup"}
    | {"sendMail", "send", "editMessageText"}
)
#: Commands that print who and where this machine is (`_Analysis._identity_command`): their
#: output is the `identity` source `os.hostname()` and `os.userInfo()` are.
_IDENTITY_COMMAND: Final = re.compile(
    r"\s*(?:whoami|hostname|uname|id|ipconfig|ifconfig|systeminfo|scutil\s+--get"
    r"|ip\s+(?:a|addr|address|route)|wmic\s+(?:computersystem|os|nic)|echo\s+(?:%username%|\$USER)"
    r"|cat\s+/etc/(?:hostname|passwd|os-release))\b",
    re.I,
)
#: TypeScript's member and parameter-property modifiers (`private async load(): Promise<void>`).
_TS_MODIFIERS: Final = frozenset({"private", "public", "protected", "override", "readonly"})
#: Options naming where a connection goes rather than what it sends (`_Analysis._sent`).
_DESTINATION_KEYS: Final = frozenset({"host", "hostname", "localAddress", "port"})
_PROCESS_CALL: Final = frozenset(
    {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
)
_DNS_CALL: Final = frozenset(
    {"lookup", "resolve", "resolve4", "resolve6", "resolveTxt", "resolveAny", "resolveCname"}
)
#: What TypeScript, Babel and esbuild wrap a `require` in when they compile an `import`.
_IMPORT_HELPERS: Final = frozenset(
    {
        "__importDefault",
        "__importStar",
        "__toESM",
        "_interopRequireDefault",
        "_interopRequireWildcard",
    }
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
    sink: str  # request | connection | dns | process | open | execute
    host: str | None
    destination: str  # drop | ip | fixed | unknown
    line: int


@dataclass(frozen=True)
class Request:
    """One request a file makes, by the URL that reaches it (`JsFlow.requests`)."""

    line: int
    #: registry: a registry tarball URL (`registry.npmjs.org/<pkg>/-/<name>-<ver>.tgz`); redirect:
    #: a URL a response gave (a `Location` header); other: anything else, a literal host included.
    #: A helper's parameter is resolved through every call of the helper in the file.
    kind: str
    #: The literal parts of the file's registry tarball URLs (`@esbuild/` in
    #: `${pkg.replace("@esbuild/", "")}`), for matching against the package's own manifest.
    parts: tuple[str, ...] = ()


@dataclass
class _Fn:
    fid: int
    params: list[str]
    start: int  # first token of the body (or of the expression body)
    end: int  # one past its last token
    expression_body: bool
    name: str | None = None
    #: An arrow function: its `this` is the enclosing function's.
    arrow: bool = False
    #: A method written in a class body (`load() {...}`): its `this` is that class's instance.
    method: bool = False
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


class _Analysis:
    def __init__(self, text: str) -> None:
        self.text = text
        self.t: list[Tok] = _Analysis._uncomma(JsEval.tokens(text, templates=True))
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
        self.raw_connections: set[tuple[int, str]] = set()  # ... to a raw socket among them
        self.bound: dict[tuple[int, str], list[tuple[int, int]]] = {}  # name -> what it is bound to
        self.instance_of: dict[tuple[int, str], int] = {}  # name bound to `new C()` -> C
        #: names bound to a messaging client -> (host, destination kind) of what it sends to
        self.bot_clients: dict[tuple[int, str], tuple[str | None, str]] = {}
        self.registry_parts: set[str] = set()  # literal parts of registry tarball URLs
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

    @staticmethod
    def _uncomma(t: list[Tok]) -> list[Tok]:
        """`(0, os_1.hostname)(...)` -- how TypeScript and Babel call an imported function -- read
        as the call it is, `os_1.hostname(...)`: the parenthesis, `0` and comma are dropped."""
        drop: set[int] = set()
        for i in range(len(t) - 4):
            if not (
                t[i].kind == "punct"
                and t[i].value == "("
                and t[i + 1].kind == "num"
                and t[i + 1].value == 0
                and t[i + 2].kind == "punct"
                and t[i + 2].value == ","
                and t[i + 3].kind == "name"
            ):
                continue
            k = i + 3
            while k + 2 < len(t) and t[k + 1].value == "." and t[k + 2].kind == "name":
                k += 2
            if (
                k + 2 < len(t)
                and t[k + 1].kind == "punct"
                and t[k + 1].value == ")"
                and t[k + 2].kind == "punct"
                and t[k + 2].value == "("
            ):
                drop.update((i, i + 1, i + 2, k + 1))
        return [tok for i, tok in enumerate(t) if i not in drop] if drop else t

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
            elif tok.kind == "punct" and tok.value == ":" and depth == 0:
                # A TypeScript parameter type (`p: Record<string, any>`): no names in it. Read as
                # names, `any` became a parameter and every later one moved along.
                k = self._type_end(k + 1, close, (",", "="))
                continue
            elif (
                tok.kind == "name"
                and tok.value not in _KEYWORDS
                and not (depth == 0 and tok.value in _TS_MODIFIERS and self.is_name(k + 1))
                and (depth == 0 or not self.is_p(k + 1, ":"))
            ):
                names.append(tok.value)
            k += 1
        return names

    def _type_end(self, k: int, stop: int, ends: tuple[str, ...]) -> int:
        """Where a TypeScript type starting at `k` ends: the first of `ends` outside its brackets
        and angle brackets, or `stop`. An object type before a body (`): { a: T } {`) is part of
        the type."""
        angle = 0
        while k < stop:
            tok = self.t[k]
            if tok.kind == "punct":
                v = str(tok.value)
                if v == "<":
                    angle += 1
                elif v in (">", ">>", ">>>"):
                    angle = max(0, angle - len(v))
                elif (
                    angle == 0
                    and v in ends
                    and not (v == "{" and self.match[k] > 0 and self.is_p(self.match[k] + 1, "{"))
                ):
                    return k
                elif v in _OPEN and self.match[k] > 0:
                    k = self.match[k] + 1
                    continue
            k += 1
        return stop

    def _past_return_type(self, close: int) -> int:
        """The token after the parameter list closing at `close`, past a TypeScript return type
        (`): Promise<string> {`, `): void =>`): where the body or the `=>` is."""
        if not self.is_p(close + 1, ":"):
            return close + 1
        stop = min(self.n, close + 80)
        end = self._type_end(close + 2, stop, ("{", "=>", ";"))
        return end if end < stop and not self.is_p(end, ";") else close + 1

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
                if self.is_p(k, "<"):  # `function f<T>(...)`
                    k = self._type_end(k, min(n, k + 40), ("(",))
                if self.is_p(k, "(") and self.match[k] > 0:
                    body = self._past_return_type(self.match[k])
                    if self.is_p(body, "{") and self.match[body] > 0:
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
                if not self.is_p(p, ")"):
                    # `(a: T): Promise<R> => ...`: back past the return type to the parameters.
                    for j in range(i - 2, max(i - 60, 0), -1):
                        if self.is_p(j, ")") and self._past_return_type(j) == i:
                            p = j
                            break
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
                    fn = _Fn(len(self.fns) + 1, params, i + 2, self.match[i + 1], False, arrow=True)
                else:
                    fn = _Fn(
                        len(self.fns) + 1, params, i + 1, self.expr_end(i + 1), True, arrow=True
                    )
                self.fn_at_token[head] = fn.fid
            elif (
                tok.kind == "name"
                # A method may be named `get`, `set` or `from` (`set(key, value) {`): those are
                # keywords only before another name.
                and (tok.value not in _KEYWORDS or tok.value in _CONTEXTUAL)
                and self.is_p(i + 1, "(")
                and self.match[i + 1] > 0
                and self.is_p(self._past_return_type(self.match[i + 1]), "{")
                and (
                    i == 0
                    or (t[i - 1].kind == "punct" and t[i - 1].value in ("{", "}", ",", ";", "*"))
                    or self.is_name(i - 1, "async")
                    or self.is_name(i - 1, "static")
                    or self.is_name(i - 1, "get")
                    or self.is_name(i - 1, "set")
                    or (t[i - 1].kind == "name" and t[i - 1].value in _TS_MODIFIERS)
                )
            ):
                body = self._past_return_type(self.match[i + 1])
                if self.match[body] > 0:
                    fn = _Fn(
                        len(self.fns) + 1,
                        self._params(i + 1),
                        body + 1,
                        self.match[body],
                        False,
                        tok.value,
                        method=True,
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

    def _classes(self) -> None:
        """Each token's innermost class body (`class_at`, 0 for none) and the scope each class
        body sits in."""
        self.class_at = [0] * self.n
        self.class_scope: dict[int, int] = {}
        self.class_by_name: dict[str, int] = {}
        ambiguous: set[str] = set()
        spans: list[tuple[int, int]] = []
        for i in range(self.n):
            if not self.is_name(i, "class") or self.is_p(i - 1, "."):
                continue
            # `class Client`, or `var Client = class {...}` as bundlers write it.
            if self.is_name(i + 1) and self.t[i + 1].value != "extends":
                named: str | None = str(self.t[i + 1].value)
            elif self.is_p(i - 1, "=") and self.is_name(i - 2):
                named = str(self.t[i - 2].value)
            else:
                named = None
            k = i + 1
            while k < min(self.n, i + 200) and not self.is_p(k, "{"):
                if (
                    self.t[k].kind == "punct"
                    and self.t[k].value in ("(", "[")
                    and self.match[k] > 0
                ):
                    k = self.match[k]
                elif self.t[k].kind == "punct" and self.t[k].value in (";", ")", "}", "=>"):
                    break
                k += 1
            if self.is_p(k, "{") and self.match[k] > 0:
                spans.append((k, self.match[k]))
                if named:
                    # A name declared by more than one class is ambiguous: `C.m()` and `new C()`
                    # cannot be resolved to one of them. Minifiers reuse short class names across
                    # a bundle, so dispatching by such a name links unrelated code (review 98: a
                    # SheetJS-bundling extension's fetch reached a spawn through two classes that
                    # shared a mangled name). Only a name one class declares is dispatchable.
                    if named in self.class_by_name:
                        ambiguous.add(named)
                    else:
                        self.class_by_name[named] = len(spans)
        for name in ambiguous:
            self.class_by_name.pop(name, None)
        for c, (open_i, close) in sorted(
            enumerate(spans, 1), key=lambda item: item[1][0] - item[1][1]
        ):  # widest first, so an inner class wins
            self.class_scope[c] = self.scope_at[open_i]
            for k in range(open_i + 1, close):
                self.class_at[k] = c

    def this_of(self, scope: int) -> tuple[int, str]:
        """Whose `this` a function sees: in a class's method, or any function inside one, that
        class's instance (`(-class, "this")`); anywhere else the one file-wide `this` as before,
        so prototype-style code (`C.prototype.m = function () { this.x }`) still shares its
        fields. Any function inside, not only an arrow: compiled async methods run their body in
        `__awaiter(this, ..., function* () {...})`, whose `this` is the method's. One file-wide
        `this` for classes let a response one class stored reach every other class in a bundle
        (review 98 P1 A/B)."""
        s, seen = scope, 0
        while s and seen < 200:
            fn = self.fns[s - 1]
            if fn.method:
                c = self.class_at[fn.start] if fn.start < self.n else 0
                if c and self.class_scope.get(c) == self.parent.get(s, 0):
                    return (-c, "this")
            s, seen = self.parent.get(s, 0), seen + 1
        return (0, "this")

    def _on_class(self, k: int) -> bool:
        """Whether name token `k` is `m` in `C.m`, `C` a class of this file."""
        return (
            self.is_p(k - 1, ".")
            and self.is_name(k - 2)
            and not self.is_p(k - 3, ".")
            and str(self.t[k - 2].value) in self.class_by_name
        )

    def _static_call(self, k: int) -> int | None:
        """The method `C.m(...)` at name token `k` calls, when `C` is a class of this file."""
        if not self._on_class(k):
            return None
        c = self.class_by_name[str(self.t[k - 2].value)]
        return self.fn_by_name.get((-c, str(self.t[k].value)))

    def method_of(self, name: str, scope: int) -> int | None:
        """The function `this.name(...)` calls: the method of the caller's own class when it has
        one, otherwise the file-wide lookup."""
        owner = self.this_of(scope)
        if owner[0] < 0:
            return self.fn_by_name.get((owner[0], name))
        return self.fn_by_name.get(self.resolve(name, scope))

    def resolve(self, name: str, scope: int) -> tuple[int, str]:
        if name == "this":
            return self.this_of(scope)
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
                    if self.is_p(k, ":"):  # `const t: string = ...`: past the TypeScript type
                        k = self._type_end(k + 1, min(self.n, k + 80), ("=", ",", ";"))
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
        """The name at the root of an assignment target ending at token `k`: `a`, `a.b.c`, `a[x]`.
        None for a member of the runtime's own objects: `process.exitCode = ok ? 0 : 1` stores
        nothing the file reads back as `process.platform`, and taking `process` as the store let
        one response reach every child process the file starts (review 98 P1 A/B)."""
        end = k
        while k >= 0:
            tok = self.t[k]
            if tok.kind == "punct" and tok.value == "]" and self.match[k] >= 0:
                k = self.match[k] - 1
                continue
            if tok.kind == "name":
                if self.is_p(k - 1, "."):
                    k -= 2
                    continue
                if k != end and tok.value in _HOST_OBJECTS:
                    return None
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
                and self.match[i + 1] > i + 2
                # `require("child_" + "process")`: the name its literals spell.
                and (spelled := self._folded(i + 2, self.match[i + 1])) is not None
            ):
                module = spelled.removeprefix("node:")
                close = self.match[i + 1]
                k = i - 1
                if self.is_p(k, "(") and self.is_name(k - 1) and t[k - 1].value in _IMPORT_HELPERS:
                    k -= 2  # `os_1 = __importDefault(require("os"))`: the helper hands it back
                member = None
                if self.is_p(close + 1, ".") and self.is_name(close + 2):
                    member = t[close + 2].value
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
        # `const api = axios.create({...})`, `got.extend(...)`: an instance sends as the module does.
        for i in range(2, self.n - 3):
            if (
                self.is_p(i - 1, "=")
                and self.is_name(i - 2)
                and self.is_name(i)
                and self.is_p(i + 1, ".")
                and self.is_name(i + 2)
                and t[i + 2].value in ("create", "extend")
                and self.is_p(i + 3, "(")
            ):
                root = self.aliases.get(str(t[i].value), str(t[i].value)).split(".")[0]
                if root in _REQUEST_MODULES:
                    self.aliases[str(t[i - 2].value)] = root

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
            and self.match[k - 2] >= 1  # `require(` may open the file
            and self.is_name(self.match[k - 2] - 1, "require")
            and self.t[self.match[k - 2] + 1].kind == "str"
        ):
            parts.append(str(self.t[self.match[k - 2] + 1].value).removeprefix("node:"))
            k = self.match[k - 2] - 1
        parts.reverse()
        # A property of something that is not a name (`/re/.exec(line)`, `f().exec(x)`) is not
        # the import of that name: `exec` destructured from child_process made every regex's
        # `.exec` a command run.
        if (
            parts
            and parts[0] in self.aliases
            and not (self.is_p(k - 1, ".") or self.is_p(k - 1, "?."))
        ):
            parts = (
                self.aliases[parts[0]].split(".", 1)[:1]
                + (
                    self.aliases[parts[0]].split(".", 1)[1:]
                    if "." in self.aliases[parts[0]]
                    else []
                )
                + parts[1:]
            )
        if len(parts) > 2 and parts[1] == "default":
            del parts[1]  # `os_1.default.hostname`: a module's default export is the module
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
                elif _REGISTRY_URL.match(str(tok.value)) and self._registry_template(k):
                    # Not a source a rule reads: what tells a registry install's request apart.
                    self.fact[k] = ("src", "registry_url")
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
                    elif (
                        v in _FS_READ
                        and self.is_p(k + 1, "(")
                        and self.match[k + 1] > 0
                        and not self._opened_to_write(k)
                    ):
                        self.fact[k] = ("read", self.match[k + 1])
                    elif (
                        v in ("readText", "read")
                        and k >= 2
                        and str(t[k - 2].value) in ("clipboard", "clipboardy")
                    ):
                        self.fact[k] = ("src", "clipboard")
                    elif (
                        (self.is_name(k - 2, "this") or self._on_class(k))
                        and self.is_p(k + 1, "(")
                        and self.match[k + 1] > 0
                    ):
                        # A method of the same class, or a static one called on its class
                        # (`WorkerHost.start(p)`).
                        self.fact[k] = ("call", v)
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
                    elif self.is_p(k + 1, "(") and self.match[k + 1] > 0:
                        self.fact[k] = ("call", v)
                    else:
                        self.fact[k] = ("ref", v)
        self._spelled_identity()

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

    def _folded(self, a: int, b: int) -> str | None:
        """The string [a, b) spells when it is only literals joined by `+`, else None."""
        parts: list[str] = []
        for i in range(a, b):
            tok = self.t[i]
            if tok.kind == "str":
                parts.append(str(tok.value))
            elif not (tok.kind == "punct" and tok.value in ("+", "(", ")")):
                return None
        return "".join(parts) if parts else None

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
                    refs.append(_Analysis.promise_key(k))  # what its executor resolves it with
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
        return out

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

    def requests(self) -> list[Request]:
        """See `JsFlow.requests`."""
        out: list[Request] = []
        parts = tuple(sorted(self.registry_parts))
        for k in range(self.n - 1):
            if not self._called(k):
                continue
            scope = self.scope_of(k)
            if self._sink_kind(k, scope) != "request":
                continue
            args = self._args(k + 1)
            kind = self._url_kind(args[0], scope, k, 0) if args else "other"
            out.append(Request(self.line(k), kind, parts if kind == "registry" else ()))
        return out

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
        for i in range(a, b):
            tok = self.t[i]
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

    @staticmethod
    def promise_key(k: int) -> tuple[int, str]:
        """The value of the `new Promise(...)` at token `k`, as a name no scope declares."""
        return (-1_000_000 - k, "Promise")

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
