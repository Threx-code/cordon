"""What the JavaScript flow analysis recognises and reports: its limits, the keywords, modules, calls and
patterns that make a source, a sink or a destination, and the Flow and Request it returns."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final

#: Files above this are not analysed: bundles of that size are third-party code concatenated, and
#: the analysis is linear but not free.
MAX_BYTES: Final = 1_500_000
#: Fixpoint rounds over the bindings and summaries. Each round follows one more hop; real chains
#: are a handful deep, and the bound keeps a pathological file linear.
MAX_ROUNDS: Final = 8
#: Parameter labels one binding may carry (see `Calls._grow`).
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
#: (`Bindings._assign_base`). `window`, `globalThis` and `module` are not among them -- a file
#: keeps its own values there.
_HOST_OBJECTS: Final = frozenset(
    {"process", "console", "Math", "JSON", "Reflect", "Symbol", "Promise", "Number", "String"}
    | {"Boolean", "Date", "Error", "Buffer", "Intl"}
)
#: A command that hands its operand to the desktop's handler for it -- a URL to the browser
#: (`Calls._opener`). `open -a <browser>` too, but not with a terminal or a script runner
#: named: `open -a Terminal x.command` runs it.
_OPENER: Final = re.compile(
    r"\s*(?:open(?!\s+-[ab]\s+\"?(?:Terminal|iTerm|Script\s?Editor|Automator|Warp|Alacritty"
    r"|kitty|Hyper|Ghostty|osascript)\b)|xdg-open|gio\s+open|wslview|sensible-browser|x-www-browser"
    r'|start\s+""|cmd(?:\.exe)?\s+/c\s+start\s+""|rundll32(?:\.exe)?\s+url\.dll,FileProtocolHandler'
    r"|explorer(?:\.exe)?)(?:\s|\"|$)",
    re.I,
)
#: Keywords only in context, ordinary names as a method's own name (`Structure._find_functions`).
_CONTEXTUAL: Final = frozenset({"get", "set", "of", "from", "as", "async", "static"})
#: The public npm registries' own hosts, at the start of a URL (`Taint._registry_template`).
_REGISTRY_URL: Final = re.compile(
    r"https?://(?:registry\.npmjs\.org|registry\.yarnpkg\.com|registry\.npmmirror\.com)/"
)
#: What a messaging client sends with (`_Analysis._opens_bot`): a message, a file, a mail.
_BOT_SEND: Final = frozenset(
    {"sendMessage", "sendDocument", "sendPhoto", "sendAudio", "sendVideo", "sendMediaGroup"}
    | {"sendMail", "send", "editMessageText"}
)
#: Commands that print who and where this machine is (`Taint._identity_command`): their
#: output is the `identity` source `os.hostname()` and `os.userInfo()` are.
_IDENTITY_COMMAND: Final = re.compile(
    r"\s*(?:whoami|hostname|uname|id|ipconfig|ifconfig|systeminfo|scutil\s+--get"
    r"|ip\s+(?:a|addr|address|route)|wmic\s+(?:computersystem|os|nic)|echo\s+(?:%username%|\$USER)"
    r"|cat\s+/etc/(?:hostname|passwd|os-release))\b",
    re.I,
)
#: TypeScript's member and parameter-property modifiers (`private async load(): Promise<void>`).
_TS_MODIFIERS: Final = frozenset({"private", "public", "protected", "override", "readonly"})
#: Options naming where a connection goes rather than what it sends (`Calls._sent`).
_DESTINATION_KEYS: Final = frozenset({"host", "hostname", "localAddress", "port"})
_PROCESS_CALL: Final = frozenset(
    {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
)
#: The calls that take a program and an argument list rather than a shell command line.
_ARGV_CALLS: Final = frozenset({"spawn", "spawnSync", "execFile", "execFileSync"})
#: Programs whose arguments are code or a package to run: an interpreter (`node -e`, `sh -c`), a
#: shell, or a package runner (`npx <pkg>`).
_RUNS_ITS_ARGUMENT: Final = re.compile(
    r"(?:^|[/\\])(?:node|nodejs|deno|bun|bunx|npx|pnpx|npm|pnpm|yarn|uvx|pipx|python[\d.]*|py"
    r"|ruby|perl|php|lua|sh|bash|zsh|dash|ksh|fish|cmd|powershell|pwsh|osascript|wscript|cscript"
    r"|mshta|rundll32|regsvr32|env|sudo|xargs|eval)(?:\.exe)?$",
    re.I,
)
#: Decompressors whose output is bytes a server or a blob chose: running that output is the
#: decoded-content dropper. `Buffer.from(x, "base64"|"hex")` and `atob(x)` are handled by name.
_DECODERS: Final = frozenset(
    {
        "gunzipSync",
        "gunzip",
        "inflateSync",
        "inflate",
        "inflateRawSync",
        "inflateRaw",
        "unzipSync",
        "unzip",
        "brotliDecompressSync",
        "brotliDecompress",
    }
)
#: The base64/hex encodings a `Buffer.from(value, enc)` DECODES (a string of code back into bytes),
#: as opposed to `.toString("base64")`, which encodes.
_DECODE_ENCODINGS: Final = frozenset({"base64", "base64url", "hex"})
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
#: Archive libraries: an archive object accumulates the files added to it, then is sent
#: (`_Analysis._opens_archive`). Only on a KNOWN archive var, since the method names are generic.
_ARCHIVE_CLASSES: Final = frozenset({"JSZip", "AdmZip", "Zip", "Packer"})
_ARCHIVE_MODULES: Final = frozenset({"jszip", "adm-zip", "archiver", "zip-stream", "yazl"})
#: Adds whose argument is a PATH the archiver reads (its contents go in): read_of the path.
_ARCHIVE_ADD_PATH: Final = frozenset(
    {"addLocalFile", "addLocalFolder", "directory", "glob", "append", "entry", "file"}
)
#: Adds whose argument is already the CONTENT (`jszip.file(name, readFileSync(p))`): arg 2.
_ARCHIVE_ADD_CONTENT: Final = frozenset({"file"})
#: Writing a response to one of these puts code a server chose on disk; the path written to then
#: carries `network_response`, so running it later is the dropper the REMOTE_CODE rule reads.
_FS_WRITE: Final = frozenset({"writeFile", "writeFileSync", "appendFile", "appendFileSync"})
_VM_RUN: Final = frozenset(
    {"runInContext", "runInNewContext", "runInThisContext", "compileFunction"}
)

_RAW_IP: Final = re.compile(
    r"^(?:https?|wss?)://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/|$)"
)
_URL: Final = re.compile(
    r"^(?:https?|wss?)://(?:[^@/\s]{1,200}@)?([^/:?#\s]+)(?::\d+)?([^?#\s]*)", re.I
)


#: The source kinds a flow reports (`JsFlow.SOURCES`): what a value read from the machine or
#: the network carries.
SOURCES: Final[tuple[str, ...]] = (
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
    #: For an `other` request, every string its URL can spell when literals in the file decide it
    #: (`JsValues`), sorted; empty when anything else does.
    urls: tuple[str, ...] = ()


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
