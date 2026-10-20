"""A named credential sent somewhere it does not belong.

`SUSPECT.EXFIL.ENVIRONMENT.001` catches the whole environment in a request, and the install-hook
composites catch a credential read beside any egress in a script that runs at install. What neither
sees is the careful version: one named credential, read at import or at call time, put in a request
to a host that is not the credential's own service.

Reading one named setting and calling its service is what every API client does -- a GitHub client
sends `GITHUB_TOKEN` to `api.github.com`, a publisher sends `NPM_TOKEN` to the registry -- so the
claim here is narrow and checkable:

* the credential has a HOME: the service that issued it and the only one it authenticates to
  (`CREDENTIAL_HOMES`); a generic `MY_SERVICE_API_KEY` has none we can know, and is not judged;
* the destination is a host written in the file -- a literal, or a name bound to one -- not a
  variable a user configures, which says nothing about where the request goes;
* the host is not the credential's home, nor a service whose purpose is to hold other services'
  credentials (a CI provider's variables API, a secrets manager).

An AWS secret access key or session token has no home at all: AWS clients sign requests with it
and never send it, so the raw value in any request to a host outside that short list is the claim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

#: Hosts whose purpose is holding other services' credentials: CI variables and secret stores. A
#: tool that registers a deployment credential with one of them sends the raw value, legitimately.
CREDENTIAL_CUSTODIANS: Final = (
    "app.terraform.io",
    "api.github.com",
    "gitlab.com",
    "circleci.com",
    "api.travis-ci.com",
    "api.travis-ci.org",
    "vault.",
    "doppler.com",
    "1password.com",
    "api.vercel.com",
    "api.netlify.com",
    "api.heroku.com",
    "api.render.com",
    "api.fly.io",
    "backboard.railway.app",
    "infisical.com",
    "akeyless.io",
    "bitwarden.com",
    "buildkite.com",
    "dev.azure.com",
    "bitbucket.org",
)


@dataclass(frozen=True)
class Home:
    """Where one family of credentials belongs: host suffixes, or words a self-hosted copy of the
    service carries in its name (`github.mycorp.com`, `npm.internal.example`)."""

    service: str
    suffixes: tuple[str, ...] = ()
    words: tuple[str, ...] = ()
    homeless: bool = False
    """Never sent by a legitimate client, to anyone (AWS signs with its secret key)."""


#: Credential names, matched against the whole environment variable name, and their homes.
CREDENTIAL_HOMES: Final[tuple[tuple[re.Pattern[str], Home], ...]] = (
    (
        re.compile(r"^AWS_(?:SECRET_ACCESS_KEY|SESSION_TOKEN)$"),
        Home("AWS", homeless=True),
    ),
    (
        re.compile(
            r"^(?:GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|GH_PAT|GITHUB_API_TOKEN|GITHUB_ACCESS_TOKEN)$"
        ),
        Home(
            "GitHub",
            (
                "github.com",
                "githubusercontent.com",
                "ghcr.io",
                "githubapp.com",
                "ghe.com",
            ),
            ("github", "ghe"),
        ),
    ),
    (
        re.compile(
            r"^(?:NPM_TOKEN|NODE_AUTH_TOKEN|NPM_AUTH_TOKEN|NPM_CONFIG__AUTH|NPM_CONFIG_TOKEN)$"
        ),
        Home(
            "npm",
            ("npmjs.org", "npmjs.com", "npm.pkg.github.com", "yarnpkg.com"),
            ("npm", "registry", "artifactory", "jfrog", "nexus", "verdaccio", "pkg", "repo"),
        ),
    ),
    (
        re.compile(
            r"^(?:PYPI_TOKEN|PYPI_API_TOKEN|PYPI_PASSWORD|TWINE_PASSWORD|TEST_PYPI_API_TOKEN)$"
        ),
        Home(
            "PyPI",
            ("pypi.org", "pythonhosted.org"),
            ("pypi", "artifactory", "jfrog", "nexus", "devpi", "pkg", "repo"),
        ),
    ),
    (
        re.compile(
            r"^(?:CI_JOB_TOKEN|GITLAB_TOKEN|GITLAB_PRIVATE_TOKEN|GITLAB_API_TOKEN|CI_REGISTRY_PASSWORD)$"
        ),
        Home("GitLab", ("gitlab.com", "gitlab.io"), ("gitlab",)),
    ),
    (
        re.compile(r"^(?:SLACK_BOT_TOKEN|SLACK_TOKEN|SLACK_USER_TOKEN|SLACK_APP_TOKEN)$"),
        Home("Slack", ("slack.com",), ()),
    ),
    (
        re.compile(r"^(?:DOCKER_PASSWORD|DOCKERHUB_TOKEN|DOCKER_HUB_TOKEN|DOCKERHUB_PASSWORD)$"),
        Home("Docker Hub", ("docker.io", "docker.com"), ("docker", "registry", "harbor")),
    ),
    (
        re.compile(r"^(?:STRIPE_SECRET_KEY|STRIPE_API_KEY)$"),
        Home("Stripe", ("stripe.com",), ()),
    ),
    (
        re.compile(r"^(?:CLOUDFLARE_API_TOKEN|CLOUDFLARE_API_KEY|CF_API_TOKEN)$"),
        Home("Cloudflare", ("cloudflare.com",), ()),
    ),
    (
        re.compile(r"^(?:DIGITALOCEAN_TOKEN|DIGITALOCEAN_ACCESS_TOKEN|DO_API_TOKEN)$"),
        Home("DigitalOcean", ("digitalocean.com",), ()),
    ),
    (
        re.compile(r"^(?:HEROKU_API_KEY)$"),
        Home("Heroku", ("heroku.com",), ()),
    ),
    (
        re.compile(r"^(?:DISCORD_TOKEN|DISCORD_BOT_TOKEN)$"),
        Home("Discord", ("discord.com", "discordapp.com", "discord.gg"), ()),
    ),
    (
        re.compile(r"^(?:CARGO_REGISTRY_TOKEN)$"),
        Home("crates.io", ("crates.io",), ("cargo", "crates", "registry", "artifactory", "jfrog")),
    ),
    (
        re.compile(r"^(?:GEM_HOST_API_KEY|RUBYGEMS_API_KEY)$"),
        Home("RubyGems", ("rubygems.org",), ("gem", "artifactory", "jfrog", "nexus")),
    ),
    (
        re.compile(r"^(?:NUGET_API_KEY|NUGET_AUTH_TOKEN)$"),
        Home("NuGet", ("nuget.org",), ("nuget", "artifactory", "jfrog", "nexus", "pkgs.dev.azure")),
    ),
)

_HOST: Final = re.compile(r"^[a-z][a-z0-9+.-]*://(?:[^@/\s]*@)?(\[[0-9a-f:.]+\]|[^/:?#\s]+)", re.I)


class SecretFlow:
    """Where a credential belongs, and whether a host is outside it."""

    @staticmethod
    def home_of(name: str) -> Home | None:
        for pattern, home in CREDENTIAL_HOMES:
            if pattern.match(name):
                return home
        return None

    @staticmethod
    def host_of(url: str) -> str | None:
        found = _HOST.match(url.strip())
        return found.group(1).lower().strip("[]") if found else None

    @staticmethod
    def misdirected(name: str, host: str | None) -> bool:
        """Whether sending the credential `name` to `host` is outside its home.

        An unknown host is never misdirected: a URL a user configures names nothing.
        """
        home = SecretFlow.home_of(name)
        if home is None or not host:
            return False
        if host in ("localhost", "127.0.0.1", "::1") or host.endswith((".local", ".internal")):
            return False
        if any(
            host == c or host.endswith("." + c) or host.startswith(c) for c in CREDENTIAL_CUSTODIANS
        ):
            return False
        if home.homeless:
            return True
        if any(host == s or host.endswith("." + s) for s in home.suffixes):
            return False
        labels = re.split(r"[.-]", host)
        return not any(word in labels or host.startswith(word) for word in home.words)


class JavaScriptFlow:
    """A named credential from `process.env` reaching a request to a host outside its home.

    No parser: JavaScript has none here without a dependency. Statement-level instead -- the names
    bound to `process.env.X` (directly or destructured), the names bound to URL literals, and every
    request call whose argument list mentions one of each. A name rebound in between, or a value
    passed through a function, is not followed; the claim stays narrow rather than guessed.
    """

    _ENV_READ = re.compile(
        r"""process\.env(?:\.([A-Z][A-Z0-9_]*)|\[\s*["'`]([A-Z][A-Z0-9_]*)["'`]\s*\])"""
    )
    _BIND = re.compile(r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)""")
    _DESTRUCTURE = re.compile(r"""(?:const|let|var)\s*\{([^}]*)\}\s*=\s*process\.env\b""")
    _CALL = re.compile(
        r"""(?<![\w$.])(?:fetch|axios(?:\.(?:get|post|put|patch|request))?|got(?:\.(?:get|post|put))?"""
        r"""|(?:https?|http2)\.(?:get|request)|request(?:\.(?:get|post))?|superagent\.(?:get|post)"""
        r"""|needle(?:\.(?:get|post))?|ky(?:\.(?:get|post))?|\$\.(?:get|post|ajax)|XMLHttpRequest)\s*\("""
    )
    _URL = re.compile(r"""["'`]((?:https?|wss?)://[^"'`\s]+)""")
    MAX_ARGUMENTS: Final = 4000

    @staticmethod
    def _arguments(text: str, open_paren: int) -> str:
        depth, index = 0, open_paren
        end = min(len(text), open_paren + JavaScriptFlow.MAX_ARGUMENTS)
        while index < end:
            character = text[index]
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    return text[open_paren + 1 : index]
            index += 1
        return text[open_paren + 1 : end]

    @staticmethod
    def findings(text: str) -> list[tuple[int, str, str]]:
        """`(offset of the request call, credential name, host)` for each misdirected send."""
        credentials: dict[str, str] = {}  # bound name -> credential name
        hosts: dict[str, str] = {}  # bound name -> host of the URL literal it holds
        for match in JavaScriptFlow._DESTRUCTURE.finditer(text):
            for part in match.group(1).split(","):
                key, _, alias = part.partition(":")
                key, alias = key.strip(), (alias.strip() or key.strip())
                if SecretFlow.home_of(key):
                    credentials[alias] = key
        for match in JavaScriptFlow._BIND.finditer(text):
            name, value = match.group(1), match.group(2)
            read = JavaScriptFlow._ENV_READ.search(value)
            if read:
                key = read.group(1) or read.group(2)
                if SecretFlow.home_of(key):
                    credentials[name] = key
            url = JavaScriptFlow._URL.search(value)
            if url:
                host = SecretFlow.host_of(url.group(1))
                if host:
                    hosts[name] = host
        found: list[tuple[int, str, str]] = []
        for call in JavaScriptFlow._CALL.finditer(text):
            arguments = JavaScriptFlow._arguments(text, call.end() - 1)
            named: set[str] = set()
            for read in JavaScriptFlow._ENV_READ.finditer(arguments):
                key = read.group(1) or read.group(2)
                if SecretFlow.home_of(key):
                    named.add(key)
            words = set(re.findall(r"[A-Za-z_$][\w$]*", arguments))
            named.update(credentials[w] for w in words & set(credentials))
            if not named:
                continue
            destinations = {
                h
                for h in (SecretFlow.host_of(u) for u in JavaScriptFlow._URL.findall(arguments))
                if h
            }
            destinations.update(hosts[w] for w in words & set(hosts))
            for key in sorted(named):
                for host in sorted(destinations):
                    if SecretFlow.misdirected(key, host):
                        found.append((call.start(), key, host))
                        break
        return found


__all__ = ["CREDENTIAL_CUSTODIANS", "CREDENTIAL_HOMES", "Home", "JavaScriptFlow", "SecretFlow"]


class JavaScriptLeak:
    """The machine's identity, or the whole environment, reaching a request.

    The JavaScript side of `AST.PY.IDENTITY_SENT` and `AST.PY.ENVIRONMENT_SENT`. Sources:
    `os.hostname()`, `os.userInfo()`, `os.networkInterfaces()` -- who and where
    this machine is -- and `process.env` as a whole object, not one named key. A source taints the
    name a statement binds it to, object literals over several lines included. Sinks: the arguments
    of a request call (`JavaScriptFlow._CALL`), or `.write`, `.end` or `.send` on an object the file
    made with `http(s).request` or `net`/`tls` `connect` -- never a file stream's `.write`. As
    narrow as `JavaScriptFlow`: one hop through a binding, nothing through a function's return.
    """

    _IDENTITY = re.compile(r"""\bos\s*\.\s*(?:hostname|userInfo|networkInterfaces)\s*\(""")
    #: The whole environment as a VALUE: not one key (`process.env.PATH`, `process.env[k]`), not a
    #: truthiness check (`process.env && ...`), not a comparison, and not its names alone
    #: (`Object.keys(process.env)`).
    _WHOLE_ENV = re.compile(
        r"""(?<!Object\.keys\()\bprocess\s*\.\s*env\b"""
        r"""(?!\s*(?:\.|\[|\?\.|&&|\|\||\?(?!\?)|[=!]==?|instanceof\b))"""
    )
    #: A string literal, blanked before names are read: `"debug"` is text, not the variable `debug`.
    _BIND = re.compile(r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*""")
    _MODULES = r"https?|http2|net|tls"
    #: `const mod = url.protocol === "https:" ? https : http`: a name for one of those modules.
    _ALIAS = re.compile(
        r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n()]{0,160})(?=;|\n)"""
    )
    _CONNECTION_CALL = r"""\s*\.\s*(?:request|get|connect|createConnection)\s*\("""
    _SEND = re.compile(r"""(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(?:write|end|send)\s*\(""")
    MAX_STATEMENT: Final = 4000

    @staticmethod
    def _statement(text: str, start: int) -> str:
        """From `start` to the `;` or line end that closes the statement at bracket depth 0."""
        depth, index = 0, start
        end = min(len(text), start + JavaScriptLeak.MAX_STATEMENT)
        while index < end:
            character = text[index]
            if character in "([{":
                depth += 1
            elif character in ")]}":
                depth -= 1
                if depth < 0:
                    break
            elif character in ";\n" and depth == 0:
                break
            index += 1
        return text[start:index]

    #: Where a function's body starts: after `=>`, or after `function name(...)`.
    _BODY = re.compile(r"""=>\s*\{|\bfunction\b\s*\*?\s*[\w$]*\s*\([^()]*\)\s*\{""")
    #: A binding whose value is a function or a class binds code, not data.
    _BINDS_CODE = re.compile(
        r"""\s*(?:async\s+)?(?:function\b|class\b|\([^()]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)"""
    )

    #: A variable's name as a value: not a property (`process.env.PATH` names no variable `env`),
    #: not an object key (`{ env: x }`). A shorthand `{ env }` is the variable and still counts.
    _NAME = re.compile(r"""(?<![\w$.])([A-Za-z_$][\w$]*)\b(?!\s*:(?!:))""")
    #: A binding to what these return holds a process, a file's contents or a path, not the value
    #: passed in: `spawnSync("bash", args, { env })` binds a result, and the environment it was given
    #: went to a child process, not into a request. Named, not guessed: an encoder or a serialiser
    #: (`JSON.stringify`, `Buffer.from`, `encrypt(...)`) keeps the data and keeps the taint.
    _LOSES_TAINT = re.compile(
        r"""\s{0,8}(?:await\s{1,8})?(?:(?:[\w$]{1,80}\s{0,4}\.\s{0,4}){0,6}(?:spawn|spawnSync|exec|execSync|execFile|execFileSync|fork"""
        r"""|readFile|readFileSync|readdir|readdirSync|existsSync|statSync|lstatSync|createReadStream|require)"""
        r"""|path\s{0,4}\.\s{0,4}(?:join|resolve|relative|dirname|basename|normalize))\s{0,4}\("""
    )

    @staticmethod
    def _without_functions(fragment: str) -> str:
        """`fragment` with every function body removed. A callback is code the request will run
        later, not data it sends: `https.get(url, (res) => { ... })` sends the URL, and whatever
        the callback reads is not in the request. In a 15,000-package random sample of npm and
        PyPI, `https.get(url, (res) => { ... })` was read as sending what its callback used."""
        out: list[str] = []
        index = 0
        while True:
            body = JavaScriptLeak._BODY.search(fragment, index)
            if body is None:
                out.append(fragment[index:])
                return "".join(out)
            out.append(fragment[index : body.end() - 1])
            depth, cursor = 0, body.end() - 1
            while cursor < len(fragment):
                if fragment[cursor] == "{":
                    depth += 1
                elif fragment[cursor] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                cursor += 1
            out.append("{}")
            index = cursor + 1

    #: How far after a binding its name still means that binding. Names are matched by text, and a
    #: bundle reuses `options`, `headers` and `env` thousands of times for unrelated values; a
    #: beacon binds what it sends and sends it a few lines later. Nearness stands in for scope.
    LOCALITY: Final = 4000

    @staticmethod
    def _blank_strings(fragment: str) -> str:
        """`fragment` with the text of its string literals removed, a template's `${...}` kept.

        A scan, not a pattern: a regex that spans an arbitrarily long string with escapes in it is
        the shape the pattern guard refuses, and one character at a time is linear by construction.
        `"debug"` is text, not the variable `debug`; `${os.hostname()}` in a template is code.
        """
        out: list[str] = []
        quote = ""
        depth = 0  # `${` nesting inside a template
        index = 0
        length = len(fragment)
        while index < length:
            char = fragment[index]
            if quote:
                if char == "\\":
                    index += 2
                    continue
                if quote == "`" and fragment.startswith("${", index):
                    quote, depth = "", 1
                    out.append(" ")
                    index += 2
                    continue
                if char == quote or (char == "\n" and quote != "`"):
                    out.append('""')
                    quote = ""
                index += 1
                continue
            if depth:
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        quote = "`"
                        index += 1
                        continue
            elif char in "'\"`":
                quote = char
                index += 1
                continue
            out.append(char)
            index += 1
        return "".join(out)

    @staticmethod
    def _kinds(fragment: str, tainted: dict[str, list[tuple[int, set[str]]]], at: int) -> set[str]:
        """What `fragment`, found at offset `at`, carries: a source in it, or a name bound to one
        within `LOCALITY` before it."""
        fragment = JavaScriptLeak._without_functions(fragment)
        # Names and sources are read with string literals blanked; a template's `${...}` is code
        # and stays.
        fragment = JavaScriptLeak._blank_strings(fragment)
        kinds: set[str] = set()
        if JavaScriptLeak._IDENTITY.search(fragment):
            kinds.add("identity")
        if JavaScriptLeak._WHOLE_ENV.search(fragment):
            kinds.add("environment")
        for word in set(JavaScriptLeak._NAME.findall(fragment)) & set(tainted):
            for offset, bound in tainted[word]:
                if at - JavaScriptLeak.LOCALITY <= offset < at:
                    kinds |= bound
        return kinds

    @staticmethod
    def findings(text: str) -> list[tuple[int, str]]:
        """`(offset of the sending call, "identity" or "environment")` for each leak."""
        if not (JavaScriptLeak._IDENTITY.search(text) or JavaScriptLeak._WHOLE_ENV.search(text)):
            return []
        tainted: dict[str, list[tuple[int, set[str]]]] = {}
        for _ in range(2):  # a second pass lets a binding taint through one earlier binding
            for match in JavaScriptLeak._BIND.finditer(text):
                if JavaScriptLeak._BINDS_CODE.match(text, match.end()):
                    continue
                if JavaScriptLeak._LOSES_TAINT.match(text, match.end()):
                    continue
                statement = JavaScriptLeak._statement(text, match.end())
                kinds = JavaScriptLeak._kinds(statement, tainted, match.start())
                if kinds and (match.start(), kinds) not in tainted.get(match.group(1), []):
                    tainted.setdefault(match.group(1), []).append((match.start(), kinds))
        modules = JavaScriptLeak._MODULES
        aliases = [
            m.group(1)
            for m in JavaScriptLeak._ALIAS.finditer(text)
            if re.search(rf"\b(?:{modules})\b", m.group(2))
            and not re.search(r"['\"`]", m.group(2).split("?", 1)[-1])
        ]
        names = "|".join([modules, *(re.escape(a) for a in aliases)])
        connection = re.compile(
            rf"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:{names}){JavaScriptLeak._CONNECTION_CALL}"""
        )
        connections = {m.group(1) for m in connection.finditer(text)}
        found: list[tuple[int, str]] = []
        for call in JavaScriptFlow._CALL.finditer(text):
            arguments = JavaScriptFlow._arguments(text, call.end() - 1)
            found += [
                (call.start(), kind)
                for kind in sorted(JavaScriptLeak._kinds(arguments, tainted, call.start()))
            ]
        for send in JavaScriptLeak._SEND.finditer(text):
            if send.group(1) not in connections:
                continue
            arguments = JavaScriptFlow._arguments(text, send.end() - 1)
            found += [
                (send.start(), kind)
                for kind in sorted(JavaScriptLeak._kinds(arguments, tainted, send.start()))
            ]
        return found
