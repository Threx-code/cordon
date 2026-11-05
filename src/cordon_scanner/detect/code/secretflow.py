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
from typing import Final

from cordon_scanner.analysis.shared.credential_homes import SecretFlow


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


__all__ = ["JavaScriptFlow"]


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
    #: The calls themselves, for a file that names the `os` module another way.
    _IDENTITY_CALLS: Final = r"(?:hostname|userInfo|networkInterfaces)"
    #: `os` under another name, in the raw text: `const o = require("os")`, `import o from "os"`,
    #: `import * as o from "node:os"`.
    _OS_NAME = re.compile(
        r"""(?:(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["'](?:node:)?os["']\s*\)"""
        r"""|import\s+(?:\*\s*as\s+)?([A-Za-z_$][\w$]*)\s+from\s*["'](?:node:)?os["'])"""
    )
    #: The calls imported by name: `const { hostname } = require("os")`, `import { userInfo } from "os"`.
    _OS_CALLS = re.compile(
        r"""\{[^}]{0,200}\b(?:hostname|userInfo|networkInterfaces)\b[^}]{0,200}\}\s*(?:=\s*require\s*\(\s*|from\s*)["'](?:node:)?os["']"""
    )
    #: A process run for who and where this machine is: its output IS the identity. Read on the raw
    #: text, because the command is a string literal (review 98, npm bulk set: `css-*-polyfill`
    #: ran `whoami`, `uname`, the interfaces and `/etc/hosts` and sent them with the hostname).
    _IDENTITY_COMMAND = re.compile(
        r"""\b(?:exec|execSync|execFileSync|spawnSync)\s*\(\s*["'`]\s*(?:whoami|hostname|id|uname|ifconfig|ipconfig|systeminfo|scutil\s|net\s+user|cat\s+/etc/(?:passwd|hosts|hostname))\b"""
    )
    #: The environment values that say who is installing: the user and machine everywhere, and in
    #: CI the repository, its organisation and who triggered the run, under each provider's name.
    #: A dependency-confusion probe sends exactly these (review 98, npm bulk set:
    #: `screenpipe-mcp-http`, `GITHUB_REPOSITORY` / `_OWNER` / `GITHUB_WORKFLOW` posted and resolved
    #: as a DNS label from a postinstall). Read on the raw text: `process.env["X"]` hides the key in
    #: a string that blanking removes.
    _IDENTITY_ENV = re.compile(
        r"""\bprocess\s*\.\s*env\s*(?:\.\s*|\[\s*["'`])(?:USER|USERNAME|LOGNAME|HOSTNAME|COMPUTERNAME"""
        r"""|USERDOMAIN|USERPROFILE|HOME|INIT_CWD|GITHUB_REPOSITORY(?:_OWNER)?|GITHUB_ACTOR"""
        r"""|GITHUB_WORKFLOW|CI_PROJECT_(?:PATH|NAMESPACE|URL)|CI_SERVER_HOST|BUILD_REPOSITORY_(?:NAME|URI)"""
        r"""|SYSTEM_(?:TEAMPROJECT|COLLECTIONURI)|BITBUCKET_(?:REPO_FULL_NAME|WORKSPACE)"""
        r"""|CIRCLE_(?:PROJECT_REPONAME|PROJECT_USERNAME|REPOSITORY_URL)|TRAVIS_REPO_SLUG"""
        r"""|BUILDKITE_(?:REPO|ORGANIZATION_SLUG)|JENKINS_URL|JOB_URL)\b"""
    )
    #: A plain assignment to a name declared earlier: `site = require("os").hostname()`.
    _ASSIGN = re.compile(r"""(?<![\w$.=!<>+\-*/%&|^])([A-Za-z_$][\w$]*)\s*=(?![=>])\s*""")
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
    #: `= value` with the blanks before it read once: all of them, or -- as `\s*` gave back to when the
    #: value did not end at a `;` or line break -- back to the last line break among them, with an
    #: empty value. Written `=\s*([^;\n()]{0,160})`, each blank given back was read 160 more times
    #: (review 98, 27-PERFORMANCE).
    _ALIAS = re.compile(
        r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=(?:\s*+|\s*(?=\n))([^;\n()]{0,160})(?=;|\n)"""
    )
    _CONNECTION_CALL = r"""\s*\.\s*(?:request|get|connect|createConnection)\s*\("""
    _SEND = re.compile(r"""(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(?:write|end|send)\s*\(""")
    MAX_STATEMENT: Final = 4000
    #: The characters `_statement` and `_blank_strings` act on; everything between is skipped in C.
    _STATEMENT_STOPS: Final = re.compile(r"[()\[\]{};\n]")
    _STRING_STOPS: Final = {
        "'": re.compile(r"['\\\n]"),
        '"': re.compile(r'["\\\n]'),
        "`": re.compile(r"[`\\$]"),
    }
    _BRACES: Final = re.compile(r"[{}]")
    _QUOTES: Final = re.compile(r"['\"`]")

    @staticmethod
    def _statement(text: str, start: int) -> str:
        """From `start` to the `;` or line end that closes the statement at bracket depth 0."""
        depth, index = 0, start
        end = min(len(text), start + JavaScriptLeak.MAX_STATEMENT)
        # Only a bracket, `;` or a line break changes anything, so the scan jumps from one to the
        # next in C rather than visiting the characters between them in Python.
        stops = JavaScriptLeak._STATEMENT_STOPS
        while True:
            stop = stops.search(text, index, end)
            if stop is None:
                index = end
                break
            index = stop.start()
            character = text[index]
            if character in "([{":
                depth += 1
            elif character in ")]}":
                depth -= 1
                if depth < 0:
                    break
            elif depth == 0:  # `;` or a line break
                break
            index += 1
        return text[start:index]

    #: Where a function's body starts: after `=>`, or after `function name(...)`. The blanks, the `*`
    #: and the name are taken possessively: each is followed by what it cannot take, so no match gives
    #: anything back, and `\s*\*?\s*[\w$]*\s*` beside each other were cubic in blanks after
    #: `function` (review 98, 27-PERFORMANCE).
    _BODY = re.compile(r"""=>\s*\{|\bfunction\b\s*+(?:\*\s*+)?[\w$]*+\s*+\([^()]*\)\s*\{""")
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
        # The same steps as one character at a time, taken only at the characters that change
        # something: a quote, a backslash, a line break, `${` or a brace. Each run between them is
        # found in C, and kept (outside a string) or dropped (inside one) whole.
        out: list[str] = []
        quote = ""
        depth = 0  # `${` nesting inside a template
        index = 0
        length = len(fragment)
        while index < length:
            if quote:
                stop = JavaScriptLeak._STRING_STOPS[quote].search(fragment, index)
                if stop is None:
                    break  # the string runs to the end: none of it is kept
                index = stop.start()
                char = fragment[index]
                if char == "\\":
                    index += 2
                    continue
                if char == "$":  # only a template stops here
                    if fragment.startswith("${", index):
                        quote, depth = "", 1
                        out.append(" ")
                        index += 2
                    else:
                        index += 1
                    continue
                out.append('""')  # the closing quote, or a line break ending '...' or "..."
                quote = ""
                index += 1
                continue
            if depth:
                stop = JavaScriptLeak._BRACES.search(fragment, index)
                if stop is None:
                    out.append(fragment[index:])
                    break
                out.append(fragment[index : stop.start()])
                index = stop.start()
                if fragment[index] == "{":
                    depth += 1
                else:
                    depth -= 1
                    if depth == 0:
                        quote = "`"
                        index += 1
                        continue
                out.append(fragment[index])
                index += 1
                continue
            stop = JavaScriptLeak._QUOTES.search(fragment, index)
            if stop is None:
                out.append(fragment[index:])
                break
            out.append(fragment[index : stop.start()])
            quote = fragment[stop.start()]
            index = stop.start() + 1
        return "".join(out)

    @staticmethod
    def _identity_in(text: str) -> re.Pattern[str]:
        """The identity sources of this file, read on blanked text: `os.hostname()`, the module
        under the names this file gives it, `require("").hostname()` (the module named in a string
        that blanking removed), and the calls imported by name."""
        calls = JavaScriptLeak._IDENTITY_CALLS
        names = {"os"} | {
            name
            for match in JavaScriptLeak._OS_NAME.finditer(text)
            for name in match.groups()
            if name
        }
        alternatives = [
            rf"""(?<![\w$])(?:{"|".join(re.escape(n) for n in sorted(names))})\s*\.\s*{calls}\s*\(""",
            rf"""\brequire\s*\(\s*""\s*\)\s*\.\s*{calls}\s*\(""",
        ]
        if JavaScriptLeak._OS_CALLS.search(text):
            alternatives.append(rf"""(?<![\w$.]){calls}\s*\(""")
        return re.compile("|".join(alternatives))

    @staticmethod
    def _kinds(
        fragment: str,
        tainted: dict[str, list[tuple[int, set[str]]]],
        at: int,
        identity: re.Pattern[str] | None = None,
        install: bool = False,
    ) -> set[str]:
        """What `fragment`, found at offset `at`, carries: a source in it, or a name bound to one
        within `LOCALITY` before it. The environment's names for who is installing count only in
        install code (`install`): a CI tool puts `CIRCLE_PROJECT_REPONAME` in its CI provider's
        API URL by design (review 98: six benign blocks for one catch, in a postinstall)."""
        raw = fragment
        fragment = JavaScriptLeak._without_functions(fragment)
        # Names and sources are read with string literals blanked; a template's `${...}` is code
        # and stays.
        fragment = JavaScriptLeak._blank_strings(fragment)
        kinds: set[str] = set()
        if (
            (identity or JavaScriptLeak._IDENTITY).search(fragment)
            or JavaScriptLeak._IDENTITY_COMMAND.search(raw)
            or (install and JavaScriptLeak._IDENTITY_ENV.search(raw))
        ):
            kinds.add("identity")
        if JavaScriptLeak._WHOLE_ENV.search(fragment):
            kinds.add("environment")
        for word in set(JavaScriptLeak._NAME.findall(fragment)) & set(tainted):
            for offset, bound in tainted[word]:
                if at - JavaScriptLeak.LOCALITY <= offset < at:
                    kinds |= bound
        return kinds

    @staticmethod
    def findings(text: str, install: bool = False) -> list[tuple[int, str]]:
        """`(offset of the sending call, "identity" or "environment")` for each leak. `install`:
        the file runs at install time (`_kinds`)."""
        identity = JavaScriptLeak._identity_in(text)
        if not (
            identity.search(JavaScriptLeak._blank_strings(text))
            or JavaScriptLeak._IDENTITY_COMMAND.search(text)
            or (install and JavaScriptLeak._IDENTITY_ENV.search(text))
            or JavaScriptLeak._WHOLE_ENV.search(text)
        ):
            return []
        tainted: dict[str, list[tuple[int, set[str]]]] = {}
        bindings = sorted(
            [*JavaScriptLeak._BIND.finditer(text), *JavaScriptLeak._ASSIGN.finditer(text)],
            key=lambda m: m.start(),
        )
        for _ in range(2):  # a second pass lets a binding taint through one earlier binding
            for match in bindings:
                if JavaScriptLeak._BINDS_CODE.match(text, match.end()):
                    continue
                statement = JavaScriptLeak._statement(text, match.end())
                # A plain assignment carries only a source written in it: `site =
                # require("os").hostname()`. Followed through names and the whole environment it
                # tainted a CLI's every reassigned option (review 98: 18 benign blocks).
                if match.re is JavaScriptLeak._ASSIGN:
                    blank = JavaScriptLeak._blank_strings(statement)
                    if not (
                        identity.search(blank) or JavaScriptLeak._IDENTITY_COMMAND.search(statement)
                    ):
                        continue
                    if (match.start(), {"identity"}) not in tainted.get(match.group(1), []):
                        tainted.setdefault(match.group(1), []).append((match.start(), {"identity"}))
                    continue
                # A process's output is not what it was given -- unless the process was run to
                # say who this machine is.
                if (
                    JavaScriptLeak._LOSES_TAINT.match(text, match.end())
                    and not JavaScriptLeak._IDENTITY_COMMAND.search(statement)
                    and not identity.search(JavaScriptLeak._blank_strings(statement))
                ):
                    continue
                kinds = JavaScriptLeak._kinds(statement, tainted, match.start(), identity, install)
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
                for kind in sorted(
                    JavaScriptLeak._kinds(arguments, tainted, call.start(), identity, install)
                )
            ]
        for send in JavaScriptLeak._SEND.finditer(text):
            if send.group(1) not in connections:
                continue
            arguments = JavaScriptFlow._arguments(text, send.end() - 1)
            found += [
                (send.start(), kind)
                for kind in sorted(
                    JavaScriptLeak._kinds(arguments, tainted, send.start(), identity, install)
                )
            ]
        return found


class JavaScriptCommandFlow:
    """What a command printed, reaching a request: `out.push(sh("uname -a"))` ... `https.get({path:
    "/c?d=" + Buffer.from(out.join()).toString("base64")})`.

    Each half is ordinary -- a build runs commands, a client calls its API -- and the flow between
    them is the act: the install hook that runs commands and ships their output (review 98, npm bulk
    set: `@years19/n8n-nodes-utils-helper-*`, a helper `sh()` around `execSync`, the outputs in an
    array, the array base64'd into a request path). Sources: a `child_process` call that returns
    output, directly or through a helper function whose body returns one. Taint follows a binding,
    a plain assignment and an array `push`, within `JavaScriptLeak.LOCALITY` characters. Sinks: the
    arguments of a request call (`JavaScriptFlow._CALL`) -- URL, path, options or body -- or
    `.write`/`.end`/`.send` on a request object.
    """

    _EXEC = r"""(?:exec|execSync|execFileSync|spawnSync)\s*\("""
    _HELPER = re.compile(
        r"""\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^()]{0,200}\)\s*\{"""
        r"""|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\b[^(]{0,40})?\([^()]{0,200}\)\s*(?:=>)?\s*\{?"""
    )
    _RETURNS_EXEC = re.compile(r"""(?:\breturn\b|=>)[^;{}]{0,200}?\b""" + _EXEC)
    _PUSH = re.compile(r"""(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(?:push|unshift|concat)\s*\(""")
    _REQUEST_OBJECT = re.compile(
        r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:https?|http2)\s*\.\s*request\s*\("""
    )
    _SEND = re.compile(r"""(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(?:write|end|send)\s*\(""")

    @staticmethod
    def _body(text: str, brace: int) -> str:
        depth, index = 0, brace
        end = min(len(text), brace + JavaScriptLeak.MAX_STATEMENT)
        while index < end:
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        return text[brace:index]

    @staticmethod
    def source(text: str) -> re.Pattern[str]:
        """Calls that return what a command printed, in this file."""
        helpers = set()
        for match in JavaScriptCommandFlow._HELPER.finditer(text):
            name = match.group(1) or match.group(2)
            head_end = match.end()
            body = (
                JavaScriptCommandFlow._body(text, head_end - 1)
                if text[head_end - 1 : head_end] == "{"
                else JavaScriptLeak._statement(text, head_end)
            )
            if JavaScriptCommandFlow._RETURNS_EXEC.search(body) or (
                text[head_end - 1 : head_end] != "{"
                and re.match(
                    r"\s*(?:(?:[\w$]+|require\s*\([^()]{0,80}\))\s*\.\s*)*"
                    + JavaScriptCommandFlow._EXEC,
                    body,
                )
            ):
                helpers.add(name)
        names = "|".join(re.escape(h) for h in sorted(helpers))
        exec_call = r"""\b(?:[\w$]{1,40}\s*\.\s*)?""" + JavaScriptCommandFlow._EXEC
        return re.compile(rf"""{exec_call}|(?<![\w$.])(?:{names})\s*\(""" if names else exec_call)

    @staticmethod
    def findings(text: str) -> list[int]:
        """Offsets of the request calls that carry a command's output."""
        if not re.search(JavaScriptCommandFlow._EXEC, text):
            return []
        source = JavaScriptCommandFlow.source(text)
        tainted: dict[str, list[int]] = {}

        def carries(fragment: str, at: int) -> bool:
            fragment = JavaScriptLeak._blank_strings(JavaScriptLeak._without_functions(fragment))
            if source.search(fragment):
                return True
            return any(
                at - JavaScriptLeak.LOCALITY <= offset < at
                for word in set(JavaScriptLeak._NAME.findall(fragment)) & set(tainted)
                for offset in tainted[word]
            )

        bindings = sorted(
            [*JavaScriptLeak._BIND.finditer(text), *JavaScriptLeak._ASSIGN.finditer(text)],
            key=lambda m: m.start(),
        )
        for _ in range(2):
            for match in bindings:
                if JavaScriptLeak._BINDS_CODE.match(text, match.end()):
                    continue
                statement = JavaScriptLeak._statement(text, match.end())
                if carries(statement, match.start()):
                    tainted.setdefault(match.group(1), []).append(match.start())
            for match in JavaScriptCommandFlow._PUSH.finditer(text):
                arguments = JavaScriptFlow._arguments(text, match.end() - 1)
                if carries(arguments, match.start()):
                    tainted.setdefault(match.group(1), []).append(match.start())
        found = [
            call.start()
            for call in JavaScriptFlow._CALL.finditer(text)
            if carries(JavaScriptFlow._arguments(text, call.end() - 1), call.start())
        ]
        requests = {m.group(1) for m in JavaScriptCommandFlow._REQUEST_OBJECT.finditer(text)}
        found += [
            send.start()
            for send in JavaScriptCommandFlow._SEND.finditer(text)
            if send.group(1) in requests
            and carries(JavaScriptFlow._arguments(text, send.end() - 1), send.start())
        ]
        return sorted(found)
