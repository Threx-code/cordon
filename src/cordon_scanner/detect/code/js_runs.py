"""The JavaScript programs a file runs from what it receives, carries or prints.

Three acts read whole-file, each from its own patterns: data arriving on a connection and run
(`received_and_run`), a file the package carries decoded into a program and started
(`decoded_program_run`), and a command's output put into a request (`command_output_sent`).
Moved out of `capability/detector.py` (0.7.0 layout: a long module only shrinks); `CapabilityDetector`
calls these and labels what they return.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.detect.code.capability.detector import CapabilityHit
from cordon_scanner.foundation.models import Capability

if TYPE_CHECKING:
    from cordon_scanner.detect.base import ScanContext
    from cordon_scanner.foundation.content import FileContent


class JsRuns:
    #: A connection JavaScript opens or accepts: a raw or TLS socket, a WebSocket, a socket.io client.
    _JS_CONNECTION: ClassVar[re.Pattern[str]] = re.compile(
        r"\bnew\s{1,4}(?:net\s{0,4}\.\s{0,4})?Socket\s{0,4}\(|\b(?:net|tls)\s{0,4}\.\s{0,4}"
        r"(?:connect|createConnection|createServer)\s{0,4}\(|\bnew\s{1,4}WebSocket\s{0,4}\(|\bio\s{0,4}\(\s{0,4}['\"`]"
        # An HTTP server: what a request carries is what arrives (review 98, npm bulk set:
        # `n8n-nodes-metricsagent` ran every POSTed command on a port its postinstall opened).
        r"|\b(?:https?|http2)\s{0,4}\.\s{0,4}create(?:Secure)?Server\s{0,4}\("
    )
    #: What arrives on it, handed to a callback: `.on('data', (d) => ...)`, `.on('message', ...)`.
    _JS_RECEIVED: ClassVar[re.Pattern[str]] = re.compile(
        r"\.\s{0,4}on\s{0,4}\(\s{0,4}['\"](?:data|message|command|cmd|exec|run)['\"]\s{0,4},\s{0,4}"
        r"(?:async\s{1,4})?(?:function\s{0,4}\w{0,40}\s{0,4})?\(?\s{0,4}(?P<arg>[A-Za-z_$][\w$]{0,40})"
    )

    @classmethod
    def received_and_run(cls, content: FileContent) -> list[CapabilityHit]:
        """JavaScript that runs, as a command, what arrives on a connection it opened.

        `client.on('data', (data) => exec(data.toString(), ...))` with the output written back:
        a reverse shell that names no shell, so the stdio-joining rule never sees it (review 98,
        `@ibm-org/custom-greeting` 1.0.1; 1.0.0 piped a named shell and was caught). The
        JavaScript twin of `_go_received_and_run`: the process start's first argument must be
        built from the received value, within the handler, and nothing else. Recorded at the
        process start as `fetch_exec`, and the connection as the egress."""
        text = content.text
        connection = cls._JS_CONNECTION.search(text) if len(text) <= 4_000_000 else None
        if connection is None:
            return []
        for received in cls._JS_RECEIVED.finditer(text):
            handler = text[received.end() : received.end() + 1500]
            # What the received value becomes before it is run: a request body accumulated
            # (`body += chunk`), then parsed and destructured (`const { c } = JSON.parse(body)`).
            names = {received["arg"]}
            for _ in range(2):
                for bound in re.finditer(
                    r"(?:\b(?:const|let|var)\s{1,4})?(\{[^}=]{1,200}\}|[\w$]{1,40})\s{0,4}\+?=\s{0,4}([^;\n]{1,200})",
                    text[received.start() : received.end() + 1500],
                ):
                    if any(
                        re.search(rf"(?<![\w$.]){re.escape(n)}\b", bound.group(2)) for n in names
                    ):
                        names |= set(re.findall(r"[A-Za-z_$][\w$]{0,40}", bound.group(1)))
            arg = "|".join(re.escape(n) for n in sorted(names))
            arg = f"(?:{arg})"
            run = re.search(
                # Called bare or on a child-process module: `re.exec(chunk)` is a regular expression.
                rf"(?:(?<![\w$.])|\b(?:child_process|childProcess|cp|proc|shell)\s{{0,4}}\.\s{{0,4}})"
                rf"(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|eval)\s{{0,4}}\(\s{{0,4}}"
                rf"(?:(?:String|Buffer\.from|JSON\.parse)\s{{0,4}}\(\s{{0,4}})?`?(?:\$\{{\s{{0,4}})?{arg}\b",
                handler,
            )
            if run is None:
                continue
            offset = received.end() + run.start()
            start = len(text[:offset].encode("utf-8"))
            egress = len(text[: connection.start()].encode("utf-8"))
            return [
                CapabilityHit(
                    capability=Capability.EGRESS,
                    rule_id="CAP.JS.RECEIVED_RUN",
                    byte_start=egress,
                    byte_end=egress + 1,
                    line=text.count("\n", 0, connection.start()) + 1,
                ),
                CapabilityHit(
                    capability=Capability.FETCH_EXEC,
                    rule_id="CAP.JS.RECEIVED_RUN",
                    byte_start=start,
                    byte_end=start + 1,
                    line=text.count("\n", 0, offset) + 1,
                ),
            ]
        return []

    #: Bytes turned into something else by a key: an XOR loop over a buffer, a cipher, base64.
    #: Decompression is not one -- a binary installer inflates a release, makes it executable and
    #: starts it, which is its job.
    _JS_BYTES_TRANSFORMED: ClassVar[re.Pattern[str]] = re.compile(
        r"\b[\w$]{1,40}\s{0,4}\[\s{0,4}[\w$]{1,40}\s{0,4}\]\s{0,4}\^=|\bcreateDecipher(?:iv)?\s{0,4}\("
    )
    #: Read from a file: what the transform works on is something the package carries.
    _JS_READS_FILE: ClassVar[re.Pattern[str]] = re.compile(r"\breadFile(?:Sync)?\s{0,4}\(")
    #: Written to disk.
    _JS_WRITES_FILE: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:writeFile(?:Sync)?|createWriteStream)\s{0,4}\("
    )
    #: What is written is a program: executable mode, an executable's own magic checked, or a
    #: program's file name.
    _JS_PROGRAM_WRITTEN: ClassVar[re.Pattern[str]] = re.compile(
        r"\bmode\s{0,4}:\s{0,4}0o?7[0-7]{2}\b|\bchmod(?:Sync)?\s{0,4}\(|0x4[dD]\b[^\n]{0,80}0x5[aA]\b"
        r"|['\"]MZ['\"]|0x7[fF]\b[^\n]{0,40}0x45\b[^\n]{0,40}0x4[cC]\b"
        r"|\.(?:exe|dll|scr|bat|cmd|ps1|vbs|hta)['\"`]"
    )
    _JS_STARTS_PROCESS: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s{0,4}\("
    )

    @classmethod
    def decoded_program_run(cls, content: FileContent) -> list[CapabilityHit]:
        """JavaScript that turns a file it carries into a program, writes it and starts it.

        A data file shipped beside the code, XOR-decrypted byte by byte, checked for `MZ`, written
        with mode 0755 and run hidden, from a function the module calls on load: the clone of
        winston published as `@winstan/binston` (review 98, npm work half); the same with a cipher
        in `@builderius/sense-ai`. In order -- a file read, its bytes XOR-ed or deciphered, written
        as a program, started -- within 3,000 characters. Base64 and decompression are not the
        transform: across 98,499 benign units they were bundles and installers doing their job."""
        text = content.text
        if len(text) > 4_000_000 or not cls._JS_READS_FILE.search(text):
            return []
        for found in cls._JS_BYTES_TRANSFORMED.finditer(text):
            read = cls._JS_READS_FILE.search(text, max(0, found.start() - 1500), found.start())
            window = text[found.start() : found.start() + 3000]
            write = cls._JS_WRITES_FILE.search(window)
            if read is None or write is None or not cls._JS_PROGRAM_WRITTEN.search(window):
                continue
            run = cls._JS_STARTS_PROCESS.search(window, write.end())
            if run is None:
                continue
            offset = found.start() + run.start()
            start = len(text[:offset].encode("utf-8"))
            return [
                CapabilityHit(
                    capability=Capability.DECODE,
                    rule_id="CAP.JS.DECODED_PROGRAM_RUN",
                    byte_start=start,
                    byte_end=start + 1,
                    line=text.count("\n", 0, offset) + 1,
                )
            ]
        return []

    #: A command started for its output: the callback's stdout, or what `execSync` returns.
    _JS_COMMAND_OUTPUT: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:(?<![\w$.])|\b(?:child_process|childProcess|cp)\s{0,4}\.\s{0,4})exec(?:File)?\s{0,4}\("
        r"[^;]{0,600}?\(\s{0,4}[\w$]{1,40}\s{0,4},\s{0,4}(?P<cb>[\w$]{1,40})"
        r"|\b(?:const|let|var)\s{1,4}(?P<sync>[\w$]{1,40})\s{0,4}=\s{0,4}(?:[\w$]{1,40}\s{0,4}\.\s{0,4})?"
        r"exec(?:File)?Sync\s{0,4}\("
    )

    @classmethod
    def command_output_sent(
        cls, content: FileContent, ctx: ScanContext | None = None
    ) -> list[CapabilityHit]:
        """JavaScript that runs a command and puts what it printed into a request.

        `exec(cmd, (e, stdout) => { const data = stdout || stderr; req.write(data) })` from a
        preinstall hook: the `elf-stats-*` packages grep the machine and post the result (review
        98, npm work half). Each half is ordinary -- a build runs commands, a client posts -- and
        the flow between them is the act. Followed through one assignment, within 2,500
        characters of the process start."""
        text = content.text
        # A bundle runs its tools' commands and calls its own APIs a line apart (a minified editor
        # extension calling `gh` and GitHub's API matched); the payloads were written by hand.
        from cordon_scanner.detect.code.capability.detector import CapabilityDetector

        if len(text) > 4_000_000 or "exec" not in text or CapabilityDetector._is_minified(content):
            return []
        for started in cls._JS_COMMAND_OUTPUT.finditer(text):
            output = started["cb"] or started["sync"]
            window = text[started.end() : started.end() + 2500]
            names = {output}
            for assigned in re.finditer(
                r"\b(?:const|let|var)\s{1,4}([\w$]{1,40})\s{0,4}=\s{0,4}([^;\n]{1,200})", window
            ):
                if any(re.search(rf"\b{re.escape(n)}\b", assigned.group(2)) for n in names):
                    names.add(assigned.group(1))
            alternatives = "|".join(re.escape(n) for n in names)
            # Into a request: the body of an `http(s).request` written in this window, a `body:` or
            # a POST's data -- never a webview message or a process's output stream.
            request = re.search(
                r"\bhttps?\s{0,4}\.\s{0,4}request\s{0,4}\(|['\"`]https?://|\bhostname\s{0,4}:",
                window,
            )
            sink = re.search(
                rf"\.\s{{0,4}}(?:write|end)\s{{0,4}}\(\s{{0,4}}(?:JSON\.stringify\(\s{{0,4}})?(?:{alternatives})\b"
                rf"|\bbody\s{{0,4}}:\s{{0,4}}(?:JSON\.stringify\(\s{{0,4}})?(?:{alternatives})\b"
                rf"|\.\s{{0,4}}(?:post|put)\s{{0,4}}\([^,]{{1,300}},\s{{0,4}}(?:{alternatives})\b",
                window,
            )
            if sink is None or request is None:
                continue
            offset = started.end() + sink.start()
            start = len(text[:offset].encode("utf-8"))
            return [
                CapabilityHit(
                    capability=Capability.FLOW,
                    rule_id="CAP.JS.COMMAND_OUTPUT_SENT",
                    byte_start=start,
                    byte_end=start + 1,
                    line=text.count("\n", 0, offset) + 1,
                )
            ]
        return cls.command_output_flowed(content, ctx)

    @classmethod
    def npm_lifecycle_code(cls, content: FileContent, ctx: ScanContext | None) -> bool:
        """A file an npm package's own install script runs, or one it imports.

        Narrower than install context: a skill's scripts and an editor extension's entry point are
        graded as install code elsewhere, because they run unasked, but they are programs a person
        uses, and they call their own services with the user's name and the repository's by
        design (review 98: an extension's activation code, a CI helper, a commit tool).
        """
        from cordon_scanner.detect.code.capability.detector import CapabilityDetector

        return (
            ctx is not None
            and ctx.distribution == "npm"
            and ctx.in_install_hook(content.path)
            and not CapabilityDetector._agent_run(content, ctx)
        )

    @classmethod
    def command_output_flowed(
        cls, content: FileContent, ctx: ScanContext | None = None
    ) -> list[CapabilityHit]:
        """The same act written as real installers write it: through a helper that returns the
        output, an array it is collected in, a request's URL or path (`JavaScriptCommandFlow`).

        Read only in npm lifecycle code (`npm_lifecycle_code`). Outside it the same flow is a
        commit message tool sending `git diff` to its model, a CLI reporting its version, an
        editor extension calling its own API: on the benign npm and Open VSX corpora it blocked
        11 packages for one more catch (review 98, 17-PROOF-REVIEW).
        """
        from cordon_scanner.detect.code.secretflow import JavaScriptCommandFlow

        if not cls.npm_lifecycle_code(content, ctx):
            return []
        text = content.text
        for offset in JavaScriptCommandFlow.findings(text):
            start = len(text[:offset].encode("utf-8"))
            return [
                CapabilityHit(
                    capability=Capability.FLOW,
                    rule_id="CAP.JS.COMMAND_OUTPUT_SENT",
                    byte_start=start,
                    byte_end=start + 1,
                    line=text.count("\n", 0, offset) + 1,
                )
            ]
        return []


__all__ = ["JsRuns"]
