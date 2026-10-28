"""Labelling: what a file can do, recorded as capability hits.

The capability rules run over a file's bytes, over string fragments joined back together, over the
shell commands written inside other languages, and over the parsed tree where the patterns cannot
see: `kind: ast` rules, a compiled Java class's constant pool, a browser store opened and decrypted,
and egress to a destination that means something on its own. On their own these are observations,
not accusations; the composite reasoning in the detector is what combines them."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.python.pyast import PythonSource
from cordon_scanner.analysis.shared import embedded
from cordon_scanner.analysis.shared.documentation import DocumentationSpans
from cordon_scanner.analysis.shared.source_paths import SourcePaths
from cordon_scanner.detect.base import (
    FileUnit,
    RuleSelector,
    ScanContext,
)
from cordon_scanner.detect.code.addresses import PublicAddress
from cordon_scanner.detect.code.capability.build_output import BuildOutput
from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.detect.code.capability.javascript import JavaScriptCapabilities
from cordon_scanner.detect.code.capability.memo import CapabilityMemo
from cordon_scanner.detect.code.capability.text_position import TextPosition
from cordon_scanner.detect.secrets.secrets import SourceSpans
from cordon_scanner.foundation.capabilities import Capability, MatchKind
from cordon_scanner.foundation.text.comments import SourceComments

if TYPE_CHECKING:
    from cordon_scanner.analysis.shared.embedded import Command
    from cordon_scanner.foundation.content import FileContent
    from cordon_scanner.rules.loader import CompiledRule

MAX_VARIANTS = 8
"""Distinct operations counted per rule before the count stops mattering.

Depth beyond a handful changes no conclusion, and the cap is what keeps a
generated file with a thousand matches from being scanned in full."""

MAX_MATCHES_EXAMINED = 64
"""Occurrences examined per rule while counting distinct operations."""


class Labelling:
    """The capability hits of one file, from its bytes and its parsed tree."""

    @classmethod
    def folded_capabilities(
        cls,
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
        from cordon_scanner.analysis.javascript.js_eval import JsEval
        from cordon_scanner.analysis.javascript.js_fold import JsFold
        from cordon_scanner.foundation.content import FileContent

        text = content.text
        folded = JsFold.fold(text) if "+" in text and JsFold.has_fragments(text) else text
        # And the names and strings the file computes from constants (`detect/js_eval.py`):
        # decoders of character codes, hex and base64, `.concat` chains, `require` under an alias.
        decoded_lines: list[int] = []
        # Hand-written loaders are small; a bundle reuses its short names across scopes, and a
        # constant bound "once" there is a different variable in each function (review 98: a
        # BigQuery extension's 480-line bundle).
        if (
            len(text) <= JavaScriptCapabilities.JS_EVAL_MAX_BYTES
            and JavaScriptCapabilities.JS_EVAL_MARKERS.search(text)
            and not BuildOutput.bundled(content)
        ):
            try:
                folded, decoded_lines = JsEval.resolve_with_decodes(folded)
            except (IndexError, KeyError, ValueError, TypeError, RecursionError):
                # The evaluator reads hostile, malformed and unusual code. If it ever trips on a
                # file, the file is read as written -- every other rule still applies -- rather
                # than the scan failing.
                decoded_lines = []
        elif len(text) <= JavaScriptCapabilities.JS_EVAL_MAX_BYTES and not BuildOutput.bundled(
            content
        ):
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
        for hit in CapabilityMemo.hits(cls, view, candidates, language):
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

    @classmethod
    def match_capabilities(
        cls,
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
        blocks, delays, folded, hits, prose, raw, tests = Labelling._excused_spans(
            candidates, content, language
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

            first = Labelling._examine_matches(
                blocks,
                capability,
                compiled,
                content,
                delays,
                distinct,
                first,
                language,
                prose,
                raw,
                regex,
                tests,
            )

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

    @staticmethod
    def _excused_spans(
        candidates: tuple[CompiledRule, ...], content: FileContent, language: str | None
    ) -> tuple[
        tuple[tuple[int, int], ...],
        frozenset[int],
        bytes | None,
        list[CapabilityHit],
        tuple[tuple[int, int], ...],
        bytes,
        tuple[tuple[int, int], ...],
    ]:
        """The regions of the file whose matches do not count: block comments, Rust test modules, Python docstrings, deferred function bodies, and the fold of split string fragments."""
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
        return blocks, delays, folded, hits, prose, raw, tests

    @staticmethod
    def _examine_matches(
        blocks: tuple[tuple[int, int], ...],
        capability: Capability,
        compiled: CompiledRule,
        content: FileContent,
        delays: frozenset[int],
        distinct: set[bytes],
        first: re.Match[bytes] | None,
        language: str | None,
        prose: tuple[tuple[int, int], ...],
        raw: bytes,
        regex: re.Pattern[bytes],
        tests: tuple[tuple[int, int], ...],
    ) -> re.Match[bytes] | None:
        """Walk one rule's matches in the file, dropping each the text's position excuses, counting the distinct operations it shows, and keeping the first that stands."""
        for index, match in enumerate(regex.finditer(raw)):
            if TextPosition.is_printed_text(content, match.start(), match.end()):
                continue
            if (
                capability is Capability.FETCH_EXEC
                and compiled.rule.id not in Labelling.QUOTED_BY_DESIGN
                and TextPosition.is_quoted_pipeline(content, match.start(), match.end())
            ):
                # A `|` inside quotes is not a pipeline. See `_is_quoted_pipeline`.
                continue
            if capability is Capability.SPAWN and TextPosition.is_literal_backtick(
                content, match.start()
            ):
                # A backtick inside single quotes is a character, not a substitution.
                # See `_is_literal_backtick`.
                continue
            if TextPosition.is_declaration(content, match.start(), match.end()):
                # `export function fetch(` defines a name; it does not call one. See
                # `DECLARATION` and `SIGNATURE_ARGUMENT`.
                continue
            if TextPosition.is_example_line(content, match.start()):
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
                Labelling.narrowed_environment(content, match.end())
            ):
                # The environment enumerated, then cut down to one prefix or handed to a
                # child process. See `_narrowed_environment`.
                continue
            if compiled.rule.id == "CAP.ANTI.ENVIRONMENT.001" and (
                Labelling._courtesy_gate(content, match.start())
            ):
                # A CI read beside a user's opt-out or a terminal test. See
                # `_courtesy_gate`.
                continue
            if SourceComments.inside_spans(blocks, match.start()) or TextPosition.is_comment(
                content, match.start(), language
            ):
                # A comment does not run. `misc/error_handler.func` in
                # `community-scripts/ProxmoxVE` explains in a comment that
                # `systemd-detect-virt` reports lxc inside a container, and that
                # sentence was reported as a check for being observed.
                continue
            if capability is Capability.EGRESS and (
                TextPosition.is_local_target(content, match.start())
                or TextPosition.is_tool_probe(content, match.start())
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
        return first

    COURTESY_GATE: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"\b(?:DO_NOT_TRACK|NO_UPDATE_NOTIFIER|NO_COLOR|FORCE_COLOR|[A-Z0-9_]*TELEMETRY[A-Z0-9_]*"
        rb"|[A-Z0-9_]*_NO_ANALYTICS|[A-Z0-9_]*_DISABLE_(?:ANALYTICS|UPDATE_CHECK|NOTIFIER))\b"
        rb"|\.\s*isTTY\b|\bisatty\s*\("
    )

    NARROWED_ENVIRONMENT: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"\.\s{0,4}filter\s{0,4}\(\s{0,4}\(?\s{0,4}[\w$]{1,20}\s{0,4}\)?\s{0,4}=>\s{0,4}/\^[A-Za-z_]{2,30}"
        rb"|\.\s{0,4}startsWith\s{0,4}\(\s{0,4}[\"'`][A-Za-z][A-Za-z0-9]{1,30}_"
        rb"|\bELECTRON_RUN_AS_NODE\b"
    )

    @staticmethod
    def narrowed_environment(content: FileContent, end: int) -> bool:
        return Labelling.NARROWED_ENVIRONMENT.search(content.raw[end : end + 160]) is not None

    @staticmethod
    def _courtesy_gate(content: FileContent, offset: int) -> bool:
        raw = content.raw
        start = raw.rfind(b"\n", 0, offset) + 1
        end = raw.find(b"\n", offset)
        line = raw[start : end if end >= 0 else len(raw)]
        return Labelling.COURTESY_GATE.search(line) is not None

    #: Fetch-and-run rules whose construct is a command line held in a string: in JavaScript
    #: that is how a command reaches `exec()`, so the quoted-pipeline exception -- written for
    #: install hints like `"curl ... | sh"` -- does not apply to them.
    QUOTED_BY_DESIGN = frozenset({"CAP.JS.COMMAND_FETCH_RUN.001"})

    @staticmethod
    def drop_excused_pattern_hits(
        content: FileContent, hits: list[CapabilityHit]
    ) -> list[CapabilityHit]:
        """Pattern hits on lines the syntax tree shows to be harmless. See
        `PythonAnalyzer.excused_lines`."""
        from bisect import bisect_right

        from cordon_scanner.analysis.python.pyast import PythonAnalyzer

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

    @classmethod
    def resolved_capabilities(
        cls, unit: FileUnit, content: FileContent, ctx: ScanContext
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
            return cls._javascript_secret_flow(content, ctx), []
        if unit.language != "python":
            return [], []

        from cordon_scanner.analysis.python.pyast import PythonAnalyzer, PythonSource

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
                        cls._span_of_line(content, hit.line)[0] + hit.column,
                        cls._span_of_line(content, hit.line)[1],
                    ),
                    byte_end=cls._span_of_line(content, hit.line)[1],
                    line=hit.line,
                    fixed=hit.fixed_command,
                    resolved=True,
                )
                for hit in resolved
            ],
            [embedded.Command(text=hit.command, line=hit.line) for hit in resolved if hit.command],
        )

    @classmethod
    def _javascript_secret_flow(
        cls, content: FileContent, ctx: ScanContext | None = None
    ) -> list[CapabilityHit]:
        """`FLOW.JS.SECRET_SENT`: a named credential in a request to a host outside its home.
        See `detect/secretflow.py`."""
        from cordon_scanner.detect.code.js_runs import JsRuns
        from cordon_scanner.detect.code.secretflow import JavaScriptFlow, JavaScriptLeak

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
            for offset, kind in JavaScriptLeak.findings(
                text, install=JsRuns.npm_lifecycle_code(content, ctx)
            )
        ]
        hits: list[CapabilityHit] = []
        for offset, capability, rule_id in sends:
            line = text.count("\n", 0, offset) + 1
            start, end = cls._span_of_line(content, line)
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

    DROP_POINT_RULE = "INTEL.EGRESS.DROP_POINT.001"

    INTERACTION_RULE = "INTEL.EGRESS.INTERACTION.001"

    @classmethod
    def ast_rule_capabilities(
        cls,
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

        from cordon_scanner.analysis.shared.ast_providers import AstProviders
        from cordon_scanner.analysis.shared.segmented_parse import WholeFileCalls

        # Rule selection already restricted `candidates` to this file's language,
        # so an ast rule here is one that applies to it. Resolve with the
        # language's provider, or return nothing when none is installed -- the
        # regex tier still ran over the file, so this is an addition that is
        # absent, not a gap that is hidden.
        provider = AstProviders.ast_provider_for(language)
        if provider is None:
            return []

        # A piece of a larger file -- its prefix, a window -- takes its calls from the whole file,
        # parsed once a statement at a time (`segmented_parse`): a piece cut inside a string parsed
        # on its own read the string as code, at a hundred times the cost.
        part = content.part_of
        whole = None
        if part is not None and hasattr(provider, "resolve_parts"):
            whole = WholeFileCalls.view(provider, part[0], part[1], content.raw)
        calls = provider.resolve_calls(content.text) if whole is None else whole
        if not calls:
            return []

        hits: list[CapabilityHit] = []
        for compiled in ast_rules:
            capability = compiled.rule.capability
            if capability is None:
                continue
            for call in compiled.match.ast_query.matching(calls):
                line_start, line_end = cls._span_of_line(content, call.line)
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

    _DETECTION_RULES: ClassVar[re.Pattern[str]] = re.compile(
        r"(?m)^[ \t]{0,8}tests:[ \t]*\n[ \t]{0,12}positive:[ \t]*$"
        r"|^[ \t]{0,8}(?:pattern-either|pattern-inside|patterns):[ \t]*$"
    )

    _SIGMA: ClassVar[tuple[re.Pattern[str], re.Pattern[str]]] = (
        re.compile(r"(?m)^detection:[ \t]*$"),
        re.compile(r"(?m)^[ \t]{1,8}condition:[ \t]"),
    )

    @classmethod
    def rule_pack(cls, content: FileContent) -> bool:
        """A detection rule pack -- Cordon's, Semgrep's, Sigma's.

        It writes down the attacks it detects as patterns and sample lines, as a rule file does
        (`RuleSelector.select_rules`): nothing runs them, and read as code every such file reports
        the malware it describes.
        """
        return (
            content.path.lower().endswith((".yaml", ".yml"))
            and not content.is_binary
            and (
                cls._DETECTION_RULES.search(content.text[:20_000]) is not None
                or all(p.search(content.text[:20_000]) for p in cls._SIGMA)
            )
        )

    _JVM_FETCH: ClassVar[frozenset[str]] = frozenset(
        {
            "java/net/URL.openConnection",
            "java/net/URL.openStream",
            "java/net/URLConnection.getInputStream",
            "java/net/HttpURLConnection.getInputStream",
            "java/net/http/HttpClient.send",
        }
    )

    _JVM_RUN: ClassVar[frozenset[str]] = frozenset(
        {
            "groovy/lang/GroovyShell.evaluate",
            "groovy/lang/GroovyShell.parse",
            "javax/script/ScriptEngine.eval",
            "java/lang/ClassLoader.defineClass",
            "java/lang/invoke/MethodHandles$Lookup.defineClass",
        }
    )

    _JVM_LOAD: ClassVar[frozenset[str]] = frozenset(
        {"java/lang/Class.forName", "java/lang/ClassLoader.loadClass"}
    )

    @classmethod
    def jvm_class(
        cls, unit: FileUnit, ctx: ScanContext
    ) -> tuple[list[CapabilityHit], tuple[CompiledRule, ...]] | None:
        """A compiled Java class, judged by what its constant pool says it does (`jvm_class.py`).

        Like a .NET assembly, a class lists every API it touches in one table, so "a request beside
        an execution" says nothing there. Two acts are read precisely: what the class fetches,
        handed to an evaluator (GroovyShell, ScriptEngine, defineClass); and a class loaded from a
        web address added to the system class loader through reflection. Command lines among its
        constants go to the shell rules as commands written in source do (review 98: two
        brandjacked Maven plugins carried both in bytecode their published sources did not have).
        """
        from cordon_scanner.analysis.jvm.jvm_class import JvmClass
        from cordon_scanner.foundation.content import FileContent

        content = unit.content
        if content.size > 5_000_000:
            return None
        refs = JvmClass.references(content.raw)
        if refs is None:
            return None
        lines = ["// JVM constant pool: the members this class calls, then its string constants"]
        lines.extend(sorted(refs.calls))
        lines.extend('"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"' for s in refs.strings)
        raw = "\n".join(lines).encode("utf-8")
        view = FileContent(path=content.path, raw=raw, size=len(raw))
        candidates = RuleSelector.select_rules(ctx.rules, language="java", path=content.path)
        if not candidates:
            return None
        hits: list[CapabilityHit] = []
        # The class makes a URL of a web address it carries. A class loader opens jar URLs and
        # defines classes from them (classworlds), and a generator names an XML namespace, and
        # neither builds a URL from a web literal: on 4,999 benign Maven jars nothing did both
        # with an evaluator or a reflective `addURL` (review 98).
        web = "java/net/URL.<init>" in refs.calls and any(
            s.startswith(("http://", "https://")) for s in refs.strings
        )
        fetched_run = web and bool(refs.calls & cls._JVM_FETCH) and bool(refs.calls & cls._JVM_RUN)
        remote_class = (
            web
            and "addURL" in refs.strings
            and "java/lang/reflect/Method.setAccessible" in refs.calls
            and bool(refs.calls & cls._JVM_LOAD)
        )
        if fetched_run or remote_class:
            for capability in (Capability.EGRESS, Capability.FETCH_EXEC):
                hits.append(
                    CapabilityHit(
                        capability=capability,
                        rule_id="CAP.JVM.CLASS_FETCH_RUN",
                        byte_start=0,
                        byte_end=0,
                        line=1,
                    )
                )
        commands = [
            embedded.Command(s[:4000], number)
            for number, s in enumerate(refs.strings, len(refs.calls) + 2)
            if cls.DOTNET_COMMAND.search(f'"{s}"')
        ]
        commands = embedded.EmbeddedCommands.decode_encoded_commands(commands)
        hits.extend(cls.embedded_capabilities(ctx, view, commands))
        return hits, candidates

    #: A string literal in a compiled assembly that is a command line, handed to the shell rules.
    DOTNET_COMMAND: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\b(?:powershell|pwsh|cmd(?:\.exe)?\s*/c|invoke-webrequest|iwr|invoke-expression|iex|"
        r"start-process|curl|wget|bitsadmin|certutil|mshta|rundll32|regsvr32|/bin/(?:ba)?sh)\b"
    )

    #: A browser's saved logins or cookies, by the files they live in.
    _BROWSER_STORE: ClassVar[re.Pattern[str]] = re.compile(
        r"[/\\\"'](?:Login\s?Data|Cookies|Web\s?Data)(?=[\"'/\\]|\s*$)|\b(?:logins\.json|key[34]\.db|cookies\.sqlite)\b"
    )

    #: Turning them back into plaintext: Windows DPAPI, Chrome's os_crypt key in `Local State`,
    #: the macOS keychain item Chromium browsers keep their key in.
    _BROWSER_DECRYPT: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:CryptUnprotectData|[Dd][Pp][Aa][Pp][Ii]|crypt32|win32crypt|ProtectedData\.Unprotect|os_crypt"
        r"|encrypted_key"
        r"|Chrome Safe Storage|Brave Safe Storage|Edge Safe Storage)\b"
    )

    @classmethod
    def browser_secrets_decrypted(cls, content: FileContent) -> list[CapabilityHit]:
        """A file that opens a browser's saved-login or cookie store and decrypts what is in it.

        Reading the database is what a browser does; turning its values back into plaintext with
        the user's DPAPI key or the browser's own key is what a stealer does, whether it sends them
        at once or leaves them for a second stage (review 98: `chrome_taker` on RubyGems wrote
        Chrome's passwords and cookies to a file). Dual-use tools that import cookies from a
        browser do it too; measured before it may block."""
        text = content.text
        if len(text) > 4_000_000:
            return []
        store = cls._BROWSER_STORE.search(text)
        if store is None or cls._BROWSER_DECRYPT.search(text) is None:
            return []
        start = len(text[: store.start()].encode("utf-8"))
        return [
            CapabilityHit(
                capability=Capability.CREDENTIAL,
                rule_id="CAP.CREDENTIAL.BROWSER_DECRYPT",
                byte_start=start,
                byte_end=start + 1,
                line=text.count("\n", 0, store.start()) + 1,
            )
        ]

    @classmethod
    def destination_capabilities(
        cls, content: FileContent, language: str | None = None
    ) -> list[CapabilityHit]:
        """Egress to a destination that means something on its own.

        Webhook ingest URLs, anonymous paste and file-drop services, and
        out-of-band interaction hosts. None of these is a finding by itself --
        software does post to webhooks -- but each is a place with no reason to
        appear in a build, an install script or a library, so it raises what an
        outbound request in that file is worth.

        The host list lives in `analysis/shared/destinations.py` rather than in a pattern pack.
        A pack would have to restate it, and a restated blocklist drifts, which
        is worse than a short one because it still looks maintained.
        """
        from cordon_scanner.analysis.shared.destinations import Destinations

        raw = content.raw
        literal_ip = cls.public_ip_url(content, language)

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
        # see `analysis.shared.documentation.DocumentationSpans.of` for the case that found it. The
        # later occurrences are still considered, because the first being prose
        # says nothing about the rest of the file.

        ignore = DocumentationSpans.of(raw, language)
        blocks = SourceComments.block_comment_spans(content.text, language)

        match = None
        for candidate in Destinations.destination_matcher().finditer(raw):
            offset = candidate.start()
            if SourceComments.inside_spans(ignore, offset) or SourceComments.inside_spans(
                blocks, offset
            ):
                continue
            if TextPosition.is_comment(content, offset, language):
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
        from cordon_scanner.analysis.shared.destinations import Destinations

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
    def public_ip_url(cls, content: FileContent, language: str | None) -> list[CapabilityHit]:
        """A URL, or a host setting, whose host is a literal public IPv4 address.

        Services are reached by name; a payload posting the environment to
        `http://54.242.228.151:8090/` does not have one. Loopback, private, link-local -- the
        cloud metadata service at 169.254.169.254 -- and the documentation ranges are ordinary
        in code and tests and are not counted.
        """

        ignore: tuple[tuple[int, int], ...] | None = None
        raw = content.raw
        matches = [
            *(cls._IP_URL.finditer(raw) if cls._IP_URL_GATE.search(raw) else ()),
            *(cls._IP_HOST.finditer(raw) if cls._IP_HOST_GATE.search(raw) else ()),
        ]
        for match in sorted(matches, key=lambda m: m.start()):
            octets = [int(part) for part in match.groups()]
            if any(o > 255 for o in octets) or not PublicAddress.is_public(octets):
                continue
            if tuple(octets) in cls._RESOLVERS:
                continue
            # Docstrings are worked out only once a public address is found: almost no file has
            # one, and the spans mean parsing the file.
            if ignore is None:
                ignore = DocumentationSpans.of(content.raw, language)
            if SourceComments.inside_spans(ignore, match.start()) or TextPosition.is_comment(
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

    @classmethod
    def embedded_capabilities(
        cls, ctx: ScanContext, content: FileContent, commands: list[Command]
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
                start, end = cls._span_of_line(content, command.line)
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


__all__ = ["Labelling"]
