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
from dataclasses import replace
from typing import TYPE_CHECKING

from cordon_scanner.analysis.javascript.js_persist import JsPersistence
from cordon_scanner.analysis.nix.nix_code import NixCode
from cordon_scanner.analysis.shared import embedded
from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    FileUnit,
    RuleSelector,
    ScanContext,
)
from cordon_scanner.detect.code.capability.anchor import FindingAnchor
from cordon_scanner.detect.code.capability.build_output import BuildOutput
from cordon_scanner.detect.code.capability.composites import CompositeEvaluator
from cordon_scanner.detect.code.capability.destinations import DestinationLabels
from cordon_scanner.detect.code.capability.grading import CompositeGrading
from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.detect.code.capability.javascript import JavaScriptCapabilities
from cordon_scanner.detect.code.capability.labelling import Labelling
from cordon_scanner.detect.code.capability.legitimate_use import LegitimateUse
from cordon_scanner.detect.code.capability.memo import CapabilityMemo
from cordon_scanner.detect.code.capability.rule_ids import CompositeRuleIds
from cordon_scanner.detect.code.capability.text_position import TextPosition
from cordon_scanner.detect.code.credential_sweep import CredentialSweep
from cordon_scanner.detect.code.decode_run import DecodeRun
from cordon_scanner.detect.code.install_payload import InstallPayload
from cordon_scanner.detect.code.keychain_owner import KeychainOwner
from cordon_scanner.detect.infra.gradle_auth import GradleBuildAuth
from cordon_scanner.foundation.capabilities import Capability, MatchKind
from cordon_scanner.foundation.models import Category, Finding

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import Unit
    from cordon_scanner.foundation.content import FileContent
    from cordon_scanner.rules.loader import CompiledRule


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
    version = "0.13.0"  # decode-run composites drop a spawn nothing decoded reaches (decode_run)
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
        labelled = self.labelled(unit, ctx)
        if labelled is None:
            return ()
        hits, candidates = labelled
        return list(self._composite_findings(unit, ctx, hits, candidates))

    def labelled(
        self, unit: FileUnit, ctx: ScanContext
    ) -> tuple[list[CapabilityHit], tuple[CompiledRule, ...]] | None:
        """The file's capability hits and the rules selected for it; None when no rule applies.

        What the composites are evaluated over, and what another detector asks when it needs
        to know what a piece of code can do: the manifest asks it of a hook's inline program.
        """
        content = unit.content
        language = unit.language
        if Labelling.rule_pack(content):
            return None
        dotnet_commands: list[embedded.Command] = []
        assembly_view = False

        # Binary files are excluded from content rules. A byte sequence in a PNG
        # that happens to spell a pattern is a false positive with no upside,
        # and the file was never source to begin with.
        #
        # A compiled .NET assembly is the exception: its metadata says, in readable form, every
        # member it calls and every string literal its code uses (`detect/dotnet_meta.py`). The
        # C# rules read that view as they read source, and a literal that is a command line goes
        # to the shell rules as a command written in source does (review 98: 22 of 23 malicious
        # NuGet releases carried their payload only in a DLL).
        if content.path.lower().endswith(".class") and content.raw[:4] == b"\xca\xfe\xba\xbe":
            return Labelling.jvm_class(unit, ctx)
        assembly = content.path.lower().endswith((".dll", ".exe")) and content.raw[:2] == b"MZ"
        if content.is_binary or assembly:
            if not assembly or content.size > 30_000_000:
                return None
            from cordon_scanner.analysis.dotnet.dotnet_meta import DotNetMetadata
            from cordon_scanner.foundation.content import FileContent

            data = content.raw
            if len(data) < content.size and content.window_source is not None:
                # An assembly past `max_file_bytes` keeps its metadata near the end: read it whole
                # (bounded above), or padding a DLL past the limit would hide what it calls.
                from contextlib import suppress

                from cordon_scanner.foundation.files.windows import WindowSourceChanged

                with suppress(OSError, WindowSourceChanged), content.window_source.reader() as read:
                    data = read(0, content.size)
            view = DotNetMetadata.view(data)
            if view is None:
                return None
            raw = view.encode("utf-8")
            content = FileContent(path=content.path, raw=raw, size=len(raw))
            language = "csharp"
            assembly_view = True
            for number, line in enumerate(view.splitlines(), 1):
                if line.startswith('"') and Labelling.DOTNET_COMMAND.search(line):
                    text = line[1:-1].replace('\\"', '"').replace("\\\\", "\\")
                    dotnet_commands.append(embedded.Command(text[:4000], number))

        candidates = RuleSelector.select_rules(ctx.rules, language=language, path=content.path)
        if not candidates:
            return None

        commands, hits, matched_content, resolved = CapabilityDetector._pattern_hits(
            assembly_view, candidates, content, ctx, dotnet_commands, language, unit
        )
        hits = CapabilityDetector._tree_capabilities(
            candidates, commands, content, ctx, hits, matched_content, resolved, unit
        )
        hits = TextPosition.off_this_machine(content, hits)
        if BuildOutput.bundled(content):
            # A compiled tool that schedules its own jobs (an agent runner's LaunchAgent, a
            # crontab writer) registers autostart entries as its feature; three Open VSX agent
            # extensions do it from dist/. The hand-written file is where an implant's is
            # (review 98).
            hits = [h for h in hits if h.rule_id != "CAP.JS.AUTOSTART.001"]
        return hits, candidates

    @staticmethod
    def _pattern_hits(
        assembly_view: bool,
        candidates: tuple[CompiledRule, ...],
        content: FileContent,
        ctx: ScanContext,
        dotnet_commands: list[embedded.Command],
        language: str | None,
        unit: FileUnit,
    ) -> tuple[list[embedded.Command], list[CapabilityHit], FileContent, list[CapabilityHit]]:
        """The pattern tier's hits and the commands written inside the file: matched over a Go file's own code, a .NET assembly's strings or the file as it is, with what the parsed tree resolves and the encoded commands decoded."""
        from cordon_scanner.foundation.content import FileContent

        matched_content = content
        if unit.language == "go" and content.size <= 2_000_000:
            # What the file builds at run time -- commands added up from a table of characters,
            # paths and endpoints XOR-decoded from byte tables -- written beside where it is built
            # (`detect/go_eval.py`), so the rules read the paths and hosts the code reaches.
            from cordon_scanner.analysis.go.go_eval import GoEval
            from cordon_scanner.foundation.content import FileContent

            view = GoEval.resolve(content.text)
            if view != content.text:
                raw = view.encode("utf-8")
                matched_content = FileContent(path=content.path, raw=raw, size=len(raw))
        if assembly_view:
            # A compiled assembly's member list puts every API it references within a few lines
            # of every other, so "a request beside an execution" says nothing there: on 489 benign
            # NuGet packages it blocked 121 (review 98). It is judged by the command lines its
            # code carries, read by the shell rules as commands written in source are.
            hits: list[CapabilityHit] = []
        else:
            hits = CapabilityMemo.hits(Labelling, matched_content, candidates, language)
            hits.extend(Labelling.folded_capabilities(matched_content, candidates, language, hits))
        resolved, commands = Labelling.resolved_capabilities(unit, content, ctx)
        commands = commands + dotnet_commands
        if not commands and language not in ("python", "csharp"):
            source = content.text
            if unit.language == "go":
                # A command assembled from a table of characters is read as the command it
                # becomes (`detect/go_eval.py`): the 2025 Go typosquats never wrote theirs down.
                from cordon_scanner.analysis.go.go_eval import GoEval

                source = GoEval.resolve(source)
            commands = embedded.EmbeddedCommands.extract(source, unit.language)
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
        return commands, hits, matched_content, resolved

    @staticmethod
    def _tree_capabilities(
        candidates: tuple[CompiledRule, ...],
        commands: list[embedded.Command],
        content: FileContent,
        ctx: ScanContext,
        hits: list[CapabilityHit],
        matched_content: FileContent,
        resolved: list[CapabilityHit],
        unit: FileUnit,
    ) -> list[CapabilityHit]:
        """The capabilities read from the file's structure rather than its bytes: parsed-tree and ast rules, embedded shell, destinations, the JavaScript flows and campaigns, credential sweeps, browser stores, Go and Nix specifics."""
        # And the plaintext of an encoded command the script runs at its own top
        # level, which is handed to no call and so reaches neither branch above.
        if unit.language in embedded.SCRIPT_LANGUAGES:
            commands.extend(embedded.EmbeddedCommands.encoded_commands_in(content.text))
        hits.extend(resolved)
        hits.extend(Labelling.ast_rule_capabilities(content, candidates, unit.language))
        if unit.language == "python" and any(
            h.capability
            in (Capability.EXECUTE, Capability.CREDENTIAL, Capability.DECODE, Capability.PERSIST)
            or h.rule_id == "CAP.EGRESS.DNS_CONSTRUCTED.001"
            for h in hits
        ):
            hits = Labelling.drop_excused_pattern_hits(content, hits)
        if unit.language in ("javascript", "typescript"):
            hits = JsPersistence.drop_named_only(content, hits)
        if GradleBuildAuth.is_build_script(content.path) and any(
            h.capability is Capability.CREDENTIAL for h in hits
        ):
            # A build's own signing passwords and publishing tokens (`detect/gradle_auth.py`).
            hits = GradleBuildAuth.drop_build_auth(content.text, hits, Capability.CREDENTIAL)
        hits.extend(Labelling.embedded_capabilities(ctx, content, commands))
        hits.extend(DestinationLabels.destination_capabilities(content, unit.language))
        hits.extend(JavaScriptCapabilities.js_downloaded_and_run(content, unit.language))
        hits.extend(JavaScriptCapabilities.js_wallet_secret_sent(content, unit.language))
        hits.extend(JavaScriptCapabilities.js_flows(content, unit.language))
        from cordon_scanner.detect.code.js_campaigns import JsCampaigns

        hits.extend(JsCampaigns.channel_follow(content, unit.language))
        hits.extend(JsCampaigns.plants_agent_config(ctx, content, unit.language))
        hits.extend(JsCampaigns.attribution_cloak(content, unit.language))
        computed = JavaScriptCapabilities.js_computed_require(content, unit.language)
        hits.extend(computed)
        if computed and not BuildOutput.bundled(content):
            # The same, in a hand-written file: the install-time composite may convict on this alone.
            # A bundle's loader computes module names by construction (review 98: two extensions'
            # dist/extension.js).
            first = computed[0]
            hits.append(replace(first, rule_id="CAP.JS.COMPUTED_REQUIRE_SOURCE"))
        hits.extend(JavaScriptCapabilities.js_spelled_names(content, unit.language))
        hits.extend(JavaScriptCapabilities.js_string_code_run(content, unit.language))
        hits.extend(CredentialSweep.hits(matched_content))
        hits.extend(Labelling.browser_secrets_decrypted(matched_content))
        if unit.language == "go":
            from cordon_scanner.detect.code.go_runs import GoRuns

            hits.extend(GoRuns.ci_environment_write(matched_content))
            hits.extend(GoRuns.received_and_run(content))
        if unit.language in ("javascript", "typescript"):
            from cordon_scanner.detect.code.js_runs import JsRuns

            hits.extend(JsRuns.received_and_run(content))
            hits.extend(JsRuns.decoded_program_run(content))
            hits.extend(JsRuns.command_output_sent(content, ctx))
        hits.extend(ScriptFetchedThenEvaluated.hits(content, unit.language))
        # A truncated file is reported by the engine, which reads every file and so sees every
        # truncation; this detector returns early for some.
        # The rest of an oversized file is read by the engine, in windows, with every rule here
        # and the other text detectors (`foundation/files/windows.py`), on the serial path and in the pool.
        if NixCode.is_nix(content.path):
            # What a Nix file declares does not run (`detect/nix_code.py`).
            hits = NixCode.keep_running(content.text, hits)
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
        # decode twice. That reasoning lives in `CompositeEvaluator._evaluate_over`, which is
        # where the counting now happens, because a composite with a proximity
        # counts what is inside its window rather than what is in the file.
        in_hook = ctx.in_install_hook(unit.path)
        in_ci = ctx.in_ci_hook(unit.path)
        in_consumer = ctx.in_consumer_install(unit.path)
        # Read by the `install_entry` and `import_entry` terms; the evaluator is this file's own.
        evaluator = CompositeEvaluator(
            in_entry=unit.path in ctx.install_entry_paths,
            in_import_entry=unit.path in ctx.import_entry_paths,
        )
        # Install-time context is decided per WINDOW, not per file. A file is in
        # the closure because a hook imports it, and importing a module defines
        # its functions without calling them -- so a pair of capabilities inside
        # a body nothing reaches does not run at install time, whatever the file
        # does. See `ScanContext.install_hook_reaches`.
        deferred = CapabilityDetector._deferred_windows(ctx, unit, in_hook)

        decode_excused = DecodeRun.excused_lines(
            unit, hits, BuildOutput.bundled_path(unit.path), [c.rule.id for c in candidates]
        )
        for compiled in candidates:
            if compiled.match.kind is not MatchKind.COMPOSITE:
                continue
            if compiled.match.scope not in {"file", "function"}:
                continue

            rule_hits = CapabilityDetector._rule_hits(compiled, unit, hits, decode_excused)
            if compiled.rule.id in CompositeRuleIds.CONTEXT_FREE:
                window = evaluator.satisfying_window(
                    compiled, rule_hits, unit.path, False, False, False, frozenset()
                )
            else:
                window = evaluator.satisfying_window(
                    compiled, rule_hits, unit.path, in_hook, in_ci, in_consumer, deferred
                )
            if window is None:
                continue

            matched_capabilities = CompositeEvaluator.capabilities_of(compiled)
            if CapabilityDetector._authenticates(
                matched_capabilities, unit, window, in_hook, compiled, hits
            ):
                # Authentication, not exfiltration. See `LegitimateUse.credential_reaches_its_own_issuer`,
                # `LegitimateUse.store_used_by_its_own_client` and `keychain_owner`.
                continue

            local_by_capability = {hit.capability: hit for hit in window}
            if InstallPayload.gate(
                compiled.rule.id, in_hook or in_consumer, local_by_capability, window, unit, ctx
            ):
                continue
            matched = matched_capabilities
            anchor = FindingAnchor.anchor(matched, local_by_capability, window)

            finding = CompositeGrading(
                compiled,
                unit,
                ctx,
                anchor,
                matched,
                window,
                file_hits=hits,
                evaluator=evaluator,
                detector_id=self.id,
            ).finding()
            if finding is not None:
                yield finding

    @staticmethod
    def _deferred_windows(
        ctx: ScanContext, unit: FileUnit, in_hook: bool
    ) -> frozenset[tuple[int, int]]:
        """The line ranges of this file's bodies an install hook defines but never calls (only while it is in a hook)."""
        return (
            frozenset(
                (first, last)
                for path, first, last in ctx.install_deferred_lines
                if path == unit.path
            )
            if in_hook
            else frozenset()
        )

    @staticmethod
    def _rule_hits(
        compiled: CompiledRule,
        unit: FileUnit,
        hits: list[CapabilityHit],
        decode_excused: frozenset[int],
    ) -> list[CapabilityHit]:
        """The hits a composite rule counts: settings are not loot, a verifiable dropper's unpacker is not a payload, excused decode runs do not count."""
        return (
            [h for h in hits if not LegitimateUse.a_setting(unit.content, h)]
            if compiled.rule.id in CompositeRuleIds.SETTINGS_ARE_NOT_LOOT
            else [h for h in hits if not InstallPayload.spawns_unpacker(unit.content, h)]
            if compiled.rule.id in CompositeRuleIds.VERIFIABLE_DROPPERS
            else DecodeRun.hits_for(compiled.rule.id, hits, decode_excused)
        )

    @staticmethod
    def _authenticates(
        matched_capabilities: tuple[Capability, ...],
        unit: FileUnit,
        window: list[CapabilityHit],
        in_hook: bool,
        compiled: CompiledRule,
        hits: list[CapabilityHit],
    ) -> bool:
        """Whether the egress is authentication, not exfiltration: a credential sent to its own issuer, a store used by its own client, a keychain read by its owner."""
        return Capability.EGRESS in matched_capabilities and (
            (
                Capability.CREDENTIAL in matched_capabilities
                and LegitimateUse.credential_reaches_its_own_issuer(unit.content, window)
            )
            # Not at install time: nothing installing a package needs its user's keys, and
            # boto3 uploads just as well to a bucket the attacker owns.
            or (not in_hook and LegitimateUse.store_used_by_its_own_client(unit.content, window))
            or (
                not in_hook
                and compiled.rule.id == CompositeRuleIds.CREDENTIAL_STORE_RULE
                and KeychainOwner.excuses(unit.content, window, hits)
            )
        )


__all__ = ["CapabilityDetector"]
