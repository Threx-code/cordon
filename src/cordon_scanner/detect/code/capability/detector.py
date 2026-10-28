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
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.javascript.js_persist import JsPersistence
from cordon_scanner.analysis.nix.nix_code import NixCode
from cordon_scanner.analysis.python.inert_literals import InertLiterals
from cordon_scanner.analysis.shared import embedded
from cordon_scanner.analysis.shared.source_paths import FIXTURE_CEILING, SourcePaths
from cordon_scanner.decide.scoring import RiskScorer, ScoringContext
from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    FileUnit,
    RuleSelector,
    ScanContext,
)
from cordon_scanner.detect.code.capability.build_output import BuildOutput
from cordon_scanner.detect.code.capability.composites import CompositeEvaluator
from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.detect.code.capability.intent import IntentSignals
from cordon_scanner.detect.code.capability.javascript import JavaScriptCapabilities
from cordon_scanner.detect.code.capability.labelling import Labelling
from cordon_scanner.detect.code.capability.legitimate_use import LegitimateUse
from cordon_scanner.detect.code.capability.load_path import LoadPath
from cordon_scanner.detect.code.capability.memo import CapabilityMemo
from cordon_scanner.detect.code.capability.text_position import TextPosition
from cordon_scanner.detect.code.credential_sweep import CredentialSweep
from cordon_scanner.detect.code.decode_run import DecodeRun
from cordon_scanner.detect.code.install_payload import InstallPayload
from cordon_scanner.detect.code.keychain_owner import KeychainOwner
from cordon_scanner.detect.code.publish_reach import PublishReach
from cordon_scanner.detect.code.store_flow import StoreFlow
from cordon_scanner.detect.infra.gradle_auth import GradleBuildAuth
from cordon_scanner.detect.secrets.secrets import RULE_MATERIAL_CEILING
from cordon_scanner.foundation.capabilities import Capability, MatchKind
from cordon_scanner.foundation.models import (
    Category,
    Evidence,
    Explanation,
    Finding,
    Location,
    Severity,
)
from cordon_scanner.foundation.samples import SampleKinds
from cordon_scanner.foundation.text.redact import Redactor

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
        hits.extend(Labelling.destination_capabilities(content, unit.language))
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
        # and the other text detectors (`core/windows.py`), on the serial path and in the pool.
        if NixCode.is_nix(content.path):
            # What a Nix file declares does not run (`detect/nix_code.py`).
            hits = NixCode.keep_running(content.text, hits)
        hits = TextPosition.off_this_machine(content, hits)
        if BuildOutput.bundled(content):
            # A compiled tool that schedules its own jobs (an agent runner's LaunchAgent, a
            # crontab writer) registers autostart entries as its feature; three Open VSX agent
            # extensions do it from dist/. The hand-written file is where an implant's is
            # (review 98).
            hits = [h for h in hits if h.rule_id != "CAP.JS.AUTOSTART.001"]
        return hits, candidates

    # -- Labelling -------------------------------------------------------

    """Asking whether a tool exists, which is not using it.

    vLLM's `run-benchmarks.sh` opens with
    `(which wget && which curl) || (apt-get update && apt-get install -y wget curl)`,
    and the egress primitive matched the word `curl`. With `bash -c` on another line
    that was `MALWARE.DROPPER.001` at CRITICAL, and pm2's `setup.deb.sh` does the same
    thing with `if command -v curl > /dev/null`.

    Anchored at the end, so it is the text immediately before the match that decides:
    `which curl` is a probe and `curl https://x/y` one line later is still a fetch."""

    """The commands an egress pattern is looking for, so their position can be found.

    The shell egress patterns are anchored at the start of the line, with a
    comment-excluding prefix before the command name, which means the MATCH begins at
    the line start and says nothing about what sits
    immediately before the command. Rather than rewrite six patterns in the pack and
    lose their own comment guard, the commands are located again here."""

    """The keywords that make what follows a definition rather than a call.

    `google/zx` exports a function called `fetch`, and the egress pattern matched it:
    `export function fetch(` was that repository's only blocking finding. Defining a
    name is not using the thing it is named after."""

    """A typed parameter list, which only a declaration has.

    Tailwind's integration helpers declare
    `exec(command: string, options?: ChildProcessOptions): Promise<string>` on an
    interface. A call passes values; `name: Type` in the parentheses is a signature, and
    so is an empty list followed by a return type."""

    """An opening parenthesis that ends its line, so the parameters are below it."""

    """`name: Type` opening a line: a parameter in a signature laid out one to a line."""

    """How many lines below an open parenthesis to look for a typed parameter.

    Three. A signature that has not named a typed parameter within three lines of
    its parenthesis is not being recognised from its first line either."""

    #: Composites whose severity does not depend on where the code runs. An orchestrator starts
    #: its agent with the checks off on purpose, from its activation code as anywhere; what makes
    #: that an attack is the instruction it carries, which is `MALWARE.AGENT.HIJACK.001`.
    CONTEXT_FREE: ClassVar[frozenset[str]] = frozenset({"SUSPECT.AGENT.UNATTENDED.001"})

    """What a CI check asks beside, when it is a courtesy and not an evasion.

    `if (process.env.DO_NOT_TRACK === '1' || process.env.CI) return;` before a licence ping, and
    `if (!process.stderr.isTTY || process.env.CI) return;` before a progress line: 29 of
    `@readystack`'s MCP linters, 37 MCP servers and 139 units of the 200K corpus were blocked as
    code hiding from analysis for these. A payload gated on not being watched has no reason to
    honour the user's opt-out or to care whether a terminal is attached; both are how a program
    is polite, and an evasion that adds one still needs another environment check, a debugger or
    a hostname test, each of which matches on its own.
    """

    """JavaScript under `build/`, `bin/` or `dist/` in a published npm package.

    In a repository those directories hold the project's own tooling, and a decode beside a
    spawn there is usually a release helper. In the tarball npm installs they are the compiled
    library and the command npm links onto PATH: `@0xengine/meow` shipped `build/validate.js`,
    which writes a base64 script to disk and runs it with bash, and the tooling ceiling held it
    at MEDIUM (review 98).
    """

    """What follows an enumeration of `process.env` when it reads one family of variables or
    passes the environment to a child: `Object.keys(process.env).filter(k => /^debug_/i.test(k))`
    is the `debug` package's options, `startsWith("LANGCHAIN_")` is LangChain's configuration,
    and `ELECTRON_RUN_AS_NODE` is vscode-languageclient starting its server. Each is bundled into
    thousands of extensions, and 6 of 8 benign ones blocked as credential theft were these (review
    98). The environment dumped whole, or sent anywhere, still matches."""

    PERSIST_RULE = "MALWARE.INSTALL.PERSIST.001"
    CALLBACK_RULE = "MALWARE.EXFIL.INSTALL_CALLBACK.001"

    """A write, or the command that installs a unit, close to where persistence is named."""

    """A chat bot's client library: the channel a webhook URL is, without the URL."""

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

    """Callees that run a function they are handed, without anybody asking again."""

    ON_REQUEST_RULES = frozenset(
        {
            "SUSPECT.DROPPER.001",
            "SUSPECT.DROPPER.REMOTE_CODE.001",
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
    """Dunders that run when a class is defined, subclassed or parameterised, not when it is
    instantiated. `__new__` is here because a metaclass's `__new__` runs at class definition."""

    DROPPER_RULE = "SUSPECT.DROPPER.001"
    #: The flow dropper (a response reaching execute/process, including written to disk then run --
    #: review 98 round 2 B). Lowered like DROPPER_RULE when the download is a verified own release,
    #: so a sha256-checked self-update stays below the gate; kept out of VERIFIABLE_DROPPERS so the
    #: no-download-run escalations do not apply to it.
    REMOTE_CODE_RULE = "SUSPECT.DROPPER.REMOTE_CODE.001"
    #: Malware grade -> its suspect grade, which a verified download leaves reporting (review 98 #28).
    WITHDRAWN_WHEN_VERIFIED: ClassVar[dict[str, str]] = {
        "MALWARE.DROPPER.001": DROPPER_RULE,
        "MALWARE.INSTALL.REMOTE_CODE.001": REMOTE_CODE_RULE,
    }

    #: Rules whose act is destroying data. They keep their severity in build tooling: a recipe
    #: runs unattended on every machine that builds, so "written to be read" does not hold.
    DESTRUCTION_RULES: ClassVar[frozenset[str]] = frozenset(
        {"SUSPECT.DESTROY.HOME_OR_ROOT.001", "MALWARE.PROTESTWARE.001"}
    )

    BEACON_RULE: ClassVar[str] = "MALWARE.EXFIL.BEACON.001"
    #: The two grades of the same dropper pattern, the only findings `VerifiedDownload` may lower.
    VERIFIABLE_DROPPERS: ClassVar[frozenset[str]] = frozenset(
        {"MALWARE.DROPPER.001", "SUSPECT.DROPPER.001"}
    )
    VERIFIED_DOWNLOAD_REASON = (
        "a checksum-verified download of the package's own release; whoever owns the release "
        "also owns the checksum, so the binary itself is not vouched for"
    )

    def _suspect_dropper_reports(
        self,
        evaluator: CompositeEvaluator,
        ctx: ScanContext,
        path: str,
        hits: list[CapabilityHit],
        rule: str = DROPPER_RULE,
    ) -> bool:
        """Whether the suspect grade (`SUSPECT.DROPPER.001`) fires on the window its malware grade
        matched: its `unless` excludes test paths, and withdrawing the one where the other does
        not report would leave the file clean."""
        suspect, fired = ctx.rules.get(rule), frozenset(hit.rule_id for hit in hits)
        return suspect is not None and evaluator.evaluate(
            suspect, {hit.capability for hit in hits}, path, in_hook=True, fired=fired
        )

    """A file inside an agent skill's folder (`.claude/skills/<name>/scripts/x.py` and kin)."""

    @staticmethod
    def _skill_script(path: str, ctx: ScanContext | None) -> bool:
        """`LoadPath.skill_script`, asked through the detector: the engine's `_skill_scripts` reaches
        it here, over the engine-to-detector import it already has."""
        return LoadPath.skill_script(path, ctx)

    """Languages with no load path: importing a Go package or referencing a Java class runs none of
    its functions, except the initialisers matched by `_LOAD_TIME_INITIALISER`."""
    """Go's `func init()`, Java's `static { ... }`, a C# static constructor, a C/C++
    `__attribute__((constructor))` and Rust's `#[ctor]`: code that runs when the package is imported,
    the class is loaded or the library is mapped -- how malicious modules run their payload."""

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

    CREDENTIAL_STORE_RULE = "SUSPECT.EXFIL.CREDENTIAL_STORE.001"
    """The one composite the authentication-filename ceiling applies to."""

    """Egress to an out-of-band interaction service. See `intel.hosts.INTERACTION_HOSTS`."""
    """Rule id for egress to a destination that is itself informative.

    Named so composites can refer to it. It is a capability label rather than a
    finding, like the AST tier's, and it exists because the capability model
    deliberately cannot tell one outbound request from another -- posting to a
    metrics endpoint and posting to a Discord webhook are both `egress`.
    """

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
        deferred = (
            frozenset(
                (first, last)
                for path, first, last in ctx.install_deferred_lines
                if path == unit.path
            )
            if in_hook
            else frozenset()
        )

        decode_excused = DecodeRun.excused_lines(
            unit, hits, BuildOutput.bundled_path(unit.path), [c.rule.id for c in candidates]
        )
        for compiled in candidates:
            if compiled.match.kind is not MatchKind.COMPOSITE:
                continue
            if compiled.match.scope not in {"file", "function"}:
                continue

            rule_hits = (
                [h for h in hits if not LegitimateUse.a_setting(unit.content, h)]
                if compiled.rule.id in self.SETTINGS_ARE_NOT_LOOT
                else [h for h in hits if not InstallPayload.spawns_unpacker(unit.content, h)]
                if compiled.rule.id in self.VERIFIABLE_DROPPERS
                else DecodeRun.hits_for(compiled.rule.id, hits, decode_excused)
            )
            if compiled.rule.id in self.CONTEXT_FREE:
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
            if Capability.EGRESS in matched_capabilities and (
                (
                    Capability.CREDENTIAL in matched_capabilities
                    and LegitimateUse.credential_reaches_its_own_issuer(unit.content, window)
                )
                # Not at install time: nothing installing a package needs its user's keys, and
                # boto3 uploads just as well to a bucket the attacker owns.
                or (
                    not in_hook and LegitimateUse.store_used_by_its_own_client(unit.content, window)
                )
                or (
                    not in_hook
                    and compiled.rule.id == self.CREDENTIAL_STORE_RULE
                    and KeychainOwner.excuses(unit.content, window, hits)
                )
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
            anchor = self._anchor(matched, local_by_capability, window)

            finding = self._composite_finding(
                compiled, unit, ctx, anchor, matched, window, file_hits=hits, evaluator=evaluator
            )
            if finding is not None:
                yield finding

    #: Composites whose source half is what a file sends: a setting it reads to configure itself is
    #: not that. See `LegitimateUse.a_setting`.
    SETTINGS_ARE_NOT_LOOT: ClassVar[frozenset[str]] = frozenset({"SUSPECT.EXFIL.DROP_POINT.001"})

    """One environment variable read by its literal name: `os.getenv("TELEGRAM_BOT_TOKEN")`,
    `process.env.DINGTALK_TOKEN`, `std::env::var("SMTP_SERVER")`. A name computed at run time
    (`os.getenv(k)`) is not this: a loop over names is how a stealer reads a list of them."""

    """What the machine is, not who: the architecture a download is picked for, the home
    directory a config file is kept under."""

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

    """Above this many capability hits, the pairwise search gives way to `CompositeEvaluator._dense_window`.

    The search is quadratic in the number of hits, and a file with four hundred of them is
    generated or enormous. It used to fall back to file scope there -- reporting more, on the
    theory that more is safe -- which made every large bundle a single window."""

    """Install-time code whose every capability sits within this many lines is one window."""

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
        """Carry a second hash: the one `ResultFolding.idiom` groups on.

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
        evaluator: CompositeEvaluator,
    ) -> Finding | None:
        rule = compiled.rule
        content = unit.content
        # A prebuilt binary from the package's own release, checked against a digest it ships
        # before anything runs (review 98, FP-2: `@ohos-ports/larksuite-cli`). Read over the whole
        # file's hits, not this window's: a credential read anywhere in it keeps the dropper.
        verified = (
            rule.id in self.VERIFIABLE_DROPPERS
            or rule.id == self.REMOTE_CODE_RULE
            or rule.id in self.WITHDRAWN_WHEN_VERIFIED
        ) and LegitimateUse.verified_release_download(
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
            and not LoadPath.runs_a_downloaded_file(hits)
        ):
            # An extension's activation entry is in the install-hook set so that a beacon there is
            # reported as one; a download it then starts is how extensions fetch their own tools,
            # and is not escalated as an install-time dropper. See `MALWARE.DROPPER.001` above.
            in_hook = False
        if rule.id in self.CONTEXT_FREE:
            in_hook = False
        no_download_runs = rule.id in self.VERIFIABLE_DROPPERS and (
            in_hook and LegitimateUse.tool_runs_nothing_downloaded(unit, ctx)
        )
        if no_download_runs and rule.id == self.DROPPER_RULE:
            # An agent's tool that never runs what it fetched is not escalated as an install-time
            # dropper; `SUSPECT.DROPPER.001` reports the pair below the gate.
            in_hook = False
        if verified and rule.id in (self.DROPPER_RULE, self.REMOTE_CODE_RULE):
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
        if compiled.rule.id in self.EXFIL_RULES and LegitimateUse.credential_for_its_own_service(
            content
        ):
            return None

        if (
            compiled.rule.id == self.BEACON_RULE
            and content.path in ctx.agent_run_paths
            and content.path not in ctx.consumer_install_paths
            and not IntentSignals.identity_in_what_is_sent(
                unit.language, content, hits if file_hits is None else file_hits
            )
        ):
            # An agent's tool is in the install-hook set so that what it does is graded as code
            # that runs unasked; an API client that names its platform in a User-Agent near its
            # request is not a beacon. As the import-time beacon `SUSPECT.EXFIL.BEACON.001`
            # requires, the machine's identity has to be IN what is sent (review 98: Asana,
            # Notion, search and transcription clients in MalSkillBench were blocked on nearness
            # alone). Where no flow is read for the language, nearness still decides.
            return None

        if (
            compiled.rule.id == "MALWARE.DROPPER.001"
            and SourcePaths.is_editor_extension(content.path)
            and not LoadPath.runs_a_downloaded_file(hits)
        ):
            # Withdrawn for the reason above. An extension's activation entry runs unasked, as an
            # install hook does -- which is what catches a beacon there -- but an extension that
            # fetches and starts its own tools (Codespaces, APKLab, DOSBox) is not a compromised
            # host. `SUSPECT.DROPPER.001` reports the same span, below the gate. A download
            # written to an executable and started keeps this rule: that is the malicious shape.
            return None

        if no_download_runs and compiled.rule.id == "MALWARE.DROPPER.001":
            # Withdrawn for the reason above: no byte the script downloads is executed, made
            # executable, or evaluated (`detect/download_flow.py`). `SUSPECT.DROPPER.001` reports
            # the same pair below the gate, and every other rule over the file still applies.
            return None

        if (
            verified
            and compiled.rule.id in self.WITHDRAWN_WHEN_VERIFIED
            and self._suspect_dropper_reports(
                evaluator, ctx, content.path, hits, self.WITHDRAWN_WHEN_VERIFIED[compiled.rule.id]
            )
        ):
            # Withdrawn for the reason above, and only where `SUSPECT.DROPPER.001` reports the same
            # span, so the file is never left clean. What is withdrawn is the claim that the content
            # is whatever the host serves: the release URL is a literal, and the digest it is held
            # to came with the package. What is not withdrawn is the question of what the binary
            # is -- whoever owns the repository owns the release and the checksum too (`08` P3) --
            # so it stays reported at MEDIUM, and every other rule over the file still applies.
            return None

        if rule.id == "MALWARE.EXFIL.BEACON.001" and LegitimateUse.loopback_only(
            CompositeEvaluator.satisfying_region(content, hits)
        ):
            # A daemon's health check on its own port: what reaches 127.0.0.1 never leaves the
            # machine, so it carries nothing anywhere (review 98, FP-3: aigentry-telepty). Any
            # other host or URL in the region keeps the rule.
            return None

        if (
            in_hook
            and rule.id == self.PERSIST_RULE
            and LegitimateUse.is_formula(content)
            and not IntentSignals.writes_near(content, hits)
            and not IntentSignals.writes_near(content, hits, writes=IntentSignals.RUBY_WRITE)
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
            if rule.id == self.PERSIST_RULE and not IntentSignals.writes_near(content, hits):
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
                CompositeEvaluator.satisfying_region(content, hits)
            )
        ):
            return None

        if (
            rule.id == "MALWARE.EXFIL.001"
            and LoadPath.agent_run(content, ctx)
            and not IntentSignals.names_untrusted_destination(content.raw)
            and not IntentSignals.ENVIRONMENT_DUMP.search(content.raw)
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
                and LegitimateUse.is_hand_run_provisioning(content.path, unit.language)
                # A skill's script is run by the agent whenever the skill is invoked.
                and not LoadPath.skill_script(content.path, ctx)
                and not IntentSignals.persists_a_download(content, hits)
            )
            # The credential-egress-execution combination outside anything that runs on its own:
            # a client reading its own key and calling its own service, a deploy script, the
            # Maven wrapper. The composite's message already says it is "a combination to be
            # aware of rather than evidence of anything"; in the long tail it was the only code
            # warning on 259 of 11,005 benign units rescanned, while in 4,269 malware samples it
            # blocked none alone (review 98). Recorded -- unless the file also names a
            # destination nobody sends their own credentials to.
            trusted_destination = not IntentSignals.names_untrusted_destination(
                content.raw
            ) and not IntentSignals.ENVIRONMENT_DUMP.search(content.raw)
            own_credential_client = (
                compiled.rule.id == "SUSPECT.EXFIL.001"
                and not in_hook
                and not ctx.in_ci_hook(content.path)
                and not ctx.in_consumer_install(content.path)
                and not LoadPath.skill_script(content.path, ctx)
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
                and LoadPath.agent_run(content, ctx)
                and trusted_destination
            )
            # Not raised back by the install escalation below: agent-run code is in the install
            # set for what no tool needs, and this is what a tool is for.
            agent_tool_client = own_credential_client and LoadPath.agent_run(content, ctx)
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
            elif (
                compiled.rule.id == self.CREDENTIAL_STORE_RULE
                and not in_hook
                and not ctx.in_consumer_install(content.path)
                and not LoadPath.agent_run(content, ctx)
                # Nor code a published package runs when it is imported (REC-2).
                and content.path not in ctx.import_entry_paths
                # A paste site, a webhook, a chat API or a bare address beside the store keeps
                # it: nobody sends their own keys there, whatever this test can follow.
                and not IntentSignals.names_untrusted_destination(content.raw)
                and not IntentSignals.CHAT_CLIENT.search(content.raw)
                and not StoreFlow.reaches(
                    content.text,
                    [h.line for h in hits if h.rule_id == "CAP.CREDENTIAL.STORE.001"],
                    [h.line for h in hits if h.capability is Capability.EGRESS],
                )
            ):
                # Nothing the file reads from the store reaches the call (`detect/store_flow.py`):
                # a dotfiles installer reading `~/.ssh/config` and running `curl | bash` forty
                # lines on. Where code runs on its own -- a hook, an agent's tool -- reading
                # somebody's keys is the act, and this does not apply.
                ceilinged = "a credential store read with nothing it reads sent anywhere"
            elif content.is_rule_material:
                # A rule set, or a test case annotated for one. `semgrep/semgrep-rules`
                # supplies `bash/curl/security/curl-eval.bash`, whose whole content is
                # the capability pair the rule next to it matches. See `core.samples`.
                ceilinged = "another analyser's rule material"
                ceiling = RULE_MATERIAL_CEILING
            elif SourcePaths.is_test_material_here(content.path, ctx):
                ceilinged = "test material"
            elif (
                compiled.rule.id in InertLiterals.CAP
                and not in_hook
                and not ctx.in_consumer_install(content.path)
                and not LoadPath.agent_run(content, ctx)
                and InertLiterals.all_inert(
                    content.path,
                    content.text,
                    content.raw,
                    [
                        (h.byte_start, h.byte_end, h.line)
                        for h in hits
                        if h.capability is InertLiterals.CAP[compiled.rule.id]
                    ],
                )
            ):
                # A command-shaped string that is only data (census D: launchpromptly's
                # redteam/attacks.py, cord-engine's demo.py): InertLiterals proves it reaches no
                # spawn, exec, sender or write. A MALICIOUS form never reaches this cascade.
                ceilinged = "a command-shaped string that reaches no sink"
                ceiling = Severity.LOW
            elif SourcePaths.is_documentation(content.path):
                ceilinged = "documentation"
                if TextPosition.is_prose(content.path):
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
                and not IntentSignals.sends_a_wallet_secret(hits)
                # A published npm package's `build/` and `bin/` are what runs, not what builds.
                and not LegitimateUse.shipped_output(content.path, ctx)
                # Nor when it wipes the machine: a build script that deletes `$HOME` or `/`
                # runs on every machine that builds, exactly as a piped download does.
                and compiled.rule.id not in CapabilityDetector.DESTRUCTION_RULES
                # A skill's `scripts/` folder is not the project's tooling: the agent runs
                # what is in it whenever the skill is invoked.
                and not LoadPath.skill_script(content.path, ctx)
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
                and not LoadPath.runs_a_downloaded_file(hits)
            ):
                # An extension fetching and starting its own tools -- a language server, a CLI,
                # a WSL or container agent -- from code the editor runs: Codespaces, APKLab and
                # DOSBox do it in their main bundle. Reported, below the gate. A download written
                # to an executable and started, as one construct, is not lowered: that is the
                # shape the malicious extensions use, `.bat` droppers included.
                ceilinged = "an editor extension fetching and starting its own tools"
                ceiling = Severity.MEDIUM
            elif compiled.rule.id == self.DROPPER_RULE and no_download_runs:
                # An agent's tool that never runs what it fetched (`detect/download_flow.py`):
                # reported, below the gate. Running, evaluating or making executable anything
                # downloaded is not lowered.
                ceilinged = "an agent's tool that never runs what it downloads"
                ceiling = Severity.MEDIUM
            elif (
                compiled.rule.id == self.REMOTE_CODE_RULE
                and content.path in ctx.import_entry_paths
                and content.path not in ctx.library_entry_paths | ctx.library_closure_paths
                and not in_hook
            ):
                # A command a person runs (`bin`), not code an install or an import runs: a CLI
                # fetching and starting its own release. npm work half: 20 legitimate, 5 malware
                # -- all 5 blocked by other rules. Reported, below the gate.
                ceilinged = "a command a person runs, never run on install or import"
                ceiling = Severity.MEDIUM
            elif content.path.rpartition("!")[2].endswith(".map"):
                # A source map carries the original sources as JSON strings for a debugger to
                # show. Nothing loads it as code, so even a download-and-run construct in it is
                # text -- the bundle it maps is scanned on its own.
                ceilinged = "a source map, which is never run"
            elif (
                SourcePaths.is_generated_artefact(content.path)
                and not LegitimateUse.flow_in_shipped_code(compiled.rule.id, content, ctx)
                and not LoadPath.runs_a_downloaded_file(hits)
                and not IntentSignals.evaluates_a_literal_payload(content)
                and not IntentSignals.turns_an_agent_on_the_user(hits)
                and not IntentSignals.sends_a_wallet_secret(hits)
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
                BuildOutput.is_minified(content)
                and not LegitimateUse.flow_in_shipped_code(compiled.rule.id, content, ctx)
                and not LoadPath.runs_a_downloaded_file(hits)
                and not IntentSignals.evaluates_a_literal_payload(content)
                and not IntentSignals.turns_an_agent_on_the_user(hits)
                and not IntentSignals.sends_a_wallet_secret(hits)
            ):
                # The same exceptions as generated output, for the same reasons. The second
                # matters most here: a long encoded payload is itself what makes a hand-written
                # file look minified (`eval(atob('...'))` in `tailwind-animation-effect`).
                ceilinged = "minified output"
            elif PublishReach.unreached(compiled.rule.id, content.path, ctx):
                ceilinged, ceiling = PublishReach.REASON, Severity.MEDIUM
            elif verified and compiled.rule.id in (self.DROPPER_RULE, self.REMOTE_CODE_RULE):
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
                    and unit.language in LoadPath.SCRIPT_LANGUAGES_RUN_BY_HAND
                )
                # A command channel -- what arrives on a connection, run -- is not a routine a
                # caller asks for; it is never lowered for running only when called.
                and not any(
                    hit.rule_id in ("CAP.GO.RECEIVED_RUN", "CAP.JS.RECEIVED_RUN") for hit in hits
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
                deferred = LoadPath.run_on_request(content, unit.language, hits, matched, ctx)
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
                    deferred == LoadPath.ON_REQUEST_REASONS[0]
                    and compiled.rule.id == "SUSPECT.PERSIST.001"
                ):
                    # A script that writes what it downloads into `~/.bashrc` or a service unit
                    # keeps running after whoever ran it has gone. Running it by hand is a moment;
                    # what it persists is not.
                    deferred = ""
                if deferred:
                    ceilinged = deferred
                    ceiling = Severity.MEDIUM
                elif compiled.rule.id == self.DROPPER_RULE and LegitimateUse.official_installs_only(
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
                    if ceilinged in LoadPath.ON_REQUEST_REASONS
                    or ceilinged in ("the tool's own official installer", PublishReach.REASON)
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


__all__ = ["CapabilityDetector"]
