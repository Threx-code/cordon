"""Grading one composite finding: whether it is reported at all, how severe it is, and why.

A composite that matched is not yet a finding. Grading decides, in order: whether it is withdrawn
(the code is doing what such code is for, or runs where the pattern is not the attack); the ceiling
its place puts on it (test material, documentation, generated, vendored or minified output, a script
a person runs) unless it hid its payload or is malicious by category; the escalation an install hook
applies after the ceiling, because install-time code runs unprompted; and the scored finding with
the reasons for each step. This was `CapabilityDetector._composite_finding`, one 611-line function;
each step is now its own method, its statements and comments unchanged.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from cordon_scanner.analysis.python.inert_literals import InertLiterals
from cordon_scanner.analysis.shared.source_paths import FIXTURE_CEILING, SourcePaths
from cordon_scanner.detect.base import (
    FileUnit,
    ScanContext,
)
from cordon_scanner.detect.code.capability.anchor import FindingAnchor
from cordon_scanner.detect.code.capability.build_output import BuildOutput
from cordon_scanner.detect.code.capability.composites import CompositeEvaluator
from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.detect.code.capability.intent import IntentSignals
from cordon_scanner.detect.code.capability.legitimate_use import LegitimateUse
from cordon_scanner.detect.code.capability.load_path import LoadPath
from cordon_scanner.detect.code.capability.rule_ids import CompositeRuleIds
from cordon_scanner.detect.code.capability.text_position import TextPosition
from cordon_scanner.detect.code.publish_reach import PublishReach
from cordon_scanner.detect.code.store_flow import StoreFlow
from cordon_scanner.detect.secrets.secrets import RULE_MATERIAL_CEILING
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.models import Category, Explanation, Finding, Location, Severity
from cordon_scanner.foundation.samples import SampleKinds
from cordon_scanner.foundation.scoring import RiskScorer, ScoringContext
from cordon_scanner.foundation.text.redact import Redactor

if TYPE_CHECKING:
    from cordon_scanner.rules.loader import CompiledRule


class CompositeGrading:
    """One composite finding of one file, graded: withdrawn, ceilinged, escalated, scored."""

    VERIFIED_DOWNLOAD_REASON = (
        "a checksum-verified download of the package's own release; whoever owns the release "
        "also owns the checksum, so the binary itself is not vouched for"
    )

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

    def __init__(
        self,
        compiled: CompiledRule,
        unit: FileUnit,
        ctx: ScanContext,
        anchor: CapabilityHit,
        matched: tuple[Capability, ...],
        hits: list[CapabilityHit],
        *,
        file_hits: list[CapabilityHit] | None,
        evaluator: CompositeEvaluator,
        detector_id: str,
    ) -> None:
        self.compiled, self.unit, self.ctx, self.anchor = compiled, unit, ctx, anchor
        self.matched, self.hits, self.file_hits = matched, hits, file_hits
        self.evaluator, self.detector_id = evaluator, detector_id
        rule = compiled.rule
        content = unit.content
        # A prebuilt binary from the package's own release, checked against a digest it ships
        # before anything runs (review 98, FP-2: `@ohos-ports/larksuite-cli`). Read over the whole
        # file's hits, not this window's: a credential read anywhere in it keeps the dropper.
        verified = (
            rule.id in CompositeRuleIds.VERIFIABLE_DROPPERS
            or rule.id == CompositeRuleIds.REMOTE_CODE_RULE
            or rule.id in CompositeRuleIds.WITHDRAWN_WHEN_VERIFIED
        ) and LegitimateUse.verified_release_download(
            unit, ctx, hits if file_hits is None else file_hits
        )

        present = {h.capability for h in hits}
        in_hook = ctx.in_install_hook(content.path)
        if (
            in_hook
            and rule.id == CompositeRuleIds.DROPPER_RULE
            and SourcePaths.is_editor_extension(content.path)
            and not LoadPath.runs_a_downloaded_file(hits)
        ):
            # An extension's activation entry is in the install-hook set so that a beacon there is
            # reported as one; a download it then starts is how extensions fetch their own tools,
            # and is not escalated as an install-time dropper. See `MALWARE.DROPPER.001` above.
            in_hook = False
        if rule.id in CompositeRuleIds.CONTEXT_FREE:
            in_hook = False
        no_download_runs = rule.id in CompositeRuleIds.VERIFIABLE_DROPPERS and (
            in_hook and LegitimateUse.tool_runs_nothing_downloaded(unit, ctx)
        )
        if no_download_runs and rule.id == CompositeRuleIds.DROPPER_RULE:
            # An agent's tool that never runs what it fetched is not escalated as an install-time
            # dropper; `SUSPECT.DROPPER.001` reports the pair below the gate.
            in_hook = False
        if verified and rule.id in (
            CompositeRuleIds.DROPPER_RULE,
            CompositeRuleIds.REMOTE_CODE_RULE,
        ):
            # Not escalated as an install-time dropper either: the hook escalation would put the
            # span straight back at CRITICAL. The ceiling below says why it is still reported.
            in_hook = False
        self.verified, self.present, self.in_hook = verified, present, in_hook
        self.no_download_runs = no_download_runs
        self.hand_run_provisioning = self.own_credential_client = self.agent_tool_client = False

    def finding(self) -> Finding | None:
        """The graded finding, or None where it is withdrawn."""
        if self._withdrawn_for_its_use() or self._withdrawn_for_where_it_runs():
            return None
        rule, in_hook, present = self.compiled.rule, self.in_hook, self.present
        severity = RiskScorer.apply_category_floor(rule.category, rule.severity)
        category = rule.category
        escalations: list[str] = []

        ceilinged, ceiling = self._ceiling(category)
        agent_tool_client = self.agent_tool_client
        if ceilinged:
            severity = min(severity, ceiling)
            escalations.append(
                f"reported below its usual severity because it sits in {ceilinged}"
                + (
                    ""
                    if ceilinged in LoadPath.ON_REQUEST_REASONS
                    or ceilinged in ("the tool's own official installer", PublishReach.REASON)
                    or ceilinged == CompositeGrading.VERIFIED_DOWNLOAD_REASON
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
        return self._scored(severity, category, escalations)

    def _withdrawn_for_its_use(self) -> bool:
        """Withdrawn for what the code is for: a credential sent to its own service, an agent's tool calling its API, a dropper that is an extension's or an agent's own tooling or a verified release."""
        compiled, unit, ctx, hits, file_hits, evaluator, content, verified, no_download_runs = (
            self.compiled,
            self.unit,
            self.ctx,
            self.hits,
            self.file_hits,
            self.evaluator,
            self.unit.content,
            self.verified,
            self.no_download_runs,
        )
        if (
            compiled.rule.id in CompositeRuleIds.EXFIL_RULES
            and LegitimateUse.credential_for_its_own_service(content)
        ):
            return True

        if (
            compiled.rule.id == CompositeRuleIds.BEACON_RULE
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
            return True

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
            return True

        if no_download_runs and compiled.rule.id == "MALWARE.DROPPER.001":
            # Withdrawn for the reason above: no byte the script downloads is executed, made
            # executable, or evaluated (`detect/download_flow.py`). `SUSPECT.DROPPER.001` reports
            # the same pair below the gate, and every other rule over the file still applies.
            return True

        # Withdrawn for the reason above, and only where `SUSPECT.DROPPER.001` reports the same
        # span, so the file is never left clean. What is withdrawn is the claim that the content
        # is whatever the host serves: the release URL is a literal, and the digest it is held
        # to came with the package. What is not withdrawn is the question of what the binary
        # is -- whoever owns the repository owns the release and the checksum too (`08` P3) --
        # so it stays reported at MEDIUM, and every other rule over the file still applies.
        return (
            verified
            and compiled.rule.id in CompositeRuleIds.WITHDRAWN_WHEN_VERIFIED
            and self._suspect_dropper_reports(
                evaluator,
                ctx,
                content.path,
                hits,
                CompositeRuleIds.WITHDRAWN_WHEN_VERIFIED[compiled.rule.id],
            )
        )

    def _withdrawn_for_where_it_runs(self) -> bool:
        """Withdrawn for where it runs or what it reaches: a loopback health check, a Homebrew formula, an editor extension that only names a path or host, a pinned fetch in CI, an agent's tool calling the service it holds a key for."""
        ctx, hits, rule, content, in_hook = (
            self.ctx,
            self.hits,
            self.compiled.rule,
            self.unit.content,
            self.in_hook,
        )
        category = self.compiled.rule.category
        if rule.id == "MALWARE.EXFIL.BEACON.001" and LegitimateUse.loopback_only(
            CompositeEvaluator.satisfying_region(content, hits)
        ):
            # A daemon's health check on its own port: what reaches 127.0.0.1 never leaves the
            # machine, so it carries nothing anywhere (review 98, FP-3: aigentry-telepty). Any
            # other host or URL in the region keeps the rule.
            return True

        if (
            in_hook
            and rule.id == CompositeRuleIds.PERSIST_RULE
            and LegitimateUse.is_formula(content)
            and not IntentSignals.writes_near(content, hits)
            and not IntentSignals.writes_near(content, hits, writes=IntentSignals.RUBY_WRITE)
        ):
            # A Homebrew formula's `install` and `post_install` run in brew's build sandbox, which
            # lets them write only under the prefix: a formula cannot plant a login item, so it has
            # to be seen writing one. What a formula names is the user's profile in its caveats or
            # `desc`, a LaunchAgent it unloads, an `etc/profile.d` under its own prefix (review 98:
            # 27 formulas in one tap). A cask runs unsandboxed and keeps the rule.
            return True

        if in_hook and SourcePaths.is_editor_extension(content.path):
            # The same reasoning, for the two rules a coding extension trips by talking: its help
            # text names `~/.zshrc` and its secret redactor names `hooks.slack.com`, megabytes of
            # bundle away from any write or request (review 98). In an extension the persistence
            # has to be written and the drop point reached; `SUSPECT.*` still reports the span.
            if rule.id == CompositeRuleIds.PERSIST_RULE and not IntentSignals.writes_near(
                content, hits
            ):
                return True
            if rule.id == CompositeRuleIds.CALLBACK_RULE and not any(
                # A request, not the destination's name: the drop point is itself an egress hit.
                h.capability is Capability.EGRESS and not h.rule_id.startswith("INTEL.")
                for h in hits
            ):
                return True

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
            and CompositeGrading.PINNED_FETCH.search(
                CompositeEvaluator.satisfying_region(content, hits)
            )
        ):
            return True

        # A skill's script or an MCP server's handler calling the service it holds a key for
        # is what such a tool is for; at install level it blocked 125 of MalSkillBench's 4,000
        # benign skills (review 98). `SUSPECT.EXFIL.001` still records the pair, and a credential
        # store, a drop point, a beacon or a callback is each its own composite.
        return (
            rule.id == "MALWARE.EXFIL.001"
            and LoadPath.agent_run(content, ctx)
            and not IntentSignals.names_untrusted_destination(content.raw)
            and not IntentSignals.ENVIRONMENT_DUMP.search(content.raw)
        )

    def _ceiling(self, category: Category) -> tuple[str, Severity]:
        """The ceiling this finding's place puts on it, and the reason ("" for none)."""
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
        hits = self.hits
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
        if category is Category.MALICIOUS or smuggled:
            return "", FIXTURE_CEILING
        self._clients()
        for run in (
            self._ceiling_for_provisioning,
            self._ceiling_for_credentials_and_material,
            self._ceiling_for_build_and_tooling,
            self._ceiling_for_generated_code,
            self._ceiling_for_running_on_request,
        ):
            found = run()
            if found is not None:
                return found
        return "", FIXTURE_CEILING

    def _clients(self) -> None:
        """Whether this is hand-run provisioning, or a client calling its own credential's service --
        and so an agent tool's client the install escalation leaves alone."""
        compiled, unit, ctx, matched, hits, content, in_hook = (
            self.compiled,
            self.unit,
            self.ctx,
            self.matched,
            self.hits,
            self.unit.content,
            self.in_hook,
        )
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
        self.hand_run_provisioning, self.own_credential_client = (
            hand_run_provisioning,
            own_credential_client,
        )
        self.agent_tool_client = agent_tool_client

    def _ceiling_for_provisioning(self) -> tuple[str, Severity] | None:
        """Machine provisioning, hand-run provisioning, an own-credential client."""
        matched, content, hand_run_provisioning, own_credential_client = (
            self.matched,
            self.unit.content,
            self.hand_run_provisioning,
            self.own_credential_client,
        )
        ceilinged, ceiling = "", FIXTURE_CEILING
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
        else:
            return None
        return ceilinged, ceiling

    def _ceiling_for_credentials_and_material(self) -> tuple[str, Severity] | None:
        """An authentication file, a store read that reaches nothing, rule or test material, an inert literal, documentation."""
        compiled, ctx, hits, content, in_hook = (
            self.compiled,
            self.ctx,
            self.hits,
            self.unit.content,
            self.in_hook,
        )
        ceilinged, ceiling = "", FIXTURE_CEILING
        if (
            compiled.rule.id == CompositeRuleIds.CREDENTIAL_STORE_RULE
            and SampleKinds.names_authentication(content.path)
        ):
            # A file named for authentication, reading a credential store. See
            # `core.samples.names_authentication`; scoped to this one rule, because
            # its premise is a store "this component does not own".
            ceilinged = "a file whose name says it handles authentication"
        elif (
            compiled.rule.id == CompositeRuleIds.CREDENTIAL_STORE_RULE
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
        else:
            return None
        return ceilinged, ceiling

    def _ceiling_for_build_and_tooling(self) -> tuple[str, Severity] | None:
        """Build tooling, an extension's or agent's own tools, a person-run command, a source map."""
        compiled, ctx, hits, content, present, in_hook, no_download_runs = (
            self.compiled,
            self.ctx,
            self.hits,
            self.unit.content,
            self.present,
            self.in_hook,
            self.no_download_runs,
        )
        ceilinged, ceiling = "", FIXTURE_CEILING
        if (
            SourcePaths.is_build_tooling(content.path)
            and Capability.FETCH_EXEC not in present
            # Nor a wallet's secret sent out: a build that ships it, ships it.
            and not IntentSignals.sends_a_wallet_secret(hits)
            # A published npm package's `build/` and `bin/` are what runs, not what builds.
            and not LegitimateUse.shipped_output(content.path, ctx)
            # Nor when it wipes the machine: a build script that deletes `$HOME` or `/`
            # runs on every machine that builds, exactly as a piped download does.
            and compiled.rule.id not in CompositeRuleIds.DESTRUCTION_RULES
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
            compiled.rule.id == CompositeRuleIds.DROPPER_RULE
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
        elif compiled.rule.id == CompositeRuleIds.DROPPER_RULE and no_download_runs:
            # An agent's tool that never runs what it fetched (`detect/download_flow.py`):
            # reported, below the gate. Running, evaluating or making executable anything
            # downloaded is not lowered.
            ceilinged = "an agent's tool that never runs what it downloads"
            ceiling = Severity.MEDIUM
        elif (
            compiled.rule.id == CompositeRuleIds.REMOTE_CODE_RULE
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
        else:
            return None
        return ceilinged, ceiling

    def _ceiling_for_generated_code(self) -> tuple[str, Severity] | None:
        """Generated, vendored or minified output that does not run what it downloads."""
        compiled, ctx, hits, content = self.compiled, self.ctx, self.hits, self.unit.content
        ceilinged, ceiling = "", FIXTURE_CEILING
        if (
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
        else:
            return None
        return ceilinged, ceiling

    def _ceiling_for_running_on_request(self) -> tuple[str, Severity] | None:
        """Unreached by a publish, a verified release, or code that runs only when asked."""
        compiled, unit, ctx, matched, hits, content, verified, present, in_hook = (
            self.compiled,
            self.unit,
            self.ctx,
            self.matched,
            self.hits,
            self.unit.content,
            self.verified,
            self.present,
            self.in_hook,
        )
        ceilinged, ceiling = "", FIXTURE_CEILING
        if PublishReach.unreached(compiled.rule.id, content.path, ctx):
            ceilinged, ceiling = PublishReach.REASON, Severity.MEDIUM
        elif verified and compiled.rule.id in (
            CompositeRuleIds.DROPPER_RULE,
            CompositeRuleIds.REMOTE_CODE_RULE,
        ):
            ceilinged = CompositeGrading.VERIFIED_DOWNLOAD_REASON
            ceiling = Severity.MEDIUM
        elif (
            compiled.rule.id in CompositeRuleIds.ON_REQUEST_RULES
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
                and compiled.rule.id != CompositeRuleIds.DROPPER_RULE
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
            elif (
                compiled.rule.id == CompositeRuleIds.DROPPER_RULE
                and LegitimateUse.official_installs_only(content, hits)
            ):
                ceilinged = "the tool's own official installer"
                ceiling = Severity.MEDIUM
        else:
            return None
        return ceilinged, ceiling

    def _scored(self, severity: Severity, category: Category, escalations: list[str]) -> Finding:
        """The finding, scored, with its evidence and the reasons for its grade."""
        unit, ctx, anchor, matched, hits, rule, content, present, in_hook = (
            self.unit,
            self.ctx,
            self.anchor,
            self.matched,
            self.hits,
            self.compiled.rule,
            self.unit.content,
            self.present,
            self.in_hook,
        )
        mode = Redactor.effective_mode(rule.evidence_policy, ctx.config.evidence)
        evidence = Redactor.build_evidence(content, anchor.byte_start, anchor.byte_end, mode)
        evidence = FindingAnchor.with_idiom_key(evidence, content, matched, hits)
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
            detector=self.detector_id,
            rule_version=rule.version,
            rulepack=rule.rulepack,
            references=rule.references,
            capabilities=tuple(sorted(matched, key=lambda c: c.value)),
        )

    def _suspect_dropper_reports(
        self,
        evaluator: CompositeEvaluator,
        ctx: ScanContext,
        path: str,
        hits: list[CapabilityHit],
        rule: str = CompositeRuleIds.DROPPER_RULE,
    ) -> bool:
        """Whether the suspect grade (`SUSPECT.DROPPER.001`) fires on the window its malware grade
        matched: its `unless` excludes test paths, and withdrawing the one where the other does
        not report would leave the file clean."""
        suspect, fired = ctx.rules.get(rule), frozenset(hit.rule_id for hit in hits)
        return suspect is not None and evaluator.evaluate(
            suspect, {hit.capability for hit in hits}, path, in_hook=True, fired=fired
        )


__all__ = ["CompositeGrading"]
