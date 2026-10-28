"""The CI rules: workflows that run untrusted code with a writable token, serialise their secret
context, publish what an outsider controls, pin actions to a mutable tag, or fetch and run unverified.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from cordon_scanner.analysis.shared.destinations import Destinations
from cordon_scanner.detect.infra.ci_exfil import (
    CREDENTIAL_FORMAT_SEARCH,
    SCHEDULED_FETCH_RUN,
    SECRET_FIELD,
    SECRET_IN_REQUEST,
    SENDS_A_VARIABLE,
    DropPoint,
    SecretInventory,
)
from cordon_scanner.detect.infra.config_paths import (
    CI_PATHS,
    VERIFIED_FETCH,
)
from cordon_scanner.detect.infra.config_rule import ConfigRule, PatternProximity
from cordon_scanner.foundation import references
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.models import Category, Confidence, Severity

if TYPE_CHECKING:
    pass

#: The whole secret context, serialised, in either spelling a workflow writes it.
#:
#: Which block the value sits in is what decides between the two rules that use
#: it, and that is read from the file's structure by `ConfigRule.enclosing_key`
#: rather than written into the pattern: a regex that crosses a YAML block has
#: to bound both the lines it skips and their length, and the product of those
#: two bounds is what `RuleLoader` refuses a rule pack for.
SERIALISED_SECRETS = (
    r"(?:toJSON[ \t]{0,32}\([ \t]{0,32}secrets[ \t]{0,32}\)"
    r"|\$\{\{[ \t]{0,32}secrets[ \t]{0,32}\}\})"
)

#: What parses a value a second time: `eval`, or a double-quoted `-c`/`-e` string handed to a
#: shell or an interpreter. A CI provider that passes untrusted values as environment variables
#: (GitLab, Bitbucket) is injectable only through one of these; a plain `$VAR` is data.
REPARSED: Final = (
    r"(?:\beval\b[^\n]{0,200}?"
    r"|\b(?:ba|z|da|k)?sh[ \t]+-c[ \t]+\"[^\"\n]{0,200}?"
    r"|\b(?:python3?|node|perl|ruby|pwsh|powershell)[ \t]+-(?:c|e|Command)[ \t]+\"[^\"\n]{0,200}?)"
)

#: Ways a build proves the bytes it fetched are the bytes it meant to fetch.
#:
#: Checksum verification, signature verification, or a transparency-log check.
#: Deliberately not "the URL contains a version number": pinning a version says what
#: was asked for and nothing about what arrived, which is the distinction this rule
#: exists to draw in the first place.
TRUSTED_ACTOR_GATE = re.compile(
    rb"(?i)if:[^\n]{0,300}?(?:github\.(?:actor|triggering_actor)"
    rb"|event\.pull_request\.user\.login|event\.(?:issue|comment)\.user\.login)"
    rb"[^\n]{0,80}?(?:==|!=|contains\(|in[ \t]*\()[^\n]{0,120}?['\"\[]"
)
"""A job that only runs for a NAMED actor.

`discourse/discourse` checks a pull request body under `pull_request_target`, checks out
the head, and gates the whole job on
`if: github.event.pull_request.user.login == 'dependabot[bot]'`. A login cannot be
spoofed and dependabot does not take contributions, so the head it checks out is
dependabot's own -- the condition is the control, and it is the one GitHub's own
documentation recommends for exactly this case.

A step down rather than silence, for the reason every mitigation here is: the trigger
plus the checkout is still the shape, and a gate somebody widens later stops being one.
The unconditional form keeps its severity, which is what the rule is named for.
"""

GITHUB_WORKFLOW_PATHS = (
    "**/.github/workflows/*.yml",
    "**/.github/workflows/*.yaml",
)
"""Workflow files only.

Several rules below are about GitHub's trigger, runner and token model, and a
`.gitlab-ci.yml` has none of it. Matching them against every file in `CI_PATHS`
would report a shape that cannot exist in the file being reported.
"""

FORK_GUARD = re.compile(
    rb"(?i)if:[^\n]{0,300}?github\.event\.pull_request\.head\.repo\.(?:full_name|fork)"
)
"""A job that only runs when the pull request came from this repository.

`head.repo.full_name == github.repository` is the documented way to keep a
fork's code off a privileged or persistent runner, and a workflow carrying it
has already made the decision the rule exists to ask about. A step down rather
than silence: the guard is one edit from being widened, and the job still runs
contributor code when somebody widens it.
"""

UNTRUSTED_DESTINATION: Final = re.compile(
    (
        Destinations.pattern() + r"|https?://(?:\d{1,3}\.){3}\d{1,3}(?![\d.])|/dev/tcp/"
        r"|\bnc[ \t]{1,4}(?:-\w{1,8}[ \t]{1,4}){0,4}[\w.-]{1,253}[ \t]{1,4}\d{2,5}\b"
    ).encode("utf-8"),
    re.IGNORECASE,
)
"""Where a pipeline has no business sending anything: a paste site, a tunnel, a webhook catcher
or interaction service (`intel.hosts`), a bare IPv4 address, a raw socket."""

UNTRUSTED_TRIGGER: Final = re.compile(
    rb"(?m)^[ \t]{0,8}(?:-[ \t]{0,4})?(?:pull_request_target|issue_comment|workflow_run)[ \t]*:?[ \t]*$"
    rb"|\bon[ \t]*:[ \t]*\[?[^\n]{0,80}\b(?:pull_request_target|issue_comment|workflow_run)\b"
)
"""A workflow trigger whose run an outside contributor can start, with the base repository's
cache scope and secrets."""

SECRET_BESIDE_EGRESS: Final = ConfigRule._p(
    PatternProximity._near(
        r"(?:\$\{\{[ \t]{0,32}secrets\.(?!GITHUB_TOKEN\b)\w{1,64}[^\n]{0,80}\}\}"
        r"|credentials[ \t]{0,32}\(|withCredentials\b"
        r"|\$\{?[A-Z_]{0,24}(?:TOKEN|SECRET|PASSWORD|APIKEY|API_KEY|CREDENTIAL)"
        r"[A-Z_]{0,24}\}?"
        r"|\$\([A-Za-z_]{0,24}(?:Token|Secret|Password|ApiKey)[A-Za-z_]{0,24}\))",
        r"(?:curl|wget|nc\s|Invoke-WebRequest|/dev/tcp|scp\s)",
    )
)
"""A named CI secret and an egress verb in one step: how a pipeline publishes, and how one steals."""

CI_RULES: tuple[ConfigRule, ...] = (
    # -- CI -------------------------------------------------------------
    ConfigRule(
        rule_id="MALWARE.CI.SECRET_EXFIL.001",
        references=(references.GITHUB_ACTIONS_HARDENING, references.HARDCODED_CREDENTIALS),
        title="CI workflow serialises its secret context",
        message=(
            "This workflow renders the whole secret context into a command's "
            "environment, or into the command itself. Every secret available to the "
            "job is materialised as a string inside a process, where it can be "
            "printed, sent anywhere, or written to an artefact -- and a step that "
            "needed one of them was handed all of them."
        ),
        remediation=(
            "Reference individual secrets by name. If a step genuinely needs several, "
            "pass each one explicitly so the set is visible in review."
        ),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category=Category.MALICIOUS,
        # The whole context, and only the whole context.
        #
        # A *named* secret near a network call was matched here too, and that is
        # a different claim wearing this one's severity: `env: TOKEN: ${{
        # secrets.NPM_TOKEN }}` beside a `curl` is how every pipeline publishes
        # anything. It produced twenty critical findings across Node's, ESLint's
        # and webpack's release workflows -- a Discord announcement, a Netlify
        # build hook, a Jenkins trigger. That shape moved to
        # `SUSPECT.CI.SECRET_EGRESS.001`, which says what was actually observed.
        #
        # And the claim the message makes -- "renders the whole secret context
        # into a COMMAND" -- is now what the pattern requires, which is the
        # second split and for the same reason as the first.
        #
        # The bare shape was asserted to have no benign reading. Measured against
        # the infrastructure corpus it produced three critical malicious findings
        # in `Azure/bicep-registry-modules`, where `avm.template.module.yml` and
        # two siblings write `githubSecrets: ${{ toJSON(secrets) }}` under
        # `with:` -- an input to a reusable workflow. A composite action cannot
        # read the secrets context, so forwarding it is a real way to pass
        # credentials into one. It over-provisions the step and it is not
        # exfiltration, and Microsoft's own module registry is not sending its
        # credentials to itself.
        #
        # `env:` and `run:` are a different act and keep this severity. That is
        # `digininja/DVWA`, which writes `ALLMYSECRETS: ${{ toJSON(secrets) }}`
        # under the `env:` of a step whose command is `env` -- every secret the
        # job holds, materialised into a process and printed. The distinction is
        # which block the entry sits in, not what is near it: the two are written
        # identically and one line apart, which is why `_under` reads the block
        # rather than a window.
        pattern=ConfigRule._p(SERIALISED_SECRETS),
        enclosing_key=(b"env", b"run", b"script", b"command", b"args"),
        paths=CI_PATHS,
        capabilities=(Capability.CREDENTIAL,),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.SECRET_OVERPROVISION.001",
        references=(references.GITHUB_ACTIONS_HARDENING,),
        title="CI workflow hands another workflow every secret it has",
        message=(
            "This workflow serialises the whole secret context into an input. A "
            "composite action cannot read `secrets` itself, so forwarding the "
            "context is a real way to pass credentials into one -- and it hands "
            "that step every secret the job can reach rather than the ones it "
            "needs. Whatever the step does next, the blast radius of a mistake "
            "in it is the entire set, and an input is a string that can be "
            "printed, logged or written to an artefact."
        ),
        remediation=(
            "Pass each secret the step needs by name. A reusable workflow takes "
            "`secrets:` entries individually, and `secrets: inherit` at least "
            "keeps the value out of an input."
        ),
        # High and suspicious, not critical and malicious: what is observable
        # here is the width of the grant, not an intent to steal. Serialising the
        # context into a command's environment keeps its severity above.
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(SERIALISED_SECRETS),
        enclosing_key=(b"with", b"secrets", b"inputs"),
        paths=CI_PATHS,
        capabilities=(Capability.CREDENTIAL,),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.SECRET_EGRESS.001",
        references=(references.GITHUB_ACTIONS_HARDENING,),
        title="Pipeline step reads a secret and sends data off the runner",
        message=(
            "A named secret and a network call appear in the same step. That is "
            "how a pipeline publishes a release and how one exfiltrates a token, "
            "and the two are the same shape from here: what separates them is "
            "where the data goes, which this cannot decide. Masking is not a "
            "control on it -- masking hides a value in the log and does nothing "
            "about its destination."
        ),
        remediation=(
            "Confirm the destination is one this project owns. A secret that a "
            "step both reads and transmits has left the boundary the CI system "
            "was protecting it inside, whether or not that was intended."
        ),
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        # Suspicious rather than malicious, and that is the whole point of
        # splitting it out of `MALWARE.CI.SECRET_EXFIL.001`. As a critical
        # malicious finding this fired on Node's Jenkins trigger, ESLint's
        # Netlify build hook and webpack's Discord release announcement --
        # twenty of them, every one a project publishing something with its own
        # credential. The observation is real and worth a reviewer's eye; the
        # conclusion it was drawing was not available from what it saw.
        #
        # Every CI system's own syntax, because each has users who assume
        # masking is a control: GitHub interpolates `${{ secrets.NAME }}`,
        # GitLab exposes `$NAME`, Jenkins binds with `credentials()` or
        # `withCredentials`, Azure uses `$(Name)`. Paired with an egress verb
        # inside a bounded window, so a pipeline that uses a secret in one job
        # and calls curl in an unrelated one is not caught.
        # `secrets.GITHUB_TOKEN` is excluded, and that single exclusion is most of
        # what this rule needed.
        #
        # It is not a secret the repository holds. GitHub mints it per job, scopes it
        # to that repository, and revokes it when the job ends -- there is nothing to
        # rotate and nothing to leak beyond the job's own lifetime and permissions.
        # Using it with `curl` or `gh` against the GitHub API is the most common thing
        # in all of CI.
        #
        # Measured across 535 repositories this rule fired in 31% of them, and every
        # sampled finding was an ordinary workflow: `release-milestone.yml`,
        # `upload-test-stats.yml`, `notify-on-merge.yml`, `label_stale_issues.yml`,
        # `send_release_notification.yml`. The rule's own notes record that it was
        # split out of the critical rule because it was firing on "every pipeline
        # publishing something with its own credential", and it was still doing
        # exactly that one severity down.
        #
        # The severity drops to MEDIUM for what remains, for the reason the message
        # itself gives: what separates publishing from exfiltration is where the data
        # goes, and this cannot decide that. A finding worth a reviewer's eye is not a
        # finding worth failing a build, and the shape is far too common to block on.
        # `MALWARE.CI.SECRET_EXFIL.001` still reports a serialised secret context at
        # CRITICAL, and `SUSPECT.CI.FETCH_EXEC.001` still reports fetch-and-run.
        severity=Severity.MEDIUM,
        pattern=SECRET_BESIDE_EGRESS,
        aggravation=UNTRUSTED_DESTINATION,
        paths=CI_PATHS,
        capabilities=(Capability.CREDENTIAL,),
    ),
    ConfigRule(
        rule_id="MALWARE.CI.SECRET_TO_DROP_POINT.001",
        references=(references.GITHUB_ACTIONS_HARDENING,),
        title="Pipeline step sends a secret to a destination no pipeline publishes to",
        message=(
            "A step reads a named secret and sends it, in the same command, to a bare IP "
            "address, a paste site, a tunnel, a webhook catcher or a raw socket. A pipeline "
            "publishes with its credentials to services the project uses; none of those is "
            "one. This is the shape of a planted workflow stealing the repository's secrets."
        ),
        remediation=(
            "Treat every secret this workflow can read as exposed and rotate it. Find who "
            "added the step, and review the account's other pushes."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        # Malicious, so the hardening tier never lowers it (`Ceilings.hardening_tier`). The
        # SUSPECT rule above stays at LOW for the common publishing shape; this one needs
        # the untrusted destination IN the same command, which publishing does not have.
        # GhostAction (2026) planted `curl` to a raw IP with named secrets on one line in
        # thousands of repositories; at LOW, 0 of 217 unique planted workflows blocked.
        category=Category.MALICIOUS,
        pattern=SECRET_BESIDE_EGRESS,
        aggravation=UNTRUSTED_DESTINATION,
        require_aggravation=True,
        one_command=True,
        confirm=DropPoint.sends_to_one,
        paths=CI_PATHS,
        capabilities=(Capability.CREDENTIAL,),
    ),
    ConfigRule(
        rule_id="MALWARE.CI.SECRET_DUMP.001",
        references=(references.GITHUB_ACTIONS_HARDENING,),
        title="Pipeline step sends secrets labelled with their own names",
        message=(
            "A request in this workflow carries secrets in its body keyed by their own names "
            "(`NAME=${{ secrets.NAME }}`). A pipeline passes a credential to the service it is "
            "for, under that service's parameter name; an inventory of secrets by name is what a "
            "planted step sends to whoever collects it, wherever that is."
        ),
        remediation=(
            "Treat every secret this workflow can read as exposed and rotate it. Find who "
            "added the step, and review the account's other pushes."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        # Measured (CDI, 2026-10-22): 0 of 18,062 benign repositories' 81,662 workflow files,
        # where the same self-named form appears 561 times outside a request (`env:` mappings).
        category=Category.MALICIOUS,
        pattern=SECRET_IN_REQUEST,
        aggravation=SECRET_FIELD,
        require_aggravation=True,
        one_command=True,
        confirm=SecretInventory.labels_a_secret_by_its_name,
        paths=CI_PATHS,
        capabilities=(Capability.CREDENTIAL,),
    ),
    ConfigRule(
        rule_id="MALWARE.CI.SCHEDULED_FETCH_EXEC.001",
        references=(references.GITHUB_ACTIONS_HARDENING,),
        title="Pipeline step installs a cron job that downloads and runs code",
        message=(
            "A step writes a crontab entry that fetches a script from the network and pipes it "
            "into a shell. Whatever is served at that address then runs on a schedule, on any "
            "runner that keeps the job -- a self-hosted runner indefinitely. A pipeline builds "
            "and publishes; it does not leave a downloader behind."
        ),
        remediation=(
            "Treat every self-hosted runner this workflow reached as compromised and rebuild it; "
            "rotate every secret the workflow can read. Find who added the step."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        # Measured (CDI, 2026-10-23): 0 of 81,662 benign workflow files (18,062 repositories).
        category=Category.MALICIOUS,
        pattern=SCHEDULED_FETCH_RUN,
        paths=CI_PATHS,
        capabilities=(Capability.EGRESS, Capability.SPAWN),
    ),
    ConfigRule(
        rule_id="MALWARE.CI.CREDENTIAL_HARVEST.001",
        references=(references.GITHUB_ACTIONS_HARDENING,),
        title="Pipeline step searches for credentials and sends what it gathered",
        message=(
            "One step searches the checkout or its history for the format of a credential (an "
            "AWS key id, an API or access token) and, in the same step, sends a variable's "
            "contents over the network. A secret scanner searches and fails the build; sending "
            "the results somewhere is collecting them."
        ),
        remediation=(
            "Treat every credential in this repository and its history as exposed and rotate "
            "it. Find who added the step, and review the account's other pushes."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        # Measured (CDI, 2026-10-22): 11 benign repositories search for these formats (their
        # own secret scanning); none sends a variable from the same step.
        category=Category.MALICIOUS,
        pattern=CREDENTIAL_FORMAT_SEARCH,
        aggravation=SENDS_A_VARIABLE,
        require_aggravation=True,
        in_shell=True,
        paths=CI_PATHS,
        capabilities=(Capability.CREDENTIAL, Capability.EGRESS),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.EXPRESSION_INJECTION.001",
        references=(references.GITHUB_ACTIONS_HARDENING, references.CODE_INJECTION),
        title="Untrusted pipeline input interpolated into a shell command",
        message=(
            "A field an outside contributor controls -- a pull request title, a "
            "branch name, a commit message -- is interpolated directly into a "
            "script. The interpolation happens before the shell sees the line, so "
            "the value is not an argument to the command; it is part of it, and a "
            "title containing a semicolon runs whatever follows with the job's "
            "token and secrets."
        ),
        remediation=(
            "Pass the value through an environment variable and reference it as "
            '"$VAR" inside the script. The interpolation then happens after the '
            "shell has parsed the line, so the value stays data."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            # Not a line that is only `KEY: ${{ ... }}`.
            #
            # That shape is the remediation this rule recommends. GitHub's own
            # guidance is to bind the untrusted value to an environment
            # variable and reference `"$VAR"` from the script, so the shell
            # parses the line before the value reaches it -- and the rule was
            # firing on exactly that, seventy-two times across Django's,
            # Grafana's and Home Assistant's workflows, telling projects that
            # had done the right thing that they had not.
            #
            # What remains is interpolation into something: a `run:` script, a
            # quoted string with other text around it, a JSON payload. That is
            # where the value becomes part of the command rather than an
            # argument to it.
            # `[ \t\r]` rather than `[ \t]` before the anchor: a repository
            # with CRLF endings leaves a carriage return there, and without it
            # the exemption silently stopped applying to every workflow written
            # on Windows -- which is the half of the world most likely to have
            # them.
            r"(?m)^(?![ \t]{0,64}[A-Za-z_][A-Za-z0-9_.-]{0,64}:"
            r"[ \t]{0,8}\$\{\{[^\n]{0,200}\}\}[ \t\r]{0,8}$)"
            # And not a key whose value never reaches a shell. The rule's own message
            # is "interpolated directly into a script", and these are not scripts.
            #
            # `concurrency.group` is the case that exposed it: DuckDB writes
            # `group: osx-${{ github.workflow }}-${{ github.ref }}-${{ github.head_ref
            # || '' }}-...` in ten workflows, which is the documented way to scope
            # cancellation per branch. A group name is a string GitHub compares for
            # equality. There is no shell, so there is nothing to inject into, and the
            # existing exemption did not apply because the line has other text around
            # the expression.
            #
            # `name`, `runs-on`, `container`, `image` and `environment` are the same:
            # GitHub consumes the value itself rather than handing it to an
            # interpreter. `key` and `restore-keys` reach a cache rather than a shell,
            # and cache poisoning is `SUSPECT.CI.ARTIFACT_POISONING.001`.
            r"(?![ \t]{0,64}(?:group|name|runs-on|container|image|environment|url"
            r"|key|restore-keys|path|tags|labels|timeout-minutes|concurrency"
            r"|cancel-in-progress|if)[ \t]{0,8}:)"
            r"[^\n]{0,300}"
            r"\$\{\{[ \t]{0,32}github\.(?:event\.(?:issue|pull_request|comment|"
            # `user.login` is NOT here. GitHub validates a login to alphanumerics and
            # single hyphens, so it cannot carry a semicolon, a backtick or a quote --
            # there is nothing to inject. A title or a body can carry anything.
            #
            # nlohmann writes `echo ${{ github.event.pull_request.user.login }} >
            # ./pr/author` and Astro writes `--body "Hello @${{ github.event.issue.user
            # .login }}"`, and both were the only blocking finding in their repository.
            r"discussion|review)\.(?:title|body)"
            r"|event\.head_commit\.message|head_ref)"
        ),
        # The claim is "interpolated into a script", so the match has to land in
        # something an interpreter parses. That replaces the list of keys whose values
        # never reach a shell, which could only ever be as long as the last repository
        # somebody measured: `concurrency.group` in DuckDB was the first, and React
        # writes `embed-title: '#${{ github.event.number }} ...'` on a Discord-notify
        # action three times, which is a string posted to a chat room.
        #
        # 216 findings across 91 of the 1,427 repositories measured.
        in_shell=True,
        paths=CI_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.ARTIFACT_POISONING.001",
        references=(references.GITHUB_ACTIONS_HARDENING, references.UNTRUSTED_INPUT_IN_BUILD),
        title="Untrusted build uploads or restores a cache it can control",
        message=(
            "This workflow runs contributor code under `pull_request_target` and "
            "also writes an artefact or a cache entry. The job has the base "
            "repository's secrets and a writable token, so anything it stores is "
            "trusted by later runs -- which turns one pull request into a "
            "persistent foothold in the pipeline."
        ),
        remediation=(
            "Do not upload artefacts or write caches from a job that runs "
            "contributor code with elevated permissions. Split the build from the "
            "privileged step."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        # THREE halves, and the third is the one that was missing: the message claims
        # the workflow "runs contributor code", and `pull_request_target` on its own
        # does not. The trigger exists so that a workflow can comment, label or triage
        # with the base repository's token, and `actions/checkout` defaults to the BASE
        # ref there -- which is why the trigger is safe when nothing checks out the head.
        #
        # `apache/beam` produced 71 findings, one per workflow: every one of its post-
        # commit suites is triggered by `pull_request_target` so that a committer can
        # run it on a contributor's branch, and every one uses `actions/cache` and
        # `actions/upload-artifact`. None of them checks out the pull request head.
        #
        # This is the same correction `SUSPECT.CI.PR_TARGET.001` above already carries,
        # made for the same reason on the rule next to it: what is exploitable is
        # checking out the head and then running it.
        pattern=ConfigRule._p(
            # A trigger KEY, for the reason `SUSPECT.CI.PR_TARGET.001` above records:
            # `servo/servo` excludes the trigger in an `if:` and was reported for it.
            r"(?:^[ \t]{0,8}pull_request_target[ \t]*:"
            r"|^[ \t]{0,8}on[ \t]*:[ \t]*\[?[^\n]{0,60}\bpull_request_target\b"
            r"|^[ \t]{0,8}-[ \t]*pull_request_target[ \t]*$)[\s\S]{0,4000}?"
            r"ref:[^\n]{0,120}(?:github\.event\.pull_request\.(?:head|merge_commit_sha)"
            r"|github\.head_ref)"
            r"[\s\S]{0,4000}?"
            r"(?:actions/upload-artifact|actions/cache|save-cache|restore-cache)"
        ),
        paths=CI_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.PR_TARGET.001",
        references=(references.GITHUB_ACTIONS_HARDENING, references.UNTRUSTED_INPUT_IN_BUILD),
        title="Workflow uses pull_request_target and checks out the pull request head",
        message=(
            "pull_request_target runs with a writable token and the base "
            "repository's secrets, and this workflow checks out the pull request "
            "head in that context. Contributor code then executes with full write "
            "access to the repository and the ability to read every secret the job "
            "can reach. This is the most commonly exploited misconfiguration in CI."
        ),
        remediation=(
            "Use pull_request for anything that runs contributor code. If "
            "pull_request_target is required to comment or label, do not check out "
            "the head ref in the same job."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        # Both halves, because the message claims both and the pattern was the
        # trigger alone: `pull_request_target`, anywhere in any workflow.
        #
        # `spf13/cobra` was reported at HIGH for a labeller workflow with no
        # checkout step in it at all -- `actions/labeler` and `pull-requests:
        # write`, which is the pattern GitHub's own documentation recommends for
        # labelling a pull request. The rule's title said "with an explicit
        # checkout", its message said "this workflow also checks out a specific
        # ref", and nothing checked.
        #
        # A BARE checkout under `pull_request_target` is not the bug either:
        # `actions/checkout` defaults to the base ref there, which is the whole
        # reason the trigger exists. What is exploitable is checking out the pull
        # request HEAD and then running it, so the ref is what this looks for.
        #
        # Window set wider than `_near`'s default: the trigger is at the top of the
        # file and the checkout is inside a job, with `permissions`, `jobs`,
        # `runs-on` and often several earlier steps between them.
        pattern=ConfigRule._p(
            PatternProximity._near(
                # The trigger, as a YAML KEY. `servo/servo` writes
                # `if: github.event_name != 'pull_request_target'` -- a guard that the
                # event is NOT that one -- and the rule matched the string inside it,
                # then found a head checkout elsewhere in the file and reported the
                # workflow for the trigger it explicitly excludes.
                #
                # A trigger is a key: `pull_request_target:` at the start of a line, or
                # the inline `on: pull_request_target` and `on: [pull_request_target]`
                # forms. A quoted occurrence in an expression is a comparison.
                r"(?:^[ \t]{0,8}pull_request_target[ \t]*:"
                r"|^[ \t]{0,8}on[ \t]*:[ \t]*\[?[^\n]{0,60}\bpull_request_target\b"
                r"|^[ \t]{0,8}-[ \t]*pull_request_target[ \t]*$)",
                r"ref:[^\n]{0,120}(?:github\.event\.pull_request\.(?:head|merge_commit_sha)"
                r"|github\.head_ref)",
                window=4000,
            )
        ),
        # A job gated on a named actor. See `TRUSTED_ACTOR_GATE`.
        mitigation=TRUSTED_ACTOR_GATE,
        paths=CI_PATHS,
    ),
    ConfigRule(
        rule_id="POLICY.CI.UNPINNED_ACTION.001",
        references=(references.OPENSSF_SCORECARD_PINNED, references.GITHUB_ACTIONS_HARDENING),
        title="Action referenced by a mutable tag",
        message=(
            "A third-party action is referenced by tag rather than by commit SHA. A "
            "tag can be moved, so what executes in this pipeline is whatever the tag "
            "points at today, with access to the job's secrets. Pinning by tag "
            "delegates that decision permanently to whoever controls the tag."
        ),
        remediation=(
            "Pin to a full commit SHA and record the version in a trailing comment: "
            "uses: owner/action@<sha>  # v4.1.0"
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        pattern=ConfigRule._p(
            r"uses:\s*(?!\./)(?!actions/)[\w.\-]+/[\w.\-]+@(?!\b[0-9a-f]{40}\b)[\w.\-]+"
        ),
        paths=CI_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.FETCH_EXEC.001",
        references=(
            references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,
            references.GITHUB_ACTIONS_HARDENING,
        ),
        title="CI step fetches and executes remote content",
        message=(
            "A pipeline step downloads something and runs it. The code that executes "
            "is whatever the remote host serves at that moment, with the job's "
            "credentials, and it is not captured by review or by any lockfile."
        ),
        remediation=(
            "Vendor the script, or pin it by digest and verify the digest before running it."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        # The same mitigation the container rule carries, for the same reason and by
        # the same argument: what runs is decided before the build rather than by
        # whoever controls a host today. Without it this rule reported `uv`'s own
        # `build-dev-binaries.yml`, nvm's installer test, and Rust's CI bootstrap at
        # HIGH for downloading a pinned release -- 50 findings across 27 of the first
        # 261 repositories measured.
        #
        # A step down, not silence. A pipe from an unpinned URL into a shell keeps its
        # severity, which is the shape the rule is named for.
        mitigation=VERIFIED_FETCH,
        # Two shapes, because there are two ways to run what you fetched. The
        # pipe is the famous one; downloading to a path and then executing that
        # path is the same act written over three clauses, and it produced only
        # the `low` unpinned-base note.
        pattern=ConfigRule._p(
            r"(?:curl|wget)[^\n|]{0,200}\|[ \t]{0,32}(?:sudo[ \t]{1,8})?(?:ba)?sh"
            # No backreference tying the downloaded path to the executed one.
            # It would be more precise, and the pattern validator refuses
            # backreferences for every rule pack -- engine patterns are held to
            # the same rule, which is the point of holding them to it. Fetching
            # to a file and making something executable in the same command is
            # signal enough; the pair has no innocent reading.
            r"|(?:curl|wget)[^\n]{0,200}?(?:-o|--output|-O)\s{1,4}[^\s]{1,200}"
            # Crosses newlines, deliberately and boundedly. A Dockerfile RUN
            # and a CI `run:` block are both written across backslash
            # continuations as a matter of course, so a gap that stops at the
            # first newline misses the ordinary spelling of this attack rather
            # than an evasion of it.
            r"[\s\S]{0,240}?chmod\s{1,4}(?:\+x|[0-7]?(?:[1357][0-7][0-7]|[0-7][1357][0-7]|[0-7][0-7][1357]))"
        ),
        # Inside something an interpreter runs. The rule's own message is "a pipeline
        # STEP downloads something and runs it", and without this it matched any
        # occurrence anywhere in a workflow file: `cloudflare/workers-sdk` documents its
        # own installer in an action input --
        #
        #     description: 'How OLD gets installed. Supported: installer-script
        #                   (curl | bash one-liner) ...'
        #
        # -- which is help text for a form field. `in_shell` is the condition the
        # expression-injection rule beside it already uses, and `run:`, `script:`, `cmd:`
        # and `entrypoint:` are the keys that hand a value to an interpreter.
        in_shell=True,
        paths=CI_PATHS,
        capabilities=(Capability.EGRESS, Capability.SPAWN),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.SELF_HOSTED_FORK.001",
        references=(references.GITHUB_ACTIONS_HARDENING, references.UNTRUSTED_INPUT_IN_BUILD),
        title="A fork's pull request runs on a self-hosted runner",
        message=(
            "This workflow is triggered by a pull request and runs on a self-hosted "
            "runner. A fork's code then executes on hardware you own and reuse: the "
            "runner keeps its filesystem, its caches, its credentials and whatever a "
            "previous job left behind, so one pull request can plant something the "
            "next job picks up. A GitHub-hosted runner is destroyed after the job."
        ),
        remediation=(
            "Run fork pull requests on GitHub-hosted runners, or gate the job on "
            "github.event.pull_request.head.repo.full_name == github.repository so "
            "that only branches in this repository reach the self-hosted one."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        # The trigger as a KEY, in the three spellings a workflow uses. A quoted
        # occurrence inside an `if:` is a comparison rather than a trigger, which
        # is the correction the two rules above already carry.
        pattern=ConfigRule._p(
            PatternProximity._near(
                r"(?:^[ \t]{0,8}pull_request(?:_target)?[ \t]*:"
                r"|^[ \t]{0,8}on[ \t]*:[ \t]*\[?[^\n]{0,60}\bpull_request(?:_target)?\b"
                r"|^[ \t]{0,8}-[ \t]*pull_request(?:_target)?[ \t]*$)",
                r"runs-on:[^\n]{0,200}self-hosted",
                window=4000,
            )
        ),
        mitigation=FORK_GUARD,
        paths=GITHUB_WORKFLOW_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.WORKFLOW_RUN_CHECKOUT.001",
        references=(references.GITHUB_ACTIONS_HARDENING, references.UNTRUSTED_INPUT_IN_BUILD),
        title="workflow_run checks out the commit that triggered it",
        message=(
            "`workflow_run` runs in the base repository's context -- a writable token "
            "and every secret -- and this workflow checks out the commit that "
            "triggered it. That commit is whatever the earlier, unprivileged workflow "
            "was running, which for a fork's pull request is contributor code. It is "
            "`pull_request_target` by another name, with the same consequence."
        ),
        remediation=(
            "Download what the first workflow produced as an artefact and treat it as "
            "data. Do not check out or execute the triggering commit from a "
            "`workflow_run` job."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            PatternProximity._near(
                r"(?:^[ \t]{0,8}workflow_run[ \t]*:"
                r"|^[ \t]{0,8}on[ \t]*:[ \t]*\[?[^\n]{0,60}\bworkflow_run\b"
                r"|^[ \t]{0,8}-[ \t]*workflow_run[ \t]*$)",
                r"ref:[^\n]{0,160}github\.event\.workflow_run\."
                r"(?:head_sha|head_branch|head_commit)",
                window=4000,
            )
        ),
        mitigation=TRUSTED_ACTOR_GATE,
        paths=GITHUB_WORKFLOW_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.CACHE_POISONING.001",
        references=(references.GITHUB_ACTIONS_HARDENING, references.UNTRUSTED_INPUT_IN_BUILD),
        title="A publishing workflow restores a cache an untrusted run can write",
        message=(
            "This workflow publishes a release artefact and also restores a cache. A "
            "cache entry written on the default branch is readable by every branch, "
            "and one written by a pull request is restorable through a prefix key -- "
            "so somebody who can run CI can decide what the release build compiles "
            "against, without changing anything in the repository."
        ),
        remediation=(
            "Do not restore caches in the job that publishes. Build the artefact in a "
            "job with no cache, or make the cache key cover every input that decides "
            "what is published."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            PatternProximity._near(
                r"(?:npm[ \t]+publish|yarn[ \t]+publish|pnpm[ \t]+publish"
                r"|twine[ \t]+upload|pypa/gh-action-pypi-publish"
                r"|cargo[ \t]+publish|gem[ \t]+push|docker[ \t]+push"
                r"|gh[ \t]+release[ \t]+create|softprops/action-gh-release)",
                r"(?:actions/cache|restore-keys[ \t]*:)",
                window=6000,
            )
        ),
        # Raised only beside a trigger an outside contributor controls, which is how a poisoned
        # cache entry reaches the default branch's scope (the 2024 Ultralytics release). A
        # tag-triggered release that restores `setup-node`'s npm cache is the ordinary shape:
        # it was a code warning on 135 of 11,005 benign units rescanned (review 98).
        aggravation=UNTRUSTED_TRIGGER,
        aggravation_in_file=True,
        paths=GITHUB_WORKFLOW_PATHS,
    ),
    ConfigRule(
        rule_id="POLICY.CI.WRITE_ALL_PERMISSIONS.001",
        references=(
            references.GITHUB_ACTIONS_HARDENING,
            references.EXECUTION_WITH_UNNECESSARY_PRIVILEGE,
        ),
        title="Workflow token is granted every write scope",
        message=(
            "`permissions: write-all` gives the job's token write access to every "
            "scope the repository has -- contents, packages, deployments, actions, "
            "security events. Everything the job runs, including every third-party "
            "action in it, can use all of it."
        ),
        remediation=(
            "Declare the scopes the job needs and nothing else, starting from "
            "`permissions: {}` and adding one at a time."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        pattern=ConfigRule._p(r"^[ \t]{0,16}permissions[ \t]*:[ \t]*write-all[ \t]*$"),
        paths=GITHUB_WORKFLOW_PATHS,
    ),
    ConfigRule(
        rule_id="POLICY.CI.UNPINNED_REUSABLE_WORKFLOW.001",
        references=(references.OPENSSF_SCORECARD_PINNED, references.GITHUB_ACTIONS_HARDENING),
        title="Reusable workflow called by a mutable ref",
        message=(
            "A reusable workflow from another repository is called by branch or tag. "
            "The whole workflow -- every step and every action inside it -- is "
            "whatever that ref points at when the job runs, and it executes with this "
            "repository's token and the secrets the caller passes it."
        ),
        remediation=(
            "Pin the call to a full commit SHA and record the version in a trailing "
            "comment: uses: owner/repo/.github/workflows/build.yml@<sha>  # v2.1.0"
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        # The action rule above cannot match this shape: its pattern expects
        # `owner/repo@ref`, and a reusable workflow carries the file path between
        # the two.
        pattern=ConfigRule._p(
            r"uses:\s*(?!\./)[\w.\-]+/[\w.\-]+/[^\s@]{1,120}\.ya?ml"
            r"@(?!\b[0-9a-f]{40}\b)[\w.\-]+"
        ),
        paths=GITHUB_WORKFLOW_PATHS,
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.GITLAB_INJECTION.001",
        references=(references.CODE_INJECTION, references.UNTRUSTED_INPUT_IN_BUILD),
        title="GitLab job interpolates a contributor-controlled variable into a script",
        message=(
            "A predefined variable an outside contributor controls -- a commit title, "
            "a branch name, a merge request title -- is handed to something that parses "
            "it again as code: `eval`, or a double-quoted `sh -c` / `python -c` string. "
            "GitLab passes these to the job's shell as environment variables, so a plain "
            "`$VAR` is data; here the value becomes part of a command, and a title "
            "containing a semicolon or a backtick runs whatever follows with the job's "
            "token and the project's variables."
        ),
        remediation=(
            "Bind the value with `variables:` and quote every use, or pass it to the "
            "command through a file. It must not be expanded into the text of a "
            "script line."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        # Only where the value is parsed a second time. GitLab's runner does not expand
        # variables in `script:`; the executing shell does, as data, so `echo "$CI_COMMIT_TITLE"`
        # runs nothing whatever the title says (docs.gitlab.com, "Where variables can be used").
        pattern=ConfigRule._p(
            REPARSED + r"\$\{?(?:CI_COMMIT_(?:TITLE|MESSAGE|DESCRIPTION|REF_NAME|BRANCH|TAG|AUTHOR)"
            r"|CI_MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME|SOURCE_PROJECT_PATH)"
            r"|CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME)\b"
        ),
        # The claim is "expanded by the shell that runs this job", so the match has
        # to land in a script. A `rules:` expression comparing the same variable is
        # how a pipeline decides whether to run at all.
        in_shell=True,
        paths=("**/.gitlab-ci.yml", "**/.gitlab-ci.yaml", "**/.gitlab/ci/*.yml"),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.BITBUCKET_INJECTION.001",
        references=(references.CODE_INJECTION, references.UNTRUSTED_INPUT_IN_BUILD),
        title="Bitbucket Pipelines step re-parses a contributor-controlled branch name",
        message=(
            "A branch or tag name -- chosen by whoever pushes it, including from a fork -- is "
            "handed to something that parses it again as code: `eval`, or a double-quoted "
            "`sh -c` / `python -c` string. Bitbucket gives the step these as environment "
            "variables, so a plain `$BITBUCKET_BRANCH` is data; here the name becomes part of "
            "a command and runs with the pipeline's repository and deployment variables."
        ),
        remediation=(
            'Pass the value as an argument ("$BITBUCKET_BRANCH"), never inside a string '
            "that is evaluated, and validate it against the shape a branch name should have."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            REPARSED + r"\$\{?(?:BITBUCKET_BRANCH|BITBUCKET_TAG|BITBUCKET_PR_DESTINATION_BRANCH"
            r"|BITBUCKET_BOOKMARK)\b"
        ),
        in_shell=True,
        paths=("**/bitbucket-pipelines.yml", "**/bitbucket-pipelines.yaml"),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.BUILDKITE_INJECTION.001",
        references=(references.CODE_INJECTION, references.UNTRUSTED_INPUT_IN_BUILD),
        title="Buildkite pipeline interpolates a contributor-controlled value at upload",
        message=(
            "`buildkite-agent pipeline upload` substitutes `$VAR` and `${VAR}` into the "
            "pipeline before any shell runs, and this command names a value the person who "
            "pushed chooses -- the branch, the tag, the commit message, the author. The value "
            "becomes part of the command text, so a commit message containing a semicolon "
            "runs whatever follows on the agent, with its secrets and its access."
        ),
        remediation=(
            "Escape it as `$$VAR` (or `\\$VAR`) so the agent's shell expands it at run time as "
            'data, and quote it there: "$$BUILDKITE_BRANCH".'
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"(?<![$\\])\$\{?BUILDKITE_(?:BRANCH|TAG|MESSAGE|BUILD_AUTHOR|BUILD_AUTHOR_EMAIL"
            r"|BUILD_CREATOR|BUILD_CREATOR_EMAIL|PULL_REQUEST_BASE_BRANCH|PULL_REQUEST_LABELS"
            r"|PULL_REQUEST_REPO)\b"
        ),
        in_shell=True,
        paths=(
            "**/.buildkite/*.yml",
            "**/.buildkite/*.yaml",
            "**/buildkite.yml",
            "**/buildkite.yaml",
        ),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.AZURE_INJECTION.001",
        references=(references.CODE_INJECTION, references.UNTRUSTED_INPUT_IN_BUILD),
        title="Azure Pipelines script interpolates a contributor-controlled value",
        message=(
            "Azure expands `$(...)` macros into the script text before the shell "
            "parses it, and this script expands a value that comes from the branch, "
            "the commit message or a pull request. A commit message containing a "
            "shell metacharacter becomes part of the command, running with the "
            "pipeline's service connections and secret variables."
        ),
        remediation=(
            "Map the value into the step's `env:` and reference it as $VAR (or "
            "$env:VAR in PowerShell), so the shell parses the line before the value "
            "reaches it."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"\$\((?:Build\.(?:SourceBranchName|SourceBranch|SourceVersionMessage"
            r"|RequestedFor|RequestedForEmail)"
            r"|System\.PullRequest\.(?:SourceBranch|SourceRepositoryURI))\)"
        ),
        in_shell=True,
        paths=(
            "**/azure-pipelines.yml",
            "**/azure-pipelines.yaml",
            "**/.azure-pipelines/*.yml",
            "**/.azure-pipelines/*.yaml",
        ),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.CIRCLE_INJECTION.001",
        references=(references.CODE_INJECTION, references.UNTRUSTED_INPUT_IN_BUILD),
        title="CircleCI step interpolates a contributor-controlled pipeline value",
        message=(
            "CircleCI substitutes `<< pipeline.git.* >>` into the step's text before "
            "the shell runs it. A branch or tag name is chosen by whoever opens the "
            "pull request, so it becomes part of the command rather than an argument "
            "to it, with the job's context and environment variables."
        ),
        remediation=(
            "Bind the value to an environment variable in the job's `environment:` "
            'block and reference it as "$VAR" inside the command.'
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(r"<<[ \t]*pipeline\.git\.(?:branch|tag)[ \t]*>>"),
        in_shell=True,
        paths=("**/.circleci/config.yml", "**/.circleci/config.yaml"),
    ),
    ConfigRule(
        rule_id="SUSPECT.CI.JENKINS_INJECTION.001",
        references=(references.CODE_INJECTION, references.UNTRUSTED_INPUT_IN_BUILD),
        title="Jenkins shell step interpolates a contributor-controlled value",
        message=(
            "A Groovy double-quoted string expands `${...}` before the shell step "
            "receives it, and this one expands a value that comes from the branch or "
            "the change request. The expansion happens in Jenkins, so quoting inside "
            "the script cannot help: the value is already part of the command by the "
            "time a shell sees it, and it runs with the credentials the job binds."
        ),
        remediation=(
            "Pass the value through `withEnv` or `environment {}` and reference it as "
            "'$VAR' inside a single-quoted `sh` block, so Groovy leaves it alone and "
            "the shell receives it as data."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        pattern=ConfigRule._p(
            r"(?:sh|bat|powershell)[ \t]*\(?[ \t]*\"[^\"\n]{0,200}"
            r"\$\{(?:env\.)?(?:BRANCH_NAME|CHANGE_BRANCH|CHANGE_TITLE|CHANGE_AUTHOR"
            r"|CHANGE_AUTHOR_DISPLAY_NAME|GIT_BRANCH|ghprbPullTitle|ghprbSourceBranch)\}"
        ),
        paths=("**/Jenkinsfile", "**/Jenkinsfile.*", "**/*.jenkinsfile"),
    ),
)


__all__ = [
    "CI_RULES",
    "FORK_GUARD",
    "GITHUB_WORKFLOW_PATHS",
    "REPARSED",
    "SECRET_BESIDE_EGRESS",
    "SERIALISED_SECRETS",
    "TRUSTED_ACTOR_GATE",
    "UNTRUSTED_DESTINATION",
    "UNTRUSTED_TRIGGER",
]
