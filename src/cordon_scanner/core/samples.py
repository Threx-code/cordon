"""Files that exist in order to be detected.

Every static-analysis tool ships two things this scanner will read: the rules it
matches with, and a corpus of files written to trip them. Both are full of the
shapes cordon is looking for, on purpose, and reporting them is reporting
another tool's fixtures back at its authors.

`semgrep/semgrep-rules` is the clearest case and was the measurement that
prompted this. 189 blocking findings, and 188 of them were samples:

    // ruleid: adafruit-api-key
    adafruit_api_token = "9zu9r6idf9c0tfcc4w26l66ij7visb8n"

That file is two lines long, and the first line says what the second is for. Its
sibling `adafruit-api-key.yaml` is the rule that matches it. The same repository
supplies `terraform/aws/security/aws-iam-admin-policy.tf` with an IAM wildcard in
it, and `yaml/kubernetes/security/privileged-container.yaml` whose `privileged:
true` is a *pattern*, not a deployment.

The class is not specific to semgrep, and any repository that vendors a rule set
has the same shape - which is most security teams' own repositories, and this
project's own rule packs. Bandit already produced the matching case for
bidirectional text: `plugins/trojansource.py` is the plugin that finds Trojan
Source, and `examples/trojansource.py` is the example it was written against.

## Two signals, both from the content

**A test annotation.** `ruleid:`, `ok:`, and their `todo` and `deep` variants are
semgrep's documented syntax for declaring what a test file is expected to
produce, and they appear nowhere else. Required at the start of a line and inside
a comment, so a credential whose own text happens to contain the word does not
qualify.

**A rule set itself.** A document whose top level is `rules:`, whose entries
carry an `id:`, and which uses the pattern and message keys a rule set uses. That
is the shape of semgrep, of this project's own packs, and of several other
YAML-configured analysers.

## Why this lowers severity rather than dropping the finding

A single comment line is cheap for an attacker to add, and a predicate that
DELETED findings would hand anybody a one-line way to silence this scanner. So
rule material is treated the way test material already is, one step further
down: the rule still runs, the finding is still made and still carries its
evidence, and it comes out at INFO -- below the default reporting threshold, so
it is out of the way, and visible to anyone who asks for INFO. Nothing is
skipped and nothing is unexaminable.

MALICIOUS findings are never ceilinged at all, here as everywhere else, so a
payload wearing a `// ruleid:` comment is reported in full.
"""

from __future__ import annotations

import re

from cordon_scanner.core.paths import basename

RULE_TEST_ANNOTATION = re.compile(
    rb"""(?mx)
    ^[ \t]*                       # start of a line, which is where a test annotation sits
    (?://|\#|--|/\*|\*|<!--)      # inside a comment, in any of the syntaxes rule corpora use
    [ \t]*
    (?:deep)?(?:todo)?            # `deepruleid:`, `todook:` and the rest of the family
    (?:ruleid|ok)
    [ \t]*:[ \t]*
    [A-Za-z0-9_.\-]{3,}           # naming a rule, which is what makes it an annotation
    """,
)
"""Semgrep's test annotations, which declare what a file is expected to produce."""

TOML_RULESET = re.compile(rb"(?m)^\[\[rules\]\][ \t]*(?:\#.*)?$")
"""A TOML detection ruleset, which is how gitleaks ships its rules.

`config/gitleaks.toml` is two thousand lines of `[[rules]]` with an `id`, a
`regex` and a `description` apiece, and sixteen of gitleaks' 151 findings were in
it. The YAML test below asks the same three questions of a YAML document."""

RULE_BUILDER = re.compile(
    rb"""(?ix)
    (?:RuleID|rule_id|ruleID|ruleId)[ \t]*[:=]
    """,
)
"""A rule identifier being assigned in source code.

Some tools build their rules in a programming language rather than declaring them
in a document. gitleaks does: `cmd/generate/config/rules/anthropic.go` constructs
a `config.Rule` with a `RuleID`, a `Regex`, and then lists its own true and false
positives to validate the regex against. 132 of that repository's 151 findings
were those files -- the sample keys a secret scanner publishes so that its rules
can be tested."""

LABELLED_SAMPLES = re.compile(
    rb"""(?ix)
    \b(?:
        tps | fps
      | true[_-]?positives | false[_-]?positives
      | validate \s* \(
    )\b
    """,
)
"""Samples labelled by what a rule is expected to say about them.

Required ALONGSIDE `RULE_BUILDER`, because neither is enough alone: a file may
name a rule id for any number of reasons, and `validate(` is an ordinary function
name. Together they are a rule and its test corpus in one file, which is the thing
this module is about."""

RULESET_HEADING = re.compile(rb"(?m)^rules:[ \t]*(?:\#.*)?$")
RULESET_ENTRY = re.compile(rb"(?m)^[ \t]*-[ \t]*id:[ \t]*\S")
RULESET_ENTRY_TOML = re.compile(rb"""(?m)^[ \t]*(?:id|regex|description)[ \t]*=[ \t]*\S""")
RULESET_BODY = re.compile(
    rb"(?m)^[ \t]*(?:patterns?|pattern-either|pattern-regex|message|languages|severity"
    rb"|metadata|capability|composite|match):",
)

INSPECTED_BYTES = 262_144
"""How much of a file is read for these signals.

A rule set declares itself in its first lines and a test corpus annotates every
sample, so a quarter of a megabyte settles the question for any real file. The
bound matters because this runs on every file in a tree and the alternative is
two full regex passes over a generated bundle.
"""


SUPPRESSION_FILES = frozenset(
    {
        ".gitleaksignore",
        ".gitleaksbaseline",
        ".semgrepignore",
        ".trivyignore",
        ".trufflehogignore",
        ".secretsignore",
        ".secrets.baseline",
        ".gitallowed",
        ".whitesource",
    }
)
"""A scanner's own record of what it has already decided to ignore.

These files exist to hold the output of another tool: fingerprints, file-and-line
references, and in several formats the matched value itself. gitleaks' own
`.gitleaksignore` produced three findings. Matched by name, which is appropriate
for a file whose name is its contract."""


def is_rule_material(raw: bytes, path: str = "") -> bool:
    """Whether this file is an analyser's rule, or a test case written for one."""
    if path and basename(path) in SUPPRESSION_FILES:
        return True
    head = raw[:INSPECTED_BYTES]
    if RULE_TEST_ANNOTATION.search(head):
        return True
    if RULE_BUILDER.search(head) and LABELLED_SAMPLES.search(head):
        return True
    if TOML_RULESET.search(head) and RULESET_ENTRY_TOML.search(head):
        return True
    return bool(
        RULESET_HEADING.search(head) and RULESET_ENTRY.search(head) and RULESET_BODY.search(head)
    )


MACHINE_PROVISIONING = re.compile(
    rb"""(?mx)
    ^[ \t]{0,16}(?:sudo[ \t]{1,4})?(?:-[ \t]{1,4})?   # under sudo, or a cloud-config list item
    (?:
        (?:apt|apt-get|aptitude)[ \t]{1,4}(?:-{1,2}[A-Za-z-]{1,20}[ \t]{1,4}){0,6}install
      | (?:yum|dnf|microdnf|zypper)[ \t]{1,4}(?:-{1,2}[A-Za-z-]{1,20}[ \t]{1,4}){0,6}install
      | apk[ \t]{1,4}(?:-{1,2}[A-Za-z-]{1,20}[ \t]{1,4}){0,6}add
      | pacman[ \t]{1,4}-S
    )
    \b
    """,
)
"""A script that installs operating-system packages as root.

This is what provisioning a machine looks like, and provisioning a machine means
fetching software and arranging for it to keep running: that is not a side effect
of the job, it IS the job. A Kubernetes node bootstrap script downloads kubectl,
writes a kubelet drop-in under `/etc/systemd/system/`, enables the unit and
appends shell completion to `.bashrc`.

`ViktorUJ/cks` supplied twenty-one of those and
`stacksimplify/terraform-on-aws-ec2` seventy-seven, all
`yum install httpd` and `systemctl enable httpd`.

Used for ONE thing: a ceiling on the persistence composite, applied in
`CapabilityDetector._composite_finding`. Deliberately not on the dropper
composite -- piping an unpinned remote script into a shell is a choice a
provisioning script still has to answer for, and `curl | bash` is how the one
real supply-chain attack in this corpus works."""


CLOUD_CONFIG = re.compile(rb"^#cloud-config\b")
"""The first line cloud-init requires of a user-data document.

A file that declares itself cloud-init user data is a provisioning script by its
own statement, and it does not have to install a package to say so."""


def is_machine_provisioning(raw: bytes) -> bool:
    """Whether this file provisions a machine."""
    head = raw[:INSPECTED_BYTES]
    return CLOUD_CONFIG.match(head) is not None or MACHINE_PROVISIONING.search(head) is not None


__all__ = [
    "CLOUD_CONFIG",
    "INSPECTED_BYTES",
    "LABELLED_SAMPLES",
    "MACHINE_PROVISIONING",
    "RULESET_BODY",
    "RULESET_ENTRY",
    "RULESET_ENTRY_TOML",
    "RULESET_HEADING",
    "RULE_BUILDER",
    "RULE_TEST_ANNOTATION",
    "SUPPRESSION_FILES",
    "TOML_RULESET",
    "is_machine_provisioning",
    "is_rule_material",
]
