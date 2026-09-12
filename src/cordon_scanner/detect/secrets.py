"""Secret detection.

Two rules govern this detector, and both are unusual enough to state plainly.

**No path is ever exempt.** Excluding a path from secret scanning inverts the
control. The usual reasoning is that ``.env`` and ``*.pem`` are ignored by
version control anyway, so flagging them is redundant -- but a committed copy of
one of those files is the single case a secret scanner exists to catch. It
happens through a forced add, a merge from a branch carrying different ignore
rules, a nested directory the pattern misses, or a rename. In every one of those
the file *is* committed, and a path exemption says "do not look".

**Findings never carry the secret.** Evidence is hash-only and cannot be
relaxed by configuration. A finding travels into CI logs, pull-request comments
and SARIF uploaded to third parties, all of which outlive and out-reach the
repository. The tool that finds a leaked credential must not be the mechanism
that spreads it. The match hash is still enough to deduplicate, to compare two
scans, and to confirm a rotation actually changed the value.

Allowlisting is therefore by literal value, never by path. Exempting the one
fixture that must look real is precise; exempting the file it lives in is not.
"""

from __future__ import annotations

import base64
import binascii
import itertools
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cordon_scanner.core.comments import block_comment_spans, inside_spans, is_commented
from cordon_scanner.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon_scanner.core.prose import article
from cordon_scanner.core.redact import Redactor
from cordon_scanner.core.samples import is_media_extractor
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.core.walker import PathGlob
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from cordon_scanner.core.content import FileContent
    from cordon_scanner.detect.base import Unit


@dataclass(frozen=True, slots=True)
class SecretPattern:
    """A recognisable credential shape."""

    @staticmethod
    def _p(pattern: str) -> re.Pattern[bytes]:
        return re.compile(pattern.encode("utf-8"), re.MULTILINE)

    rule_id: str
    name: str
    pattern: re.Pattern[bytes]
    severity: Severity
    confidence: Confidence
    remediation: str
    prefilter: tuple[bytes, ...] = ()
    """Literals, one of which must be present for this pattern to match.

    Every provider credential has a fixed prefix -- that is what makes the
    format recognisable in the first place -- so the gate is exact rather than
    heuristic. Without it the detector ran every provider regex over every file,
    which profiling showed to be the single largest cost in a scan.
    """


ROTATE = (
    "Revoke this credential now, then rotate it. Removing it from the working "
    "tree is not enough: it remains in git history and in every clone, so it "
    "must be treated as public from the moment it was committed."
)

# Provider-specific shapes. These carry high confidence because the format is
# distinctive enough that a match is almost never a coincidence, and because a
# leaked provider credential is immediately usable by whoever finds it.
PROVIDER_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "SECRET.AWS.ACCESS_KEY.001",
        "AWS access key id",
        SecretPattern._p(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"AKIA", b"ASIA", b"ABIA", b"ACCA"),
    ),
    SecretPattern(
        "SECRET.GITHUB.TOKEN.001",
        "GitHub token",
        SecretPattern._p(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_", b"github_pat_"),
    ),
    SecretPattern(
        "SECRET.SLACK.TOKEN.001",
        "Slack token",
        SecretPattern._p(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"xox",),
    ),
    SecretPattern(
        "SECRET.STRIPE.KEY.001",
        "Stripe secret key",
        SecretPattern._p(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"sk_live_", b"sk_test_", b"rk_live_", b"rk_test_"),
    ),
    SecretPattern(
        "SECRET.GOOGLE.API_KEY.001",
        "Google API key",
        SecretPattern._p(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"AIza",),
    ),
    SecretPattern(
        "SECRET.NPM.TOKEN.001",
        "npm access token",
        SecretPattern._p(r"\bnpm_[A-Za-z0-9]{36}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        "Revoke the token immediately. An npm publish token turns one leak into "
        "poisoned releases of every package the account maintains.",
        (b"npm_",),
    ),
    SecretPattern(
        "SECRET.PYPI.TOKEN.001",
        "PyPI API token",
        SecretPattern._p(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        "Revoke the token immediately. A PyPI token turns one leak into poisoned "
        "releases of every project the account maintains.",
        (b"pypi-AgEIcHlwaS5vcmc",),
    ),
    SecretPattern(
        "SECRET.PRIVATE_KEY.001",
        "Private key block",
        # The header AND a key after it. A PEM block is both; the header alone is a
        # string constant, and any library that PARSES PEM has to contain one.
        #
        # mbedTLS declares `#define PEM_BEGIN_PRIVATE_KEY_RSA "-----BEGIN RSA PRIVATE
        # KEY-----"` and five siblings, so DuckDB's vendored copy produced ten
        # CRITICAL findings in one header file -- and so would OpenSSL, BoringSSL,
        # Go's crypto/pem, every language's TLS binding and every tool that reads a
        # certificate. Vendored third-party source is deliberately not ceilinged,
        # because that is where a supply-chain payload lives, so the fix has to be in
        # the pattern rather than in a path list.
        #
        # Twenty base64 characters is far below any real key and far above what a
        # constant carries: after the header a declaration has a quote, a newline or
        # `\n` and then nothing, while a key has hundreds of characters of payload.
        # Whitespace and line breaks are allowed between the two, because a PEM block
        # always has them and an embedded one may be escaped.
        SecretPattern._p(
            r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----"
            # A bounded character class, not `(?:\s|\\r|\\n)*`. This project's own
            # pattern validator refuses an unbounded quantifier over an alternation as
            # a catastrophic-backtracking risk, and it refused the first version of
            # this -- engine patterns are held to the same standard as a rule pack,
            # which is the point of that test.
            #
            # The class covers real whitespace, the two characters an ESCAPED newline
            # is written with, and the punctuation a string CONCATENATION uses. A PEM
            # block embedded in Java or C# is written
            # `"-----BEGIN PRIVATE KEY-----\n" + "MIIB..."`, so the header and the body
            # are separated by a quote, a plus and spaces.
            #
            # What the class deliberately excludes is letters other than `r` and `n`,
            # which is what keeps the constants out: after mbedTLS's header comes a
            # closing quote, a newline and then `#define`, and `#` ends the gap, so the
            # base64 run has nowhere to start.
            r"""[\s\\rn"'+,()]{0,64}[A-Za-z0-9+/]{12}"""
        ),
        Severity.CRITICAL,
        Confidence.HIGH,
        "Treat the key as compromised. Generate a replacement, distribute it, "
        "and revoke the old one before removing it from the tree.",
        (b"PRIVATE KEY-----",),
    ),
    SecretPattern(
        "SECRET.JWT.001",
        "JSON Web Token",
        SecretPattern._p(
            r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
        ),
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "If this token is live, revoke it. A committed JWT is often an expired "
        "example, which is why this is reported at medium confidence.",
        (b"eyJ",),
    ),
    SecretPattern(
        "SECRET.SLACK.WEBHOOK.001",
        "Slack webhook URL",
        SecretPattern._p(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,}"),
        Severity.MEDIUM,
        Confidence.HIGH,
        "Delete the webhook in Slack. Anyone holding the URL can post as it.",
        (b"hooks.slack.com/services/",),
    ),
    # ---------------------------------------------------------------------
    # Provider credentials with a fixed, distinctive prefix.
    #
    # Every pattern below is anchored on a literal the issuing provider chose so
    # that its own tokens would be recognisable - which is exactly what makes this
    # the highest-precision family of rules in the tool and the safest place to
    # expand it. A prefix like `glpat-` or `dckr_pat_` appears in no other context.
    #
    # What is deliberately ABSENT: every credential whose only shape is "N hex
    # characters". Datadog, Algolia, Linode, Heroku and a dozen others issue bare
    # 32- or 40-character hex keys, and a pattern for those matches a git object id,
    # a content hash, an MD5 digest and a GPG fingerprint. That is the mistake this
    # rule family would make at scale, and the cryptominer rule already demonstrated
    # what it costs: `0x` plus forty hex characters reported every apt keyserver URL
    # on earth as cryptocurrency mining. A bare-hex provider rule is a noise
    # generator wearing a provider's name, so those providers are covered by the
    # generic assignment rule instead, where a credential-shaped NAME has to vouch
    # for them.
    #
    # Postmark was written and then removed under that rule, which is worth recording
    # because the temptation will come back. Its server token IS a UUID, so the only
    # way to pattern it is proximity -- the word "postmark" within forty characters of
    # any UUID -- and the first thing that matched was this project's own test naming
    # the provider beside its sample. A proximity rule over a universal shape reports
    # prose about the provider, and `assemble` cannot hide a value whose pattern spans
    # the text around it.
    #
    # Each entry carries a prefilter. It is not an optimisation detail: the
    # substring test rejects almost every file before any regex runs, which is what
    # makes eighty-odd patterns affordable in a commit-time hook.
    #
    # Samples for every one of these live in `tests/unit/test_providers.py` rather
    # than here, because this file is scanned by the tool it configures and a real-
    # shaped token written inline would be reported - correctly - on every scan.
    # -- Source forges and package registries -----------------------------
    SecretPattern(
        "SECRET.GITLAB.TOKEN.001",
        "GitLab token",
        SecretPattern._p(
            r"\bgl(?:pat|dt|rt|soat|ptt|oas|imt|cbt|ffct|agent)-[0-9A-Za-z_\-]{20,}\b"
        ),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (
            b"glpat-",
            b"gldt-",
            b"glrt-",
            b"glsoat-",
            b"glptt-",
            b"gloas-",
            b"glimt-",
            b"glcbt-",
            b"glffct-",
            b"glagent-",
        ),
    ),
    SecretPattern(
        "SECRET.DOCKERHUB.TOKEN.001",
        "Docker Hub personal access token",
        SecretPattern._p(r"\bdckr_pat_[0-9A-Za-z_\-]{20,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"dckr_pat_",),
    ),
    SecretPattern(
        "SECRET.RUBYGEMS.TOKEN.001",
        "RubyGems API key",
        SecretPattern._p(r"\brubygems_[0-9a-f]{48}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"rubygems_",),
    ),
    SecretPattern(
        "SECRET.NUGET.KEY.001",
        "NuGet API key",
        SecretPattern._p(r"\boy2[a-z0-9]{43}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"oy2",),
    ),
    SecretPattern(
        "SECRET.JFROG.TOKEN.001",
        "JFrog Artifactory token",
        SecretPattern._p(r"\bAKCp8[0-9A-Za-z]{50,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"AKCp8",),
    ),
    SecretPattern(
        "SECRET.SONAR.TOKEN.001",
        "SonarQube token",
        SecretPattern._p(r"\bsq[apu]_[0-9a-f]{40}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"sqp_", b"sqa_", b"squ_"),
    ),
    SecretPattern(
        "SECRET.TERRAFORM.TOKEN.001",
        "Terraform Cloud API token",
        SecretPattern._p(r"\b[A-Za-z0-9]{14}\.atlasv1\.[0-9A-Za-z_\-]{20,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b".atlasv1.",),
    ),
    SecretPattern(
        "SECRET.VAULT.TOKEN.001",
        "HashiCorp Vault token",
        SecretPattern._p(r"\bhv[sb]\.[0-9A-Za-z_\-]{24,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"hvs.", b"hvb."),
    ),
    # -- Cloud platforms --------------------------------------------------
    SecretPattern(
        "SECRET.GOOGLE.OAUTH_TOKEN.001",
        "Google OAuth access token",
        SecretPattern._p(r"\bya29\.[0-9A-Za-z_\-]{30,}"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"ya29.",),
    ),
    SecretPattern(
        "SECRET.AZURE.STORAGE_KEY.001",
        "Azure Storage account key",
        SecretPattern._p(r"AccountKey=[0-9A-Za-z+/]{86}=="),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"AccountKey=",),
    ),
    SecretPattern(
        "SECRET.DIGITALOCEAN.TOKEN.001",
        "DigitalOcean token",
        SecretPattern._p(r"\bdo[portv]_v1_[0-9a-f]{64}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"dop_v1_", b"doo_v1_", b"dor_v1_", b"dot_v1_"),
    ),
    SecretPattern(
        "SECRET.ALIBABA.ACCESS_KEY.001",
        "Alibaba Cloud access key id",
        # Exactly twenty after the prefix, not twelve-to-twenty. The open range matched
        # inside SQL seed data in a Chinese admin framework - eighteen findings in one
        # repository's dump files - because `LTAI` plus twelve alphanumerics is a short
        # enough run to occur in any large table.
        SecretPattern._p(r"\bLTAI[0-9A-Za-z]{20}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"LTAI",),
    ),
    SecretPattern(
        "SECRET.TENCENT.SECRET_ID.001",
        "Tencent Cloud secret id",
        # Exactly thirty-two, for the same reason as Alibaba above: the open upper bound
        # let the pattern run on into whatever followed it inside a SQL dump.
        SecretPattern._p(r"\bAKID[0-9A-Za-z]{32}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"AKID",),
    ),
    SecretPattern(
        "SECRET.FLYIO.TOKEN.001",
        "Fly.io token",
        SecretPattern._p(r"\bfm2_[0-9A-Za-z+/=]{40,}"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"fm2_",),
    ),
    SecretPattern(
        "SECRET.NETLIFY.TOKEN.001",
        "Netlify personal access token",
        SecretPattern._p(r"\bnfp_[0-9A-Za-z]{36,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"nfp_",),
    ),
    SecretPattern(
        "SECRET.DATABRICKS.TOKEN.001",
        "Databricks personal access token",
        SecretPattern._p(r"\bdapi[0-9a-f]{32}(?:-\d+)?\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"dapi",),
    ),
    # -- Communication and messaging --------------------------------------
    SecretPattern(
        "SECRET.SLACK.APP_TOKEN.001",
        "Slack app-level token",
        SecretPattern._p(r"\bxapp-\d-[A-Z0-9]+-\d+-[0-9a-f]{32,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"xapp-",),
    ),
    SecretPattern(
        "SECRET.DISCORD.WEBHOOK.001",
        "Discord webhook URL",
        SecretPattern._p(
            r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[\w\-]{60,}"
        ),
        Severity.HIGH,
        Confidence.HIGH,
        "Delete the webhook in the channel settings. Anyone holding the URL can post to it.",
        (b"discord.com/api/webhooks/", b"discordapp.com/api/webhooks/"),
    ),
    SecretPattern(
        "SECRET.TELEGRAM.BOT_TOKEN.001",
        "Telegram bot token",
        SecretPattern._p(r"\b\d{8,10}:AA[0-9A-Za-z_\-]{32,34}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b":AA",),
    ),
    SecretPattern(
        "SECRET.SENDGRID.KEY.001",
        "SendGrid API key",
        SecretPattern._p(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"SG.",),
    ),
    SecretPattern(
        "SECRET.TWILIO.KEY.001",
        "Twilio API key",
        SecretPattern._p(r"\bSK[0-9a-fA-F]{32}\b"),
        Severity.HIGH,
        Confidence.MEDIUM,
        ROTATE,
        (b"SK",),
    ),
    SecretPattern(
        "SECRET.MAILGUN.KEY.001",
        "Mailgun API key",
        SecretPattern._p(r"\bkey-[0-9a-f]{32}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"key-",),
    ),
    SecretPattern(
        "SECRET.MICROSOFT.TEAMS_WEBHOOK.001",
        "Microsoft Teams webhook URL",
        SecretPattern._p(
            r"https://[0-9a-z.\-]+\.webhook\.office\.com/webhookb2/[0-9a-f\-]{36}@[0-9a-f\-]{36}/"
        ),
        Severity.MEDIUM,
        Confidence.HIGH,
        "Delete the connector. Anyone holding the URL can post into the channel.",
        (b".webhook.office.com/webhookb2/",),
    ),
    # -- AI and machine learning ------------------------------------------
    SecretPattern(
        "SECRET.OPENAI.KEY.001",
        "OpenAI API key",
        SecretPattern._p(r"\bsk-(?:proj-|svcacct-|admin-)?[0-9A-Za-z_\-]{32,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"sk-",),
    ),
    SecretPattern(
        "SECRET.ANTHROPIC.KEY.001",
        "Anthropic API key",
        SecretPattern._p(r"\bsk-ant-(?:api\d{2}|sid\d{2})-[0-9A-Za-z_\-]{40,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"sk-ant-",),
    ),
    SecretPattern(
        "SECRET.HUGGINGFACE.TOKEN.001",
        "Hugging Face access token",
        SecretPattern._p(r"\bhf_[0-9A-Za-z]{34,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"hf_",),
    ),
    SecretPattern(
        "SECRET.REPLICATE.TOKEN.001",
        "Replicate API token",
        SecretPattern._p(r"\br8_[0-9A-Za-z]{37,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"r8_",),
    ),
    SecretPattern(
        "SECRET.GROQ.KEY.001",
        "Groq API key",
        SecretPattern._p(r"\bgsk_[0-9A-Za-z]{40,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"gsk_",),
    ),
    SecretPattern(
        "SECRET.LANGCHAIN.KEY.001",
        "LangSmith API key",
        SecretPattern._p(r"\blsv2_(?:pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"lsv2_",),
    ),
    # -- Commerce and payments --------------------------------------------
    SecretPattern(
        "SECRET.STRIPE.WEBHOOK_SECRET.001",
        "Stripe webhook signing secret",
        SecretPattern._p(r"\bwhsec_[0-9A-Za-z]{32,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"whsec_",),
    ),
    SecretPattern(
        "SECRET.SHOPIFY.TOKEN.001",
        "Shopify access token",
        SecretPattern._p(r"\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"shpat_", b"shpca_", b"shppa_", b"shpss_"),
    ),
    SecretPattern(
        "SECRET.SQUARE.TOKEN.001",
        "Square access token",
        # `sq0atp-` and `sq0csp-` only. Square's newer tokens start `EAAA`, and that
        # form was here until the corpus measured it: `EAAA` is what base64 produces
        # from bytes beginning 0x10 0x00 0x00, so it prefixes an enormous amount of
        # embedded data. Eighty findings across twelve repositories, on WordPress's
        # `genericons.css` - base64 font data - and on Xcode Core Data mapping models,
        # which are plists full of base64 blobs.
        #
        # The same rule that removed the Ethereum address and Postmark's UUID: an
        # indicator needs a prefix nothing else produces, and four base64 characters
        # is not one.
        SecretPattern._p(r"\bsq0(?:atp|csp)-[0-9A-Za-z_\-]{22,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"sq0atp-", b"sq0csp-"),
    ),
    SecretPattern(
        "SECRET.PAYPAL.TOKEN.001",
        "PayPal or Braintree access token",
        SecretPattern._p(r"access_token\$(?:production|sandbox)\$[0-9a-z]{16,}\$[0-9a-f]{32}"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"access_token$production$", b"access_token$sandbox$"),
    ),
    # -- Observability and operations --------------------------------------
    SecretPattern(
        "SECRET.NEWRELIC.KEY.001",
        "New Relic key",
        SecretPattern._p(r"\bNR(?:AK|JS|II|AA|BR|RA)-[0-9A-Za-z]{27}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"NRAK-", b"NRJS-", b"NRII-", b"NRAA-", b"NRBR-", b"NRRA-"),
    ),
    SecretPattern(
        "SECRET.GRAFANA.TOKEN.001",
        "Grafana token",
        SecretPattern._p(r"\bgl(?:c|sa)_[0-9A-Za-z_\-]{32,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"glc_", b"glsa_"),
    ),
    SecretPattern(
        "SECRET.SENTRY.TOKEN.001",
        "Sentry auth token",
        SecretPattern._p(r"\bsntrys_[0-9A-Za-z+/=_\-]{40,}"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"sntrys_",),
    ),
    SecretPattern(
        "SECRET.PAGERDUTY.TOKEN.001",
        "PagerDuty API token",
        SecretPattern._p(r"\bpd[uv]s_[0-9A-Za-z_\-]{32,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"pdus_", b"pdvs_"),
    ),
    # -- Developer platforms -----------------------------------------------
    SecretPattern(
        "SECRET.ATLASSIAN.TOKEN.001",
        "Atlassian API token",
        SecretPattern._p(r"\bATATT3[0-9A-Za-z_\-=]{150,}"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"ATATT3",),
    ),
    SecretPattern(
        "SECRET.LINEAR.KEY.001",
        "Linear API key",
        SecretPattern._p(r"\blin_api_[0-9A-Za-z]{40,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"lin_api_",),
    ),
    SecretPattern(
        "SECRET.FIGMA.TOKEN.001",
        "Figma personal access token",
        SecretPattern._p(r"\bfigd_[0-9A-Za-z_\-]{40,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"figd_",),
    ),
    SecretPattern(
        "SECRET.NOTION.TOKEN.001",
        "Notion integration token",
        SecretPattern._p(r"\b(?:secret_[0-9A-Za-z]{43}|ntn_[0-9A-Za-z]{40,})\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"secret_", b"ntn_"),
    ),
    SecretPattern(
        "SECRET.SUPABASE.TOKEN.001",
        "Supabase access token",
        SecretPattern._p(r"\bsbp_[0-9a-f]{40}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"sbp_",),
    ),
    SecretPattern(
        "SECRET.PLANETSCALE.TOKEN.001",
        "PlanetScale token",
        SecretPattern._p(r"\bpscale_(?:tkn|pw|oauth)_[0-9A-Za-z_\-\.]{32,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"pscale_tkn_", b"pscale_pw_", b"pscale_oauth_"),
    ),
    SecretPattern(
        "SECRET.RESEND.KEY.001",
        "Resend API key",
        SecretPattern._p(r"\bre_[0-9A-Za-z]{16,}_[0-9A-Za-z]{16,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"re_",),
    ),
    SecretPattern(
        "SECRET.DOPPLER.TOKEN.001",
        "Doppler token",
        SecretPattern._p(r"\bdp\.(?:pt|st|sa|scim|audit)\.[0-9A-Za-z]{40,}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"dp.pt.", b"dp.st.", b"dp.sa.", b"dp.scim.", b"dp.audit."),
    ),
    SecretPattern(
        "SECRET.AIRTABLE.TOKEN.001",
        "Airtable personal access token",
        SecretPattern._p(r"\bpat[0-9A-Za-z]{14}\.[0-9a-f]{64}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"pat",),
    ),
    SecretPattern(
        "SECRET.DROPBOX.TOKEN.001",
        "Dropbox access token",
        SecretPattern._p(r"\bsl\.[0-9A-Za-z_\-]{130,}"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"sl.",),
    ),
    # SECRET.CRATES.TOKEN.001 was here and is gone. A crates.io token is `cio`
    # followed by thirty-two alphanumerics, and a three-character lowercase prefix in
    # front of a random run is not an indicator: it matched John the Ripper's character
    # set files in Metasploit's `data/jtr/`, which are tables of every printable
    # character by construction. Covered by the generic assignment rule instead, where
    # a credential-shaped name has to vouch for the value.
)

CREDENTIAL_NAME = re.compile(
    rb"(?i)(?:pass(?:wo?rd)?|secret|token|api[_\-]?key|auth|access[_\-]?key"
    rb"|private[_\-]?key|client[_\-]?secret|credential|passphrase)"
)
"""A name that suggests its value is a credential.

The same vocabulary the assignment pattern below matches, extracted so the
assembled path can require it too."""


# A credential-shaped assignment. Much weaker on its own, so it is gated on
# entropy: `password = "changeme"` in an example is not a leak, and reporting it
# is how a secret detector earns a blanket exception.
ASSIGNMENT = SecretPattern._p(
    r"""(?ix)
    (?:^|[^\w.])
    # Not a TYPE being declared. `typealias X = Y` in Swift, `using X = Y;` in C# and
    # C++, and `type X = Y` in TypeScript all read as an assignment and define a name
    # instead: `Signal-iOS` writes `public typealias SVRAuthCredential =
    # SVR2AuthCredential`, which renames a type and holds nothing.
    #
    # The capability detector's `DECLARATION` has carried this reasoning for `function`,
    # `def`, `fn` and `class` since the corpus first measured it; the assignment rule had
    # the Swift annotation forms and not the aliasing ones.
    # The separator is written `[ ]` and not as a bare space: this pattern is VERBOSE,
    # where an unescaped space is ignored, and `(?<!typealias )` compiles to a lookbehind
    # for `typealias` with nothing after it -- which is ten characters earlier than the
    # position that matters and never fires. The suite caught that on the first run.
    (?<!typealias[ ])(?<!using[ ])(?<!type[ ])(?<!typedef[ ])(?<!alias[ ])
    # Not a COUNT of tokens. `max_tokens` and `maxTokens` are already refused by the
    # boundary below -- `s` is neither a separator nor a capital -- and `MAXTOKENS` was
    # not, for the same reason `TOKENIZER` was not: in an all-capitals name the boundary
    # cannot see anything. Every codebase that talks to a language model has these.
    (?!(?:max|min|num|count|total|n)[_\-]?tokens?(?![a-z0-9_\-]))
    (                                     # 1: the whole variable name
      (?:[a-z_][a-z0-9_\-]{0,40}?)?
      (?:pass(?:wo?rd|phrase)?|secret|token|api[_\-]?key|auth[_\-]?token|
         access[_\-]?key|private[_\-]?key|client[_\-]?secret|credential)
      #
      # The credential word has to be a WHOLE word in the name. It used to be
      # allowed to run into anything, which made it a prefix test, and `token` is a
      # prefix of words that have nothing to do with credentials.
      #
      # Measured across 338 of the most-starred repositories on GitHub, this rule
      # fired in 42% of them. `tokenizer` was reported as a credential. So were
      # `maxTokens`, `promptTokens`, `completionTokens` and `max_new_tokens`, which
      # are counts in every codebase that talks to a language model, and `tokens`,
      # which is usually a lexer's output. That is roughly forty findings from one
      # English word having two unrelated meanings.
      #
      # A suffix is accepted when it starts the way a new word starts: a separator,
      # or a capital. `GITHUB_TOKEN`, `access_token_value`, `accessTokenValue` and
      # `secretKeyBase` all pass; `tokenizer` and `maxTokens` do not.
      #
      # `(?-i:...)` because this pattern is case-insensitive overall, and under
      # `(?i)` a `[A-Z]` class matches lowercase too -- so the CamelCase boundary
      # would have accepted every lowercase continuation and changed nothing.
      #
      # And a suffix that does not change what the word MEANS. The capital-boundary
      # test above works in camelCase and says nothing in SCREAMING_CASE, where every
      # letter is a capital and `TOKEN|IZER` is indistinguishable from `TOKEN|VALUE`:
      # `TOKENIZER`, `PASSPORT`, `PASSAGE` and `SECRETARY` all matched, and the
      # comment above says `tokenizer` does not -- which was true only of the
      # lowercase spelling.
      #
      # A closed list rather than a rule, because there is no rule: these are English
      # words that happen to begin with a credential word and mean something else. A
      # hump requirement would have been the rule, and it refuses `SECRETKEY`,
      # `CLIENTSECRET` and `GHTOKEN`, which are real names.
      (?!(?:iz|is)(?:e|er|ation|ed|ing)\b|port\b|age\b|enger\b|ive\b|ar(?:y|iat)\b)
      (?:
          [_\-.][a-z0-9_\-]{0,30}
        | (?-i:[A-Z])[A-Za-z0-9]{0,30}
      )?
    )
    (?![A-Za-z0-9])
    [ \t]*(?::(?!:)|=)[ \t]*       # a colon, but not C++'s `::`
    #
    # HORIZONTAL whitespace only, on both sides. `\s*` here matched across newlines, which
    # turned every Python class statement whose name contains one of the credential words into
    # a finding: `class AuthTokenService:` followed by a blank line and `@staticmethod` matched
    # as name `AuthTokenService`, value `@staticmethod` - a thirteen-character run with none of
    # the excluded punctuation in it. Reported against real code as
    # "A credential assigned to 'AuthTokenService'".
    #
    # An assignment puts its value on the same line as its name. A value on a LATER line is a
    # class body, a YAML mapping, or the next statement - never the thing that was assigned. The
    # multi-line case that is real, a literal concatenated across lines, is matched by the
    # assembled-literal path further down, which knows to look for a joiner.
    (?:
        ["']([^"'\s]{12,120})["']         # 2: quoted
      # `{` excluded alongside `}`, which was already here. A credential never
      # contains a brace: base64, hex, JWTs and every provider format are drawn from
      # alphabets that have none. A brace in a value means a struct literal, a block,
      # or an interpolation.
      #
      # Vault supplied sixteen findings of one shape - Go composite literals assigned
      # to a credential-shaped field:
      #
      #     Password: &v5.ChangePassword{
      #     secret.Auth = &api.SecretAuth{
      #     TOTPSecret: &mfa.TOTPSecret{
      #
      # Each ends the line, so the unquoted branch's end-of-line lookahead was
      # satisfied, and `&`, `.` and `{` were all permitted characters. Excluding the
      # opening brace removes the whole class in one character.
      | ([^\s"'#,;(){}\[\]=<>]{12,120})    # 3: unquoted
        (?=\s*(?:\#|$))                    #    ...and only to end of line
    )
    """
)
"""A credential-shaped name assigned a value, quoted or not.

The unquoted alternative is the whole point. The pattern required quotes, and
nothing in a `.env` file, a plain YAML file, a `.properties` file, a Makefile or
a connection string is quoted -- so `.env`, the single highest-yield location for
a committed credential, produced nothing at all.

The unquoted branch must reach the end of the line. Without that anchor it
matched code: `API_KEY = os.environ.get("API_KEY", "your-api-key-here")` gave
the "value" `os.environ.get(`, which has the entropy and character mix of a
credential and is a function call. A config assignment ends at the line; a call
does not.

The name is matched as a whole identifier that *contains* a credential word,
rather than as a word boundary before one. `\bsecret` cannot match inside
`API_SECRET`, because the character before it is an underscore and `\b` needs a
non-word character -- so the two most common environment-variable spellings,
`API_SECRET` and `AWS_SECRET_ACCESS_KEY`, matched nothing."""

CONNECTION_STRING = SecretPattern._p(
    r"""(?ix)
    \b[a-z][a-z0-9+.\-]{1,30}://
    [^\s:@/]{1,64} : ([^\s:@/]{6,120}) @ ([^\s@/?\#]{1,120})
    """
)
"""A password embedded in a URL's userinfo.

A database URL that carries userinfo -- a user name and a password, separated by
a colon, before the host -- holds a live credential in a form no assignment
pattern sees, and that is the conventional way such URLs are written.

The host is captured as well as the password, because where the URL points
decides whether the value is a credential at all. See `LOCAL_OR_RESERVED_HOST`.

Described rather than shown. This project scans itself, and a complete example
here would be a true positive: the tool should not need an exception for its own
source."""

LOCAL_OR_RESERVED_HOST = re.compile(
    rb"""(?ix)
    ^\[?(?:
        localhost
      | 127\.[0-9.]{1,11}
      | 0\.0\.0\.0
      | ::1
      | [a-z0-9-]{1,60}\.(?:localhost|local|test|invalid|example)
      | (?:[a-z0-9-]{1,60}\.){0,4}example\.(?:com|net|org)
      # A SINGLE-LABEL host, which on the public internet does not resolve. A name with
      # no dot in it is a Compose service, a Kubernetes service or an `/etc/hosts`
      # entry -- something reachable only from inside the thing that defines it.
      # SQLAlchemy's `setup.cfg` declares a connection URL per driver against
      # `mssql2022`, which is the name of the container its own test suite starts, and
      # the credential in them is `scott:tiger` -- Oracle's demonstration account since
      # 1979. Its loopback variants were already excused by the line above and these
      # were not, which is the same fixture written for a container instead of a port.
      | [a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?
    )\]?(?::[0-9]{1,5})?$
    """
)
"""Hosts nobody's production credential authenticates to.

Loopback, the `.test`/`.invalid`/`.example`/`.localhost` names RFC 6761 reserves
for exactly this, and the `example.com` family RFC 2606 reserves for
documentation. A URL pointing at one of them is a test fixture or a manual
page, and axios alone had a dozen of them -- `http://urluser:urlpass@127.0.0.1`
appears in its adapter tests because testing basic auth requires a URL with
basic auth in it.

Deliberately not extended to private ranges. A credential for `10.0.0.5` is a
credential for something real, and treating an internal address as a
documentation address is how an internal leak goes unreported."""

PASSWORD_HASH = re.compile(
    rb"^(?:\$(?:2[abxy]?|argon2(?:id|i|d)?|pbkdf2(?:-sha\d{1,3})?|scrypt|bcrypt|"
    rb"[156]|sha1|md5|y|7)\$|\{(?:SSHA|SHA|MD5|CRYPT|PBKDF2)\}|pbkdf2_sha\d{1,3}\$)"
)
"""A stored password hash, which is not a password.

The whole point of the format is that it can sit in a database, in a fixture and in a
repository: it is one-way, salted, and deliberately slow to attack. `$2a$`, `$2y$` and
`$2b$` are bcrypt, `$argon2id$` and `$pbkdf2-sha256$` name themselves, `$6$` is
sha512crypt, and `{SSHA}` is LDAP's. Django writes `pbkdf2_sha256$...`.

Two of seventy sampled assignment findings were one -- a bcrypt hash assigned to
`$password` in one PHP seed file and to `$passwordHash` in another -- and every seed
script, test fixture and `/etc/shadow` example in existence carries them. Recognised by
the prefix rather than by entropy, because a hash has exactly the entropy of the
credential it replaced, which is the property that makes entropy useless here.
"""


def is_password_hash(value: bytes) -> bool:
    """Whether this value is a stored hash rather than the credential it came from."""
    return PASSWORD_HASH.match(value) is not None


CANONICAL_UUID = re.compile(
    rb"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
)
"""A UUID, exactly and nothing else.

Reported at MEDIUM rather than HIGH, and reported rather than dismissed. Both halves
are deliberate.

A UUID genuinely is a secret in some systems -- `vimagick/dockerfiles` sets
`SESSION_SECRET` to one and PhotoPrism sets `PHOTOPRISM_OIDC_SECRET` to one, in compose
files anybody can read -- so dismissing the shape would be a miss.

But it is also the commonest identifier format in computing and the one an example
value is generated in: those two compose files are examples, and `JamesWoolfenden/pike`
has a third in a Terraform fixture. 122 bits in a format whose purpose is
identification is weaker evidence than forty characters of base62, whose only purpose
is to be a key, and the severity should say so."""

MINIFIED_LINE = 1000
"""How long a line has to be before the file is build output rather than source.

The same number the capability detector uses, stated here rather than imported for the
same reason the key-corpus ceilings are: `detect.secrets` is where the path predicates
live and it must not depend on a sibling detector for a constant.

A minified bundle has no line breaks, so one line is the whole file. Nothing anybody
writes by hand reaches a thousand characters on one line -- and the files that do and
are not minified, a data table or a long base64 blob, are build output too."""

SEQUENTIAL_RUN = 6
"""How many consecutive ascending characters make a value a sequence.

Entropy cannot tell `abcdefghijklmnopqrstuvwxyz0123456789` from a random string of
the same length: as a multiset of characters it is maximally diverse, which is what
Shannon entropy measures. What it is not is unpredictable.

Grafana assigns that exact value to `TOKEN_ALPHABET` in a branch-name generator --
it is the alphabet the generator draws FROM -- and Celery's documentation writes an
AWS access key as the alphabet in order.

Six rather than eight, and `123456abcdef` is why: Fastlane documents
`sonar_token: "123456abcdef"`, which is two runs of six and nothing else. Adding
`123456` to the placeholder vocabulary was tried first and five provider patterns
refused it within one run -- a Telegram bot token opens with a numeric chat id and a
Discord webhook url is two of them, so their own samples were being dismissed. A
SEQUENCE is the right mechanism for this value and a substring was not.

Six is still long enough that nothing generated contains such a run by chance, and the
`SEQUENTIAL_SHARE` floor below is what carries the weight: forty per cent of the value
has to sit inside runs that long.
"""


SEQUENTIAL_SHARE = 0.4
"""And how much of the value that run has to be.

Presence alone is too weak: a fake written by hand often has `1234567890` in the
middle of it, and so could a real credential. What distinguishes an alphabet from
key material is that the sequence IS the value -- 26 of
`abcdefghijklmnopqrstuvwxyz0123456789`, 24 of `provider_abcdefghijklmnopqrstuvwx` --
rather than ten characters of forty.
"""


def looks_sequential(value: bytes) -> bool:
    """Whether this value is mostly a run of consecutive characters.

    EVERY run counts towards the share, not just the longest one, and "mostly" is why.
    The alphabet and the digits are two runs, because `9` and `a` are not adjacent
    codepoints -- so `ci-deploy-check-key-0123456789abcdefghijklmnopqrstuvwxyz-throwaway`,
    which is this project's own CI `SECRET_KEY` and is as plainly not a credential as a
    value gets, scored 26 against a threshold of 26.4 and was reported at HIGH. Summed,
    it is 36 of 66 characters.

    Safe because of what it asks of real key material: a generated credential has no
    run of six consecutive codepoints at all, so its total is zero however many runs are
    added up. Measured against every value this suite keeps as a guard -- a GitLab PAT,
    an AWS key, a PostHog key, the PikPak client secret -- the longest run is two.
    """
    total = 0
    longest = run = 1
    for previous, current in itertools.pairwise(value):
        if current == previous + 1:
            run += 1
        else:
            if run >= SEQUENTIAL_RUN:
                total += run
            run = 1
        longest = max(longest, run)
    if run >= SEQUENTIAL_RUN:
        total += run
    return longest >= SEQUENTIAL_RUN and total >= SEQUENTIAL_SHARE * len(value)


MIN_ASSIGNMENT_ENTROPY = 2.8
"""Entropy floor for a credential-shaped assignment.

Below this the value is a word or a placeholder rather than a generated secret.

Lowered from 3.2. Shannon entropy over a short sample is bounded by log2(len),
so a genuine 21-character credential scores about 3.05 and was discarded by the
old floor -- the docstring's premise, that real key material sits well above
3.5, holds only for long values. The floor is compensated by a character-class
diversity test, which distinguishes `S3cr3tP4ssw0rdXyz9Qq` from `passwordpassword`
far better than entropy alone does at this length.
"""

MIN_ASSEMBLED_ENTROPY = 4.0
"""Entropy floor for a value built by concatenation.

Higher than the floor for a plain assignment, and deliberately so. Assembly is
also how ordinary code builds paths, messages and URLs, so the bar for calling
one a credential on entropy alone has to sit above anything a human wrote by
hand. A value with a known credential prefix skips this entirely -- the prefix
is the evidence."""

MIN_ASSEMBLED_LENGTH = 20
"""How long an assembled value must be before entropy is consulted.

Shannon entropy over a short sample is bounded by log2 of its length, so a
15-character value cannot reach the floor above whatever it contains. Testing
it would only produce a number that means nothing."""

CREDENTIAL_PREFIXES = (
    b"AKIA",
    b"ASIA",
    b"ghp_",
    b"gho_",
    b"ghu_",
    b"ghs_",
    b"ghr_",
    b"github_pat_",
    b"glpat-",
    b"xox",
    b"sk_live_",
    b"sk-",
    b"npm_",
    b"AIza",
    # Private key headers only. `-----BEGIN` also opens a CERTIFICATE, which
    # is public by design and is committed on purpose in every TLS test suite
    # -- it produced thirty-nine findings in OkHttp alone.
    b"-----BEGIN PRIVATE KEY",
    b"-----BEGIN RSA PRIVATE KEY",
    b"-----BEGIN EC PRIVATE KEY",
    b"-----BEGIN DSA PRIVATE KEY",
    b"-----BEGIN OPENSSH PRIVATE KEY",
    b"-----BEGIN PGP PRIVATE KEY",
    b"-----BEGIN ENCRYPTED PRIVATE KEY",
)
"""Prefixes that exist to make a credential format recognisable.

A value starting with one of these is a credential regardless of what its
entropy says, which matters because a padded or low-variety token sits below any
sensible entropy floor while still being live."""

MIN_CHARACTER_CLASSES = 2
"""How many of {lower, upper, digit, symbol} a value must use.

Generated key material almost always mixes at least two. A dictionary word or a
repeated filler string uses one, and those are what the entropy floor was
carrying alone."""

# Values that look like secrets and are not. Matched by literal value, never by
# path, because a path exemption would also hide a real credential that happened
# to land in the same file.
PLACEHOLDER = re.compile(
    rb"(?i)(example|sample|dummy|placeholder|redacted|your[_\-]?|"
    # A mask, which is the string a logger puts WHERE a secret was. `actions/runner`
    # declares `PasswordRemovedMask = "**password-removed**"` and four more beside it,
    # in the utility whose job is to keep secrets out of logs.
    rb"removed|masked|scrubbed|redact|"
    rb"changeme|xxxx|test[_\-]?only|fake|not[_\-]?a[_\-]?real|\.\.\.|"
    # A run of zeros, which is what somebody types when a field is required and they
    # have nothing to put in it. `home-assistant/core`'s llama_cpp integration ships
    # `DEFAULT_API_KEY = "sk-0000000000000000000"` -- a local server that checks the
    # prefix and ignores the rest. Six zeros in a row, as a substring test: the odds
    # of that inside real base64 key material are about one in five billion.
    rb"0{6}|"
    # The rest of the vocabulary a test value is written in. `token="xoxb-wire-probe"`
    # and `token='123456:fixture'` are both wire-contract probes in
    # `NousResearch/hermes-agent`, and they say so.
    rb"fixture|probe|stub|canary|sentinel|scaffold|hardcoded|"
    # Filler text, which is what a value says when somebody needed A value. GORM's CI
    # starts SQL Server with `MSSQL_SA_PASSWORD: LoremIpsum86`.
    #
    # Two words only. `hunter2`, `letmein` and `changeit` were in this list for one run
    # and three tests refused them: this codebase uses `hunter2Sup3rSecretV` as its
    # stand-in for a REAL credential, and every entry here is a substring test, so a
    # short common word dismisses anything containing it. The suite was right -- a value
    # is not a placeholder because it opens with a joke.
    rb"lorem|ipsum|"
    # Values that announce they are not credentials. Vault's rollback test sets
    # `bindpass="intentionally-wrong-password"`, which is a sentence saying so.
    rb"wrong|invalid|bogus|nonexistent|do[_\-]?not[_\-]?use|deliberately|intentional|"
    # The words themselves, used as their own placeholder. Documentation is
    # written `redis://username:password@host`, and reading that as a
    # credential produced eighty-seven findings across Django's, Scrapy's and
    # axios's docs and tests. A real credential is not spelled "password".
    # A qualifier in front is allowed, because `next_token = continuation_token` is
    # one variable assigned to another and so is every pagination loop ever written.
    # Airflow's Glue hook supplied it; the value is an identifier, not a value.
    #
    # Anchored at both ends, which is what keeps it narrow: the WHOLE value has to
    # read as a name ending in a credential word. `glpat-AAAAAAAAAAAAAAAA` does not,
    # and neither does any base64 or hex run.
    rb"^(?:[a-z][a-z0-9]{0,20}[_-]){0,3}(?:my|your|the|some|a|next|prev|previous|"
    rb"continuation|page|current|new|old|raw|temp|tmp)?[_-]?"
    rb"(?:user(?:name)?|pass(?:wo?rd)?|token|secret|apikey|api[_-]?key|"
    rb"login|admin|root|credential)s?[0-9]{0,6}[=:]?$|"
    # The same sentence with the separators left out, which is how it is written when
    # somebody types it into a seed script: `password: 'thisIsAPassword123'` in
    # `immich`. The whole value has to read as those words run together, and the
    # vocabulary is closed, so nothing generated can fall into it.
    rb"^(?:this|that|it|here)?(?:is)?(?:a|an|the|my|your|our)?"
    rb"(?:very|super|really|not)?(?:long|short|strong|weak|secure|insecure|bad|good)?"
    rb"(?:user(?:name)?|pass(?:wo?rd)?|token|secret|api[_-]?key|key|login|credential)"
    rb"s?[0-9]{0,8}$|"
    # Any brace interpolation, not just `{{` and `${`. An f-string such as
    # `f"https://x:{TOKEN}@host"` is a template, and the braces say so; the
    # value that ends up there at runtime is not in this file.
    rb"<[^>]{3,}>|\{[^}]{0,64}\}|\$\{|"
    # A bare variable reference, not only a braced one. Configuration
    # templates are written `private_key = $dir/private/cakey.pem` and
    # `secret = $insta::secret`; the value at runtime is not in this file, and
    # OpenSSL's own `.cnf` templates produced hundreds of findings in every
    # project that vendors it.
    # `$` at a word boundary only. A template writes `$dir/private/cakey.pem`, where
    # the `$` follows whitespace or a separator; a PayPal access token is spelled
    # `access_token$production$<id>$<secret>`, where every `$` follows a letter.
    #
    # Without the boundary this alternative matched the `$p` inside a real PayPal
    # token, so that pattern could fire and its finding was then discarded as a
    # placeholder every single time - a rule that runs, matches, and reports nothing.
    # The provider-sample gate found it before it shipped; nothing else would have,
    # because a rule whose findings are all dropped looks exactly like a rule with
    # nothing to find.
    rb"(?<![A-Za-z0-9_])\$[A-Za-z_]|"
    # `$$` is the shell's process id, so a value carrying one is different on every run.
    # `Hmbown/Codewhale` writes `TOKEN="smoke_test_token_$$"` in a smoke test.
    rb"\$\$|"
    # The Windows spelling of the same thing. Django's documentation extension
    # builds `token = "%HOMEPATH%\\" + token[2:]`, which the assembled-literal path
    # folded into a twelve-character value assigned to something called `token` and
    # reported at HIGH. `%VAR%` says the value arrives from the environment exactly
    # as plainly as `$VAR` does, and any build script that touches Windows paths is
    # full of it.
    rb"%[A-Za-z_][A-Za-z0-9_]{0,64}%|"
    # `[PROPERTY_NAME]`, which is how an MSI or WiX installer and several
    # configuration formats write a value to be substituted at install time.
    # MongoDB's installer fragment sets `Password='[MONGO_SERVICE_ACCOUNT_PASSWORD]'`,
    # naming the property rather than holding it.
    rb"\[[A-Z_][A-Z0-9_]{2,64}\]|"
    # A template in doubled brackets, which is what a Go template with custom
    # delimiters looks like and what Grafana's `index.html` carries:
    # `data-recording-token="[[.MeticulousAIRecordingToken]]"`.
    rb"\[\[[ \t]{0,4}[.$A-Za-z_]|"
    # A printf conversion, which makes the value a format string:
    # `_TEX_DISPLAY_TOKEN = "HERMESTEXDISPLAY%dHERMESTEXEND"` is a marker a renderer
    # substitutes into, not a token.
    rb"%[-+ #0]{0,3}[0-9]{0,3}(?:\.[0-9]{1,3})?[sdifgGxXoeEc]|"
    # Interpolation and substitution that braces do not cover. Swift writes
    # `"\(token)"` and the shell writes `"$(get_token)"`, and in both the value at
    # runtime is not in this file -- `displayToken = "\(baseDisplayToken)\(suffix)"`
    # and `auth_token="$(cmux_computer_use_auth_token)"` were both reported at HIGH
    # in `manaflow-ai/cmux`, which assigns neither a credential nor a literal.
    rb"\\\(|\$\()"
)


#: Credentials the vendor publishes ON PURPOSE, as a fixture everyone shares.
#:
#: Not placeholders and not examples: these are live, working values that are meant
#: to be in your repository, because the service they authenticate to is an emulator
#: running on your own machine. Reporting one is not a near miss, it is a statement
#: that is wrong on its face.
#:
#: The first entry is the Azure Storage emulator key, which Azurite and the older
#: Storage Emulator both ship. It was found reported at CRITICAL in Celery's
#: `docker-compose.yml` and `tox.ini` and in two of Elasticsearch's Azure tests -- and
#: the fact that the SAME eighty-eight characters appear in two unrelated projects is
#: the proof that it is a shared public fixture rather than anybody's secret. Every
#: Azure development setup in the world contains it, alongside the account name
#: `devstoreaccount1`.
#:
#: Matched on the exact value, which is what makes this safe: an exact string cannot
#: over-suppress the way a shape can. A list of published fixtures grows by one entry
#: per vendor and can never quietly widen.
#:
#: Deliberately NOT the place for "credentials we think are probably fake". That
#: judgement belongs to `PLACEHOLDER`, which tests for the shapes humans use when they
#: mean "put yours here". This list is only for values a vendor documents as public.
FIREBASE_WEB_CONFIG = re.compile(rb"(?i)authDomain[\"'\s:]{1,6}[^\"'\s]{1,200}firebaseapp\.com")
"""Firebase's web configuration object, identified by the field only it has.

`excalidraw` commits one in `.env.development` and `.env.production` as
`VITE_APP_FIREBASE_CONFIG='{"apiKey":"AIzaSy...","authDomain":"x.firebaseapp.com",...}'`.
Firebase's own documentation says this object is not a secret: the browser needs every
field in it to reach the project at all, so it ships in the bundle by construction, and
what protects the data is the security rules rather than the key.

Identified on `authDomain` pointing at `firebaseapp.com`, which is the server half of
the handshake and appears in no other kind of configuration. The name it is assigned to
cannot answer this -- `VITE_APP_FIREBASE_CONFIG` is public by contract and
`names_public_by_contract` would have said so, but the key is inside a JSON blob and
the name the assignment rule sees is `apiKey`.
"""

FIREBASE_CONFIG_WINDOW = 400
"""How far around a key to look for the `authDomain` that identifies its config."""


def is_firebase_web_config(raw: bytes, start: int, end: int) -> bool:
    """Whether this key sits inside Firebase's published web configuration object."""
    window = raw[max(0, start - FIREBASE_CONFIG_WINDOW) : end + FIREBASE_CONFIG_WINDOW]
    return FIREBASE_WEB_CONFIG.search(window) is not None


PUBLIC_BY_DESIGN_PREFIXES = (
    # PostHog's PROJECT api key, which is write-only ingestion and goes in the browser.
    # PostHog's own documentation says to put it in client-side code; the secret one is
    # the personal api key, spelled `phx_`, and that prefix is deliberately not here.
    #
    # `browser-use`, `Fission-AI/OpenSpec` and `hoppscotch` each commit one in their
    # telemetry module, and a finding about it has no remediation: nothing to rotate,
    # nothing to remove, and it is already in every published bundle.
    b"phc_",
    # RevenueCat's PUBLIC SDK keys, which ship inside the app binary because that is
    # where the SDK runs. `appl_` is the Apple platform key and `goog_` the Android
    # one; the secret is the v2 API key, which RevenueCat spells `sk_`, and that
    # prefix is deliberately not here. `AFFiNE` declares one in its paywall bridge.
    b"appl_",
    b"goog_",
)
"""Credential prefixes whose whole purpose is to be published.

Checked at the finding site rather than in `NOT_A_SECRET`, and the distinction matters:
the patterns must go on refusing to launder a prefixed value, because that is what
stops `"glpat-" + "AAAA..."` from reading as an identifier. What this list says is
narrower -- that for these specific prefixes the value being present is not a leak.
"""


def is_public_by_design(value: bytes) -> bool:
    """Whether this value is a credential that is meant to be in the repository."""
    return value.startswith(PUBLIC_BY_DESIGN_PREFIXES)


#: Client configuration files a vendor generates for you to SHIP.
#:
#: Firebase's `google-services.json` and `GoogleService-Info.plist` hold an `AIza` key,
#: and Google's own documentation says that key is not a secret: it identifies the
#: project, access is controlled by Firebase security rules, and every Android and iOS
#: binary that uses Firebase carries it where anybody can read it with `strings`.
#:
#: `SECRET.GOOGLE.API_KEY.001` reported it in eight corpus repositories -- `nickbutcher/
#: plaid`, `deckerst/aves`, SmartTube, two of `nisrulz/flutter-examples`, Firebase's own
#: `mock-google-services.json`, and FlutterFire's service-worker example -- at HIGH,
#: with a remediation that says to rotate it. There is nothing to rotate.
#:
#: Scoped to these FILENAMES and to that one rule. An `AIza` key anywhere else stays a
#: finding, because a Google Cloud api key with billing or a server-side key is a real
#: one and is written the same way.
CLIENT_CONFIG_FILES = (
    "**/google-services.json",
    "**/mock-google-services.json",
    "**/google-services-*.json",
    "**/GoogleService-Info.plist",
    "**/GoogleService-Info-*.plist",
    "**/firebase-messaging-sw.*",
    "**/firebase_options.dart",
    "**/firebaseConfig.*",
    # An Android manifest, which is compiled into the APK and readable in any copy of
    # it. A Maps key goes here as `com.google.android.geo.API_KEY` because that is
    # where the Maps SDK reads it from, and Google restricts it to the app's signing
    # certificate rather than keeping it secret. `DrKLO/Telegram` keeps six of them
    # across its debug, release and standalone manifests.
    "**/AndroidManifest.xml",
    "**/AndroidManifest_*.xml",
)

CLIENT_CONFIG_RULES = frozenset({"SECRET.GOOGLE.API_KEY.001"})
"""The rules `CLIENT_CONFIG_FILES` excuses. Nothing else in those files is excused."""


PLACEHOLDER_KEY = re.compile(
    rb"(?i)(?:^|[^\w.])(?:placeholder|example|examples|hint|sample|demo|default_?value"
    rb"|dummy|template|format|pattern|mask)[\s\]\)\}]{0,4}[=:][^\n]{0,40}$"
)
"""A key whose VALUE is an illustration, by the key's own name.

A form field's `placeholder` is the greyed-out text in the box. `anything-llm` writes
`placeholder="sk-myApiKeyToAccessMyChromaInstance"`, `makeplane/plane` writes
`placeholder: "sk-asddassdfasdefqsdfasd23das3dasdcasd"` and a GitLab one beside it.

Matched against the text BEFORE the credential rather than against the credential, and
applied to the provider patterns, which is the difference that matters: `PLACEHOLDER`
reads the value and cannot see that the key is called `placeholder`, and the provider
patterns deliberately consult almost nothing -- a `ghp_` prefix is a token wherever it
sits. The key's own name is the exception, because it is a statement by the author about
what the value is for.
"""

PRESIGNED_CREDENTIAL = re.compile(rb"(?i)X-Amz-Credential=")
"""The public half of a SigV4 signature, which a presigned URL carries by construction.

`Asabeneh/30-Days-Of-Python` ships a 14,000-row Hacker News dataset, and one row holds a
GitHub-generated presigned S3 URL with `X-Amz-Credential=AKIA................` in the
query string. A presigned URL exists to be handed to somebody: the key ID is in it by
design, the signature is what authorises, and the signature expires.
"""


PROSE_RUN = re.compile(rb"[A-Za-z]{2,24}(?: [A-Za-z0-9][A-Za-z0-9,.';:!?()\-]{0,23}){2,16}")
"""Three or more space-separated words, which is what a sentence decodes to.

Spaces are the whole of it. The first draft allowed `-` and `.` as separators too, and
`invented-secret-value-x9` -- the value an existing test uses precisely because it is
not a secret but must still be reported as one -- read as prose. A hyphenated
identifier is not a sentence; nothing written by a person to be read goes three words
without a space.
"""

MIN_PROSE_DECODE = 12
"""How many decoded bytes before reading them as prose means anything.

Short enough that a four-word sentence qualifies, long enough that three random
bytes landing on printable characters do not.
"""


def decodes_to_prose(matched: bytes) -> bool:
    """Whether the body of this credential is base64 for an English sentence.

    `Significant-Gravitas/AutoGPT` ships Supabase's GoTrue configuration, and one
    commented line carries a Stripe-shaped webhook secret whose body decodes to a
    sentence announcing itself an example of a shorter base64 string. Upstream wrote
    it to illustrate the field's format.

    The claim is about randomness, not about the wording. A real secret is random
    bytes, and random bytes are printable ASCII with probability around a third per
    byte -- so a body of any length that decodes to words, spaces and punctuation
    throughout is not random, whatever the words say.

    The prefix is stripped first: a provider prefix is ASCII by construction and
    would otherwise be what the test reads.
    """
    body = matched.rsplit(b"_", 1)[-1].rsplit(b"-", 1)[-1]
    if len(body) < MIN_PROSE_DECODE:
        return False
    padded = body + b"=" * (-len(body) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (ValueError, binascii.Error):
        return False
    if len(decoded) < MIN_PROSE_DECODE:
        return False
    printable = sum(1 for byte in decoded if 0x20 <= byte < 0x7F)
    if printable != len(decoded):
        return False
    return PROSE_RUN.search(decoded) is not None


AWS_SECRET_SHAPE = re.compile(rb"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")
"""The shape of an AWS secret access key: forty characters of base64 alphabet."""

AWS_KEY_ID_RULES = frozenset({"SECRET.AWS.ACCESS_KEY.001"})
"""The rules the pairing test below applies to."""

AWS_PAIR_WINDOW = 400
"""How far from a key id to look for the secret that would make it usable."""

LONE_KEY_ID_NOTE = (
    " No secret access key appears beside it, and an access key id on its own cannot "
    "authenticate -- it is the public name of a credential rather than the credential. "
    "Reported below its usual severity for that reason: it still identifies an account, "
    "and if the secret half is held somewhere a reader can reach, the pair is live."
)
"""Said on the finding, because a reader who is not told why will assume a mistake."""


def is_lone_access_key_id(raw: bytes, start: int, end: int, rule_id: str) -> bool:
    """Whether this AWS access key id appears without the secret half.

    An access key id is the public name of a credential, not the credential.
    `rust-lang/rust` commits two of them in `src/ci/github-actions/jobs.yml` with a
    comment above explaining the scheme: the ids are in the repository so a key can
    be rotated on one branch while another keeps the old one, and the secrets are in
    the CI provider's store. Knowing an id buys an attacker nothing.

    So this grades rather than dismisses. An id still identifies an account and is
    worth seeing; it is not the emergency that a usable key pair is, and reporting it
    at the same severity is what makes a reader stop reading.

    The secret half is forty characters of base64 alphabet, which is distinctive
    enough to find and common enough that a coincidence keeps the finding at its full
    severity -- the safe direction. `yt-dlp` hardcodes a genuine pair a line apart
    and is unaffected.
    """
    if rule_id not in AWS_KEY_ID_RULES:
        return False
    window = raw[max(0, start - AWS_PAIR_WINDOW) : end + AWS_PAIR_WINDOW]
    return AWS_SECRET_SHAPE.search(window) is None


WORD_VALUE_CHARS = re.compile(rb"[A-Za-z0-9_.\-]{4,120}")
"""The characters a concatenated-identifier value may contain.

No `+`, `/`, `=`, `~`, `@`, `:` or anything else. Base64 and the connection-string
shapes carry at least one of those, which is most of what keeps them out before the
word test below runs at all.
"""

WORD_SEGMENT = re.compile(rb"[A-Z][a-z]{2,20}|[a-z]{3,20}")
"""One word: a capital and two lowercase letters, or three lowercase on their own.

Three without a capital, two with one. The capital is evidence that somebody chose a
boundary there, and a two-letter run with none is what a generated value is full of:
`hc2wb63opyfxnwn` is a real corpus credential whose runs are `hc`, `wb` and
`opyfxnwn`, and an earlier draft of this asked only for two lowercase and dismissed
it. An existing guard value caught that within one run, which is what the guard is
for.

What the asymmetry costs is `ss2022Method` and `SsoEmail2faSessionToken`, whose
`ss` and `fa` are real words' worth of letters and too short to prove it. Both stay
reported, which is the safe direction.
"""

MIN_WORD_SEGMENTS = 2
"""How many words before a value is a name rather than a string that happens to read.

One word is `password` or `fluttergo`, which this would dismiss either way and which
`PLACEHOLDER` and the entropy floor already answer. Two is where the claim starts to
mean something: nothing generated produces two consecutive real words.
"""


def reads_as_words(value: bytes) -> bool:
    """Whether this value is identifiers concatenated rather than a generated run.

    Measured against the corpus's own assignment findings: it dismisses
    `echarge1Today` and eleven siblings -- `api_key="bdc1DischargePower"` in an energy
    monitor, where `api_key` is the name of a data point and the value is the metric --
    along with `ss2022Method`, `SsoEmail2faSessionToken`, `Pkcs12SafeBag` (which is a
    C# base class, not a value at all) and `abc123def456`.

    Against the true positives in the same sample it dismisses none. Every one of
    `bR4SJwOkvnG5WvVJ`, `dbw2OtmVEeuUvIptb1Coyg`, `Og9Vr1L8Ee6bh0olFxFDRg`,
    `k0VMxyIJF9S35f3x2uaw5IWAl6Y536O7` and twenty more fails on a letter run that is
    one or two characters or three capitals -- which is what a generated value is made
    of and what a word is not.

    Digits and separators divide words and are otherwise ignored: the question is only
    ever asked of the letters.
    """
    if WORD_VALUE_CHARS.fullmatch(value) is None:
        return False
    words: list[bytes] = []
    for run in re.findall(rb"[A-Za-z]+", value):
        # Split each letter run at its capitals, so `SsoEmail` is two words and not one
        # unpronounceable eight-letter one.
        words.extend(part for part in re.findall(rb"[A-Z]?[a-z]*", run) if part)
    if len(words) < MIN_WORD_SEGMENTS:
        return False
    return all(WORD_SEGMENT.fullmatch(word) for word in words)


URL_RUN = re.compile(rb"[a-z][a-z0-9+.\-]{1,12}://[^\s\"'`<>]{1,2000}")
"""A URL, taken as far as the first character that cannot be in one."""


def is_url_parameter(raw: bytes, start: int) -> bool:
    """Whether this match is a query parameter of a URL rather than an assignment.

    `iptv-org/iptv` lists five streams in `streams/my.m3u` whose playlist URLs carry
    `?token=` and `&auth_key=`, each a signed link with an epoch in it;
    `Asabeneh/30-Days-Of-Python`'s dataset holds a Vimeo CDN link of the same shape.

    A token in a URL is a signed link: it was issued to be handed to somebody, it
    authorises one object rather than an account, and it expires. It is graded rather
    than dropped, because a URL is also where a real API key gets pasted when somebody
    is in a hurry, and a graded finding still says where to look.

    Searched over the 2KB before the match so a long playlist line is covered, and the
    URL has to actually contain the match: a URL on the line above does not count.
    """
    window_start = max(0, start - 2000)
    for found in URL_RUN.finditer(raw, window_start, start + 1):
        if found.start() <= start < found.end():
            return b"?" in raw[found.start() : start] or b"&" in raw[found.start() : start]
    return False


MIN_BASE64_RETEST = 12
"""How many decoded bytes before re-asking the value predicates means anything."""


def decoded_is_not_a_secret(value: bytes) -> bool:
    """Whether the base64 this value holds decodes to something already dismissed.

    The predicates in this file read a value. A value that is base64 hides the thing they
    would read, and the corpus writes both halves down: `Cloudron` assigns a base64 blob
    to a key called `password` and puts the plaintext in a comment on the same line, and
    `harvester` assigns one that decodes to the words "encrypted password" with a hyphen
    between them.

    Both are described rather than quoted, because this file is scanned by the tool it
    configures and a faithful copy of a credential-shaped assignment is a true positive.
    The self-scan test caught the first draft of this docstring within one run, which is
    the same lesson the comment about an Icelandic word for "password" records further
    up.

    So decode once and ask the same questions of the result. Nothing new is claimed --
    whatever `PLACEHOLDER`, `NOT_A_SECRET` and `reads_as_words` already refuse, they
    refuse through a base64 layer too.
    """
    text = _decoded_text(value)
    if not text:
        return False
    decoded = text.encode("ascii")
    return (
        PLACEHOLDER.search(decoded) is not None
        or NOT_A_SECRET.match(decoded) is not None
        or reads_as_words(decoded)
    )


def _decoded_text(value: bytes) -> str:
    """The printable ASCII this value's base64 holds, or an empty string.

    Shared by `decoded_is_not_a_secret` and the name comparison, which ask different
    questions of the same bytes.
    """
    if len(value) < MIN_BASE64_RETEST or not set(value) <= B64_ALPHABET:
        return ""
    try:
        decoded = base64.b64decode(value + b"=" * (-len(value) % 4), validate=True)
    except (ValueError, binascii.Error):
        return ""
    decoded = decoded.strip()
    if len(decoded) < 4 or any(byte < 0x20 or byte >= 0x7F for byte in decoded):
        return ""
    return decoded.decode("ascii")


EXAMPLE_LITERAL_INTRO = re.compile(
    rb"(?i)(?:example|examples|longdesc|usage|synopsis|help)[A-Za-z0-9_]{0,20}"
    rb"[\s:=,]{0,8}(?:[A-Za-z0-9_.]{0,40}\([\s]{0,4}(?:[A-Za-z0-9_.]{0,40}\([\s]{0,4}){0,2})?$"
)
"""A declaration that says the string literal about to open is an example.

Every Go CLI built on cobra writes its help text this way, and `kubectl` is the one the
corpus found: `set_credentials.go` declares
`setCredentialsExample = templates.Examples(` and six lines into the raw string shows
`kubectl config set-credentials cluster-admin --username=admin --password=...`. The
password is an example of a flag, in the text the command prints when you ask it for
help.

`EXAMPLE_PROMPT` cannot see this -- a kubectl example block has no `$` or `>>>` in front
of it, because the reader is meant to copy the line as it stands. What identifies it is
the author's own name for the variable.
"""

EXAMPLE_LITERAL_WINDOW = 120
"""How far back from the opening backtick to look for that declaration."""


def is_inside_example_literal(raw: bytes, start: int, language: str | None) -> bool:
    """Whether this match sits in a Go raw string declared as example or help text.

    Go only. A raw string is delimited by backticks and cannot contain one, so parity
    answers whether an offset is inside one: an odd number of backticks before it means
    the last of them opened the string the offset sits in. No other language in the
    corpus spells a multi-line literal this way, and the ones that use a triple quote or
    a hash-delimited raw string need a parser rather than a count.
    """
    if language != "go":
        return False
    before = raw[:start]
    if before.count(b"`") % 2 == 0:
        return False
    opening = before.rfind(b"`")
    head = before[max(0, opening - EXAMPLE_LITERAL_WINDOW) : opening]
    return EXAMPLE_LITERAL_INTRO.search(head) is not None


def is_illustrated_by_its_key(raw: bytes, start: int) -> bool:
    """Whether the text just before this match names it as an example."""
    return PLACEHOLDER_KEY.search(raw, max(0, start - 120), start) is not None


def is_presigned_credential(raw: bytes, start: int) -> bool:
    """Whether this match is the key id inside a presigned URL's query string."""
    return PRESIGNED_CREDENTIAL.search(raw, max(0, start - 60), start) is not None


def is_client_configuration(path: str, rule_id: str) -> bool:
    """Whether this rule is reporting a key the vendor generated to be shipped."""
    return rule_id in CLIENT_CONFIG_RULES and _names(path, CLIENT_CONFIG_FILES)


PUBLISHED_PRIVATE_KEY_BODIES = (
    # Vagrant's insecure ed25519 key, the successor to the RSA one below. It lives at
    # `keys/vagrant.key.ed25519` in `hashicorp/vagrant` and on every box that has not
    # replaced it, which is the whole point: Vagrant inserts a generated keypair on
    # first boot and this is what it uses to get in and do that.
    #
    # The slice starts at the public point and not at the armour. An unencrypted
    # OpenSSH-format ed25519 key opens with a fixed seventy characters -- the format
    # name, `none` twice for the cipher and the kdf, and the key count -- and the first
    # draft of this entry was exactly those bytes, which would have dismissed every
    # ed25519 private key in existence.
    b"QyNTUxOQAAACDdWHcQaTZc8Q6nycsP0CqMNRfsLxvYVxqKosrHyTp+WA",
    # The Vagrant insecure keypair, shipped in every base box since 2010 and
    # documented by HashiCorp as insecure: Vagrant replaces it on first `vagrant up`,
    # and its whole purpose is to be known. It is committed in `hashicorp/vagrant`
    # itself -- twice, once per algorithm -- and in every repository that vendors a
    # box or a test harness built on one.
    #
    # Matched on the body rather than the path, because the path is whatever the
    # vendoring project called it.
    b"MIIEogIBAAKCAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzI",
)
"""Private keys whose publication is the point.

Matched on a prefix of the base64 body, which for an RSA key encodes the modulus and
is therefore unique to the keypair. A prefix rather than the whole body so that line
wrapping and the header variant do not matter.

Checked against the FILE rather than against the match, and that is not a detail: the
private-key pattern captures the armour plus twelve base64 characters, and the first
twelve characters of every 2048-bit RSA key are the same -- `MIIEogIBAAKC` is the DER
header, not the modulus. Testing the match would have excused every RSA key there is.
"""

PUBLISHED_KEY_WINDOW = 400
"""How far past the armour to look for a published body.

Bounded so that a file holding the Vagrant key AND a real one reports the real one. The
body begins on the line after the header, so a few hundred bytes is generous."""


def holds_published_key(raw: bytes, start: int) -> bool:
    """Whether the key armour at `start` introduces a key its vendor publishes."""
    window = raw[start : start + PUBLISHED_KEY_WINDOW]
    return any(known in window for known in PUBLISHED_PRIVATE_KEY_BODIES)


PEM_BODY = re.compile(rb"-{3,6}BEGIN[ A-Z0-9]{0,60}-{3,6}([\s\S]{0,8000}?)-{3,6}END")

MIN_PEM_BODY = 60
"""How many base64 characters a PEM block needs before it can be a key.

An Ed25519 private key in PKCS#8 is about sixty-four; an EC P-256 key in SEC1 is about
a hundred and twenty; RSA runs into the hundreds. Below sixty there is no key of any
algorithm, so the block is an ILLUSTRATION of the format:

    key_content: "-----BEGIN EC PRIVATE KEY-----\nfewfawefawfe\n-----END EC PRIVATE KEY-----"

is `fastlane`'s documentation for its App Store Connect action, and twelve characters of
keyboard mash is what an example looks like. `juspay/hyperswitch` writes the same shape
into an OpenAPI `example =` annotation.

Checked against the FILE rather than the match, for the reason `holds_published_key`
already records: the provider pattern captures the armour plus twelve characters, which
is too little to judge either question.
"""


DECLARED_NAME = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{2,60}")
"""An identifier. Every one in the window is asked, last first."""

#: The DECLARATION LINE, and only that.
#:
#: Two earlier attempts are worth recording. Anchoring the identifier to the end of the
#: text found nothing at all -- the armour usually begins on its own line, so what sits
#: immediately before it is a newline and some indentation. Taking the last four
#: identifiers in a 160-byte window then reached the line above, and a test written in
#: the same pass caught it: `let sampleOther = 1` one line up excused `let realKey`.
#:
#: So: drop the trailing whitespace the armour's own line contributed, and take what
#: follows the last newline in what is left. That is the line the author wrote the name
#: on, which is the only line that makes a claim about this value.

DECLARED_NAME_WINDOW = 160
"""How far back from the armour to look for the name that introduces it."""


def key_name_is_illustrative(raw: bytes, start: int) -> bool:
    """Whether the name declaring this key says it is a sample.

    `PLACEHOLDER_KEY` asks the same question of the provider patterns and asks it of the
    SEPARATOR: a key word, then `=` or `:`, then the value. That shape does not reach a
    language where the name carries the word in the middle of itself. `vapor` declares

        static var sampleServerPrivateKeyPEM: String

    and then a full-length RSA key -- real key material, generated to be shipped in a
    development target, and `holds_illustrative_key` cannot help because the body is a
    genuine key of genuine length.

    So the name is read the way every other name in this file is read, with
    `names_placeholder`: split on separators and camel-case humps, and ask whether any
    word is one the author uses to mean "not real". `sample` is one; `test` deliberately
    is not, for the reason `NOT_REAL_WORDS` records.
    """
    head = raw[max(0, start - DECLARED_NAME_WINDOW) : start].rstrip()
    declaration = head.rsplit(b"\n", 1)[-1]
    return any(
        names_placeholder(name.decode("utf-8", errors="replace"))
        for name in DECLARED_NAME.findall(declaration)
    )


def holds_illustrative_key(raw: bytes, start: int) -> bool:
    """Whether the armour at `start` introduces something too small or too marked to be
    a key.

    Two tests over one window. The body may be too short to encode a key of any
    algorithm -- see `MIN_PEM_BODY` -- or it may carry a placeholder marker that the
    44-byte match cannot see: `n8n`'s Google credential documents the field as
    `'-----BEGIN PRIVATE KEY-----\nXIYEvQIBADANBg<...>0IhA7TMoGYPQc=\n-----END ...'`,
    where the elision in the middle is the whole point.
    """
    window = raw[start : start + 8000]
    match = PEM_BODY.match(window)
    if match is None:
        return False
    body = match.group(1)
    if PLACEHOLDER.search(body):
        return True
    return sum(1 for byte in body if byte in B64_ALPHABET) < MIN_PEM_BODY


B64_ALPHABET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


PUBLISHED_CREDENTIALS = frozenset(
    {
        # Azure Storage emulator, account `devstoreaccount1`.
        b"Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
        # MinIO's default root credentials, which its own quickstart prints.
        b"minioadmin",
        # Grafana's default `secret_key`, which ships in `conf/defaults.ini` in every
        # installation. It turns up twice in one repository -- once in that file and once
        # as a Go constant in `apps/advisor/.../security_config_step.go`, where the
        # advisor's whole job is to tell an operator they have not changed it.
        b"SW2YcwTIb9zpOOhoPsMm",
        # The account NAME the emulator key above belongs to. The key was listed and
        # the name was not, so `Azure/azure-sdk-for-cpp` writing
        # `auto accessKey = "devstoreaccount1";` reported an access key.
        b"devstoreaccount1",
        # Google's documented reCAPTCHA test keys, published so that a test suite can
        # always pass the challenge. The site key is the other half and is public by
        # definition. Copied into a great many repositories, because Google's own
        # documentation says to.
        b"6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe",
        b"6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI",
        # AWS's documented example credentials, which appear in the signing
        # specification and in most of its SDK documentation.
        b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        b"AKIAIOSFODNN7EXAMPLE",
        # The Stripe documentation's test card and publishable fixtures are covered by
        # PLACEHOLDER's `test` handling; nothing further is needed for them here.
        #
        # Supabase's self-host quickstart, whose `docker-compose.yml` every project
        # that self-hosts Supabase copies. `Significant-Gravitas/AutoGPT` keeps it at
        # `autogpt_platform/db/docker/docker-compose.yml`, and the file identifies
        # itself twice over: it opens with `name: supabase`, and the anon and
        # service-role JWTs beside this value carry `"iss": "supabase-demo"` in their
        # payloads -- the tokens say whose demo they are. This one has no claims to
        # read, which is why it is listed and they are not.
        b"UpNVntn3cDxHJpq99YMc1T1AQgQpc8kfYTuRgBiYa15BLrx8etQoXz3gZv1/u2oq",
    }
)


TEST_MATERIAL_PATHS = (
    "**/test/**",
    "**/tests/**",
    "**/testing/**",
    "**/__tests__/**",
    "**/testdata/**",
    "**/fixture/**",
    "**/fixtures/**",
    "**/spec/**",
    "**/examples/**",
    # Gradle source sets and the JVM world's own names for the same thing.
    # Elasticsearch keeps twenty-nine TLS test keys under `x-pack/plugin/
    # security/qa/`, which is a test tree wearing a name no `test/` glob
    # matches.
    "**/qa/**",
    "**/javaRestTest/**",
    "**/yamlRestTest/**",
    "**/internalClusterTest/**",
    "**/integTest/**",
    # The rest of the Gradle source-set family, which is the same convention with a
    # different prefix. Spring Boot keeps nineteen TLS keys under
    # `src/dockerTest/resources/` -- a client certificate per integration test, each
    # generated by a script in the same tree -- and the four names above were the only
    # ones the list happened to have met.
    "**/dockerTest/**",
    "**/integrationTest/**",
    "**/functionalTest/**",
    "**/systemTest/**",
    "**/smokeTest/**",
    "**/apiTest/**",
    "**/e2eTest/**",
    "**/acceptanceTest/**",
    "**/componentTest/**",
    "**/contractTest/**",
    "**/performanceTest/**",
    "**/unitTest/**",
    # A test server, a test certificate directory, a mock API. Puppeteer's
    # `packages/testserver/key.pem`, Istio's `pilot/cmd/pilot-agent/status/test-cert/`,
    # and n8n's `scripts/mock-api/` are each a fixture the name declares.
    "**/testserver/**",
    "**/test-server/**",
    "**/test-cert/**",
    "**/test-keys*",
    "**/mock-api/**",
    # Any directory whose name opens with `mock-`. VS Code keeps
    # `scripts/mock-llm-server/` and `scripts/mock-policy-server/`, which are servers
    # that exist to be talked to by tests, and whose canned responses include tokens.
    "**/mock-*/**",
    "**/mock-server/**",
    "**/mockserver/**",
    # A fuzzing corpus, which is inputs by definition. OpenSSL's `fuzz/` carries a
    # DTLS server with a key in it, and every project that vendors OpenSSL carries it
    # again.
    "**/fuzz/**",
    "**/fuzzing/**",
    # And the two other names the same thing goes by. `php-src` keeps its inputs at
    # `sapi/fuzzer/corpus/exif/`, where neither glob above reaches: a fuzzer corpus is
    # malformed input on purpose, which is why `bug62523_1.jpg` is a JPEG that is not
    # one. A `corpus/` directory holds samples in every project that has one --
    # this one included.
    "**/fuzzer/**",
    "**/corpus/**",
    # An environment template, whose whole purpose is to be copied and filled in.
    # `Significant-Gravitas/AutoGPT` ships `autogpt_platform/backend/.env.default` and
    # `frontend/.env.default`; `.env.example` is the commoner spelling and
    # `.env.dist`, `.env.template` and `.env.sample` are the rest of them.
    "**/.env.default",
    "**/.env.defaults",
    "**/.env.example",
    "**/.env.examples",
    "**/.env.sample",
    "**/.env.template",
    "**/.env.dist",
    "**/.env.*.example",
    # A directory named for a vulnerability is a reproduction of it. `vulhub` keeps one
    # per CVE -- `jumpserver/CVE-2023-42820/config.env` holds the weak credentials the
    # environment exists to be exploited through -- and so does every security
    # researcher's notes directory.
    "**/CVE-[0-9]*/**",
    "**/cve-[0-9]*/**",
    "**/*_test.*",
    "**/*_tests.*",
    "**/test_*.*",
    "**/*.test.*",
    "**/*.spec.*",
    # A Storybook story is example data by construction: `MHSanaei/3x-ui` declares a
    # base64 `secretKey` in `JsonEditor.stories.tsx` so the editor has something to
    # render. The convention is as fixed as `*.test.*`.
    "**/*.stories.*",
    # A file whose NAME says it holds sample data. `**/sample/**` and `**/samples/**`
    # have always been here as directories; PowerToys keeps
    # `InternalPage.SampleData.cs`, which is the same statement in a filename.
    "**/*sampledata*",
    "**/*sample_data*",
    "**/*testdata*",
    "**/*.story.*",
    # A bare `t/`, which is Celery's and a good deal of Python's and Perl's test
    # root. Celery keeps eight RSA test keypairs under `t/unit/security/`, and
    # every `test`-shaped glob above misses a directory called `t`.
    #
    # Reported at CRITICAL, eight times, on a file whose own docstring opens "Keys
    # and certificates for tests" and names the script that generated them. That is
    # the shape that gets a secret scanner switched off: a project cannot act on it,
    # cannot delete the keys, and has nothing to do but suppress the rule.
    "t/**",
    "**/t/unit/**",
    "**/t/integration/**",
    # Go's and Rust's conventions, which are not directories at all.
    "**/testdata/**",
    "**/*_test.go",
    "**/tests.rs",
    # Where a project keeps the material its tests need without calling it a test.
    "**/mocks/**",
    "**/mock/**",
    "**/stubs/**",
    "**/golden/**",
    "**/snapshots/**",
    "**/__snapshots__/**",
    "**/__mocks__/**",
    "**/benchmarks/**",
    "**/bench/**",
    "**/e2e/**",
    "**/integration/**",
    "**/acceptance/**",
    "**/conformance/**",
    "**/regress/**",
    "**/demo/**",
    "**/demos/**",
    "**/sample/**",
    "**/samples/**",
    # Formats that exist only to hold translated strings. An Inno Setup language file
    # is named after the language -- `localsend` ships `Icelandic.isl` -- and gettext,
    # Apple, Flutter, Fluent and XLIFF each have one extension and one purpose. `.resx`
    # is deliberately absent: a .NET resource file is general-purpose and holds
    # connection strings as readily as labels.
    "**/*.isl",
    "**/*.po",
    "**/*.pot",
    "**/*.strings",
    "**/*.stringsdict",
    "**/*.arb",
    "**/*.ftl",
    "**/*.xlf",
    "**/*.xliff",
    # A file called exactly `test`, which is what a single test script is called when
    # there is only one. VLC's url-parser tests live in `share/lua/intf/test.lua` and
    # pass a URL with credentials in it, because testing a url parser requires one.
    "**/test.*",
    # And a directory whose name ENDS in `examples`. `KaringX/karing` keeps
    # `README_examples/clash/config.yaml`, which `**/examples/**` cannot see.
    "**/*examples/**",
    "**/*example/**",
    # And a filename that says the material is not real. `nccgroup/sadcloud` ships
    # `static/example.key.pem`, `arminc/terraform-ecs` ships `ecs_fake_private`, and
    # `**/*.example.*` needed something before the dot.
    "**/example.*",
    "**/example-*",
    "**/*fake*",
    "**/*insecure*",
    "**/*dummy*",
    # Hyphenated and compound spellings. `fixtures/` was listed and
    # `test-fixtures/` was not, which is the spelling Vault uses -- twenty-one
    # private keys under `api/test-fixtures/keys/`,
    # `command/agent/test-fixtures/reload/` and six more directories, every one of
    # them a generated certificate for a TLS reload test, all reported at CRITICAL.
    "**/test-fixtures/**",
    "**/testfixtures/**",
    "**/test-data/**",
    "**/test_data/**",
    "**/test-files/**",
    "**/test_files/**",
    "**/test-resources/**",
    "**/testresources/**",
    # Go's conventions, which are files rather than directories.
    "**/testing.go",
    "**/testutil/**",
    "**/testutils/**",
    "**/testhelpers/**",
    "**/testsupport/**",
    "**/*_test_helper.*",
    "**/*_test_helpers.*",
    "**/*_testhelpers.*",
    "**/*_test_util.*",
    "**/*_test_utils.*",
    "**/*_testing.*",
    # Where a TLS test keeps its generated material, whatever the tree calls it.
    "**/testcerts/**",
    "**/test-certs/**",
    "**/test_certs/**",
    "**/testcertificates/**",
    "**/test-certificates/**",
    "**/test_certificates/**",
    "**/test_creds/**",
    "**/test-creds/**",
    "**/testcreds/**",
    # A directory named after the certificate standard holds certificate material for
    # the code that parses it. `mongodb/mongo` keeps twenty-eight keys under
    # `x509/static/` -- a CA, an intermediate, a rollover pair, OCSP responders, and
    # PKCS#1 and PKCS#8 encrypted variants -- which is a hierarchy built for an
    # authentication test suite, and gRPC's vendored `test_creds/` is thirteen more.
    # Nobody keeps a production key in a directory called `x509`.
    "**/x509/**",
    "**/test-ca/**",
    "**/test_ca/**",
    "**/testca/**",
    # BoringSSL's `bogo` TLS interoperability suite, which every serious TLS library
    # vendors in order to test against it: rustls keeps five keys under `bogo/keys/`
    # and a four-algorithm CA hierarchy under `test-ca/`, 33 findings in one
    # repository, every one generated by a script in the same tree.
    "**/bogo/**",
    # A local development stack. `devenv/` is Grafana's, and the convention is common:
    # a docker-compose tree of localhost services with credentials invented so the
    # stack comes up. Eight of Grafana's nineteen remaining findings were there --
    # `password: grafana12345`, an Authentik token, an InfluxDB init password, a
    # generated `key.pem` -- and none of them authenticates to anything outside a
    # laptop.
    "**/devenv/**",
    "**/dev-env/**",
    # A development container, which is the same thing one layer up: `.devcontainer/`
    # describes the environment a contributor is given, and n8n's declares a
    # privileged docker-compose service and a seeded password so the codespace comes
    # up.
    "**/.devcontainer/**",
    # A test runner's own configuration. `pytest.ini` and `tox.ini` describe how the
    # suite runs, including the environment it runs with -- dify sets a token in one.
    "**/pytest.ini",
    "**/tox.ini",
    "**/.pytest.ini",
    # API mocking and object factories. Mirage, FactoryBot and friends exist to
    # produce plausible-looking data, so a generated password is the point of the
    # file: Vault's `ui/mirage/factories/ldap-credential.js` was reported twice.
    "**/mirage/**",
    "**/factories/**",
    "**/factory/**",
    "**/msw/**",
    "**/__fixtures__/**",
    # Teaching material, which is the same thing as `examples/` with a different
    # name on it. `antonputra/tutorials` produced 211 blocking findings across 200
    # numbered lesson directories -- an RBAC wildcard here, an open security group
    # there, a demo CA key, a MongoDB URL with `devops123` in it -- and every one is
    # a lesson rather than a deployment. `ViktorUJ/cks` is a Kubernetes exam lab with
    # the same shape under `tasks/*/labs/`.
    #
    # `examples/`, `demo/`, `sample/` and `samples/` were already here, and these are
    # the names the same material goes under when the repository is a course.
    "**/lessons/**",
    "**/lesson/**",
    "**/tutorial/**",
    "**/tutorials/**",
    "**/labs/**",
    "**/lab/**",
    "**/exercises/**",
    "**/exercise/**",
    "**/workshop/**",
    "**/workshops/**",
    "**/katas/**",
    "**/course/**",
    "**/courses/**",
    # Integration-test directories that do not spell it "integration".
    # Keycloak's `testsuite/` holds a complete PKI -- a root CA, intermediates, OCSP
    # responders, per-client keys -- built for its integration suite, and 68 of its 73
    # findings were in it.
    "**/testsuite/**",
    "**/test-suite/**",
    "**/integtest/**",
    "**/integtests/**",
    "**/itest/**",
    "**/functest/**",
    "**/smoketest/**",
    "**/smoke/**",
    # Known-answer test vectors. A cryptography library's vector corpus is
    # private keys by the hundred, and every one of them is published: the
    # `pyca/cryptography` tree holds 102 under `vectors/cryptography_vectors/`,
    # each a key whose purpose is to be the input to a test of the parser that
    # reads it. They were reported at CRITICAL, which for a library whose job is
    # to implement the formats is a rule that cannot be satisfied.
    "**/vectors/**",
    "**/test-vectors/**",
    "**/test_vectors/**",
    "**/testvectors/**",
    "**/kat/**",
    # Directory names that END in the convention. Swift packages and .NET
    # solutions name a test target after what it tests -- `cmuxTests/`,
    # `CmuxSentryScrubbingTests/`, `CMUXAgentLaunchTests/` -- and no glob above
    # matches a directory whose name merely finishes with it.
    "**/*tests/**",
    # And the file-level equivalents, which are how Swift, Java, Kotlin, C# and
    # Scala name a test file. Go and Python are covered above by `*_test.*` and
    # `test_*.*`.
    "**/*test.swift",
    "**/*tests.swift",
    "**/*test.cs",
    "**/*tests.cs",
    "**/*test.java",
    "**/*tests.java",
    "**/*test.kt",
    "**/*tests.kt",
    "**/*spec.kt",
    "**/*test.scala",
    "**/*spec.scala",
    "**/*test.php",
    "**/*tests.php",
    "**/*test.rb",
    "**/*test.m",
    "**/*test.mm",
)

#: Paths whose content is written to be read by a person, not executed.
#:
#: Documentation gets the same treatment as test material and for a closely related
#: reason: a credential-shaped string in a document is an EXAMPLE far more often
#: than it is a live key, because showing the shape of a connection string is how
#: you document a connection string.
#:
#: Celery's SQS page carries `sqs://ABCDEFGHIJKLMNOPQRST:ZYXK7Niyn...@` and, two
#: lines below, `sqs://aws_access_key_id:aws_secret_access_key@` as the format. The
#: first was reported at HIGH. Its access key is the alphabet in order.
#:
#: Ceilinged rather than suppressed, and the distinction matters: a real key pasted
#: into a README leaks exactly as far as one in a settings file, and plenty have
#: been. It stays in the report, below the severity that fails a build, with the
#: caveat saying why.
DOCUMENTATION_PATHS = (
    "**/docs/**",
    "**/doc/**",
    "**/documentation/**",
    "**/*.md",
    "**/*.rst",
    "**/*.adoc",
    "**/*.asciidoc",
    "**/*.asc",
    "**/*.org",
    "**/*.textile",
    "**/*.txt",
    "**/*.mdx",
    "**/*.ipynb",
    # A man page, in the nine sections roff uses. `rclone/rclone.1` is its whole
    # command reference as one generated troff file, and the examples in it are
    # examples -- `rclone lsf :ftp: --ftp-pass=...` is a line somebody is meant to
    # read and adapt.
    "**/*.[1-9]",
    "**/README*",
    "**/CHANGELOG*",
    "**/CONTRIBUTING*",
    "**/*.example",
    "**/*.example.*",
    "**/*.sample",
    "**/*.sample.*",
    "**/*.template",
    "**/*.dist",
    # Localisation catalogues. The value beside a key called `password` is the WORD
    # "password" in another language: a Danish translation file was reported for
    # `password = "Adgangskode"`. Every project with a translated login form has one
    # of these for every language it supports, so the count scales with how
    # international the project is.
    "**/locales/**",
    # The rest of the names a translation catalogue goes under. The note above names
    # the case exactly -- "the value beside a key called `password` is the WORD
    # 'password' in another language" -- and then the list had one glob for it.
    # Keycloak keeps its under `theme/keycloak.v2/admin/messages/messages_de.properties`
    # and ships dozens of languages: `resetPasswordConfirmation=Passwortbestätigung` was
    # reported as a credential, and 40 of its 61 remaining findings were that shape.
    "**/locale/**",
    "**/messages/**",
    "**/messages_*.*",
    "**/i18n/**",
    "**/translations/**",
    "**/translation/**",
    "**/lang/**",
    "**/langs/**",
    "**/locale/**",
    "**/translations/**",
    "**/i18n/**",
    "**/lang/**",
    "**/*.po",
    "**/*.pot",
    "**/*.xliff",
    "**/*.arb",
    "**/*.resx",
)
"""Where a credential is usually one somebody generated for the suite.

Four hundred and eighty-eight of the five hundred and seventy-six private keys
found across thirty-eight production repositories were here, and every one of
them was a key made so a TLS test would have something to serve. A tool that
reports those at critical is a tool people stop reading, and the reason is not
that the keys are not keys -- they are, and the pattern is right about them.

So this changes what is claimed, not whether it is claimed. The finding is
still emitted, still says a private key is committed, and still says why that
matters; what it stops doing is failing a build over `tests/fixtures/key.pem`.
A production key committed under `tests/` is genuinely under-reported by this,
which is the trade being made, and the message says so where the finding is
read rather than here."""

FIXTURE_CEILING = Severity.MEDIUM
"""The most a secret in test material may be reported at."""

RULE_MATERIAL_CEILING = Severity.INFO
"""The most a finding inside another analyser's rule material may be reported at.

Lower than `FIXTURE_CEILING`, because the two say different things. A credential
under `tests/` is a real string that was probably generated for the suite and
might not have been. A credential on the line after `// ruleid: adafruit-api-key`
is a sample published so that a scanner can be tested against it -- the file
exists to be detected, and there is no version of that finding a reader acts on.

INFO rather than nothing, for the reason in `core.samples`: a predicate that
deleted findings would be a one-line bypass. INFO sits below the default
reporting threshold, so the finding is out of a reader's way by default and is
there for anyone who asks for it."""

FIXTURE_CONFIDENCE = Confidence.MEDIUM
"""And the most it may claim about being live.

This one is confidence rather than severity because it is a statement about
what the value is: a PEM private-key header under `tests/fixtures` is
certainly a private key and is very unlikely to be one that protects
anything."""


def _names(path: str, globs: tuple[str, ...]) -> bool:
    """Whether a path matches any of these globs, ignoring case.

    Every one of these lists is a list of CONVENTIONS, and the conventions are
    spelled differently by ecosystem: Swift and .NET capitalise `Tests/`, Apple
    capitalises `Documentation/`, Maven lowercases `src/test/java`. Matching
    case-sensitively meant the lists were Unix- and Python-shaped and silently
    missed whole ecosystems -- `manaflow-ai/cmux` had fifty-nine credential
    findings in `cmuxTests/` and `Packages/.../Tests/`, none of which any glob
    here matched.

    The globs are lowered too, so `**/javaRestTest/**` keeps working.
    """
    lowered = path.lower()
    return any(PathGlob.matches(lowered, glob.lower()) for glob in globs)


DOCUMENTED_NAMES = frozenset(
    {
        "DOCUMENTATION",
        "EXAMPLES",
        "RETURN",
        "RETURNS",
        "USAGE",
        "HELP",
        "EPILOG",
        "LONG_DESCRIPTION",
        "__doc__",
    }
)
"""Module-level names whose value is documentation rather than configuration.

`DOCUMENTATION`, `EXAMPLES` and `RETURN` are Ansible's module contract: every one
of its thousands of modules carries a YAML document inside a string, and the
examples in it are written the way examples are -- a `password` key with a
memorable phrase after it, a `token` key with a UUID, a `bootstrap_secret` with
another one.

`community.general` produced 29 findings and every one was inside such a block,
including the Slack module's own description of what a bot token looks like. The
path-based documentation test cannot see this: the file is `plugins/modules/
consul_token.py`, which is source, and the documentation is inside it.

Described rather than quoted, because this project scans itself and a faithful
copy of those three lines is three findings -- which is how the attribute-docstring
case below was found."""


def documentation_spans(text: str) -> tuple[tuple[int, int], ...]:
    """Byte ranges of this Python source that are documentation.

    Every docstring, and every module-level assignment of a string literal to one of
    `DOCUMENTED_NAMES`. Parsed rather than matched, because the question is which
    STRING a byte offset falls in and a regex cannot answer that about a language
    with three quoting styles and nesting.

    Returns nothing for anything that does not parse, which is the safe direction:
    an unparsable file gets no exemption.
    """
    import ast

    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return ()

    encoded = text.encode("utf-8", errors="surrogatepass")
    starts = [0]
    for index, byte in enumerate(encoded):
        if byte == 0x0A:
            starts.append(index + 1)

    def span(node: ast.AST) -> tuple[int, int] | None:
        """The byte range a node occupies.

        `col_offset` is a UTF-8 byte offset within its line, which is what this needs
        and is the one thing about `ast` positions that is convenient here."""
        line = getattr(node, "lineno", None)
        end_line = getattr(node, "end_lineno", None)
        if line is None or end_line is None or not 0 < end_line <= len(starts):
            return None
        start = starts[line - 1] + getattr(node, "col_offset", 0)
        end = starts[end_line - 1] + getattr(node, "end_col_offset", 0)
        if end <= start:
            return None
        return start, min(end, len(encoded))

    found: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            # Every bare string statement, which is every docstring: a module's, a
            # class's, a function's, and the attribute docstrings PEP 258 describes --
            # the string that follows an assignment and documents it. A string
            # expression whose value is discarded does nothing at runtime; it is there
            # to be read.
            #
            # This project's own source made the case: the docstring under
            # `DOCUMENTED_NAMES` quotes the Ansible examples that prompted this, and
            # the self-scan reported three credentials in it. Collecting only the first
            # statement of each scope -- which is what "docstring" means to `ast` --
            # missed the convention this codebase is written in.
            bounds = span(node)
            if bounds:
                found.append(bounds)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            if not isinstance(node.value.value, str):
                continue
            names = {target.id for target in node.targets if isinstance(target, ast.Name)}
            if names & DOCUMENTED_NAMES:
                bounds = span(node)
                if bounds:
                    found.append(bounds)
    return tuple(found)


TEST_MODULE_ATTRIBUTE = "#[cfg(test)]"
"""Rust's marker for code that only exists when the tests are built.

Rust keeps unit tests in the file they test, at the bottom, under
`#[cfg(test)] mod tests { ... }`. That is the language's convention rather than a
layout choice, so a path glob cannot see it: `rustfs/src/auth.rs` is source, and
its 51 credential findings were assertions about constant-time comparison using
`AKIAIOSFODNN7EXAMPLE` as a sample.

`rustfs` itself splits its own source on this exact string for its own tooling,
two hundred lines below one of the findings.
"""

MAX_TEST_MODULE_SCAN = 4_000_000
"""A bound on the brace matching below, so a pathological file cannot spin."""


OPENERS = {0x7B: 0x7D, 0x5B: 0x5D, 0x28: 0x29}
"""The three bracket pairs Rust delimits an item with: braces, square, round."""

ATTRIBUTE_SKIP = 4_000
"""How far past one `#[cfg(test)]` to look for the item it applies to.

Enough for a stack of attributes and a doc comment between the marker and the thing
it marks, and short enough that a marker applying to nothing cannot reach across a
file to the next unrelated block.
"""


def _item_start(encoded: bytes, after: int) -> int:
    """Where the item a `#[cfg(test)]` applies to begins.

    Past the whitespace, the comments and any FURTHER attributes. The last of those is
    why this is a loop and not a `find`: `#[cfg(test)]` followed by `#[derive(Debug)]`
    has its first bracket inside the second attribute, and stopping there would make
    the span the derive and not the module.
    """
    index = after
    limit = min(len(encoded), after + ATTRIBUTE_SKIP)
    while index < limit:
        byte = encoded[index]
        if byte in b" \t\r\n":
            index += 1
        elif encoded.startswith(b"//", index):
            newline = encoded.find(b"\n", index)
            index = limit if newline < 0 else newline + 1
        elif encoded.startswith(b"/*", index):
            close = encoded.find(b"*/", index)
            index = limit if close < 0 else close + 2
        elif byte == 0x23:  # `#`, the start of another attribute
            end = _matching(encoded, encoded.find(b"[", index))
            if end < 0:
                return index
            index = end
        else:
            return index
    return index


def _matching(encoded: bytes, opening: int) -> int:
    """One past the bracket closing the one at `opening`, or -1 if it never closes.

    Counts all three bracket kinds together rather than only the one it was given,
    because a brace inside square brackets has to be paired before the square ones
    can close. Strings are not parsed, which is the approximation this accepts: a
    lone unpaired bracket inside a string literal moves the end of the span.
    """
    if opening < 0 or encoded[opening] not in OPENERS:
        return -1
    depth = 0
    index = opening
    while index < len(encoded):
        byte = encoded[index]
        if byte in OPENERS:
            depth += 1
        elif byte in (0x7D, 0x5D, 0x29):
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return -1


def test_module_spans(text: str) -> tuple[tuple[int, int], ...]:
    """Byte ranges of Rust test code.

    From each `#[cfg(test)]` to the end of the item it introduces. Usually that item is
    `mod tests { ... }` and the end is the matching brace, but the attribute is legal on
    anything, and `atuinsh/atuin` puts it on a struct FIELD: every pattern in its
    redaction table carries a `#[cfg(test)] tests: &[Test { ... }, Test { ... }]` list of
    sample credentials. Taking the first brace ended that span inside the first element
    and reported the second, so the opener is whichever of `{`, `[` or `(` comes first.

    A statement has no brackets at all -- `#[cfg(test)] use super::*;` -- and ends at its
    semicolon. An item whose brackets never close ends the span at the end of the file,
    which is where a Rust test module conventionally ends anyway.
    """
    encoded = text.encode("utf-8", errors="surrogatepass")
    marker = TEST_MODULE_ATTRIBUTE.encode()
    if marker not in encoded[:MAX_TEST_MODULE_SCAN]:
        return ()

    spans: list[tuple[int, int]] = []
    position = 0
    while True:
        start = encoded.find(marker, position)
        if start < 0:
            break
        head = _item_start(encoded, start + len(marker))
        opening = -1
        for index in range(head, min(len(encoded), head + ATTRIBUTE_SKIP)):
            byte = encoded[index]
            if byte in OPENERS:
                opening = index
                break
            if byte == 0x3B:  # `;` -- a statement, which is the whole item
                spans.append((start, index + 1))
                break
        else:
            opening = -1
        if opening < 0:
            if not spans or spans[-1][0] != start:
                spans.append((start, len(encoded)))
            position = spans[-1][1]
            continue
        end = _matching(encoded, opening)
        spans.append((start, len(encoded) if end < 0 else end))
        position = spans[-1][1]
    return tuple(spans)


#: Words that end in "test" and are not about testing.
#:
#: `**/*test/**` was added to `TEST_MATERIAL_PATHS` for `caddytest/` and two existing
#: tests refused it within one run: `docs/latest/guide.md` and `src/latest/config.py`
#: are not test trees, and they were right. A glob cannot tell a compound from a word
#: that happens to end the same way, so the exceptions are named.
NOT_A_TEST_WORD = frozenset(
    {
        # The one that was measured: `docs/latest/` and `src/latest/` are release
        # directories and two existing tests said so.
        "latest",
        "contest",
        "protest",
        "attest",
        "detest",
        # English forms the superlative of an adjective ending in `t` by adding `est`,
        # so every one of them ends in the four letters this predicate looks for. None
        # of these has been seen naming a directory; they are here because the class is
        # real and a reader should not have to rediscover it.
        "fastest",
        "greatest",
        "lightest",
        "brightest",
        "shortest",
        "softest",
        "quietest",
        "smartest",
        "neatest",
        "sweetest",
    }
)

TEST_DIRECTORY_SUFFIXES = ("test", "tests", "testing")

TEST_DIRECTORY_COMPOUNDS = (
    *TEST_DIRECTORY_SUFFIXES,
    # Words that make a directory test material when they are PART of its name. A
    # directory called `examples/` or `demo/` outright is already a glob in
    # `TEST_MATERIAL_PATHS`; this is the compound spelling, which a glob cannot see.
    #
    # `mbedtls` keeps two RSA keys in `yotta/data/example-benchmark/main.cpp`.
    # `docker-mailserver` ships a TLS key under `demo-setups/`. `coolify` seeds four
    # of them from `database/seeders/`, and `postal` keeps a signing key in
    # `docker/ci-config/`.
    "example",
    "examples",
    "demo",
    "demos",
    "sample",
    "samples",
    "seeder",
    "seeders",
    "fixture",
    "fixtures",
    "mock",
    "mocks",
    # `ut` for unit test, which is the convention across Yandex's C++ projects and the
    # ones that took their layout: `catboost` keeps a TLS key at
    # `library/cpp/neh/ut/server.pem`. An exact part, like `ci` below.
    "ut",
    # A continuous-integration directory holds what the pipeline needs rather than what
    # the product ships. `postal` keeps a signing key in `docker/ci-config/` and
    # `dragonflydb` a TLS key in `contrib/charts/dragonfly/ci/`. An exact part, so
    # `pci-config` and `uci/` are untouched.
    "ci",
)
"""Words that make a compound directory name test material. See `names_test_directory`."""

TEST_FILE_WORDS = (
    *TEST_DIRECTORY_SUFFIXES,
    # The other names a project gives the same thing, in a FILENAME only. A directory
    # called `examples/` or `samples/` is already a glob in `TEST_MATERIAL_PATHS`; these
    # are the one-file spellings. `photoprism` keeps three session tokens in
    # `internal/entity/auth_session_fixtures.go`, beside the entity it builds them for,
    # which is where Go convention puts them.
    "fixture",
    "fixtures",
    "mock",
    "mocks",
    "stub",
    "stubs",
    "seed",
    "seeds",
    "seeder",
    "seeders",
    "dummy",
    "sample",
    "samples",
    "example",
    "examples",
    # `demo` is a directory compound word and was not a filename one, which is the same
    # statement written one level down. `MichaelCade/90DaysOfDevOps` keeps
    # `2022/Days/Kubernetes/pacman-stateful-demo.yaml`, a privileged pod manifest in a
    # course.
    "demo",
    "demos",
    # The markers a project puts on a file that is NOT the production one. A key called
    # `local.key`, `key.default.pem`, `localhost.pem` or `autograph_localdev_config.yaml`
    # is the one the quickstart generates: `wp-calypso`, `c2cgeoportal`,
    # `addons-server` and `elasticsearch-py` each commit one.
    #
    # A filename only. `dev/` and `local/` as directory names reach much too far -- a
    # `dev/` directory is where plenty of projects keep real tooling -- and the directory
    # question is answered by `TEST_MATERIAL_PATHS` already.
    "local",
    "localhost",
    "localdev",
    "dev",
    "default",
    "defaults",
)
"""Words in a filename that say the file holds material written for a test.

Not used for directories. `seed` and `example` as directory names reach too far -- a
`seed/` directory in a data pipeline is production input and `example/` is where a
library keeps code somebody is meant to run -- and the directory question is answered
by `TEST_MATERIAL_PATHS` and `names_test_directory` already.
"""


def names_test_file(path: str) -> bool:
    """Whether the FILENAME says it is test infrastructure.

    `huggingface/transformers` keeps its committed Hub token in
    `src/transformers/testing_utils.py`, which no `test_*` or `*_test.*` glob matches and
    which is not in a test directory either -- the helpers live beside the library.

    Split on the separators a filename uses, so `testing_utils` counts and `latest`
    does not, which is the same distinction `names_test_directory` draws one level up.
    `conftest` is named because pytest's convention spells it as one word.

    The extension is a separator too. `*.test.*` and `*.spec.*` are already globs in
    `TEST_MATERIAL_PATHS`, but the plural `utils.tests.js` is not and is just as clear,
    and reading the whole name rather than the stem costs nothing: `latest.py` and
    `manifest.py` are single parts either way.
    """
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    parts = re.split(r"[._\-]+", name)
    return "conftest" in parts or any(part in TEST_FILE_WORDS for part in parts)


def names_test_directory(path: str) -> bool:
    """Whether any DIRECTORY in this path says it holds test material.

    Beyond what a glob can say. A project spells its own test tree with its own name in
    front -- Caddy keeps two TLS keys in `caddytest/`, Radarr keeps an HTML file named
    `.jpg` under `src/NzbDrone.Core.Test/Files/`, and okio keeps a deliberately corrupt
    zip under `okio-testing-support/` -- and `**/test/**` sees none of them.

    A segment counts if it ENDS in one of the suffixes, or if any dot-, dash- or
    underscore-separated part of it IS one. The deny-list above is what keeps `latest`
    out; see `NOT_A_TEST_WORD`.
    """
    for segment in path.lower().replace("\\", "/").split("/")[:-1]:
        if not segment or segment in NOT_A_TEST_WORD:
            continue
        # A dunder-wrapped directory is a tooling convention, not product source:
        # `__tests__`, `__mocks__`, `__snapshots__`, `__fixtures__`, `__pycache__`, and
        # the variants every project invents -- Storybook keeps a text file named
        # `Primary.png` under `__mockdata__/src/__screenshots__/`, which no `__mocks__`
        # or `__snapshots__` glob can see.
        if len(segment) > 4 and segment.startswith("__") and segment.endswith("__"):
            return True
        if segment.endswith(TEST_DIRECTORY_SUFFIXES):
            return True
        parts = re.split(r"[.\-_]+", segment)
        if any(part in TEST_DIRECTORY_COMPOUNDS for part in parts):
            return True
    return False


def is_test_material(path: str) -> bool:
    """Whether a path is where a project keeps things its tests need."""
    return _names(path, TEST_MATERIAL_PATHS) or names_test_directory(path) or names_test_file(path)


def is_documentation(path: str) -> bool:
    """Whether a path holds prose written to be read rather than executed."""
    return _names(path, DOCUMENTATION_PATHS)


def is_published_credential(matched: bytes) -> bool:
    """Whether the matched text contains a credential its vendor publishes.

    A substring test rather than equality, because the match usually carries the
    field that introduced the value -- `AccountKey=` and then the key -- and the
    published fixture is the value, not the assignment around it.
    """
    return any(known in matched for known in PUBLISHED_CREDENTIALS)


#: Where a project keeps the tooling that builds, tests and releases it.
#:
#: Measured across 338 of the most-starred repositories on GitHub, roughly HALF of
#: every `SUSPECT.EXFIL.001`, `SUSPECT.DROPPER.001` and `SUSPECT.ANTI_ANALYSIS.001`
#: finding landed here -- `scripts/dist.sh`, `packaging/utils/coverity-scan.sh`,
#: `.buildkite/scripts/dra-workflow.trigger.sh`, `publish_vec_binaries.sh`,
#: `setup.py`. Each of those reads a token from the environment, calls an API and
#: runs a command, which is credential plus egress plus spawn, which is the
#: composite. It is also what publishing a release IS.
#:
#: The composite's own documentation admitted this shape was the problem -- "a deploy
#: script that pushes and posts to Slack" is in the comment explaining why a third
#: signal was added -- and it was still firing on exactly that, in a third of all
#: repositories.
#:
#: What separates publishing from exfiltration is where the data goes, which the rule
#: cannot decide offline. So this is a ceiling, not a suppression, and three things
#: keep it from being a hole:
#:
#: `MALICIOUS` findings are never ceilinged, so a dropper is still a dropper here.
#: The install-hook escalation is applied AFTER, so anything that runs unprompted
#: reaches CRITICAL regardless of the directory it sits in. And a script in here runs
#: when somebody runs it, which is not the threat model the composites are calibrated
#: for -- that one is code executing without being asked.
BUILD_TOOLING_PATHS = (
    "scripts/**",
    "**/scripts/**",
    "script/**",
    "**/.github/**",
    "**/.buildkite/**",
    "**/.circleci/**",
    "**/.gitlab/**",
    "**/.azure-pipelines/**",
    "ci/**",
    "**/ci/**",
    "**/build/**",
    "**/packaging/**",
    "**/tools/**",
    "**/tool/**",
    # webpack keeps its build helpers in `tooling/` and its bootstrap in `setup/`,
    # neither of which `tools/` reaches.
    "**/tooling/**",
    "**/dev-tools/**",
    "**/devtools/**",
    "**/build-tools/**",
    "**/buildtools/**",
    "**/build-tools-internal/**",
    "**/setup/**",
    "**/bin/**",
    "**/etc/**",
    "**/utils/build/**",
    "**/hack/**",
    "**/dev/**",
    "**/devel/**",
    "**/devel-common/**",
    "**/contrib/**",
    "**/infra/**",
    "**/Makefile",
    "**/makefile",
    "**/*.mk",
    "**/setup.py",
    "**/conftest.py",
    "**/noxfile.py",
    "**/tasks.py",
    "**/Rakefile",
    "**/Gruntfile.js",
    "**/gulpfile.js",
    # Named for what they do, wherever they live. `publish_simdjson_binaries.sh`
    # sits under `libs/simdjson/native/`, which no directory glob reaches.
    # The verb has to be a whole word, the same discipline the credential keywords
    # needed: `**/publish*` also matched `src/publisher.py`, which is application
    # code. A separator or the end of the stem after the verb, never an arbitrary
    # continuation.
    "**/publish",
    "**/publish.*",
    "**/publish_*",
    "**/publish-*",
    "**/release.*",
    "**/release_*.sh",
    "**/release-*.sh",
    "**/deploy.*",
    "**/deploy_*.sh",
    "**/deploy-*.sh",
    "**/upload_*.sh",
    "**/upload-*.sh",
    "**/bootstrap.*",
    "**/bootstrap_*.sh",
    # `install/` as a DIRECTORY, not just `install.sh`. The Proxmox helper-script
    # collection keeps `install/mysql-install.sh`, `install/zammad-install.sh` and a
    # hundred siblings, each of which sets up a systemd unit - and persistence is what
    # an installer is for. `SUSPECT.PERSIST.001` produced five hundred findings across
    # 104 repositories, and installer directories were most of them.
    "**/install/**",
    "**/installer/**",
    "**/installers/**",
    "**/provision/**",
    "**/provisioning/**",
    "**/install.sh",
    "**/install_*.sh",
    "**/install-*.sh",
    "**/*-release.sh",
    "**/*_release.sh",
    "**/*-deploy.sh",
    "**/*_deploy.sh",
    "**/*_binaries.sh",
    "**/*-binaries.sh",
)

#: Build output: the compiled form of source that was reviewed in its readable form.
#:
#: A minified bundle contains a decoder next to an evaluator because that is what a
#: module loader is. `pdf.worker.min.mjs`, `.yarn/releases/yarn-4.17.1.cjs` and a
#: bundled GitHub Action's `dist/index.js` were all reported for decode-and-execute,
#: and all three are generated.
#:
#: Deliberately NOT including `vendor/` or `node_modules/`. Those hold somebody
#: else's SOURCE, which is exactly where a supply-chain payload lives, and ceilinging
#: them would blunt the rules where they matter most.
GENERATED_ARTEFACT_PATHS = (
    "**/*.min.js",
    "**/*.min.mjs",
    "**/*.min.cjs",
    "**/*.min.css",
    "**/*.bundle.js",
    "**/*.bundle.mjs",
    "**/.yarn/releases/**",
    "**/.yarn/plugins/**",
    "**/dist/**",
    "**/build/static/**",
    "**/*.map",
    "**/*.pb.go",
    "**/*_pb2.py",
    "**/*_pb2_grpc.py",
    "**/*.pb.cc",
    "**/*.generated.*",
    "**/generated/**",
    "**/__generated__/**",
)


def is_build_tooling(path: str) -> bool:
    """Whether a path is the project's own build, test or release tooling."""
    return _names(path, BUILD_TOOLING_PATHS)


def is_generated_artefact(path: str) -> bool:
    """Whether a path is build output rather than source somebody wrote."""
    return _names(path, GENERATED_ARTEFACT_PATHS)


BULK_DATA_EXTENSIONS = frozenset({".csv", ".tsv", ".psv", ".jsonl", ".ndjson"})
"""Extensions whose whole purpose is one record per line."""

BULK_DATA_ROWS = 200
"""How many rows before a file of records is a dataset rather than a table somebody typed.

High enough that a hand-maintained mapping -- a country list, a feature matrix, a
fixture of twenty users -- is nowhere near it, and low enough that anything scraped or
exported clears it easily.
"""


def is_bulk_data(path: str, rows: int) -> bool:
    """Whether this file is a dataset rather than something a person wrote line by line.

    `Asabeneh/30-Days-Of-Python` ships a twenty-thousand-row Hacker News export for its
    exercises, and one row's link is a Vimeo CDN URL with a signed `token=` in the query
    string. The row was scraped from a web page in 2016; nobody chose to put it there,
    and the signature expired the same day.

    A grade and not a dismissal, for the reason every ceiling in this file is: a
    dataset of ten thousand real API keys is a leak, and the collapse rules are what
    keep it from being ten thousand findings. What the grade says is that a credential
    here arrived with the data.
    """
    extension = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return extension in BULK_DATA_EXTENSIONS and rows >= BULK_DATA_ROWS


VENDORED_SEGMENTS = frozenset(
    {
        "node_modules",
        "bower_components",
        "vendor",
        "vendored",
        "third_party",
        "thirdparty",
        "3rdparty",
        "deps",
        "external",
        "site-packages",
        "dist-packages",
        ".venv",
        "venv",
        "pods",
        "carthage",
        ".cargo",
        ".gradle",
        ".m2",
        ".nuget",
        "gems",
        "bundle",
    }
)
"""Path segments under which the code belongs to somebody else.

The manifest detector has asked this question since the beginning -- whether a
`package.json` belongs to an installed dependency -- and the content detectors never
did, so a finding in vendored source was graded as though this repository had written
it. Homebrew vendors the `plist` gem under
`Library/Homebrew/vendor/bundle/ruby/4.0.0/gems/plist-3.7.2/`, whose XML parser decodes
base64 and evaluates, which is what a plist parser does. Node vendors OpenSSL under
`deps/`; Moby vendors a hundred Go modules under `vendor/`.

A ceiling rather than an exemption, because vendored code is exactly where a
supply-chain attack lands. It stays in the report, saying so, at a severity that does
not fail somebody else's build on this project's behalf."""


def is_vendored(path: str) -> bool:
    """Whether this path is inside a vendored dependency."""
    return any(segment.lower() in VENDORED_SEGMENTS for segment in path.split("/"))


#: Name endings that say the value is configuration ABOUT a credential.
#:
#: `REFRESH_TOKEN_COOKIE_PATH=/api/v1/auth/token/refresh/` was reported at HIGH as
#: "a credential assigned to 'REFRESH_TOKEN_COOKIE_PATH'". The value is a URL path.
#: The name says so.
#:
#: Matched on the NAME rather than the value, and that is the point. The obvious
#: fix was to widen the path shape in `NOT_A_SECRET`, which refuses this value only
#: because `v1` has a digit in it and because of the trailing slash. Widening it
#: would have been a bad trade: a real AWS secret key looks like
#: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` -- slashes, digits, segment-shaped --
#: and a path alternative permissive enough to accept a versioned URL accepts that
#: too. The rule would have gone quiet on the exact credential it exists to find.
#:
#: A name is safer ground because a developer chose it to describe the value. What
#: is given up is the case where somebody names the secret itself
#: `SECRET_KEY_FILE`; and even there, a value with a recognisable provider shape is
#: still caught by the provider patterns, which do not consult the name at all.
#: Only the generic entropy heuristic steps back.
#:
#: `KEY` is deliberately absent. `SECRET_KEY` and `API_KEY` are what this rule is
#: for.
CONFIGURATION_SUFFIXES = (
    "path",
    "paths",
    "url",
    "urls",
    "uri",
    "endpoint",
    "host",
    "hostname",
    "port",
    "dir",
    "directory",
    "file",
    "filename",
    "header",
    "field",
    "param",
    "params",
    "query",
    "cookie",
    "prefix",
    "suffix",
    "name",
    "names",
    "label",
    "ttl",
    "timeout",
    "expiry",
    "expires",
    "lifetime",
    "algorithm",
    "algo",
    "hasher",
    "encoding",
    "length",
    "min_length",
    "max_length",
    "rounds",
    "iterations",
    "enabled",
    "required",
    "env",
    "var",
    "variable",
    "scheme",
    "format",
    "pattern",
    "regex",
    "version",
    "type",
    "kind",
    "mode",
    "policy",
    "count",
    "counts",
    "limit",
    "limits",
    "size",
    "sizes",
    # Turned up by measuring against real repositories, each the last word of a name
    # that declares something about a credential rather than being one.
    "units",
    "unit",
    "scope",
    "scopes",
    "methodname",
    "classname",
    "fieldname",
    "keyname",
    "varname",
    "id",
    "ids",
    "index",
    "key_id",
    "column",
    "table",
    "default",
    "example",
    "placeholder",
    "hint",
    "description",
    "title",
    "message",
    "error",
    "status",
    "state",
    "flag",
    "source",
    "target",
    "provider",
    "backend",
    "strategy",
    "handler",
    "validator",
    "serializer",
    "parser",
    "encoder",
    "decoder",
)


#: Words that say the value is a location, wherever they appear in the name.
#:
#: Checked anywhere rather than only at the end, unlike `CONFIGURATION_SUFFIXES`,
#: because a location word is not a suffix -- `vaultPathTokenCreate` is a route and
#: `TOKEN_URL_OVERRIDE` is a URL, and in both the telling word is in the middle.
LOCATION_WORDS = frozenset(
    {
        "path",
        "paths",
        "url",
        "urls",
        "uri",
        "uris",
        "endpoint",
        "endpoints",
        "route",
        "routes",
        "location",
        "locations",
        "dir",
        "directory",
        "folder",
        "host",
        "hostname",
        "address",
        "addr",
        # `link`, which is what half the front-end world calls a URL. Ant Design's
        # token table declares `customizeTokenLink:
        # '/docs/react/customize-theme#customize-design-token'`, and a link is a place
        # to go by the same argument `url` and `endpoint` are.
        "link",
        "links",
        "href",
    }
)


#: Words in a NAME that say the value was never meant to work.
#:
#: Distinct from `PLACEHOLDER`, which reads the value. These read the name, for the
#: case where the author wrote a realistic-looking value on purpose: Home Assistant's
#: TOTP module declares `DUMMY_SECRET = "FPPTH34D4E3MI2HG"`, a valid base32 secret
#: whose whole job is to be verified against and fail, so that a login attempt for a
#: user who has no MFA configured takes the same time as one who does.
#:
#: Deliberately short, and `test` is deliberately absent. A `TEST_API_KEY` in CI is
#: very often a real key for a test account, and the fixture ceiling already covers
#: the case where the surrounding path says test material. Each word here is an
#: assertion by the author that the value does not authenticate to anything.
NOT_REAL_WORDS = frozenset(
    {
        "dummy",
        "fake",
        "bogus",
        "placeholder",
        "example",
        "sample",
        "notreal",
        "invalid",
        "nonexistent",
        "mock",
        "stub",
        "canary",
        # `demo` is here and `test` is not, and the asymmetry is deliberate. A
        # `TEST_API_KEY` in CI is very often a real key for a test account; demo data is
        # data nobody authenticates to. `**/demo/**` has been a test-material path since
        # the beginning, so this only says the same thing about the name.
        "demo",
    }
)


PEM_ARMOUR_ONLY = re.compile(rb"^-{3,6}(?:BEGIN|END)[ A-Z0-9]{0,60}-{3,6}$")
"""A PEM delimiter and nothing else.

The armour is the one part of a PEM file that carries no key material: it is the same
five words in every key ever generated. Any code that parses, writes or validates PEM
has both lines in it as literals -- `home-assistant/core`'s WeatherKit config flow
repairs a pasted key with `header = "-----BEGIN PRIVATE KEY-----"` and a `startswith`.

Checked here rather than in `NOT_A_SECRET` because the ASSEMBLED path must not consult
it. `M = "-----BEGIN " + "PRIVATE KEY" + "-----"` folds to the same value and is the
opposite case: nobody splits a PEM header across a concatenation except to get it past
a scanner, and `test_a_private_key_header_split_apart` refused this fix within one run
for exactly that reason.
"""


def _fold(text: str) -> str:
    """A name reduced to letters and digits, lowercased."""
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def value_is_the_name(name: str, value: str) -> bool:
    """Whether the value is the NAME, written in another case or separator style.

    `V2_UPGRADE_TOKEN = "v2UpgradeToken"` in `bitwarden/android`,
    `TOKEN_STORAGE_INITIALIZATION = 'token_storage_initialization'` in `gemini-cli`,
    `SUCCESSFULLY_TOKENIZED = "successfully_tokenized"`, `SERVER_PASSWORD1 =
    "serverPassword1"`. Four of seventy sampled assignment findings, and the shape is
    the commonest thing a credential-shaped constant holds: an enum member, a storage
    key, a feature flag, a telemetry event -- the name, spelled the way the wire spells
    it.

    Folded to letters and digits so that the comparison is about the WORDS rather than
    the convention: camelCase against SCREAMING_SNAKE, a hyphen against an underscore.
    Exact equality after folding, not a prefix or a containment test, because
    `API_KEY = "api_key_aB3kQ9mZ2xT7"` is a real credential with its own name in front
    of it and has to stay reported.
    """
    folded = _fold(value)
    return bool(folded) and folded == _fold(name)


MIN_RESTATED_NAME = 6
"""How much of the name must appear in the value before the overlap means anything.

Six folded characters. `api_key` folds to six and `token` to five, which is the line
this is drawn at: a five-letter word turns up inside a random run often enough to
matter, and six with the rest of the value accounted for does not.
"""

MAX_RESTATE_RUNS = 2
"""How many runs of letters-or-digits may be left over after removing the name.

This is what keeps `API_KEY = "api_key_aB3kQ9mZ2xT7"` reported -- a real credential
with its own name in front of it, which `value_is_the_name` refuses containment for.
Once `apikey` is removed, `ab3kq9mz2xt7` is eight alternating runs. Two is a prefix
like `dev` or a suffix like `12345`, and nothing more.
"""


def value_restates_the_name(name: str, value: str) -> bool:
    """Whether the value is the name with at most a word or a number attached.

    `value_is_the_name` asks for exact equality after folding, and explains why
    containment is refused: a real credential often carries its own name in front of
    it. This asks the narrower question -- is the value the name, plus almost nothing?

    `E2E_ADMIN_PASSWORD: E2eAdmin12345` in `langgenius/dify`'s end-to-end workflow
    shares `e2eadmin` with its name and then five digits.
    `bot_token: 123456789:telegram-bot-token` contains `bottoken` and is otherwise the
    word `telegram` and a run of digits. `detectorXMLFactoryBypass=XMLFactoryBypass`
    in `netty`'s `.fbprefs` is the name's own tail, with nothing left over at all.
    """
    folded_name, folded_value = _fold(name), _fold(value)
    if len(folded_name) < MIN_RESTATED_NAME or not folded_value:
        return False
    if folded_value in folded_name:
        remainder = ""
    elif folded_name in folded_value:
        remainder = folded_value.replace(folded_name, "", 1)
    else:
        shared = 0
        for a, b in zip(folded_name, folded_value, strict=False):
            if a != b:
                break
            shared += 1
        if shared < MIN_RESTATED_NAME:
            return False
        remainder = folded_value[shared:]
    runs = re.findall(r"[a-z]+|[0-9]+", remainder)
    return len(runs) <= MAX_RESTATE_RUNS


#: Prefixes a build tool treats as PUBLIC, by documented contract.
#:
#: Every one of these frameworks inlines a variable with the prefix into the client
#: bundle, and says so: Next.js `NEXT_PUBLIC_`, Vite `VITE_`, SvelteKit and Astro
#: `PUBLIC_`, Create React App `REACT_APP_`, Vue CLI `VUE_APP_`, Gatsby `GATSBY_`, Nuxt
#: `NUXT_PUBLIC_`, Expo `EXPO_PUBLIC_`, Storybook `STORYBOOK_`.
#:
#: A value under one of them is in the shipped JavaScript where anybody can read it, so
#: a finding about it has no remediation: it is not leaked, it is published.
#: `unionlabs/union` declares `PUBLIC_LOG_TOKEN` and the name is the contract.
#:
#: This is a guarantee a build tool makes rather than a shape somebody chose, which is
#: why it is a prefix list and not a heuristic. `NEXT_PUBLIC_SECRET_KEY` holding a real
#: server secret is a mistake the framework already made public; the place to catch that
#: is a review of what was put there, not a scanner calling it a leak.
PUBLIC_ENV_PREFIXES = (
    "next_public_",
    "nuxt_public_",
    "expo_public_",
    "public_",
    "vite_",
    "react_app_",
    "vue_app_",
    "gatsby_",
    "storybook_",
)


def names_public_by_contract(name: str) -> bool:
    """Whether a build tool compiles this variable into the client bundle by design."""
    folded = name.lower().lstrip("_")
    return folded.startswith(PUBLIC_ENV_PREFIXES)


def names_placeholder(name: str) -> bool:
    """Whether the variable's own name says its value is not a real credential."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    words = re.split(r"[_\-.]+", spaced.strip("_-.").lower())
    return bool(NOT_REAL_WORDS & set(words))


def names_configuration(name: str) -> bool:
    """Whether this variable name describes a credential rather than holding one.

    Compared against the final word, not as a substring. `TOKEN_PATHS` is
    configuration; `TOKEN_PATHOLOGY` is not a word anybody writes, and a substring
    test would treat `SECRET_KEY_FILENAME_OVERRIDE` and `SECRET_KEYFILE` as the same
    shape when only one of them is.

    CamelCase counts as a separator, because half the world spells a compound name
    that way and splitting on `_` and `-` alone could not see it. Measured across the
    most-starred repositories on GitHub, that blind spot reported
    `AntiforgeryTokenFieldName` in ASP.NET Core, `awsContainerAuthorizationTokenEnv`
    in the AWS SDK, `SpiffeJwtNormalizedTokenUnits` in Vault, `credentialType` and
    `CredentialScope` -- every one of them a field name, an environment variable
    name, a unit or a type, and every one of them ending in a word already on this
    list.
    """
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    words = re.split(r"[_\-.]+", spaced.strip("_-.").lower())
    if not words:
        return False

    # A location word ANYWHERE in the name, not only at the end. `path`, `url` and
    # `endpoint` say the value is somewhere to go, and that is true of the name
    # whatever order its words are in.
    #
    # Vault declares nine Go constants called `vaultPathTokenCreate`,
    # `vaultPathTokenRevokeSelf`, `vaultPathTokenLookup` and so on, each holding an
    # API route like "auth/token/create". Every one was reported as a credential,
    # because the last word is `create` and the word that matters is in the middle.
    if LOCATION_WORDS & set(words):
        return True

    last = words[-1]
    if last in CONFIGURATION_SUFFIXES:
        return True
    # Two-word endings such as `MIN_LENGTH`, written with the separator.
    return len(words) >= 2 and f"{words[-2]}_{last}" in CONFIGURATION_SUFFIXES


NOT_A_SECRET = re.compile(
    rb"""(?x)
    ^(?:
        [A-Za-z_][\w.-]{0,120}:[A-Za-z_0-9/][\w.:/+-]{0,200}  # module:attribute, or a
        # secret-store reference, which is the same shape with hyphens in it. Grafana
        # writes `SLACK_BOT_TOKEN=community-slack-bot:token` in its workflows -- the
        # name of a vault entry and the field to read from it -- twenty-eight times,
        # and the hyphens were the only reason this alternative did not already cover
        # it.
        #
        # A DIGIT after the colon as well as a letter, and a path after it. TeamCity
        # spells a store reference `credentialsJSON:57e22787-e451-48ed-9fea-b9bf30775b36`
        # -- five findings in one repository, every one a pointer to a credential the
        # build server holds -- and Postfix spells a map
        # `smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd`, which is a file
        # path with a type in front of it.
      | projects/[\w-]{1,60}/secrets/[\w.-]{1,120}(?:/versions/[\w.-]{1,40})?
        # A Google Secret Manager resource name, which is the thing you pass to the API
        # INSTEAD of the secret. `SLACK_SIGNING_SECRET =
        # "projects/455826092000/secrets/SlackSigningSecret/versions/latest"`.
      | arn:aws:(?:secretsmanager|ssm|kms)[\w:/.-]{1,200}
        # The AWS equivalent, and the two other services a secret is fetched from.
      | https://[\w.-]{1,80}\.vault\.azure\.net/[\w./-]{1,120}
        # And Azure's, which is a URL rather than a name.
      | -{1,2}[A-Za-z][\w:+.-]{0,60}(?:=[^\s]{0,120})?
        # A COMMAND-LINE FLAG. `habitat` sets
        # `HAB_STUDIO_SECRET_NODE_OPTIONS="--dns-result-order=ipv4first"` in three
        # scripts: the variable's name carries `SECRET` because that is the prefix
        # Habitat uses to pass a variable into its build studio, and the value is
        # node's own option string.
      | (?:\.{0,2}/|~/|[A-Za-z]:\\)[\w.@+-]{1,60}(?:[/\\][\w.@+ -]{1,60}){0,16}/?
        # A FILESYSTEM PATH. A credential is not a path, and a name ending in `_FILE`,
        # `_PATH` or `_MAPS` holds one by construction.
      | [0-9]{1,4}(?:\.[0-9]{1,6}){1,4}
        [\w.+~:-]{0,40}
        # A VERSION. Debian writes `5.0.0+~cs13.3.24-1build1` in a package list, and a
        # version string has dots and digits where a credential has entropy.
      | [@$]{0,2}[A-Za-z_0-9][\w-]{0,60}
        (?:(?:\.|::)[@$]{0,2}[A-Za-z_0-9][\w-]{0,60}){1,8}  # a dotted name or scope,
        # with the sigils and the separators other languages use. Ruby writes
        # `@next_token = @scanner.next_token` and
        # `token = Homebrew::EnvConfig.github_packages_token`, PHP writes `$this->x`,
        # and a segment may begin with a digit: Rails writes
        # `ACCESS_TOKEN_UPDATE_FREQUENCY = 24.hours.freeze`. Each of those is a
        # reference to other code, and each was a credential finding.
      | 0[xX]?[0-9a-fA-F]{16,128}                    # a hex digest or identifier,
      # with or without the `0x` a contract address and a git object id are written
      # with. `toeverything/AFFiNE` declares `quoteToken:
      # "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"`, which is an Ethereum address --
      # the same forty hex characters the mining rule refuses to match for being
      # indistinguishable from a GPG fingerprint.
      | [0-9a-fA-F]{16,128}
      | /?[A-Za-z_.-]{1,60}(?:/[A-Za-z_.-]{1,60}){1,12} # a path, absolute or not
      # A ROOTED path, which may contain digits. The branch above deliberately admits
      # none: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` is an AWS secret key with two
      # slashes in it, and allowing digits there would excuse every one of them.
      #
      # A leading `/` or `./` is what separates the two. Stirling-PDF declares its API
      # routes as constants -- `REMOVE_PASSWORD = "/api/v1/security/remove-password"` --
      # and `v1` was the only reason that did not read as a path. A key is not written
      # with a leading slash; a route is written with nothing else.
      | (?:~|\.{0,2})/[A-Za-z0-9_.~@%+-]{1,60}(?:/[A-Za-z0-9_.~@%+-]{1,60}){0,12}
        (?:[#?][A-Za-z0-9_.~@%+=&-]{0,80})?/?
      # A fragment or a query on the end of it. Ant Design's token table links to
      # `/docs/react/customize-theme#customize-design-token`, which is a place in a
      # document.
      # `~/` as well as `/` and `./`. Ray's cluster config writes
      # `ssh_private_key: ~/ray-bootstrap-key.pem`, which names a file on the machine
      # rather than holding a key.
      | (?=_{0,2}[A-Za-z]{8,80}[0-9]{0,2}$)(?=[^a-z]{0,84}[a-z])(?=[^A-Z]{0,84}[A-Z])
        _{0,2}[A-Za-z]{8,80}[0-9]{0,2}             # a mixed-case type or name
        # Up to two TRAILING digits, and nowhere else. A field in a remote API is
        # named that way when the vendor ran out of names: `home-assistant/core`'s
        # Growatt integration describes each sensor with
        # `api_key="eChargeToday1"`, where `api_key` is the name of the field in
        # Growatt's response and the value is that field's name. Generated key
        # material carries digits THROUGHOUT -- a base64 or base62 run of this
        # length with every digit at the end does not occur.
        # Leading underscores, because a private member is written that way in C++,
        # Python and TypeScript alike: `auto bypass = _recoveredFromDisk` in
        # `mongodb/mongo` was reported as a credential assignment between two member
        # variables.
      # Twelve stays. Raising it to twenty, to let `continuation_token` through, was
      # tried and the existing suite refused it within one run:
      # `glpat-AAAAAAAAAAAAAAAA` is sixteen repeated characters, so a padded GitLab
      # token became "a separated identifier". `test_a_separator_does_not_launder_key_
      # material` exists for exactly that, and it was right.
      #
      # The variable-reference case is handled in `PLACEHOLDER` instead, where the
      # mechanism for "the words themselves, used as their own name" already lived.
      | (?![A-Za-z0-9_-]{0,60}(?:[a-z]{12,64}|[A-Z]{12,64}|[0-9]{12,64}))
        _{0,2}[A-Za-z][A-Za-z0-9]{0,23}(?:[_-]{1,2}[A-Za-z0-9]{1,23}){1,14}_{0,2}
                                                     # a separated identifier.
        # `[_-]{1,2}` and fourteen segments rather than one and eight. Stable
        # Diffusion's webui assigns
        # `DontStealMyGamePlz__WINNERS_DONT_USE_DRUGS__DONT_COPY_THAT_FLOPPY` to
        # `checksum_token`, which is a joke in English with doubled underscores in it,
        # and neither the separator nor the length fitted. The negative lookahead above
        # is what keeps this from swallowing key material, and it is unchanged.
      # A hyphenated lowercase phrase, with no digit in it: a slug, a header value, a
      # passphrase made of words. Kubernetes names every controller
      # `serviceaccount-token-controller`, and Elasticsearch's license utilities declare
      # `DEFAULT_PASS_PHRASE = "elasticsearch-license"`. The long-run guard above refuses
      # both, because `elasticsearch` is thirteen lowercase characters -- it cannot tell
      # a word from a padded run.
      #
      # Generated key material is base64, base62 or hex: it has digits, or mixed case,
      # or both. A value that is lowercase letters and separators and nothing else is
      # something somebody typed.
      # `_{0,4}` at each end rather than two at the front. A marker string is written
      # with as many underscores as it takes to be unmistakable: V8's fuzzer declares
      # `SMOKE_TEST_END_TOKEN = '___foozzie___smoke_test_end___'`, which is three at
      # each end and a doubled separator in the middle.
      | _{0,4}[a-z]{3,24}(?:[_.-]{1,3}[a-z]{2,24}){1,8}_{0,4}
      # The same thing with DIGITS in it, and a slash allowed as a separator. A slug is
      # written `border-violet-500/30` (a Tailwind class in `toeverything/AFFiNE`),
      # `worldmonitor-free-map-panel-access-v1`, `pm-27278-v2-password-registration`
      # (a Bitwarden feature flag) and `gh-app_installation_id`.
      #
      # What keeps this away from key material is the absence of CAPITALS together with
      # the requirement for a separator. Generated base64, base62 and base58 all mix
      # case -- every value this suite keeps as a guard does -- and a lowercase-only run
      # with no separator in it is not matched here at all.
      | (?![0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$)
        [a-z0-9]{1,16}(?:[_.\-/][a-z0-9]{1,16}){2,12}/?
      # A trailing separator, because a route is written with one: Superset declares
      # `GUEST_TOKEN: 'api/v1/security/guest_token/'`, which is four segments and a
      # slash.
      # NOT a lowercase UUID, which is five hyphenated segments of sixteen characters
      # or fewer and would otherwise read as a slug. A UUID is graded to MEDIUM and
      # reported -- see `CANONICAL_UUID` -- and dismissing it here would have undone
      # that one alternative later in the same pattern. An existing test caught it.
      #
      # Three segments at least, each of sixteen characters at most, and no capital
      # anywhere. Each bound is doing work. The segment cap is what keeps a token out:
      # `sec-01e0d4agf6pfvwdjwxp61n3fvg` is two segments and the second is twenty-six
      # characters, so it is not matched and stays reported. Three segments is what
      # makes it a PHRASE rather than a prefixed value -- a slug is several words.
      # And the all-capitals form of the same thing: a header name, an environment
      # variable, a constant. ASP.NET Core declares
      # `MSAspNetCoreWinAuthToken = "MS-ASPNETCORE-WINAUTHTOKEN"`, where the guard
      # objects to `WINAUTHTOKEN` being twelve capitals.
      #
      # `glpat-AAAAAAAAAAAAAAAA` is unaffected by both and stays reported: it mixes case,
      # which neither of these admits.
      | _{0,4}[A-Z]{2,24}(?:[_.-][A-Z0-9]{2,24}){1,10}_{0,4}
      # A SENTINEL: one run of capitals wrapped in underscores, which is what a
      # substitution marker looks like. `PROGRAMDATA_TOKEN = '__PROGRAMDATA__'` in
      # `flow-launcher` is a placeholder an installer replaces with a path, and
      # `publicKeyToken="@_EM_PUBLIC_KEY_TOKEN@"` is the same idea wearing `@`.
      | _{1,4}[A-Z][A-Z0-9]{1,40}_{1,4}
      | [a-z][a-z0-9+.-]{1,15}://[^@\s]{1,200}       # a URL carrying no userinfo
      | [A-Za-z0-9][A-Za-z0-9._-]{0,80}@[A-Za-z0-9-]{1,60}
        (?:\.[A-Za-z0-9-]{1,60}){1,6}                 # a name qualified by a domain
      | (?:meth|class|func|ref|attr|mod|data|exc|obj|doc|term|py:[a-z]{1,10})
        :[`~][^\s]{1,110}                           # a Sphinx cross-reference
      # An EXPRESSION rather than a literal. Swift and Kotlin mark optionality,
      # force-unwrapping, inout arguments and member shorthand with characters no
      # generated credential contains, and every one of these is a declaration or
      # a reference that assigns no value at all:
      #
      #     public let credential: CmxIrohAdmissionCredential?
      #     private var socketPasswordObserver: NSObjectProtocol?
      #     let refreshToken = originalRefreshToken!
      #     let pendingToken = pendingWriter?.provisionalToken.id
      #     passwordAuthorization: &passwordAuthorization
      #     pendingSizingPassIntent = .inputChange
      #
      # `manaflow-ai/cmux` is a Swift codebase and supplied forty-three of those
      # against one real key. A marker is REQUIRED: a bare identifier is not
      # covered here, because `phc_Kq3Wd7Rt9Zx2Vb5Nm8Jf4Hs6Lp1Gy0Cu3Ae7Tn2Qi9Z` is
      # also a bare identifier and is a PostHog key.
      # `?` and `#` join the set. An Android layout writes
      # `app:passwordToggleTint="?colorControlNormal"`, where `?` is the theme-attribute
      # reference, and Meson writes `search_token = '#mesondefine'`.
      | [&*!~@+?#-]{1,2}\.?[$A-Za-z_][\w.?!@/-]{0,120}  # an operator-led expression,
      # `/` and `@` inside it as well as in front. A YAML tag is `!!python/tuple`, and a
      # build substitution marker is `@_EM_PUBLIC_KEY_TOKEN@`.
      # `++` and `--` because a counter is written `const token = ++tokenRef.current`
      # -- four of those in one repository -- and a CSS custom property is written
      # `inputTokenAccent: "--series-input-token"`, which is the NAME of a variable.
      # including Ruby's `@name` and `@@name`, which are a reference with no dot in it
      # A YAML alias is the commonest of those and earns its own note: `password:
      # *keyFileData` refers to an anchor defined elsewhere in the document, and
      # `mongodb/mongo` has fifteen across its resmoke suite definitions. `<<` is the
      # merge key that usually accompanies them.
      # A literal with a shell variable on the END of it. `kSecret =
      # "AWS4$AWS_SECRET_ACCESS_KEY"` is the SigV4 key-derivation prefix: the secret
      # arrives from the environment and the literal is the four characters in front.
      #
      # ALL-CAPS after the `$`, which is what distinguishes it from a PayPal access
      # token -- `access_token$production$<id>$<secret>` has lowercase and hex segments,
      # and `PLACEHOLDER`'s word-boundary guard exists so that pattern keeps firing.
      | [^\n$]{0,40}\$\{?[A-Z][A-Z0-9_]{5,60}\}?
      | <<[ \t]*\*?[A-Za-z_][\w-]{0,120}            # a YAML merge key
      # A value carrying a backslash. Generated key material is base64, base62 or
      # hex, and none of those alphabets contains one -- so a backslash means an
      # escape sequence, a Windows path or a regular expression. Boost's graphviz
      # parser assigns a lexer pattern to `basic_id_token`, and every parser in
      # existence has a few.
      | [^\n]{0,60}\\[^\n]{0,120}                   # anything carrying a backslash
      # Or a parenthesis. Kafka builds a `toString()` out of
      # `"DelegationTokenImage(" + String.join(...)`, which folds to a value that opens
      # a call. base64, base62 and hex have no parentheses in their alphabets, so one in
      # a value means code or a formatted string.
      | [^\n]{0,60}[()\[\]][^\n]{0,120}
      # A coordinate: `group:artifact:version`, `host:port:db`. The single-colon form is
      # above; `gkd-kit/gkd` declares
      # `lsposed-hiddenapibypass = "org.lsposed.hiddenapibypass:hiddenapibypass:6.1"` in
      # its Gradle version catalogue, which is three segments and a dependency.
      | [A-Za-z_][\w.-]{0,80}(?::[A-Za-z0-9_.+-]{1,80}){2,5}
      # A value that ENDS in a colon. No credential format does: base64 pads with
      # `=`, base62 and hex have no punctuation at all, and every provider prefix
      # puts its separator in the middle. A trailing colon means the value is the
      # NAME of a field, a label or a prefix -- `gorhill/uBlock`'s MV3 rule editor
      # carries an autocomplete table of nineteen entries, every one of them
      # `{ token: 'urlFilter:' }`, and the key is called `token` because that is
      # what a parser calls the thing it is completing.
      | [-$@.]{0,2}[A-Za-z_][\w.+-]{0,120}(?::[A-Za-z0-9_.+-]{0,120}){0,5}:
      # A COMMA-SEPARATED list, which is a list. No credential format contains a
      # comma: base64's alphabet has none, base62 and hex have no punctuation at all,
      # and a connection string separates with semicolons. `cherry-studio` declares
      # `defaultByPassRules = 'localhost,127.0.0.1,::1'` -- a proxy bypass list whose
      # name contains "pass" because it contains "byPass".
      | [^\n,]{0,16}(?:,[^\n,]{0,16}){1,16}
      # Sixteen items of sixteen characters rather than twelve of forty, which is the
      # same budget spent where the lists actually are: js-beautify declares its void
      # elements as one comma-separated string of fifteen tag names, and a list is
      # longer than it is wide.
      #
      # Sixteen on BOTH bounds, not a product under a thousand. The pattern validator
      # has two separate caps and this alternative met the wrong one first: a repeat
      # above `LARGE_REPEAT` counts as unbounded for the `(a+)+` check, so `{0,24}`
      # inside `{1,40}` read as an unbounded quantifier enclosing another even though
      # the product was 960.
      # A value carrying a NON-ASCII character. Every credential format there is --
      # base64, base64url, base62, base32, hex -- is ASCII by specification, so a byte
      # above 0x7f means human language. `localsend` ships Inno Setup language files
      # named after the language, and `Icelandic.isl` assigns the Icelandic word for
      # "password" to `WizardPassword`; Keycloak has the same thing in forty-odd
      # `messages_<locale>.properties`, and `dbeaver` in twelve.
      #
      # The words are described rather than written: this pattern is a bytes literal,
      # which cannot hold a non-ASCII character, and a comment beside a rule in a file
      # this tool scans is the wrong place for a faithful copy either way.
      #
      # The trade, stated rather than hidden: a committed password containing an
      # accented letter is missed by THIS rule. Its whole evidence is a
      # credential-shaped name beside an entropy measure, which is exactly the
      # evidence prose defeats -- and a provider-prefixed value is matched by that
      # provider's pattern, which consults none of this.
      | [^\n]{0,80}[\x80-\xff][^\n]{0,120}
      # A Ruby symbol, which is a name with a colon in front of it. RuboCop declares
      # `COMPLEX_STRING_BEGIN_TOKEN = :tSTRING_BEG`, naming one of the parser's token
      # types, and every cop that matches on token types has a few.
      | :[A-Za-z_]\w{0,120}[?!]?
      # A ROUTE TEMPLATE, which names its parameters with a colon. `twentyhq/twenty`
      # declares `ApiKeyDetail: 'api-webhooks/apis/:apiKeyId'`, and every Express and
      # React Router path in existence is written this way.
      | [A-Za-z0-9_.~/-]{0,80}/:[A-Za-z_]\w{0,40}[A-Za-z0-9_.~/:-]{0,80}
      # A TYPE or SCHEMA reference: a mixed-case identifier ending in one of the words
      # a type is named with. `stablyai/orca` declares
      # `resumeToken: Base64Url32ByteSchema`, a Zod schema, and the mixed-case
      # alternative above cannot admit it because the digits are in the middle.
      # A PREDICATE reference: a camelCase name opening with a word that asks a
      # question. `cline` writes `const apiKey = usesExplicitSigV4Auth`, which is a
      # boolean the line above computed, and the mixed-case alternative cannot admit it
      # because the digit sits in the middle.
      | (?-i:(?:is|has|have|use|uses|used|should|can|could|will|was|were|did|does|must
        |allow|allows|enable|enabled|disable|disabled|need|needs|require|requires|skip
        |include|includes|exclude|supports|support|prefer|prefers)
        [A-Z][a-z]{2,20}[A-Za-z0-9]{0,40})
      # Google's C++ constant convention: a `k` and then PascalCase WORDS. gRPC writes
      # `oauth2AccessToken:kDefaultOauth2AccessToken`, naming a constant defined above.
      #
      # Each hump has to carry three or more consecutive lowercase letters, and there
      # have to be at least two humps. `k[A-Z][A-Za-z0-9]{2,60}` was the first draft and
      # it would have excused roughly one random base62 secret in a hundred and fifty:
      # any value beginning with a `k` and a capital. Real words are what distinguishes
      # a constant's name from a generated run, so real words are what it asks for.
      | (?-i:k(?:[A-Z][a-z]{2,20}[0-9]{0,3}){2,8})
      | [A-Za-z][A-Za-z0-9]{0,60}
        (?:Schema|Type|Config|Options|Props|Model|Factory|Builder|Service|Provider
          |Handler|Manager|Client|Request|Response|Error|Exception|Enum|Interface
          |Dto|Entity|Context|Store|Reducer|Selector|Hook|Guard|Filter|Pipe)
      # A PARAMETER STRING: two or more `=` signs with nothing long between them.
      # Jellyfin builds an ffmpeg filter as `vpp_rkrga=format=bgra:afbc=1`, and base64
      # carries at most two `=` and only at the end.
      #
      # The length cap is what keeps an Azure connection string out:
      # `AccountKey=` is followed by eighty-eight characters of base64, and every run
      # here is at most twenty-four.
      | [^\n=]{1,24}=[^\n=]{1,24}=[^\n=]{0,24}(?:=[^\n=]{0,24}){0,4}
      # Semicolon-separated `key=value` pairs whose values are lowercase words. Symfony
      # declares console styles that way -- `TOKEN_STRING: "fg=yellow;options=bold"` --
      # and a terminal style is not a credential.
      #
      # Lowercase values only, which is what keeps an Azure connection string out:
      # `AccountKey=` is mixed case and its value is base64 with `+`, `/` and `=` in it.
      | [a-z][a-z0-9-]{0,20}=[a-z0-9-]{1,24}(?:;[a-z][a-z0-9-]{0,20}=[a-z0-9-]{1,24}){0,10}
      | \.[A-Za-z_][\w.?!-]{0,120}                  # member shorthand
      | [$A-Za-z_][\w$-]{0,60}
        (?:[?!&]{0,2}\.[$A-Za-z_]?[\w$-]{0,60}){1,8}[?!]{0,2}  # a chain, however it navigates
        # Two trailing marks, not one. Kotlin force-unwraps with `!!`, and
        # `DrKLO/Telegram` writes `curAccessToken = tokenResponse.accessToken!!` --
        # a chain AND a force-unwrap, which neither this branch nor the bare
        # force-unwrap branch below could match on its own.
        # `&.` is Ruby's safe navigation and is a separator like any other:
        # `pass = proxy_uri&.password` reads a value off another object and assigns no
        # literal at all.
        # `$` inside a segment as well as at the front. A TextMate grammar writes
        # `{ token: 'keyword.tag-$0' }`, where `$0` is the capture group the scope is
        # built from, and every syntax definition in a editor is full of them.
      | [$A-Za-z_][\w-]{0,60}[?!]{1,2}              # a name declared optional, or
      # force-unwrapped twice: Kotlin writes `webPoTokenStreamingPot =
      # webPoTokenGenerator!!`, which is a reference and assigns nothing.
      # A command in backticks, which is a shell substitution: `ente` writes
      # `museum_jwt_secret=`gen_jwt_secret`` in its setup script, and the value at
      # runtime is whatever that function prints.
      | ["']?[ \t]*\+[ \t]*[A-Za-z_$][\w$.]{0,60}[\s\S]{0,200}
        # A CONCATENATION. PrestaShop builds an ajax body as
        # `data: "token="+employee_token+'&ajax=1&action=...'`, where the credential-shaped
        # name is a query parameter in a string and the value is the rest of the
        # expression. A `+` straight after the opening quote is the author joining this
        # fragment to a variable, which is where the real value lives.
      | `[^`\n]{1,120}`
      # A regular expression literal. `NO_NEED_TOKEN_REG =
      # /text|hard_line_break|soft_line_break/` in `marktext` is a pattern, and the
      # alternation inside it is what makes it one.
      | /[^/\n]{1,120}/[gimsuyxd]{0,6}
    )$
    """
)
"""Values with a credential-shaped *name* that are plainly not credentials.

Matched by shape, not by path. `secrets = "cordon_scanner.detect.secrets:SecretDetector"`
in this project's own `pyproject.toml` has a name containing `secret`, a quoted
value of 36 characters, high entropy and three character classes -- everything
the generic assignment rule looks for, and it is an entry-point declaration.

PascalCase is included with camelCase because C# declares inheritance with a
colon -- `class QueryJsonSelectToken : TestFixtureBase` reads as an assignment
to the pattern below, and the name contains "Token" because the API is called
SelectToken.

That alternative used to be written as capitalised words: an initial letter
then runs of `[A-Z][a-z]+`. It could not express an acronym or a trailing
initialism, so `passwd: HTTPPasswordMgrWithDefaultRealm` and `session_token:
AuthenticationBackendXY` -- a type annotation in each case, assigning nothing
at all -- were reported as credentials, and a typed Python or TypeScript
codebase produces those by the hundred.

What it asks now is only that the value is eight or more letters with no digit
and no symbol in it, in mixed case. The trade is stated rather than hidden: an
all-letter passphrase assigned to a credential-shaped name is missed by *this*
rule. Generated key material is base64, base62 or hex and effectively always
carries a digit; a run of letters that long with none is a name somebody wrote.
A passphrase with a provider prefix is still matched by that provider's
pattern, which does not consult this list at all.

The hex alternative reaches down to sixteen characters rather than
thirty-two. `publicKeyToken = cc7b13ffcd2ddd51` in a .NET `App.config` is an
assembly identifier and is public by definition; hex is low entropy over its own
alphabet, so a short hex run is an identifier or a digest far more often than
it is key material. It accepts either case, because `2E75CB6A...` and
`2e75cb6a...` are the same digest and OpenSSL's own test vectors are written in
the upper one.

The separated-identifier alternative replaced the snake_case and
SCREAMING_CASE ones it subsumes. Those two required a single case throughout,
and the values that reach here are mixed: OpenSSL's EVP test data assigns
`ALICE_cf_brainpoolP160r1` to a key called `PrivateKey`, naming a key defined
elsewhere in the same file, and seven hundred and twenty-eight of those were
reported as leaked credentials in every project that vendors OpenSSL.

What makes it an identifier rather than key material is the word separators
together with what sits between them: generated secrets are one unbroken run,
so a value with no `_` or `-` is never matched here, and a value whose
separators merely punctuate a long run of one character class is not matched
either. That second half is the lookahead. Without it `"glpat-" +
"AAAAAAAAAAAAAAAA"` reads as a two-segment identifier, which is precisely the
shape of a provider token this tool has no dedicated pattern for.

A Sphinx cross-reference is documentation, not an assignment. Prose reaches
this rule because the name group matches inside a word -- "bypasses" ends in
"pass" plus "es" -- and a role such as ``:meth:`Registry.new``` that follows it
has a colon and no whitespace, which is the shape the unquoted branch looks
for.

A URL is excluded only when it carries no userinfo. `token_url =
"https://oauth2.googleapis.com/token"` is an endpoint, not a credential, and
naming an OAuth endpoint after the thing it issues is the convention rather
than the exception. A URL that does embed a credential is matched by the
connection-string rule, which is where that finding belongs.

camelCase allows no digits, and that restriction is load-bearing rather than
tidy. Written as `[a-z]+(?:[A-Z][a-z0-9]*)+` it also matches
`kR9mT2nQ8vL4xW7yZ3bC6dF1` -- base62 key material alternates case and includes
digits, so a permissive camelCase rule excludes exactly the values this
detector exists to find. Requiring letters after each capital separates an
identifier from a token.

camelCase is covered for the same reason as the other identifier shapes, and
found the same way: `firstTokenOfCallee = calleeParenCount` in ESLint's indent
rule is one variable assigned another, and the name contains "Token" because a
linter's tokens are lexical. The path alternative accepts a leading slash --
`credentials_file = /random/file/which/does/not/exist.yml` in Prometheus's test
data is a filename, and requiring a relative path missed every absolute one.

Hyphens are allowed inside a dotted name because scoped identifiers use them:
`token = "entity.other.attribute-name"` in a syntax theme is a TextMate scope,
and a hyphen-free pattern reported a hundred and forty of them across three
real projects.

The two identifier alternatives cover assignment between names rather than to a
literal. `token = TOKEN_BLOCK_BEGIN` in a lexer is one constant being given
another, and the unquoted branch of the assignment pattern -- which exists to
catch `PASSWORD=hunter2` in a dotenv file -- reads the right-hand side as a
value. Three of five widely used packages reported a credential for this shape.

The snake_case alternative covers the shape every enum, constant table and
string-union has: `SECRET_EXPOSURE = "secret_exposure"`, `AUTH_TOKEN_HEADER =
"authorization"`. Generated key material is never all-lowercase words joined by
underscores -- it carries digits and mixed case, which is where its entropy
comes from -- so requiring that shape to be *absent* costs no detection and
removes a noise class that appears in almost every codebase. This project's own
taxonomy module was the first thing it flagged.

Kept narrow and anchored: each alternative must match the whole value, so a
credential that merely contains a dot is unaffected."""


_LITERAL = re.compile(rb"""'([^'\n]{0,240})'|"([^"\n]{0,240})\"""")
"""One quoted string literal.

Two branches, each a simple character run. Nothing nests, so this cannot be
made to backtrack -- the same property Cordon requires of every rule pack
pattern, and the engine does not get an exemption from it."""

_WHITESPACE = re.compile(rb"\s")
"""Any space in a value.

Separates prose and SQL from key material better than entropy does at these
lengths, because a generated credential is a single token by construction."""

_JOINER = re.compile(rb"^[\s\\]{0,32}[+.][\s\\]{0,32}$")
"""What may sit between two literals for them to still be one value.

Concatenation is `+` in most languages and `.` in PHP and Perl; a trailing
backslash continues the line. Anything else -- a comma, a parenthesis, an
identifier -- means these are two separate values rather than one split one.

An operator is **required**, not merely permitted. Allowing whitespace alone
merges any two literals that happen to sit on consecutive lines, which is what
a list of regex patterns in a rule pack, a table of URLs in `pyproject.toml`
and a fenced code block in a document all look like -- each of which this
flagged before the requirement was added."""


def fold_concatenations(raw: bytes) -> Iterator[tuple[int, int, bytes]]:
    """Adjacent string literals joined into the value they build.

    The fallback for everything the AST tier does not cover: JavaScript, PHP,
    Go, and any Python that will not parse. It understands only that literals
    separated by a joiner form one value, which is the form a split credential
    actually takes and is far short of understanding the language.

    Single literals are not returned. Those are contiguous bytes that the
    ordinary patterns have already matched.
    """
    run: list[bytes] = []
    start = 0
    end = 0

    for match in _LITERAL.finditer(raw):
        piece = match.group(1) if match.group(1) is not None else match.group(2)
        if piece is None:
            continue

        if run and _JOINER.match(raw[end : match.start()]):
            run.append(piece)
            end = match.end()
            continue

        if len(run) > 1:
            yield start, end, b"".join(run)

        run = [piece]
        start, end = match.start(), match.end()

    if len(run) > 1:
        yield start, end, b"".join(run)


class SecretDetector(BaseDetector):
    """Finds committed credentials."""

    id = "secrets"
    # 0.2.1: the assignment pattern no longer matches across a newline. The bump is not
    # cosmetic - `ScanCache.detector_signature` is `id@version`, and it is the ONLY thing that
    # invalidates a cached result when a detector's behaviour changes. Without it, everyone who
    # upgrades keeps being served the false positives this release removes, out of a cache whose
    # other inputs (file content, rulepack hash, config) are all unchanged.
    # 0.3.0: documentation embedded in source is recognised, the credential keyword
    # has to end a word, and several expression shapes are no longer credentials. Same
    # reasoning as the note above: the version is what invalidates a cached result.
    version = "0.11.0"
    categories = frozenset({Category.MALICIOUS, Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True)

    def __init__(self) -> None:
        self._documentation: dict[str, tuple[tuple[int, int], ...]] = {}
        """Documentation spans, by path. See `_inside_documentation`."""

        self._test_modules: dict[str, tuple[tuple[int, int], ...]] = {}
        """Rust test-module spans, by path. See `_inside_test_module`."""

        self._blocks: dict[str, tuple[tuple[int, int], ...]] = {}
        """`/* ... */` spans, by path. See `_is_commented`."""

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        content = unit.content
        if content.is_binary:
            return ()

        findings: list[Finding] = []
        seen: set[str] = set()

        raw = content.raw

        for spec in PROVIDER_PATTERNS:
            # Every provider credential has a fixed prefix; that is what makes
            # the format recognisable. A substring test is orders of magnitude
            # cheaper than the regex and rejects almost every file.
            if spec.prefilter and not any(lit in raw for lit in spec.prefilter):
                continue
            for match in spec.pattern.finditer(raw):
                # Named distinctly from `raw`. Reusing that name here rebinds
                # the file content to the matched token, so every later
                # prefilter tests the previous match instead of the file and
                # silently stops finding anything.
                matched = match.group(0)
                if PLACEHOLDER.search(matched) or is_published_credential(matched):
                    continue
                if is_client_configuration(unit.path, spec.rule_id):
                    continue
                if spec.rule_id in CLIENT_CONFIG_RULES and is_firebase_web_config(
                    raw, match.start(), match.end()
                ):
                    # Firebase's published web configuration. See
                    # `is_firebase_web_config`; scoped to the same rule the file-name
                    # test is, because nothing else in a `.env` is excused by it.
                    continue
                if looks_sequential(matched):
                    # The alphabet in order, inside a provider prefix. `TryGhost/Ghost`
                    # documents Stripe with `sk_live_abcdefghij...XYZ` and
                    # `headroomlabs` writes `Bearer sk-ant-api03-abcdefghij...`. This
                    # test has always been applied to the generic rule and not to these.
                    continue
                if is_illustrated_by_its_key(raw, match.start()):
                    continue
                if is_presigned_credential(raw, match.start()):
                    continue
                if decodes_to_prose(matched):
                    # The body is base64 for a sentence. See `decodes_to_prose`.
                    continue
                if (
                    holds_published_key(raw, match.start())
                    or holds_illustrative_key(raw, match.start())
                    # Or the name in front of it says it is a sample. See
                    # `key_name_is_illustrative`: `holds_illustrative_key` reads the BODY
                    # and cannot help when the body is a real key of real length, which
                    # is what `vapor` ships in its development target.
                    or key_name_is_illustrative(raw, match.start())
                ):
                    continue
                digest = Evidence.hash_bytes(matched)
                if digest in seen:
                    continue
                seen.add(digest)
                # An access key id with no secret beside it is graded, not dropped. See
                # `is_lone_access_key_id`.
                lone = is_lone_access_key_id(raw, match.start(), match.end(), spec.rule_id)
                findings.append(
                    self._finding(
                        spec,
                        unit,
                        ctx,
                        match.start(),
                        match.end(),
                        matched,
                        grade=Severity.MEDIUM if lone else None,
                        note=LONE_KEY_ID_NOTE if lone else "",
                    )
                )

        findings.extend(self._assembled_findings(unit, ctx, seen))
        findings.extend(self._assignment_findings(unit, ctx, seen))
        findings.extend(self._connection_findings(unit, ctx, seen))
        return self._one_per_credential(findings)

    #: A line of a doctest or an interactive transcript, which is documentation.
    #:
    #: Django's template parser documents itself with a doctest line assigning a
    #: filter expression -- `variable`, a pipe, `default:` and a quoted default --
    #: to a local called `token`. The assignment rule read the filter expression as
    #: a credential assigned to `token` and reported it at HIGH. A transcript is
    #: prose that happens to be executable, and a value in one is an illustration
    #: of a format by construction.
    #:
    #: The example is described rather than quoted, because this file is scanned by
    #: the tool it configures and the literal form trips the rule it documents.
    #:
    #: `>>>` and `...` are Python's doctest prompts; `$` and `#` are a shell
    #: transcript; `In [n]:` is IPython's.
    EXAMPLE_PROMPT = re.compile(
        r"""^\s*(?:>>>|\.\.\.|\$\s|#\s|In\s\[\d+\]:)""",
    )

    def _inside_test_module(self, unit: FileUnit, offset: int) -> bool:
        """Whether this offset falls in a Rust `#[cfg(test)]` module.

        The language's own convention for where unit tests live, which is the file they
        test. `rustfs/src/auth.rs` supplied 51 findings that way -- assertions about
        constant-time comparison, using AWS's documented example key as a sample.

        Cached per file for the same reason the documentation spans are.
        """
        if unit.language != "rust":
            return False
        cached = self._test_modules.get(unit.path)
        if cached is None:
            cached = test_module_spans(unit.content.text)
            self._test_modules[unit.path] = cached
        return any(start <= offset < end for start, end in cached)

    def _inside_documentation(self, unit: FileUnit, offset: int) -> bool:
        """Whether this offset falls in documentation embedded in the source itself.

        A docstring, or one of Ansible's `DOCUMENTATION`/`EXAMPLES`/`RETURN` blocks.
        The path test cannot answer this -- `plugins/modules/consul_token.py` is
        source, and the example token is inside it -- and `community.general` produced
        29 findings that way, every one an example written the way examples are.

        Cached per file, because a module with a documentation block usually has
        several findings in it and the parse is the expensive half.
        """
        if unit.language != "python":
            return False
        cached = self._documentation.get(unit.path)
        if cached is None:
            cached = documentation_spans(unit.content.text)
            self._documentation[unit.path] = cached
        return any(start <= offset < end for start, end in cached)

    def _is_commented(self, unit: FileUnit, offset: int) -> bool:
        """Whether this assignment is a remark rather than an assignment.

        Applied to the GENERIC rule only, and not to the provider patterns. This
        rule's evidence is a credential-ish name beside a high-entropy value, which
        prose defeats: a TensorFlow header explains in a comment what a compiler pass
        renames instructions to, in a sentence ending "pass" and a colon and an
        example name, and that reads to this rule as a credential assignment.

        A provider pattern is different and is left alone. A GitHub token prefix
        followed by thirty-six characters is a token wherever it sits, including on a
        line somebody commented out instead of rotating. See `core.comments`.
        """
        content = unit.content
        line = content.line_text(content.line_of(offset))
        if is_commented(line, content.column_of(offset) - 1, unit.language):
            return True

        # And the block the per-line test cannot see. Its heuristic asks whether the
        # line begins with `*`, which is what a documentation comment looks like and
        # not what a paragraph of prose looks like. Cached per file for the reason
        # `_inside_documentation` is: a file with a long comment usually has several
        # matches inside it, and the pass over the text is the expensive half.
        cached = self._blocks.get(unit.path)
        if cached is None:
            cached = block_comment_spans(content.text, unit.language)
            self._blocks[unit.path] = cached
        return inside_spans(cached, offset)

    @staticmethod
    def _is_example_line(content: FileContent, offset: int) -> bool:
        """Whether this offset is on a line that is a transcript, not code."""
        line = content.line_text(content.line_of(offset))
        return bool(line) and SecretDetector.EXAMPLE_PROMPT.match(line) is not None

    @staticmethod
    def _one_per_credential(findings: list[Finding]) -> list[Finding]:
        """Collapse findings of the same rule over overlapping bytes.

        Deduplication inside each path is by the hash of the matched VALUE, and two
        paths that match different slices of one credential do not share it. Celery's
        test keypairs came back eight times, and two of those were the same key
        reported twice: spans [158, 199] and [168, 200] on the same line, one from the
        provider pattern matching the PEM header and one from the assembled-literal
        path folding the Python triple-quoted string around it. Different bytes,
        different hash, same key, and nothing in the report to tell a reader that
        from two keys.

        The PEM header is named rather than written, for the same reason as above.

        A post-filter rather than a check inside each path, because the duplication is
        BETWEEN paths and a per-path guard cannot see across them -- which is how the
        first attempt at this missed it entirely.

        The widest span wins. Both findings describe one credential and the longer
        match is the one that located more of it, so it is the more useful evidence to
        keep.
        """
        ordered = sorted(
            findings,
            key=lambda f: (
                f.rule_id,
                -((f.evidence.span or (0, 0))[1] - (f.evidence.span or (0, 0))[0]),
                (f.evidence.span or (0, 0))[0],
            ),
        )
        kept: list[Finding] = []
        claimed: dict[str, list[tuple[int, int]]] = {}
        for finding in ordered:
            span = finding.evidence.span
            if span is None:
                kept.append(finding)
                continue
            ranges = claimed.setdefault(finding.rule_id, [])
            if any(start < span[1] and span[0] < end for start, end in ranges):
                continue
            ranges.append(span)
            kept.append(finding)
        # Back to the order the paths produced them in, so output stays stable.
        order = {id(f): i for i, f in enumerate(findings)}
        return sorted(kept, key=lambda f: order[id(f)])

    def _assembled_findings(
        self, unit: FileUnit, ctx: ScanContext, seen: set[str]
    ) -> Iterable[Finding]:
        """Credentials split across a concatenation.

        Every pattern above needs a contiguous run of bytes, and `"ghp_" + "..."`
        is not one. The value is identical to the interpreter and invisible to
        the regex, which makes a `+` the cheapest way to commit a live
        credential past a secret scanner -- cheaper than encoding it, since the
        code still reads as ordinary.

        Folding first and matching afterwards means these need no patterns of
        their own: the provider shapes are matched against the assembled value
        exactly as they are against a literal one, and report the same rule.
        """
        for start, end, value, assembled, name in self._folded_values(unit):
            if PLACEHOLDER.search(value) or NOT_A_SECRET.match(value):
                continue
            if not assembled and PEM_ARMOUR_ONLY.match(value):
                # A literal the analyser merely resolved, not one built from parts.
                # `assembled` is the whole distinction: the armour on its own is how
                # PEM-handling code names its delimiters, and the armour SPLIT across
                # a concatenation is how somebody gets a key past a scanner.
                continue

            digest = Evidence.hash_bytes(value)
            if digest in seen:
                # Already reported from a contiguous match. The hash is over the
                # value rather than its spelling, so the split and whole forms of
                # one credential are recognised as the same secret.
                continue

            spec = self._assembled_spec(value, assembled=assembled, name=name)
            if spec is None:
                continue

            seen.add(digest)
            yield self._finding(spec, unit, ctx, start, end, value)

    @staticmethod
    def _assembled_spec(
        value: bytes, *, assembled: bool = True, name: str | None = None
    ) -> SecretPattern | None:
        """What an assembled value is, if it is anything.

        A provider shape is decisive on its own: those prefixes exist to make
        the format recognisable, and nothing else produces them. Beyond that the
        bar is deliberately higher than for a contiguous literal, because
        assembly is also how ordinary code builds paths, messages and URLs. The
        entropy floor is the one from the audit rather than the assignment
        floor, so `"pre" + "fix" + "-" + slug` cannot reach it.
        """
        for provider in PROVIDER_PATTERNS:
            if provider.prefilter and not any(lit in value for lit in provider.prefilter):
                continue
            if provider.pattern.search(value):
                return provider

        if any(value.startswith(prefix) for prefix in CREDENTIAL_PREFIXES):
            return SecretPattern(
                rule_id="SECRET.GENERIC.ASSIGNMENT.001",
                name="credential assembled from parts",
                pattern=ASSIGNMENT,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                remediation=ROTATE,
            )

        if not assembled:
            # A plain literal, carried here only because Python joins adjacent
            # literals with no operator. The provider shapes and prefixes above
            # apply to it; the entropy heuristic below does not, because its
            # justification is that building a value from pieces is not how a
            # URL or an identifier is written -- and applied to every constant
            # it reports every long URL in the project as a credential.
            return None

        if len(value) < MIN_ASSEMBLED_LENGTH:
            return None

        if not (name and CREDENTIAL_NAME.search(name.encode("utf-8", "replace"))):
            # The contiguous path reaches this rule only through a pattern that
            # requires a credential-shaped *name*, and the assembled path
            # dropped that requirement -- so any high-entropy concatenation
            # anywhere qualified, and jQuery, Guava's cache tests and a great
            # deal of ordinary string building were reported as credentials.
            #
            # Provider shapes and known prefixes above still fire whatever the
            # name is, which is right: a GitHub token is one regardless of what
            # it was assigned to. Entropy alone is not, and needs the name to
            # mean anything.
            return None

        if _WHITESPACE.search(value):
            # Key material is one token. Entropy alone cannot tell a credential
            # from a sentence -- Shannon entropy rewards a varied alphabet, and
            # `"SELECT id, name" + " FROM packages"` scores 4.48, well above any
            # floor prose is supposed to sit below. What actually separates them
            # is that a generated secret never contains a space.
            return None

        decoded = value.decode("utf-8", errors="replace")
        if Redactor.shannon_entropy(decoded) < MIN_ASSEMBLED_ENTROPY:
            return None
        if SecretDetector._character_classes(decoded) < MIN_CHARACTER_CLASSES:
            return None

        return SecretPattern(
            rule_id="SECRET.GENERIC.ASSIGNMENT.001",
            name="high-entropy value assembled from parts",
            pattern=ASSIGNMENT,
            severity=Severity.HIGH,
            # Assembly is the signal. A value of this entropy could be a hash or
            # an identifier, but building one out of pieces is not how either is
            # written, and it is exactly how a credential is hidden.
            confidence=Confidence.MEDIUM,
            remediation=ROTATE,
        )

    @staticmethod
    def _folded_values(unit: FileUnit) -> Iterable[tuple[int, int, bytes, bool, str | None]]:
        """Concatenated string values, folded to what they evaluate to.

        Python goes through the AST, which folds `+` chains, `"".join` and
        f-strings of constants, and knows an assignment from an expression.
        Everything else -- and any Python that will not parse -- falls back to
        joining adjacent literals in the bytes, which handles the common form
        without pretending to understand the language.
        """
        content = unit.content

        if unit.language == "python":
            from cordon_scanner.detect.pyast import PythonAnalyzer

            starts = content.line_starts
            for item in PythonAnalyzer.assembled(content.text):
                if not item.value:
                    continue
                index = min(max(item.line - 1, 0), len(starts) - 1)
                start = starts[index]
                end = starts[index + 1] if index + 1 < len(starts) else len(content.raw)
                yield (
                    start,
                    end,
                    item.value.encode("utf-8", "surrogatepass"),
                    item.assembled,
                    item.name,
                )
            if PythonAnalyzer.parses(content.text):
                return

        for start, end, value in fold_concatenations(content.raw):
            # The byte fold has no name to offer. Provider shapes and prefixes
            # still apply; the entropy branch does not, which is the honest
            # consequence of not knowing what the value was called.
            yield start, end, value, True, None

    # A credential-shaped assignment needs one of these words present. Checking
    # for them first avoids running a large alternation over files that cannot
    # match it.
    ASSIGNMENT_PREFILTER = (
        b"pass",
        b"Pass",
        b"PASS",
        b"secret",
        b"Secret",
        b"SECRET",
        b"token",
        b"Token",
        b"TOKEN",
        b"key",
        b"Key",
        b"KEY",
        b"auth",
        b"Auth",
        b"AUTH",
    )

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        """Every rule this detector can emit, provider shapes included.

        `cordon rules show SECRET.AWS.ACCESS_KEY.001` answered "no such rule"
        for a rule the tool emits, which is the plainest possible statement that
        the rule set was not reviewable.
        """
        declared = [
            DeclaredRule(
                id=spec.rule_id,
                title=f"Committed credential: {spec.name}",
                severity=spec.severity,
                confidence=spec.confidence,
                category=Category.SUSPICIOUS,
                detector=SecretDetector.id,
                remediation=spec.remediation,
            )
            for spec in PROVIDER_PATTERNS
        ]
        declared.append(
            DeclaredRule(
                id="SECRET.GENERIC.ASSIGNMENT.001",
                title="Credential-shaped value assigned to a credential-shaped name",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=SecretDetector.id,
                remediation=ROTATE,
            )
        )
        declared.append(
            DeclaredRule(
                id="SECRET.URL.CREDENTIAL.001",
                title="Credential embedded in a URL",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=SecretDetector.id,
                remediation=ROTATE,
            )
        )
        # Deduplicated: several provider shapes share a rule id on purpose,
        # because they are the same finding about the same kind of credential.
        unique: dict[str, DeclaredRule] = {}
        for rule in declared:
            unique.setdefault(rule.id, rule)
        return tuple(unique.values())

    @staticmethod
    def _character_classes(value: str) -> int:
        """How many of {lower, upper, digit, symbol} the value uses."""
        return sum(
            (
                any(c.islower() for c in value),
                any(c.isupper() for c in value),
                any(c.isdigit() for c in value),
                any(not c.isalnum() for c in value),
            )
        )

    def _connection_findings(
        self, unit: FileUnit, ctx: ScanContext, seen: set[str]
    ) -> Iterable[Finding]:
        """Passwords embedded in a URL's userinfo.

        See CONNECTION_STRING. A worked example is deliberately not written out
        here, for the reason given there.
        """
        raw = unit.content.raw
        if b"://" not in raw:
            return
        for match in CONNECTION_STRING.finditer(raw):
            value = match.group(1)
            # An identifier in the credential position is a field name rather
            # than a credential. Connection documentation is written with the
            # field names themselves standing in for the values -- the AWS key
            # id and secret spelled out where the credentials would go -- and
            # reading that as a leak produced fifty-two findings across
            # SQLAlchemy's, httpx's and Celery's documentation.
            if PLACEHOLDER.search(value) or NOT_A_SECRET.match(value):
                continue
            if LOCAL_OR_RESERVED_HOST.match(match.group(2)):
                continue
            # One character class is a word, not a generated credential.
            # `strongpassword` and `urlpass` are what documentation writes
            # where a password goes, and neither has a digit, a capital or a
            # symbol in it. The assignment rule has carried this test for the
            # same reason; this one had only the placeholder list, which cannot
            # enumerate every way somebody spells "put your password here".
            if self._character_classes(value.decode("utf-8", "replace")) < MIN_CHARACTER_CLASSES:
                continue
            digest = Evidence.hash_bytes(value)
            if digest in seen:
                continue
            seen.add(digest)
            spec = SecretPattern(
                rule_id="SECRET.URL.CREDENTIAL.001",
                name="credential embedded in a URL",
                pattern=CONNECTION_STRING,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                remediation=ROTATE,
            )
            yield self._finding(spec, unit, ctx, match.start(), match.end(), value)

    def _assignment_findings(
        self, unit: FileUnit, ctx: ScanContext, seen: set[str]
    ) -> Iterable[Finding]:
        raw = unit.content.raw
        if not any(lit in raw for lit in self.ASSIGNMENT_PREFILTER):
            return
        for match in ASSIGNMENT.finditer(raw):
            # Group 1 is the name; 2 the quoted value, 3 the unquoted one.
            value = match.group(2) or match.group(3)
            if not value or PLACEHOLDER.search(value) or NOT_A_SECRET.match(value):
                continue
            if reads_as_words(value):
                # The value is words rather than a generated run. See `reads_as_words`.
                continue
            if decoded_is_not_a_secret(value):
                # The base64 decodes to something already refused. See
                # `decoded_is_not_a_secret`.
                continue
            if is_firebase_web_config(raw, match.start(1), match.end()):
                # Firebase's published web configuration. The provider path has asked
                # this since the eighth pass; `excalidraw` assigns the whole object to
                # one variable, so the generic rule sees `apiKey` inside a JSON blob and
                # had to ask it too.
                continue
            if is_published_credential(value) or decodes_to_prose(value):
                # Both tests were on the provider path only, which is backwards: a
                # vendor's published default is usually assigned to an ordinary name
                # rather than carrying a provider prefix. Supabase's self-host
                # `docker-compose.yml` assigns its `SECRET_KEY_BASE` that way, and every
                # project that copies the file copies the value.
                continue

            decoded = value.decode("utf-8", errors="replace")
            if Redactor.shannon_entropy(decoded) < MIN_ASSIGNMENT_ENTROPY:
                continue
            if looks_sequential(value):
                # An alphabet, not a secret. See `looks_sequential`.
                continue
            if self._character_classes(decoded) < MIN_CHARACTER_CLASSES:
                # Carries what the entropy floor used to carry alone. A
                # dictionary word or a repeated filler uses one class; generated
                # key material almost always mixes at least two.
                continue

            digest = Evidence.hash_bytes(value)
            if digest in seen:
                continue
            seen.add(digest)

            if (
                PEM_ARMOUR_ONLY.match(value)
                or is_public_by_design(value)
                or is_password_hash(value)
            ):
                continue

            name = match.group(1).decode("utf-8", errors="replace")
            if (
                names_configuration(name)
                or names_placeholder(name)
                or names_public_by_contract(name)
            ):
                continue
            if _decoded_text(value) and value_restates_the_name(name, _decoded_text(value)):
                # The base64 decodes to the name plus almost nothing. `harvester` writes
                # `db-password: ZGJwYXNzd29yZDEx`, which is `dbpassword11`, and the
                # question `value_restates_the_name` asks could not see through the
                # encoding.
                continue
            if value_restates_the_name(name, decoded):
                # The value is the name plus a word or a number. See
                # `value_restates_the_name`, and `value_is_the_name` for why the plain
                # containment test this narrows is refused.
                continue
            if value_is_the_name(name, decoded):
                # An enum member, a feature flag, a storage key: the value is the name
                # written the way the wire spells it. See `value_is_the_name`.
                continue
            if SecretDetector._is_example_line(unit.content, match.start(1)):
                continue
            if is_inside_example_literal(raw, match.start(1), unit.language):
                # A Go raw string the author named as example or help text. See
                # `is_inside_example_literal`.
                continue
            if self._is_commented(unit, match.start(1)):
                continue
            # The name's own offset, not the match's. The pattern opens with
            # `(?:^|[^\w.])`, which on every line but the first consumes the
            # newline that ended the line before -- so `match.start()` sits on
            # the previous line and every finding from this rule pointed one
            # line above the credential.
            spec = SecretPattern(
                rule_id="SECRET.GENERIC.ASSIGNMENT.001",
                name=f"credential assigned to {name!r}",
                pattern=ASSIGNMENT,
                # A UUID is graded down rather than dismissed. See `CANONICAL_UUID`:
                # it really is the secret in some systems, and it is also the format an
                # example value is generated in.
                severity=(
                    Severity.MEDIUM
                    if CANONICAL_UUID.match(value) or is_url_parameter(raw, match.start(1))
                    # A query parameter of a URL is a signed link. Graded for the same
                    # reason a UUID is -- it is usually not a credential and sometimes
                    # is. See `is_url_parameter`.
                    else Severity.HIGH
                ),
                # Medium, not high: a high-entropy string assigned to something
                # named `token` is usually a credential and is sometimes a hash,
                # an identifier or a fixture. The finding is worth a look and is
                # not worth failing a build on its own.
                confidence=Confidence.MEDIUM,
                remediation=ROTATE,
            )
            yield self._finding(spec, unit, ctx, match.start(1), match.end(), value)

    def _finding(
        self,
        spec: SecretPattern,
        unit: FileUnit,
        ctx: ScanContext,
        start: int,
        end: int,
        raw: bytes,
        grade: Severity | None = None,
        note: str = "",
    ) -> Finding:
        content = unit.content
        line = content.line_of(start)
        rule_material = content.is_rule_material
        fixture = not rule_material and (
            is_test_material(content.path) or self._inside_test_module(unit, start)
        )
        documentation = not (rule_material or fixture) and (
            is_documentation(content.path) or self._inside_documentation(unit, start)
        )
        # Generated output, which this detector was the only one not to ceiling.
        # Jest vendors `.yarn/releases/yarn-4.18.0.cjs` -- five megabytes of bundled
        # JavaScript -- and a credential-shaped assignment inside a bundle belongs to
        # whichever library was bundled, not to the repository that committed the
        # artefact.
        # A media extractor, which holds the key the site's own web player holds. Asked
        # before the generated-output family because the caveat is a different claim: the
        # value is real and is not the project's to rotate. See
        # `core.samples.is_media_extractor`.
        extractor = not (rule_material or fixture or documentation) and is_media_extractor(
            content.raw
        )
        generated = not (rule_material or fixture or documentation or extractor) and (
            is_generated_artefact(content.path)
            or is_vendored(content.path)
            # Or a dataset: twenty thousand rows of scraped web pages is not source
            # somebody wrote, and it is graded for the same reason build output is.
            # See `is_bulk_data`.
            or is_bulk_data(content.path, content.line_count)
            # Or minified, which is build output that was not given a build output's
            # name. `alibaba/nacos` serves `console/src/main/resources/static/legacy/
            # js/main.js`, a bundle on one line of 300KB, and `**/*.min.js` cannot see
            # it. The capability detector has ceilinged on this since it measured the
            # same thing; this detector was comparing names only.
            or content.longest_line > MINIFIED_LINE
        )
        ceilinged = rule_material or fixture or documentation or generated or extractor
        ceiling = RULE_MATERIAL_CEILING if rule_material else FIXTURE_CEILING
        severity = min(spec.severity, ceiling) if ceilinged else spec.severity
        # A grade the caller worked out from the value itself, rather than from where
        # the file sits. It lowers and never raises, so it composes with the ceilings
        # above in either order.
        if grade is not None:
            severity = min(severity, grade)
        confidence = min(spec.confidence, FIXTURE_CONFIDENCE) if ceilinged else spec.confidence
        caveat = ""
        if rule_material:
            caveat = (
                " The file is another analyser's rule material -- a rule set, or a test "
                "case annotated for one -- so a credential-shaped string in it was "
                "published in order to be detected. Reported for the record only."
            )
        elif fixture:
            caveat = (
                " It sits under a path that holds test material, where a credential "
                "of this shape is usually generated for the test suite, so it is "
                "reported below its usual severity -- but a real key committed here "
                "leaks exactly as far as one committed anywhere else."
            )
        elif generated:
            caveat = (
                " It sits in generated build output or in bulk data rather than in "
                "source somebody wrote, so a credential-shaped string in it came from "
                "whatever was bundled or exported, and it is reported below its usual "
                "severity."
            )
        elif extractor:
            caveat = (
                " It sits in a media extractor, which holds the key the site's own web "
                "player holds -- read out of a public page, still in that page, and not "
                "this project's to rotate. Reported below its usual severity for that "
                "reason: it is a real credential, and the party who can act on it is the "
                "one who published it."
            )
        elif documentation:
            caveat = (
                " It sits in documentation, where a credential-shaped string is "
                "usually an example of the format rather than a live value, so it is "
                "reported below its usual severity -- but a real key pasted into a "
                "README leaks exactly as far as one in a settings file, and plenty "
                "have been."
            )

        return Finding(
            rule_id=spec.rule_id,
            category=Category.SUSPICIOUS,
            severity=severity,
            confidence=confidence,
            message=(
                f"{article(spec.name).capitalize()} {spec.name} appears in this file. "
                f"Anything committed is in git "
                f"history and in every clone, so it must be treated as public from "
                f"the moment it landed, whether or not it is still in the working "
                f"tree.{caveat}{note}"
            ),
            location=Location(
                path=content.path,
                line=line,
                column=content.column_of(start),
                byte_start=start,
                byte_end=end,
                project=unit.project,
            ),
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(raw),
                # Hash-only, and not overridable. `--evidence full` is typed by
                # somebody debugging a false positive, not by somebody thinking
                # about where the log ends up.
                redaction=RedactionMode.HASH_ONLY,
                span=(start, end),
                metadata=(("kind", spec.name),),
            ),
            remediation=spec.remediation,
            explanation=Explanation(
                summary=f"Detected a {spec.name}.",
                matched_rule=spec.rule_id,
                escalations=("the value is withheld from this report; the hash identifies it",),
            ),
            risk=ctx.scorer.score(
                severity,
                confidence,
                ScoringContext(
                    in_install_hook=ctx.in_install_hook(content.path),
                    capabilities=frozenset(),
                ),
            ),
            detector=self.id,
        )


__all__ = [
    "CREDENTIAL_PREFIXES",
    "FIXTURE_CEILING",
    "FIXTURE_CONFIDENCE",
    "LOCAL_OR_RESERVED_HOST",
    "MIN_ASSEMBLED_ENTROPY",
    "MIN_ASSEMBLED_LENGTH",
    "MIN_ASSIGNMENT_ENTROPY",
    "PROVIDER_PATTERNS",
    "RULE_MATERIAL_CEILING",
    "TEST_MATERIAL_PATHS",
    "SecretDetector",
    "fold_concatenations",
    "is_test_material",
    "is_vendored",
]
