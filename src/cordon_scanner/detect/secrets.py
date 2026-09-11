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

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

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
        SecretPattern._p(r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----"),
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
        SecretPattern._p(r"\bLTAI[0-9A-Za-z]{12,20}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        ROTATE,
        (b"LTAI",),
    ),
    SecretPattern(
        "SECRET.TENCENT.SECRET_ID.001",
        "Tencent Cloud secret id",
        SecretPattern._p(r"\bAKID[0-9A-Za-z]{32,}\b"),
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
        SecretPattern._p(r"\b(?:sq0(?:atp|csp)-[0-9A-Za-z_\-]{22,}|EAAA[0-9A-Za-z_\-]{56,})\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"sq0atp-", b"sq0csp-", b"EAAA"),
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
    SecretPattern(
        "SECRET.CRATES.TOKEN.001",
        "crates.io API token",
        SecretPattern._p(r"\bcio[0-9A-Za-z]{32}\b"),
        Severity.CRITICAL,
        Confidence.HIGH,
        ROTATE,
        (b"cio",),
    ),
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
      | ([^\s"'#,;()}\[\]=<>]{12,120})    # 3: unquoted
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
    rb"changeme|xxxx|test[_\-]?only|fake|not[_\-]?a[_\-]?real|\.\.\.|"
    # The words themselves, used as their own placeholder. Documentation is
    # written `redis://username:password@host`, and reading that as a
    # credential produced eighty-seven findings across Django's, Scrapy's and
    # axios's docs and tests. A real credential is not spelled "password".
    rb"^(?:my|your|the|some|a)?[_-]?"
    rb"(?:user(?:name)?|pass(?:wo?rd)?|token|secret|apikey|api[_-]?key|"
    rb"login|admin|root|credential)s?[0-9]{0,3}$|"
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
    # The Windows spelling of the same thing. Django's documentation extension
    # builds `token = "%HOMEPATH%\\" + token[2:]`, which the assembled-literal path
    # folded into a twelve-character value assigned to something called `token` and
    # reported at HIGH. `%VAR%` says the value arrives from the environment exactly
    # as plainly as `$VAR` does, and any build script that touches Windows paths is
    # full of it.
    rb"%[A-Za-z_][A-Za-z0-9_]{0,64}%)"
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
PUBLISHED_CREDENTIALS = frozenset(
    {
        # Azure Storage emulator, account `devstoreaccount1`.
        b"Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
        # MinIO's default root credentials, which its own quickstart prints.
        b"minioadmin",
        # The Stripe documentation's test card and publishable fixtures are covered by
        # PLACEHOLDER's `test` handling; nothing further is needed for them here.
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
    "**/*_test.*",
    "**/*_tests.*",
    "**/test_*.*",
    "**/*.test.*",
    "**/*.spec.*",
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
    # Where a TLS test keeps its generated material, whatever the tree calls it.
    "**/testcerts/**",
    "**/test-certs/**",
    # API mocking and object factories. Mirage, FactoryBot and friends exist to
    # produce plausible-looking data, so a generated password is the point of the
    # file: Vault's `ui/mirage/factories/ldap-credential.js` was reported twice.
    "**/mirage/**",
    "**/factories/**",
    "**/factory/**",
    "**/msw/**",
    "**/__fixtures__/**",
    # Integration-test directories that do not spell it "integration".
    "**/integtest/**",
    "**/integtests/**",
    "**/itest/**",
    "**/functest/**",
    "**/smoketest/**",
    "**/smoke/**",
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
    "**/*.txt",
    "**/*.mdx",
    "**/*.ipynb",
    "**/README*",
    "**/CHANGELOG*",
    "**/CONTRIBUTING*",
    "**/*.example",
    "**/*.sample",
    "**/*.template",
    "**/*.dist",
    # Localisation catalogues. The value beside a key called `password` is the WORD
    # "password" in another language: a Danish translation file was reported for
    # `password = "Adgangskode"`. Every project with a translated login form has one
    # of these for every language it supports, so the count scales with how
    # international the project is.
    "**/locales/**",
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

FIXTURE_CONFIDENCE = Confidence.MEDIUM
"""And the most it may claim about being live.

This one is confidence rather than severity because it is a statement about
what the value is: a PEM private-key header under `tests/fixtures` is
certainly a private key and is very unlikely to be one that protects
anything."""


def is_test_material(path: str) -> bool:
    """Whether a path is where a project keeps things its tests need."""
    return any(PathGlob.matches(path, glob) for glob in TEST_MATERIAL_PATHS)


def is_documentation(path: str) -> bool:
    """Whether a path holds prose written to be read rather than executed."""
    return any(PathGlob.matches(path, glob) for glob in DOCUMENTATION_PATHS)


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
    return any(PathGlob.matches(path, glob) for glob in BUILD_TOOLING_PATHS)


def is_generated_artefact(path: str) -> bool:
    """Whether a path is build output rather than source somebody wrote."""
    return any(PathGlob.matches(path, glob) for glob in GENERATED_ARTEFACT_PATHS)


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
    {"path", "paths", "url", "urls", "uri", "uris", "endpoint", "endpoints", "route", "routes"}
)


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
        [A-Za-z_][\w.]{0,120}:[A-Za-z_][\w.]{0,120}   # module:attribute
      | [A-Za-z_][\w-]{0,60}(?:\.[A-Za-z_][\w-]{0,60}){1,8}  # a dotted name or scope
      | [0-9a-fA-F]{16,128}                          # a hex digest or identifier
      | /?[A-Za-z_.-]{1,60}(?:/[A-Za-z_.-]{1,60}){1,12} # a path, absolute or not
      | (?=[A-Za-z]{8,80}$)(?=[^a-z]{0,80}[a-z])(?=[^A-Z]{0,80}[A-Z])
        [A-Za-z]{8,80}                             # a mixed-case type or name
      | (?![A-Za-z0-9_-]{0,60}(?:[a-z]{12,64}|[A-Z]{12,64}|[0-9]{12,64}))
        _?[A-Za-z][A-Za-z0-9]{0,23}(?:[_-][A-Za-z0-9]{1,23}){1,8} # a separated identifier
      | [a-z][a-z0-9+.-]{1,15}://[^@\s]{1,200}       # a URL carrying no userinfo
      | (?:meth|class|func|ref|attr|mod|data|exc|obj|doc|term|py:[a-z]{1,10})
        :[`~][^\s]{1,110}                           # a Sphinx cross-reference
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
    version = "0.2.1"
    categories = frozenset({Category.MALICIOUS, Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True)

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
                digest = Evidence.hash_bytes(matched)
                if digest in seen:
                    continue
                seen.add(digest)
                findings.append(self._finding(spec, unit, ctx, match.start(), match.end(), matched))

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

            decoded = value.decode("utf-8", errors="replace")
            if Redactor.shannon_entropy(decoded) < MIN_ASSIGNMENT_ENTROPY:
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

            name = match.group(1).decode("utf-8", errors="replace")
            if names_configuration(name):
                continue
            if SecretDetector._is_example_line(unit.content, match.start(1)):
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
                severity=Severity.HIGH,
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
    ) -> Finding:
        content = unit.content
        line = content.line_of(start)
        fixture = is_test_material(content.path)
        documentation = not fixture and is_documentation(content.path)
        ceilinged = fixture or documentation
        severity = min(spec.severity, FIXTURE_CEILING) if ceilinged else spec.severity
        confidence = min(spec.confidence, FIXTURE_CONFIDENCE) if ceilinged else spec.confidence
        caveat = ""
        if fixture:
            caveat = (
                " It sits under a path that holds test material, where a credential "
                "of this shape is usually generated for the test suite, so it is "
                "reported below its usual severity -- but a real key committed here "
                "leaks exactly as far as one committed anywhere else."
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
                f"tree.{caveat}"
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
    "TEST_MATERIAL_PATHS",
    "SecretDetector",
    "fold_concatenations",
    "is_test_material",
]
