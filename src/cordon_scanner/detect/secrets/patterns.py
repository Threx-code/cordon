"""The shapes credentials come in: each provider's token format, the assignment and connection-string
shapes a secret is written in, and the hosts a connection string can name without leaving the
machine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cordon_scanner.foundation.models import (
    Confidence,
    Severity,
)


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
        # The lengths GitHub documents, rather than a floor below them. The body
        # was `[A-Za-z0-9_]{20,}`, and twenty is not a length GitHub issues: a
        # classic token is `ghp_` and exactly 36 base62 characters, and a
        # fine-grained one is `github_pat_`, 22, `_`, and 59.
        #
        # `JamesWoolfenden/pike` generates Terraform fixtures for its IAM policy
        # tool, and one of them sets `token = "ghp_<twenty-five lowercase
        # letters>"`. That is not a token by length or by alphabet, and it was
        # CRITICAL at HIGH confidence because the pattern asked for twenty of
        # anything. A prefix is what makes these patterns worth having; the length
        # is the other half of the format.
        SecretPattern._p(
            r"""(?x)
            \b(?:
                (?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}
              | github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}
            )\b
            """
        ),
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
    # Samples for every one of these live in `tests/unit/judge/test_providers.py` rather
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
      # And the credential word has to BEGIN a word, not end one. The prefix above
      # is free-form, so `pass` matched inside `Bypass`: netty's `.fbprefs` declares
      # `detectorXMLFactoryBypass=XMLFactoryBypass|true`, a FindBugs preference, and
      # it was reported as a credential at HIGH. The closed list is the same device
      # the suffix test below uses, and for the same reason -- a general rule would
      # have to refuse a lowercase run, which is how `dbpassword` is written.
      (?<!by)(?<!com)(?<!sur)(?<!over)(?<!under)(?<!tres)(?<!encom)
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
      # `;`, `<` and `>` excluded for the reason `{` is excluded below: no credential
      # format contains them. base64, hex, JWTs and every provider shape are drawn
      # from alphabets that have none, and a semicolon in a value means a statement
      # or a package name. `apache/dubbo` builds its jakarta sources with an Ant
      # task -- `<replace token="tri.websocket;" value="tri.websocket.jakarta;">` --
      # where `token=` is the attribute that names the search string.
        ["']([^"'\s;<>]{12,120})["']       # 2: quoted
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
      # A backtick for the same reason, and it is what prose looks like:
      # `openapi-generator`'s objc template says "To add or remove api key, use
      # `setApiKey:forApiKeyIdentifier:`" in a doc comment, which parsed as the name
      # `setApiKey` assigned `forApiKeyIdentifier:`.` and reported at HIGH.
      | ([^\s"'#,;(){}\[\]=<>`]{12,120})   # 3: unquoted
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
    [^\s:@/]{1,64} : ([^\s:@/]{6,120}) @
    (
        # An IPv6 literal, which is the one host form that carries colons.
        \[[0-9a-f:.]{2,45}\]
        # Or a dot-separated sequence of letter-digit-hyphen labels, which is
        # every other host there is.
      | [a-z0-9](?:[a-z0-9.\-]{0,120})?
    )
    """
)
r"""A password embedded in a URL's userinfo.

A database URL that carries userinfo -- a user name and a password, separated by
a colon, before the host -- holds a live credential in a form no assignment
pattern sees, and that is the conventional way such URLs are written.

The host is captured as well as the password, because where the URL points
decides whether the value is a credential at all. See `LOCAL_OR_RESERVED_HOST`.

**Matched as a host, not as "everything up to a delimiter."** The host group was
`[^\s@/?\#]{1,120}`, which excludes whitespace and the characters that end the
authority component of a URL -- and not the quote that ends the STRING the URL
is written inside. A URL in source code is nearly always quoted, so the captured
host came back as `my.example.com")`, and `LOCAL_OR_RESERVED_HOST` is anchored at
both ends: every reserved-host exclusion it makes silently failed for any URL
inside a quoted expression. Ruby's own `lib/uri/generic.rb` documents `uri.user=`
with `URI.parse("http://john:S3nsit1ve@my.example.com")` in an RDoc comment, and
that was reported at high severity -- a credential for the domain RFC 2606
reserves so that documentation can do exactly this.

A consequence worth naming: a host written as a template expression -- Docker
Swarm's `@{{ index .Service.Labels ... }}_postgres` -- no longer matches at all,
where before it matched as an opaque run of characters. That is the same
judgement in a different place. A host nothing can resolve is not a host a
credential authenticates to, and the template has to be rendered before there is
anything to point at.

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

MIN_KEY_BODY = 16
"""Characters a prefixed credential carries after its prefix; the shortest real ones carry 20+."""

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


__all__ = [
    "ASSIGNMENT",
    "CONNECTION_STRING",
    "CREDENTIAL_NAME",
    "LOCAL_OR_RESERVED_HOST",
    "MIN_KEY_BODY",
    "PEM_ARMOUR_ONLY",
    "PROVIDER_PATTERNS",
    "ROTATE",
    "SecretPattern",
]
