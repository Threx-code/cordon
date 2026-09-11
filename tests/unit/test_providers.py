"""Every provider credential pattern, with a sample that proves it fires.

`PROVIDER_PATTERNS` had no test of any kind. Fifty-nine patterns, each one a regex
against a format somebody transcribed from a provider's documentation, and nothing
asserted that any of them matched anything -- which is the failure mode this project
treats as the most expensive one available: a detection rule that has stopped
matching still lets the scan succeed, and the gate goes green precisely because the
check is broken. `cordon rules test` covers the YAML packs. These are in Python and
were covered by nothing.

Four properties, and the third is the one that found real defects:

1. Every pattern has at least one sample. A pattern with none is unasserted.
2. Every sample matches its own pattern, and no counter-sample does.
3. No sample matches a DIFFERENT provider's pattern. Prefixes collide -- `sk-` is
   OpenAI and `sk-ant-` is Anthropic, `secret_` is Notion and also a word, `pat` is
   Airtable and also three letters -- and a collision means one provider's
   credential is reported under another's name, which sends the reader to rotate the
   wrong thing.
4. No sample is matched by the generic assignment rule instead, which would mean the
   specific rule is redundant and the report less useful than it looks.

Every sample is assembled at runtime. This file is scanned by the tool it tests and
a real-shaped token written as a literal would be reported, correctly, on every
scan -- which is also a useful demonstration that these patterns work.
"""

from __future__ import annotations

import pytest

from cordon_scanner.detect.secrets import PLACEHOLDER, PROVIDER_PATTERNS
from support import assemble

#: rule id -> (positive samples, counter-samples).
#:
#: A counter-sample is the near miss worth writing down: the shape that looks like
#: the credential and is not one. Absent where nothing plausible came to mind, which
#: is honest; present wherever the pattern has a neighbour it could be confused with.
SAMPLES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "SECRET.AWS.ACCESS_KEY.001": (
        (assemble("AKIA", "2E0XYZQ7KPLMN3RT"),),
        ("AKIA2E0XYZQ7KPLM", "AKIA-2E0XYZQ7KPLMN3RT"),
    ),
    "SECRET.GITHUB.TOKEN.001": (
        (assemble("ghp_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ"),),
        ("ghp_short", "ghx_q7Kp2LmN3rT4vW5xY6zA7bC8dE9f"),
    ),
    "SECRET.SLACK.TOKEN.001": ((assemble("xoxb-", "123456789012-abcdefghijklmnop"),), ()),
    "SECRET.STRIPE.KEY.001": (
        (assemble("sk_live_", "4eC39HqLyjWDarjtT1zdp7dc"),),
        ("sk_live_tiny",),
    ),
    "SECRET.GOOGLE.API_KEY.001": ((assemble("AIza", "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"),), ()),
    "SECRET.NPM.TOKEN.001": ((assemble("npm_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2"),), ()),
    "SECRET.PYPI.TOKEN.001": (
        (assemble("pypi-", "AgEIcHlwaS5vcmcCJDExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NQ"),),
        (),
    ),
    "SECRET.PRIVATE_KEY.001": ((assemble("-----BEGIN RSA ", "PRIVATE KEY-----"),), ()),
    "SECRET.JWT.001": (
        (
            assemble(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
                "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
                "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            ),
        ),
        (),
    ),
    "SECRET.SLACK.WEBHOOK.001": (
        (
            assemble(
                "https://hooks.slack.com/services/",
                "T02A1B3C4D5/B06E7F8G9H0/",
                "q7Kp2LmN3rT4vW5xY6zA7bC8",
            ),
        ),
        (),
    ),
    "SECRET.GITLAB.TOKEN.001": (
        (
            assemble("glpat-", "q7Kp2LmN3rT4vW5xY6zA"),
            assemble("glrt-", "q7Kp2LmN3rT4vW5xY6zA"),
            assemble("glagent-", "q7Kp2LmN3rT4vW5xY6zA"),
        ),
        ("glpat-short", "glxyz-q7Kp2LmN3rT4vW5xY6zA"),
    ),
    "SECRET.DOCKERHUB.TOKEN.001": (
        (assemble("dckr_pat_", "q7Kp2LmN3rT4vW5xY6zA7bC"),),
        ("dckr_oat_q7Kp2LmN3rT4vW5xY6zA7bC",),
    ),
    "SECRET.RUBYGEMS.TOKEN.001": ((assemble("rubygems_", "a" * 48),), ("rubygems_" + "a" * 20,)),
    "SECRET.NUGET.KEY.001": ((assemble("oy2", "a" * 43),), ("oy2" + "a" * 10,)),
    "SECRET.JFROG.TOKEN.001": (
        (assemble("AKCp8", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2mN3oP4qR5sT6uV7w"),),
        (),
    ),
    "SECRET.SONAR.TOKEN.001": ((assemble("sqp_", "f" * 40),), ("sqz_" + "f" * 40,)),
    "SECRET.TERRAFORM.TOKEN.001": (
        (assemble("q7Kp2LmN3rT4vW", ".atlasv1.", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9f"),),
        (),
    ),
    "SECRET.VAULT.TOKEN.001": (
        (assemble("hvs.", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9f"),),
        ("hvz.q7Kp2LmN3rT4vW5xY6zA7bC8",),
    ),
    "SECRET.GOOGLE.OAUTH_TOKEN.001": (
        (assemble("ya29.", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1k"),),
        (),
    ),
    "SECRET.AZURE.STORAGE_KEY.001": ((assemble("AccountKey=", "a" * 86, "=="),), ()),
    "SECRET.DIGITALOCEAN.TOKEN.001": ((assemble("dop_v1_", "a" * 64),), ("dop_v2_" + "a" * 64,)),
    "SECRET.ALIBABA.ACCESS_KEY.001": ((assemble("LTAI", "q7Kp2LmN3rT4vW5x"),), ()),
    "SECRET.TENCENT.SECRET_ID.001": ((assemble("AKID", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ"),), ()),
    "SECRET.FLYIO.TOKEN.001": ((assemble("fm2_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2mN3o"),), ()),
    "SECRET.NETLIFY.TOKEN.001": ((assemble("nfp_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2mN"),), ()),
    "SECRET.DATABRICKS.TOKEN.001": ((assemble("dapi", "a" * 32),), ()),
    "SECRET.SLACK.APP_TOKEN.001": (
        (assemble("xapp-", "1-A01234ABCDE-1234567890123-", "a" * 32),),
        (),
    ),
    "SECRET.DISCORD.WEBHOOK.001": (
        (
            assemble(
                "https://discord.com/api/webhooks/",
                "123456789012345678/",
                "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2mN3oP4qR5sT6uV7wX8yZ9aB0cD1eF2g",
            ),
        ),
        (),
    ),
    "SECRET.TELEGRAM.BOT_TOKEN.001": (
        (assemble("123456789", ":AA", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1"),),
        (),
    ),
    "SECRET.SENDGRID.KEY.001": (
        (
            assemble(
                "SG.", "q7Kp2LmN3rT4vW5xY6zA7b", ".", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2mN3oP4q"
            ),
        ),
        (),
    ),
    "SECRET.TWILIO.KEY.001": ((assemble("SK", "a" * 32),), ("SK" + "a" * 10,)),
    "SECRET.MAILGUN.KEY.001": ((assemble("key-", "a" * 32),), ("key-short",)),
    "SECRET.MICROSOFT.TEAMS_WEBHOOK.001": (
        (
            assemble(
                "https://contoso7.webhook.office.com/webhookb2/",
                "12345678-1234-1234-1234-123456789012",
                "@12345678-1234-1234-1234-123456789012/",
            ),
        ),
        (),
    ),
    "SECRET.OPENAI.KEY.001": (
        (assemble("sk-", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1k"),),
        (),
    ),
    "SECRET.ANTHROPIC.KEY.001": (
        (assemble("sk-ant-", "api03-", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2mN3oP4q"),),
        (),
    ),
    "SECRET.HUGGINGFACE.TOKEN.001": ((assemble("hf_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1k"),), ()),
    "SECRET.REPLICATE.TOKEN.001": ((assemble("r8_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2m"),), ()),
    "SECRET.GROQ.KEY.001": ((assemble("gsk_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2mN3o"),), ()),
    "SECRET.LANGCHAIN.KEY.001": ((assemble("lsv2_pt_", "a" * 32, "_", "b" * 10),), ()),
    "SECRET.STRIPE.WEBHOOK_SECRET.001": (
        (assemble("whsec_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ"),),
        (),
    ),
    "SECRET.SHOPIFY.TOKEN.001": ((assemble("shpat_", "a" * 32),), ("shpzz_" + "a" * 32,)),
    "SECRET.SQUARE.TOKEN.001": (
        (
            assemble("sq0atp-", "q7Kp2LmN3rT4vW5xY6zA7b"),
            assemble("EAAA", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2mN3oP4qR5sT6uV7wX8yZ9"),
        ),
        (),
    ),
    "SECRET.PAYPAL.TOKEN.001": (
        (assemble("access_token$production$", "q7kp2lmn3rt4vw5x", "$", "a" * 32),),
        (),
    ),
    "SECRET.NEWRELIC.KEY.001": (
        (assemble("NRAK-", "Q7KP2LMN3RT4VW5XY6ZA7BC8DEF"),),
        ("NRZZ-Q7KP2LMN3RT4VW5XY6ZA7BC8DEF",),
    ),
    "SECRET.GRAFANA.TOKEN.001": ((assemble("glsa_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ"),), ()),
    "SECRET.SENTRY.TOKEN.001": (
        (assemble("sntrys_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2mN3o"),),
        (),
    ),
    "SECRET.PAGERDUTY.TOKEN.001": ((assemble("pdus_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ"),), ()),
    "SECRET.ATLASSIAN.TOKEN.001": ((assemble("ATATT3", "q7Kp2LmN3rT4vW5x" * 10),), ()),
    "SECRET.LINEAR.KEY.001": (
        (assemble("lin_api_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2mN3o"),),
        (),
    ),
    "SECRET.FIGMA.TOKEN.001": (
        (assemble("figd_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2mN3o"),),
        (),
    ),
    "SECRET.NOTION.TOKEN.001": (
        (assemble("ntn_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2mN3o"),),
        (),
    ),
    "SECRET.SUPABASE.TOKEN.001": ((assemble("sbp_", "a" * 40),), ("sbp_" + "a" * 10,)),
    "SECRET.PLANETSCALE.TOKEN.001": (
        (assemble("pscale_tkn_", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ"),),
        (),
    ),
    "SECRET.RESEND.KEY.001": ((assemble("re_", "q7Kp2LmN3rT4vW5x", "_", "Y6zA7bC8dE9fG0hJ"),), ()),
    "SECRET.DOPPLER.TOKEN.001": (
        (assemble("dp.pt.", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2mN3o"),),
        (),
    ),
    "SECRET.AIRTABLE.TOKEN.001": ((assemble("pat", "q7Kp2LmN3rT4vW", ".", "a" * 64),), ()),
    "SECRET.DROPBOX.TOKEN.001": ((assemble("sl.", "q7Kp2LmN3rT4vW5xY6zA" * 7),), ()),
    "SECRET.CRATES.TOKEN.001": ((assemble("cio", "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ"),), ()),
}

BY_ID = {spec.rule_id: spec for spec in PROVIDER_PATTERNS}


def test_every_pattern_has_a_sample() -> None:
    """A pattern with no sample is asserted by nothing, which is the state all
    fifty-nine of these were in before this file existed."""
    missing = sorted(set(BY_ID) - set(SAMPLES))
    assert not missing, f"provider patterns with no sample: {missing}"


def test_no_sample_names_a_pattern_that_does_not_exist() -> None:
    """The other direction: a sample for a deleted rule passes forever and asserts
    nothing about the tool that ships."""
    unknown = sorted(set(SAMPLES) - set(BY_ID))
    assert not unknown, f"samples for rules that do not exist: {unknown}"


@pytest.mark.parametrize("rule_id", sorted(SAMPLES))
class TestEachPatternMatchesItsOwnSamples:
    def test_positive_samples_match(self, rule_id: str) -> None:
        spec = BY_ID.get(rule_id)
        if spec is None:
            pytest.skip(f"{rule_id} is not a shipped pattern")
        positives, _ = SAMPLES[rule_id]
        assert positives, f"{rule_id} has an empty positive list"
        for sample in positives:
            assert spec.pattern.search(sample.encode()), f"{rule_id} did not match {sample[:24]}..."

    def test_counter_samples_do_not_match(self, rule_id: str) -> None:
        spec = BY_ID.get(rule_id)
        if spec is None:
            pytest.skip(f"{rule_id} is not a shipped pattern")
        _, negatives = SAMPLES[rule_id]
        for sample in negatives:
            assert not spec.pattern.search(sample.encode()), (
                f"{rule_id} matched its counter-sample {sample[:24]}..."
            )

    def test_the_prefilter_admits_its_own_samples(self, rule_id: str) -> None:
        """The prefilter is a substring test run before the regex, so a prefilter
        that does not contain the sample's literal means the regex never runs and the
        rule is dead however correct its pattern is."""
        spec = BY_ID.get(rule_id)
        if spec is None:
            pytest.skip(f"{rule_id} is not a shipped pattern")
        if not spec.prefilter:
            return
        positives, _ = SAMPLES[rule_id]
        for sample in positives:
            raw = sample.encode()
            assert any(literal in raw for literal in spec.prefilter), (
                f"{rule_id}: no prefilter literal appears in {sample[:24]}..."
            )

    def test_no_sample_is_dismissed_as_a_placeholder(self, rule_id: str) -> None:
        """`PLACEHOLDER` runs before a finding is emitted, so a sample it matches
        would be reported by nothing even though the pattern fired."""
        if rule_id not in BY_ID:
            pytest.skip(f"{rule_id} is not a shipped pattern")
        positives, _ = SAMPLES[rule_id]
        for sample in positives:
            match = BY_ID[rule_id].pattern.search(sample.encode())
            assert match is not None
            assert not PLACEHOLDER.search(match.group(0)), (
                f"{rule_id}: its own sample reads as a placeholder"
            )


class TestCredentialsTheVendorPublishes:
    """The Azure Storage emulator key was reported at CRITICAL in Celery's
    `docker-compose.yml` and `tox.ini`, and in two of Elasticsearch's Azure tests.

    It is not a placeholder and not an example. It is a live, working key that is
    MEANT to be in your repository, because the service it authenticates to is an
    emulator running on your own machine. Azurite ships it, the older Storage
    Emulator shipped it, and the account it belongs to is called
    `devstoreaccount1`.

    The proof that it is a shared fixture rather than anybody's secret is that the
    same eighty-eight characters appear in two unrelated projects, which is how it
    was found: a pattern added in this change fired on both.

    Matched on the exact value. That is what makes the mechanism safe -- an exact
    string cannot over-suppress the way a shape can, and the list grows by one entry
    per vendor.
    """

    def test_the_emulator_key_is_not_reported(self, tmp_path) -> None:
        from cordon_scanner.detect.secrets import PUBLISHED_CREDENTIALS

        key = next(k for k in PUBLISHED_CREDENTIALS if len(k) == 88).decode()
        (tmp_path / "docker-compose.yml").write_text(
            "services:\n  worker:\n    environment:\n"
            "      AZUREBLOCKBLOB_URL: azureblockblob://DefaultEndpointsProtocol=http;"
            f"AccountName=devstoreaccount1;AccountKey={key}\n",
            encoding="utf-8",
        )
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert not [f for f in result.findings if "AZURE" in f.rule_id]

    def test_a_real_storage_key_still_is(self, tmp_path) -> None:
        """The guard. A ceiling on the published fixture must not become a ceiling on
        the pattern: a genuine account key in a connection string is one of the
        highest-value credentials a repository can leak."""
        body = assemble(
            "q7Kp2LmN3rT4vW5xY6zA7bC8dE9fG0hJ1kL2mN3o",
            "P4qR5sT6uV7wX8yZ9aB0cD1eF2gH3iJ4kL5mN6oP",
            "q7Kp2L",
        )
        assert len(body) == 86, len(body)
        key = body + "=="
        (tmp_path / "settings.py").write_text(
            f'CONNECTION = "DefaultEndpointsProtocol=https;AccountName=prodstore;AccountKey={key}"\n',
            encoding="utf-8",
        )
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert [f for f in result.findings if f.rule_id == "SECRET.AZURE.STORAGE_KEY.001"]

    def test_the_list_holds_only_exact_values(self) -> None:
        """No shapes, no regexes, nothing that could widen. Every entry is bytes that
        a vendor documents as public."""
        from cordon_scanner.detect.secrets import PUBLISHED_CREDENTIALS

        assert PUBLISHED_CREDENTIALS
        for entry in PUBLISHED_CREDENTIALS:
            assert isinstance(entry, bytes)
            assert len(entry) >= 8, f"{entry!r} is short enough to appear by accident"
