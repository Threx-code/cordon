"""Configuration layering, strict validation, and ceiling enforcement.

These are security tests, not parser tests. The configuration layer is what
stops a scanned repository from disabling its own inspection, so each case here
corresponds to a way an attacker with commit access would try to blind the tool.
"""

from __future__ import annotations

import pytest

from cordon.core.config import (
    MIN_JUSTIFICATION_CHARS,
    Config,
    OrgConstraints,
    Policy,
    _load_yaml_subset,
    load_org_policy,
)
from cordon.core.errors import ConfigError, PolicyViolationError
from cordon.core.limits import DEFAULT_LIMITS
from cordon.core.models import Category, Confidence, Severity


def parse(text: str) -> Config:
    return Config.from_dict(_load_yaml_subset(text, source="test.yaml"), source="test.yaml")


# ---------------------------------------------------------------------------
# YAML subset parser
# ---------------------------------------------------------------------------


class TestYamlSubset:
    def test_nested_mappings_and_sequences(self) -> None:
        data = _load_yaml_subset(
            """
            scan:
              severity_threshold: medium
              exclude:
                - node_modules/
                - "vendor/"
            """,
            source="t",
        )
        assert data["scan"]["severity_threshold"] == "medium"
        assert data["scan"]["exclude"] == ["node_modules/", "vendor/"]

    def test_scalar_types(self) -> None:
        data = _load_yaml_subset(
            "a: 1\nb: 2.5\nc: true\nd: false\ne: null\nf: text\ng: 'quoted'\n", source="t"
        )
        assert data == {
            "a": 1,
            "b": 2.5,
            "c": True,
            "d": False,
            "e": None,
            "f": "text",
            "g": "quoted",
        }

    def test_flow_collections(self) -> None:
        data = _load_yaml_subset("a: [1, 2, 3]\nb: {x: 1, y: two}\n", source="t")
        assert data["a"] == [1, 2, 3]
        assert data["b"] == {"x": 1, "y": "two"}

    def test_folded_block_scalar_joins_lines_and_clips(self) -> None:
        data = _load_yaml_subset(
            "msg: >\n  first line\n  second line\nnext: 1\n", source="t"
        )
        assert data["msg"] == "first line second line\n"
        assert data["next"] == 1

    def test_literal_block_scalar_keeps_line_breaks(self) -> None:
        data = _load_yaml_subset("msg: |\n  one\n  two\n", source="t")
        assert data["msg"] == "one\ntwo\n"

    def test_chomping_indicator_strips_trailing_newline(self) -> None:
        """`|` and `|-` are not equivalent, and collapsing them makes a value
        silently differ from what the author wrote."""
        assert _load_yaml_subset("msg: |-\n  one\n  two\n", source="t")["msg"] == "one\ntwo"
        assert _load_yaml_subset("msg: >-\n  one\n  two\n", source="t")["msg"] == "one two"

    def test_comments_ignored(self) -> None:
        data = _load_yaml_subset("# leading\na: 1  # trailing\n", source="t")
        assert data == {"a": 1}

    def test_sequence_of_mappings(self) -> None:
        data = _load_yaml_subset(
            """
            items:
              - name: one
                value: 1
              - name: two
                value: 2
            """,
            source="t",
        )
        assert data["items"] == [{"name": "one", "value": 1}, {"name": "two", "value": 2}]

    @pytest.mark.parametrize(
        ("text", "fragment"),
        [
            ("a: &anchor\n", "anchors"),
            ("a: *alias\n", "anchors"),
            ("a: !!python/object\n", "anchors"),
            ("a:\n\tb: 1\n", "tab"),
        ],
    )
    def test_dangerous_yaml_constructs_are_refused(self, text: str, fragment: str) -> None:
        """Anchors, aliases and tags are hazards in untrusted YAML.

        Not implementing them is the safest way to not be vulnerable to them,
        and a clear error beats a silent misparse of something the author
        believed was in effect.
        """
        with pytest.raises(ConfigError, match=fragment):
            _load_yaml_subset(text, source="t")


# ---------------------------------------------------------------------------
# Strict validation
# ---------------------------------------------------------------------------


class TestStrictValidation:
    def test_unknown_top_level_key_is_an_error(self) -> None:
        with pytest.raises(ConfigError, match="unknown key"):
            parse("scanners:\n  malware: true\n")

    def test_misspelled_key_is_an_error_not_a_default(self) -> None:
        """A silently ignored typo means the operator believes a threshold is
        set when the default is in force. That is the whole failure mode."""
        with pytest.raises(ConfigError, match="sevrity_threshold"):
            parse("scan:\n  sevrity_threshold: high\n")

    def test_misspelled_key_suggests_the_real_one(self) -> None:
        with pytest.raises(ConfigError) as exc:
            parse("scan:\n  exclud:\n    - a/\n")
        assert exc.value.hint and "exclude" in exc.value.hint

    def test_string_where_list_expected(self) -> None:
        with pytest.raises(ConfigError, match="must be a list"):
            parse("scan:\n  exclude: node_modules/\n")

    def test_unknown_severity_lists_valid_values(self) -> None:
        with pytest.raises(ConfigError, match="info, low, medium, high, critical"):
            parse("scan:\n  severity_threshold: extreme\n")

    def test_unsupported_version_is_refused(self) -> None:
        with pytest.raises(ConfigError, match="version"):
            parse("version: 99\n")

    def test_absent_config_is_not_an_error(self, tmp_path) -> None:
        """A tool that refuses to run without configuration is a tool most
        repositories never adopt."""
        assert Config.discover(tmp_path) == Config.default()


# ---------------------------------------------------------------------------
# Suppressions
# ---------------------------------------------------------------------------


VALID_JUSTIFICATION = "x" * MIN_JUSTIFICATION_CHARS


class TestSuppressionValidation:
    def test_valid_suppression_parses(self) -> None:
        cfg = parse(
            "suppressions:\n"
            "  - rule: SUSPECT.SPAWN.001\n"
            "    path: tools/release.py\n"
            f"    justification: {VALID_JUSTIFICATION}\n"
            "    expires: 2027-01-01\n"
        )
        assert len(cfg.suppressions) == 1
        assert cfg.suppressions[0].rule == "SUSPECT.SPAWN.001"

    @pytest.mark.parametrize("missing", ["rule", "path", "justification", "expires"])
    def test_every_field_is_required(self, missing: str) -> None:
        fields = {
            "rule": "X.001",
            "path": "a.py",
            "justification": VALID_JUSTIFICATION,
            "expires": "2027-01-01",
        }
        del fields[missing]
        text = "suppressions:\n  - " + "\n    ".join(f"{k}: {v}" for k, v in fields.items()) + "\n"
        with pytest.raises(ConfigError, match=missing):
            parse(text)

    def test_path_only_suppression_is_refused(self) -> None:
        """A path-only suppression is a directory hole: it exempts that location
        from every rule, and vendored or generated directories are exactly where
        a payload prefers to sit."""
        with pytest.raises(ConfigError, match="rule"):
            parse(
                "suppressions:\n"
                "  - path: vendor/\n"
                f"    justification: {VALID_JUSTIFICATION}\n"
                "    expires: 2027-01-01\n"
            )

    def test_thin_justification_is_refused(self) -> None:
        """'false positive' records that somebody decided, not what or why."""
        with pytest.raises(ConfigError, match="at least"):
            parse(
                "suppressions:\n"
                "  - rule: X.001\n"
                "    path: a.py\n"
                "    justification: false positive\n"
                "    expires: 2027-01-01\n"
            )

    def test_malformed_date_is_refused(self) -> None:
        with pytest.raises(ConfigError, match="ISO date"):
            parse(
                "suppressions:\n"
                "  - rule: X.001\n"
                "    path: a.py\n"
                f"    justification: {VALID_JUSTIFICATION}\n"
                "    expires: next year\n"
            )

    def test_expired_suppression_stops_suppressing(self) -> None:
        cfg = parse(
            "suppressions:\n"
            "  - rule: X.001\n"
            "    path: a.py\n"
            f"    justification: {VALID_JUSTIFICATION}\n"
            "    expires: 2020-01-01\n"
        )
        assert cfg.active_suppressions() == ()
        assert len(cfg.expired_suppressions()) == 1


# ---------------------------------------------------------------------------
# Failure policy
# ---------------------------------------------------------------------------


class TestPolicy:
    def test_fail_on_severity_and_category(self) -> None:
        cfg = parse(
            "policy:\n"
            "  fail_on:\n"
            "    - critical\n"
            "    - high\n"
            "    - category: malicious\n"
        )
        assert cfg.policy.fail_on_severity is Severity.HIGH
        assert Category.MALICIOUS in cfg.policy.fail_on_categories

    def test_unknown_category_lists_valid_values(self) -> None:
        with pytest.raises(ConfigError, match="malicious"):
            parse("policy:\n  fail_on:\n    - category: badgers\n")

    def test_default_fails_on_high_and_malicious(self) -> None:
        policy = Policy.default()
        assert policy.fail_on_severity is Severity.HIGH
        assert policy.fail_on_categories == frozenset({Category.MALICIOUS})

    def test_low_confidence_does_not_gate_by_default(self) -> None:
        """Without this floor the noisiest rule in the pack sets the gate."""
        assert Policy.default().min_confidence_to_fail is Confidence.MEDIUM


# ---------------------------------------------------------------------------
# The organisation ceiling
# ---------------------------------------------------------------------------


ORG_POLICY = """
version: 1
name: test-baseline

enforce:
  detectors_required: [capability, manifest, lockfile]
  min_severity_threshold: medium
  allow_network: false
  allow_plugins: false
  allow_limit_increase: false

suppressions:
  max_duration_days: 90
  require_justification: true
  require_approver: true
  forbid_categories: [malicious]
  forbid_path_only: true

scan:
  severity_threshold: medium
  limits:
    max_file_bytes: 5242880
"""


@pytest.fixture
def org(tmp_path):
    path = tmp_path / "org.yaml"
    path.write_text(ORG_POLICY)
    return load_org_policy(path)


class TestOrgCeiling:
    """Each case is a way a hostile repository config would blind the scanner."""

    @pytest.mark.parametrize(
        ("label", "text", "fragment"),
        [
            (
                "disable a required detector",
                "scan:\n  detectors:\n    capability: false\n",
                "required by organisation policy",
            ),
            (
                "raise the reporting threshold",
                "scan:\n  severity_threshold: critical\n",
                "less strict",
            ),
            (
                "enable network access",
                "scan:\n  offline: false\n",
                "network access",
            ),
            (
                "enable third-party plugins",
                "scan:\n  allow_plugins: true\n",
                "plugins",
            ),
            (
                "raise a resource limit",
                "scan:\n  limits:\n    max_file_bytes: 999999999\n",
                "exceeds the organisation ceiling",
            ),
        ],
    )
    def test_weakening_is_blocked(self, org, label: str, text: str, fragment: str) -> None:
        org_config, constraints = org
        with pytest.raises(PolicyViolationError, match=fragment):
            parse(text).clamped_by(org_config, constraints)

    def test_overlong_suppression_is_blocked(self, org) -> None:
        org_config, constraints = org
        text = (
            "suppressions:\n"
            "  - rule: X.001\n"
            "    path: a.py\n"
            "    approved_by: me\n"
            f"    justification: {VALID_JUSTIFICATION}\n"
            "    expires: 2036-01-01\n"
        )
        with pytest.raises(PolicyViolationError, match="exceeding the maximum"):
            parse(text).clamped_by(org_config, constraints)

    def test_suppression_without_approver_is_blocked(self, org) -> None:
        org_config, constraints = org
        text = (
            "suppressions:\n"
            "  - rule: X.001\n"
            "    path: a.py\n"
            f"    justification: {VALID_JUSTIFICATION}\n"
            "    expires: 2026-10-01\n"
        )
        with pytest.raises(PolicyViolationError, match="approver"):
            parse(text).clamped_by(org_config, constraints)

    def test_conflict_names_the_specific_setting(self, org) -> None:
        """Silent clamping leaves the owner believing a setting is in force when
        it is not, and then nothing anywhere signals that the layers disagree."""
        org_config, constraints = org
        with pytest.raises(PolicyViolationError) as exc:
            parse("scan:\n  offline: false\n").clamped_by(org_config, constraints)
        assert "network access" in str(exc.value)
        assert exc.value.hint and "ceiling" in exc.value.hint

    # -- legitimate use must keep working -------------------------------

    def test_empty_config_is_accepted_and_clamped(self, org) -> None:
        """An inherited default is not an assertion the author made, so it is
        clamped silently rather than raised as a conflict. Getting this wrong
        blocks every well-behaved repository."""
        org_config, constraints = org
        merged = parse("version: 1\n").clamped_by(org_config, constraints)
        assert merged.limits.max_file_bytes == 5242880
        assert merged.offline is True

    def test_repository_may_be_stricter(self, org) -> None:
        org_config, constraints = org
        merged = parse("scan:\n  severity_threshold: low\n").clamped_by(org_config, constraints)
        assert merged.severity_threshold is Severity.LOW

    def test_repository_may_lower_a_limit(self, org) -> None:
        org_config, constraints = org
        merged = parse("scan:\n  limits:\n    max_file_bytes: 1024\n").clamped_by(
            org_config, constraints
        )
        assert merged.limits.max_file_bytes == 1024

    def test_repository_may_exclude_paths(self, org) -> None:
        org_config, constraints = org
        merged = parse("scan:\n  exclude:\n    - gen/\n").clamped_by(org_config, constraints)
        assert "gen/" in merged.exclude

    def test_valid_approved_suppression_is_accepted(self, org) -> None:
        org_config, constraints = org
        text = (
            "suppressions:\n"
            "  - rule: X.001\n"
            "    path: a.py\n"
            "    approved_by: security-team\n"
            f"    justification: {VALID_JUSTIFICATION}\n"
            "    expires: 2026-10-01\n"
        )
        merged = parse(text).clamped_by(org_config, constraints)
        assert len(merged.suppressions) == 1


class TestDetectorDefaults:
    def test_detectors_are_opt_out_not_opt_in(self) -> None:
        """A detector absent from the config runs. The alternative means a new
        detector ships disabled everywhere and protects nobody until every
        repository is edited, which in practice is never."""
        cfg = parse("scan:\n  detectors:\n    secrets: false\n")
        assert cfg.detector_enabled("secrets") is False
        assert cfg.detector_enabled("capability") is True
        assert cfg.detector_enabled("a-detector-invented-tomorrow") is True

    def test_no_policy_still_forbids_suppressing_malware(self) -> None:
        assert Category.MALICIOUS in OrgConstraints.permissive().forbid_suppressing


class TestFingerprint:
    def test_is_stable_across_equal_configs(self) -> None:
        assert parse("scan:\n  severity_threshold: high\n").fingerprint() == parse(
            "scan:\n  severity_threshold: high\n"
        ).fingerprint()

    def test_changes_when_detection_changes(self) -> None:
        """Any change that could alter a finding must invalidate the cache. A
        stale cached 'clean' is a false negative, which is the failure that
        matters."""
        base = Config.default().fingerprint()
        assert parse("scan:\n  severity_threshold: high\n").fingerprint() != base
        assert parse("scan:\n  exclude:\n    - a/\n").fingerprint() != base
        assert parse("scan:\n  detectors:\n    secrets: false\n").fingerprint() != base
        assert parse("scan:\n  limits:\n    max_file_bytes: 42\n").fingerprint() != base

    def test_unchanged_by_presentation_only_settings(self) -> None:
        """Evidence mode cannot change whether a finding exists, so it must not
        invalidate a cache entry."""
        assert parse("evidence: none\n").fingerprint() == Config.default().fingerprint()


class TestLimits:
    def test_stricter_of_takes_the_minimum(self) -> None:
        a = DEFAULT_LIMITS.merged(max_file_bytes=100, max_files=999)
        b = DEFAULT_LIMITS.merged(max_file_bytes=200, max_files=10)
        merged = a.stricter_of(b)
        assert merged.max_file_bytes == 100
        assert merged.max_files == 10

    def test_unknown_limit_key_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unknown limit"):
            DEFAULT_LIMITS.from_dict({"max_file_size": 1})

    def test_auto_workers_survives_the_merge(self) -> None:
        """0 means automatic, not unlimited, so a naive minimum would silently
        disable parallelism."""
        a = DEFAULT_LIMITS.merged(max_workers=0)
        b = DEFAULT_LIMITS.merged(max_workers=4)
        assert a.stricter_of(b).max_workers == 4
