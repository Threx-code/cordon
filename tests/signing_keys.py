"""Generate docs/12-SIGNING-KEYS.md from the keys pinned in this build.

    python tests/signing_keys.py > docs/12-SIGNING-KEYS.md

Generated, never hand-written: a fingerprint copied by hand is one typo from naming a key nobody
holds, and a page that says a key is published when the build pins none is the overclaim this
project's documents exist to avoid. `tests/unit/test_signing_keys.py` fails when the page and the
pinned files disagree.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

REPOSITORY = "Threx-code/cordon"
WORKFLOW = f"https://github.com/{REPOSITORY}/.github/workflows/release.yml"
ISSUER = "https://token.actions.githubusercontent.com"


class SigningKeysPage:
    """The page, as lines."""

    @staticmethod
    def render() -> str:
        from cordon_scanner.intel.dbsync import AdvisoryBundle
        from cordon_scanner.intel.feed import Feed, FeedRoles

        lines = [
            "# Signing keys",
            "",
            "Every key that signs something a Cordon client trusts, and how to check it. Generated from the",
            "keys pinned in this build by `python tests/signing_keys.py`; a test fails if this page and the",
            "pinned files disagree.",
            "",
            "## Release artefacts: Sigstore, no long-lived key",
            "",
            "The wheel, the sdist and the container image are signed keyless by the release workflow. There",
            "is no fingerprint to publish: what you verify is the identity that signed, which only that",
            "workflow in this repository can present.",
            "",
            "```bash",
            "# the container image",
            "cosign verify ghcr.io/threx-code/cordon@sha256:<digest> \\",
            f"  --certificate-identity-regexp '^{WORKFLOW}@refs/tags/v' \\",
            f"  --certificate-oidc-issuer {ISSUER}",
            "",
            "# the wheel and sdist (build provenance)",
            f"gh attestation verify cordon_scanner-<version>-py3-none-any.whl --repo {REPOSITORY}",
            "```",
            "",
            "## Intel feed root",
            "",
        ]
        root = Feed.pinned_root()
        if root is None:
            lines += [
                "**Not pinned in this build.** The feed root is created at the key ceremony",
                "(`scripts/key_ceremony.py`) and committed as `src/cordon_scanner/intel/data/feed-root.json`.",
                "Until then the feed is off: a scan makes no request and uses the installed advisory database.",
            ]
        else:
            signed = root["signed"]
            lines += [
                f"Root version {signed['version']}, expires {signed['expires']}. A key id is the SHA-256 of the",
                "key's canonical JSON (`FeedRoles.key_id`).",
                "",
                "| Role | Threshold | Key id |",
                "|---|---|---|",
            ]
            for role, spec in sorted(signed["roles"].items()):
                for keyid in spec["keyids"]:
                    lines.append(
                        f"| {role} | {spec['threshold']} of {len(spec['keyids'])} | `{keyid}` |"
                    )
        lines += ["", "## Advisory database bundle", ""]
        public = AdvisoryBundle.pinned_key_hex()
        if not public:
            lines += [
                "**Not pinned in this build.** Created at the key ceremony and committed as",
                "`src/cordon_scanner/intel/data/advisory-signing-key.json`. Until then",
                "`advisories sync --bundle` refuses to install a downloaded bundle; `advisories sync`",
                "builds the database locally instead.",
            ]
        else:
            key = {"keytype": "ed25519", "public": public}
            lines += [
                "| Key | Key id | Public key |",
                "|---|---|---|",
                f"| advisories | `{FeedRoles.key_id(key)}` | `{public}` |",
            ]
        return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.stdout.write(SigningKeysPage.render())
