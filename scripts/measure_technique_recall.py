"""Detection rate by attack technique.

Reproduces the technique rows of the README's detection table. The corpus
directories carry the ground truth: each is a named technique, and its
`expected.yaml` states what has to be found.

    python3 scripts/measure_technique_recall.py
"""

import json
import pathlib
import subprocess
import sys
import tempfile

TECHNIQUE = {
    "Install-hook attacks": [
        "exfil-python-install-hook",
        "npm-postinstall-local",
        "install-beacon-reconnaissance",
        "install-command-decrypt-exec",
        "cryptominer-install",
    ],
    "Credential exfiltration": [
        "browser-credential-theft",
        "credential-theft-js",
        "exfil-discord-webhook",
        "exfil-dns-tunnel",
        "exfil-via-helper-module",
        "gitlab-secret-exfil",
        "ci-secret-exfil",
        "gradle-exfil",
        "secret-split-literal",
    ],
    "Obfuscated payloads": [
        "obfuscated-loader",
        "xor-decode-loader",
        "decode-chain-multistage",
        "anti-analysis-gated",
        "trojan-source",
        "polyglot-png",
        "encoded-powershell-dropper",
    ],
    "Download-and-execute payloads": [
        "dropper-decode-fetch",
        "dropper-shell-python",
        "decode-exec-js",
        "ansible-fetch-exec",
        "make-fetch-exec",
        "msbuild-fetch-exec",
        "cmake-fetch-unverified",
        "container-fetch-exec",
        "embedded-shell-node",
        "embedded-shell-python",
        "binary-in-scripts",
    ],
    "Persistence mechanisms": ["persistence-js"],
    "Typosquatting": ["typosquat-no-lockfile"],
    "Supply-chain integrity": [
        "compromised-npm-package",
        "lockfile-foreign-source",
        "sbom-drift",
        "submodule-http",
    ],
    "CI/CD pipeline attacks": ["ci-expression-injection", "ci-pr-target-checkout"],
    "Infrastructure misconfiguration": [
        "iac-public-ingress",
        "cfn-iam-wildcard",
        "k8s-rbac-wildcard",
        "k8s-sys-admin",
    ],
}

root = pathlib.Path(__file__).resolve().parent.parent / "corpus" / "malicious"
rows = {}
for label, samples in TECHNIQUE.items():
    hit = total = 0
    missed = []
    for name in samples:
        d = root / name
        if not d.is_dir():
            continue
        total += 1
        out = pathlib.Path(tempfile.mkdtemp()) / "o.json"
        subprocess.run(  # noqa: S603 -- this interpreter, on a corpus directory in this repository
            [
                sys.executable,
                "-m",
                "cordon_scanner.cli",
                "scan",
                str(d),
                "--format",
                "json",
                "-o",
                str(out),
            ],
            capture_output=True,
        )
        try:
            fs = json.loads(out.read_text())["findings"]
        except Exception:
            fs = []
        if any(f.get("category") in ("malicious", "suspicious") for f in fs):
            hit += 1
        else:
            missed.append(name)
    rows[label] = (hit, total, missed)
    rate = f"{hit / total:.0%}" if total else "n/a"
    print(
        f"{label:34} {hit:3}/{total:<3} {rate:>5}  {'missed: ' + ', '.join(missed) if missed else ''}"
    )
pathlib.Path("techniques.json").write_text(
    json.dumps({k: {"hit": v[0], "total": v[1], "missed": v[2]} for k, v in rows.items()}, indent=1)
)
