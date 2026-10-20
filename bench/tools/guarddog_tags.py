#!/usr/bin/env python3
"""Tag every real malicious sample with the behaviours an independent scanner finds in it.

```
  malicious samples (DataDog, malregistry) ──► GuardDog 3 (Datadog's scanner, its own rules)
                                                    │  threat-* rules that matched
                                                    ▼
                                    FAMILIES: GuardDog rule -> attack-matrix family
                                                    │
                                                    ▼
                         /out/guarddog-tags.jsonl   one line per sample: families, rules
```

The tags come from a third party, so a family's detection rate is not Cordon grading itself:
Cordon's verdicts (from `run.py malware`) are joined to these afterwards. Only GuardDog's `threat-*`
rules tag; its `capability-*` rules describe dual-use abilities and say nothing on their own.

    docker run --rm --network none -v cordon-bench-data:/data:ro -v cordon-bench-results:/out \\
      -v "$PWD:/s:ro" cordon-guarddog:bench python /s/bench/guarddog_tags.py --workers 6

Resumable: samples already in the output are skipped. Nothing in a sample is executed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suites"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from run import Harness

#: GuardDog 3.2.0 rule -> the family in `tests/attack/verdicts.py` it is evidence of.
FAMILIES = {
    "threat-process-download-exec": "dropper",
    "threat-process-powershell-encoded": "dropper",
    "threat-network-reverse-shell": "remote-access",
    "threat-network-exfiltration": "exfil",
    "threat-network-exfil-messenger": "exfil",
    "threat-network-dns-exfil": "exfil",
    "threat-network-exfil-sysinfo": "exfil",
    "threat-filesystem-read": "secret-source",
    "threat-runtime-environment-read": "secret-source",
    "threat-filesystem-autostart": "persist",
    "threat-filesystem-destruction": "destroy",
    "threat-process-cryptomining": "miner",
    "threat-process-injection-dll": "injection",
    "threat-process-memory": "injection",
    "threat-runtime-keylogging": "collection",
    "threat-runtime-screencapture": "collection",
    "threat-runtime-self-propagation": "lateral",
    "threat-runtime-system-info": "discovery",
    "threat-process-sysinfo": "discovery",
    "threat-runtime-enumeration": "discovery",
    "threat-process-spawn-silent": "interpreter",
    "threat-runtime-dynamic-loader": "interpreter",
    "threat-runtime-obfuscation-import-exec": "obfuscation",
    "threat-runtime-obfuscation": "obfuscation",
    "threat-runtime-obfuscation-api": "obfuscation",
    "threat-runtime-obfuscation-base64exec": "obfuscation",
    "threat-runtime-obfuscation-chr": "obfuscation",
    "threat-runtime-obfuscation-dynamic-eval": "obfuscation",
    "threat-runtime-obfuscation-general": "obfuscation",
    "threat-runtime-obfuscation-hidden-code": "obfuscation",
    "threat-runtime-obfuscation-js-mangling": "obfuscation",
    "threat-runtime-obfuscation-log-suppress": "obfuscation",
    "threat-runtime-obfuscation-pyarmor": "obfuscation",
    "threat-runtime-obfuscation-steganography": "obfuscation",
    "threat-runtime-obfuscation-unicode": "obfuscation",
    "threat-setup-network-in-install": "supply-chain",
    "threat-setup-suspicious-imports": "supply-chain",
    "threat-setup-import-aliasing": "supply-chain",
    "threat-npm-preinstall-script": "supply-chain",
    "threat-npm-dependency-confusion": "supply-chain",
    "threat-npm-http-dependency": "supply-chain",
    "threat-network-outbound-shady-links": "exfil",
    "threat-process-hooks": "supply-chain",
    "typosquatting": "supply-chain",
}

#: The DataDog folder -> the GuardDog sub-command that reads it. Skills are read as source trees.
ECOSYSTEM = {"npm": "npm", "pypi": "pypi", "ide_extensions": "extension", "ai-skills": "pypi"}


class GuardDogTags:
    @staticmethod
    def rules(document: dict[str, object]) -> list[str]:
        results = document.get("results")
        if not isinstance(results, dict):
            return []
        return sorted(name for name, found in results.items() if found)

    @staticmethod
    def tag(name: str, archive: Path, ecosystem: str) -> dict[str, object]:
        command = ECOSYSTEM.get(ecosystem, "pypi")
        with tempfile.TemporaryDirectory(prefix="gd-") as work:
            target: Path | None = archive
            if name.startswith("datadog/") and archive.suffix != ".vsix":
                try:
                    target = Harness._unzip_datadog(archive, Path(work))
                except Exception as exc:
                    return {"sample": name, "error": f"unzip: {type(exc).__name__}"}
            if target is None:
                return {"sample": name, "error": "empty"}
            try:
                out = subprocess.run(
                    ["guarddog", command, "scan", str(target), "--output-format", "json"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                ).stdout
                document = json.loads(out[out.index("{") :])
            except (subprocess.TimeoutExpired, ValueError) as exc:
                return {"sample": name, "error": type(exc).__name__}
        rules = GuardDogTags.rules(document)
        return {
            "sample": name,
            "ecosystem": ecosystem,
            "rules": rules,
            "families": sorted({FAMILIES[r] for r in rules if r in FAMILIES}),
        }

    @classmethod
    def main(cls) -> int:
        parser = argparse.ArgumentParser(
            description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument("--data", type=Path, default=Path("/data"))
        parser.add_argument("--out", type=Path, default=Path("/out/guarddog-tags.jsonl"))
        parser.add_argument("--workers", type=int, default=6)
        args = parser.parse_args()
        done: set[str] = set()
        if args.out.exists():
            done = {
                json.loads(line)["sample"]
                for line in args.out.read_text(encoding="utf-8").splitlines()
                if line
            }
        samples = [s for s in Harness.malware_samples(args.data) if s[0] not in done]
        print(f"{len(done)} tagged, {len(samples)} to go", flush=True)
        lock = Lock()
        with args.out.open("a", encoding="utf-8") as sink, ThreadPoolExecutor(args.workers) as pool:
            for count, row in enumerate(pool.map(lambda s: cls.tag(*s), samples), start=1):
                with lock:
                    sink.write(json.dumps(row) + "\n")
                    sink.flush()
                if count % 500 == 0:
                    print(f"{count}/{len(samples)}", flush=True)
        print("done", flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(GuardDogTags.main())
