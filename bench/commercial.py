"""Socket and Snyk, run on the same inputs as the rest of the benchmark (G7).

Both are commercial services and need an API key the person running the benchmark holds:

    SOCKET_SECURITY_API_KEY   Socket's package API: one verdict per release, by purl
    SNYK_TOKEN                the Snyk CLI: vulnerabilities per lockfile

Without a key the tool is reported as not run, with the reason, in the summary -- never left out
quietly, because a comparison table that silently lacks the competitor a buyer asked about reads
as if Cordon won by default. With one, every input either gets an answer or is recorded as "no
answer" for that input, exactly as the open-source tools are.

Socket is asked by package URL rather than by file, so it judges the same releases Cordon scanned
(the DataDog and malregistry samples, the benign top packages) and needs the network; it runs in
its own suite for that reason, while the malware and benign suites keep the network off.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

SOCKET_URL = "https://api.socket.dev/v0/purl?alerts=true&compact=false"
SOCKET_BATCH = 100
#: What counts as Socket blocking a release: an alert its own taxonomy calls malware, or any alert it
#: grades critical. Stated here so the reading is reviewable; it is the closest thing Socket has to
#: a default "block" verdict through its API.
SOCKET_BLOCKING_TYPES = frozenset({"malware", "gptMalware", "troll", "criticalCVE"})


@dataclass(frozen=True, slots=True)
class CommercialVerdict:
    tool: str
    sample: str
    blocked: bool | None
    detail: str


class SocketApi:
    """Socket's package API, batched, with a fake-able transport."""

    def __init__(
        self, token: str, post: Callable[[str, bytes, dict[str, str]], bytes] | None = None
    ) -> None:
        self.token = token
        self.post = post or self._post

    @staticmethod
    def _post(url: str, body: bytes, headers: dict[str, str]) -> bytes:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310 - fixed https URL
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
            return bytes(response.read(64 << 20))

    def verdicts(self, samples: Iterable[tuple[str, str]]) -> list[CommercialVerdict]:
        """`(sample id, purl)` pairs -> one verdict each; an unanswered purl is "no answer"."""
        pending = list(samples)
        out: list[CommercialVerdict] = []
        headers = {
            "Authorization": "Basic " + base64.b64encode(f"{self.token}:".encode()).decode(),
            "Content-Type": "application/json",
            "User-Agent": "cordon-benchmark",
        }
        for start in range(0, len(pending), SOCKET_BATCH):
            batch = pending[start : start + SOCKET_BATCH]
            body = json.dumps({"components": [{"purl": purl} for _, purl in batch]}).encode()
            try:
                answers = self.parse(self.post(SOCKET_URL, body, headers))
            except (urllib.error.URLError, OSError, ValueError) as exc:
                out.extend(
                    CommercialVerdict("socket", s, None, f"request failed: {type(exc).__name__}")
                    for s, _ in batch
                )
                continue
            for sample, purl in batch:
                answer = answers.get(self.key(purl))
                if answer is None:
                    out.append(
                        CommercialVerdict("socket", sample, None, "no answer for this release")
                    )
                    continue
                blocking = [
                    a
                    for a in answer
                    if a.get("type") in SOCKET_BLOCKING_TYPES or a.get("severity") == "critical"
                ]
                kinds = sorted({str(a.get("type")) for a in blocking})
                out.append(
                    CommercialVerdict(
                        "socket",
                        sample,
                        bool(blocking),
                        ", ".join(kinds) or f"{len(answer)} non-blocking alert(s)",
                    )
                )
        return out

    @staticmethod
    def key(purl: str) -> str:
        return purl.lower()

    @classmethod
    def parse(cls, body: bytes) -> dict[str, list[dict[str, Any]]]:
        """Socket answers newline-delimited JSON, one package per line, each with its alerts."""
        answers: dict[str, list[dict[str, Any]]] = {}
        for line in body.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if not isinstance(item, dict) or item.get("_type") == "summary":
                continue
            purl = item.get("purl") or cls._compose(item)
            if not purl:
                continue
            alerts = [a for a in item.get("alerts") or [] if isinstance(a, dict)]
            answers[cls.key(str(purl))] = alerts
        return answers

    @staticmethod
    def _compose(item: dict[str, Any]) -> str:
        kind, name, version = item.get("type"), item.get("name"), item.get("version")
        namespace = item.get("namespace")
        if not (kind and name and version):
            return ""
        return f"pkg:{kind}/{namespace + '/' if namespace else ''}{name}@{version}"


class SnykCli:
    """`snyk test --json` over a lockfile directory, as (version, identifiers) groups."""

    def __init__(self, run: Callable[[list[str]], tuple[int, str, float]]) -> None:
        self.run = run

    def vulnerabilities(self, directory: str) -> list[tuple[str, frozenset[str]]]:
        code, out, _ = self.run(["snyk", "test", "--all-projects", "--json", directory])
        if code not in (0, 1):
            raise RuntimeError(out[:200])
        return self.parse(out)

    @staticmethod
    def parse(out: str) -> list[tuple[str, frozenset[str]]]:
        start = min((i for i in (out.find("{"), out.find("[")) if i != -1), default=-1)
        if start == -1:
            raise ValueError("no JSON in snyk output")
        document = json.loads(out[start:])
        projects = document if isinstance(document, list) else [document]
        groups: list[tuple[str, frozenset[str]]] = []
        for project in projects:
            for vulnerability in (
                project.get("vulnerabilities", []) if isinstance(project, dict) else []
            ):
                identifiers = vulnerability.get("identifiers") or {}
                ids = {str(vulnerability.get("id", ""))}
                for values in identifiers.values() if isinstance(identifiers, dict) else []:
                    ids.update(str(v) for v in values or [])
                groups.append((str(vulnerability.get("version", "")), frozenset(ids - {""})))
        return groups


class Commercial:
    """Which commercial tools can run here, and why not when they cannot."""

    @staticmethod
    def availability(environ: dict[str, str] | None = None) -> dict[str, str | None]:
        env = os.environ if environ is None else environ
        return {
            "socket": None
            if env.get("SOCKET_SECURITY_API_KEY")
            else "not run: SOCKET_SECURITY_API_KEY is not set",
            "snyk": None if env.get("SNYK_TOKEN") else "not run: SNYK_TOKEN is not set",
        }
