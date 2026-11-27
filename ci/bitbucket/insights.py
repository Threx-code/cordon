"""Posts the dependency review to Bitbucket Code Insights on the pull request's commit.

`cordon-scanner review --format bitbucket` writes `{"report": ..., "annotations": [...]}`. Bitbucket Pipelines runs an
authenticating proxy beside every step: a request sent through it, with no credential of its own, is made with the
pipeline's identity for this repository only, and the Reports API accepts it. So no token is stored, read or sent here.
The report is put first, then its annotations in the batches of at most 100 the API takes.

Run as `python /insights.py REVIEW.json`; it reads the repository, the commit and the proxy from the step's
environment, and touches nothing else.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request
from typing import Any, ClassVar


class CodeInsights:
    #: Pipelines' authenticating proxy, as a pipe's container reaches it (Bitbucket's own documentation).
    PROXY: ClassVar[str] = "http://host.docker.internal:29418"
    #: Through the proxy the API is asked over plain http; the proxy makes the https request.
    API: ClassVar[str] = "http://api.bitbucket.org/2.0/repositories"
    REPORT_ID: ClassVar[str] = "cordon-dependency-review"
    BATCH: ClassVar[int] = 100
    TIMEOUT: ClassVar[int] = 30

    @staticmethod
    def opener() -> urllib.request.OpenerDirector:
        proxy = os.environ.get("CORDON_INSIGHTS_PROXY", CodeInsights.PROXY)
        return urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy}))

    @staticmethod
    def segment(value: str) -> str:
        if not value or "/" in value or value in {".", ".."}:
            raise ValueError("the repository, owner and commit must each be one path segment")
        return urllib.parse.quote(value, safe="")

    @classmethod
    def base(cls) -> str:
        owner = cls.segment(os.environ["BITBUCKET_REPO_OWNER"])
        slug = cls.segment(os.environ["BITBUCKET_REPO_SLUG"])
        commit = cls.segment(os.environ["BITBUCKET_COMMIT"])
        return f"{cls.API}/{owner}/{slug}/commit/{commit}/reports/{cls.REPORT_ID}"

    @classmethod
    def send(cls, opener: urllib.request.OpenerDirector, method: str, url: str, body: Any) -> int:
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            method=method,
            headers={"Content-Type": "application/json"},
        )
        with opener.open(request, timeout=cls.TIMEOUT) as response:
            return int(response.status)

    @classmethod
    def post(cls, review: dict[str, Any]) -> int:
        opener, base = cls.opener(), cls.base()
        cls.send(opener, "PUT", base, review["report"])
        annotations = list(review.get("annotations") or ())
        for start in range(0, len(annotations), cls.BATCH):
            cls.send(opener, "POST", f"{base}/annotations", annotations[start : start + cls.BATCH])
        return len(annotations)

    @classmethod
    def main(cls, argv: list[str]) -> int:
        review = json.loads(open(argv[1], encoding="utf-8").read())
        count = cls.post(review)
        print(f"Code Insights: report {review['report']['result']}, {count} annotation(s)")
        return 0


if __name__ == "__main__":
    sys.exit(CodeInsights.main(sys.argv))
