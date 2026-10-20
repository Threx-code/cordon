#!/usr/bin/env python3
"""A random draw of ordinary packages across registries, streamed into a bounded queue.

Every registry's full name list (or a uniform random walk over its paginated catalogue where no
list exists) is sampled with a fixed seed; each draw's current release archive is downloaded,
checked against the registry digest where one is published, and written to QUEUE/<eco>/ via a
.part rename so the scanner only ever sees complete files. Never installed, never run. The
downloader stalls while the queue holds more than --max-queued files, so disk use stays bounded:
the scanner (longtail_scan.py, no network) deletes each archive after reading it.

    docker run --rm -v cordon-corpus-q:/q -v "$PWD/bench:/tools:ro" \
      -v "$PWD/bench/longtail:/out" python:3.12-slim python -I /tools/longtail_fetch.py

Output: /out/manifest.jsonl, one line per archive queued: ecosystem, name, version, url, digest.
Resumable: names already in the manifest or in /out/failed.jsonl are skipped.

Rebuilding the same corpus later (for a newer scanner, or to keep the archives):

    docker run --rm -v cordon-corpus-q:/q -v "$PWD/bench:/tools:ro" \
      -v "$PWD/bench/longtail:/in:ro" -v "$PWD/rescan:/out" python:3.12-slim \
      python -I /tools/longtail_fetch.py --from-manifest /in/manifest.jsonl

then run longtail_scan.py against the same queue (add --keep to keep the archives on the volume).
Every digest recorded in the manifest is a sha256 of the bytes fetched, or the registry's own.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import random
import re
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import ClassVar

UA = {
    "User-Agent": "cordon-benign-corpus-study (research; contact via github.com/Threx-code/cordon)"
}
MAX_ARCHIVE = 32 << 20
SEED = 20261012

TARGETS = {
    "npm": 92000,
    "pypi": 45000,
    "crates": 7000,
    "rubygems": 7000,
    "nuget": 7000,
    "packagist": 7000,
    "go": 7000,
    "maven": 5000,
    "pub": 3000,
    "hex": 3000,
    "openvsx": 3000,
    "cran": 3000,
    "hackage": 2000,
    "conda": 2000,
    "helm": 1500,
    "galaxy": 1500,
    "terraform": 1500,
    "mcp": 2500,
}
OVERDRAW = 1.6  # names drawn per target: some have no archive, are too big, or fail


class Http:
    pause: ClassVar[dict[str, float]] = {}
    lock = threading.Lock()

    @classmethod
    def get(cls, url: str, limit: int = 256 << 20, accept: str | None = None, head: bool = False):
        host = urllib.parse.urlsplit(url).netloc
        polite = {
            "crates.io": 1.0,
            "hex.pm": 0.7,
            "search.maven.org": 0.5,
            "galaxy.ansible.com": 0.3,
            "registry.terraform.io": 0.2,
            "artifacthub.io": 0.3,
            "hackage.haskell.org": 0.1,
        }.get(host, 0)
        for attempt in range(4):
            if polite:
                with cls.lock:
                    wait = cls.pause.get(host, 0) - time.monotonic()
                    cls.pause[host] = max(time.monotonic(), cls.pause.get(host, 0)) + polite
                if wait > 0:
                    time.sleep(wait)
            headers = dict(UA)
            headers["Accept-Encoding"] = "gzip"
            if accept:
                headers["Accept"] = accept
            try:
                # `head` asks for the headers of a GET: Terraform's download endpoint answers a GET
                # with 204 and the source in X-Terraform-Get, and Artifact Hub refuses HEAD (405).
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=90) as r:
                    if head:
                        return r.headers
                    body = r.read(limit + 1)
                    if r.headers.get("Content-Encoding") == "gzip":
                        body = gzip.decompress(body)
                    return body
            except urllib.error.HTTPError as e:
                if e.code in (404, 410, 403, 401, 400):
                    raise
                time.sleep(3 + attempt * 5)
            except (urllib.error.URLError, TimeoutError, OSError):
                time.sleep(3 + attempt * 5)
        raise OSError(f"could not fetch {url}")

    @classmethod
    def json(cls, url: str, **kw):
        return json.loads(cls.get(url, accept=kw.pop("accept", "application/json"), **kw))


# --- name sources: each returns a list of opaque "draw" items for its resolver -------------------


class Names:
    @staticmethod
    def npm(rng, n):
        meta = Http.json("https://registry.npmjs.org/all-the-package-names/latest")
        tgz = Http.get(meta["dist"]["tarball"])
        with tarfile.open(fileobj=io.BytesIO(tgz)) as t:
            member = next(m for m in t.getmembers() if m.name.endswith("names.json"))
            names = json.load(t.extractfile(member))
        return rng.sample(names, n)

    @staticmethod
    def pypi(rng, n):
        d = Http.json("https://pypi.org/simple/", accept="application/vnd.pypi.simple.v1+json")
        return rng.sample([p["name"] for p in d["projects"]], n)

    @staticmethod
    def rubygems(rng, n):
        names = [x for x in Http.get("https://rubygems.org/names").decode().split("\n")[1:] if x]
        return rng.sample(names, n)

    @staticmethod
    def packagist(rng, n):
        return rng.sample(Http.json("https://packagist.org/packages/list.json")["packageNames"], n)

    @staticmethod
    def pub(rng, n):
        return rng.sample(Http.json("https://pub.dev/api/package-names")["packages"], n)

    @staticmethod
    def hackage(rng, n):
        d = Http.json("https://hackage.haskell.org/packages/")
        return rng.sample([p["packageName"] for p in d], n)

    @staticmethod
    def cran(rng, n):
        text = Http.get("https://cran.r-project.org/src/contrib/PACKAGES").decode(
            "utf-8", "replace"
        )
        out = []
        for block in text.split("\n\n"):
            f = dict(re.findall(r"^(Package|Version|MD5sum): (.+)$", block, re.M))
            if "Package" in f:
                out.append((f["Package"], f.get("Version"), f.get("MD5sum")))
        return rng.sample(out, n)

    @staticmethod
    def conda(rng, n):
        d = Http.json("https://conda.anaconda.org/conda-forge/noarch/repodata.json")
        newest: dict[str, tuple] = {}
        # .tar.bz2 only: Cordon does not open the zstd .conda format (recorded as a finding of
        # this study), and a corpus of archives it cannot read measures nothing.
        for fn, p in (d.get("packages") or {}).items():
            key = (p.get("timestamp") or 0, fn)
            if p["name"] not in newest or key > newest[p["name"]][0]:
                newest[p["name"]] = (key, fn, p.get("sha256"), p.get("version"))
        items = [(name, v[1], v[2], v[3]) for name, v in newest.items()]
        return rng.sample(items, min(n, len(items)))

    @staticmethod
    def crates(rng, n):
        # crates.io refuses deep pages of its listing API and points at its database dump. The
        # dump is a 2 GB zip; only its crates.csv member is read, through HTTP range requests.
        import csv
        import zipfile

        class RangeFile(io.RawIOBase):
            def __init__(self, url):
                self.url, self.pos = url, 0
                req = urllib.request.Request(url, headers={**UA, "Range": "bytes=0-0"})
                with urllib.request.urlopen(req, timeout=120) as r:
                    self.size = int(r.headers["Content-Range"].rsplit("/", 1)[1])

            def seekable(self):
                return True

            def readable(self):
                return True

            def tell(self):
                return self.pos

            def seek(self, off, whence=0):
                self.pos = {0: off, 1: self.pos + off, 2: self.size + off}[whence]
                return self.pos

            def readinto(self, b):
                if self.pos >= self.size or not len(b):
                    return 0
                end = min(self.size, self.pos + max(len(b), 1 << 20)) - 1
                req = urllib.request.Request(
                    self.url, headers={**UA, "Range": f"bytes={self.pos}-{end}"}
                )
                with urllib.request.urlopen(req, timeout=120) as r:
                    data = r.read()
                k = min(len(b), len(data))
                b[:k] = data[:k]
                self.pos += k
                return k

        url = "https://static.crates.io/db-dump.zip"
        with zipfile.ZipFile(io.BufferedReader(RangeFile(url), 1 << 20)) as z:
            member = next(i for i in z.namelist() if i.endswith("data/crates.csv"))
            text = io.TextIOWrapper(z.open(member), encoding="utf-8", newline="")
            csv.field_size_limit(1 << 30)
            names = [row["name"] for row in csv.DictReader(text)]
        return rng.sample(names, n)

    @staticmethod
    def hex(rng, n):
        out, pages = [], rng.sample(range(1, 260), 260 - 1)
        for p in pages:
            if len(out) >= n:
                break
            try:
                pk = Http.json(f"https://hex.pm/api/packages?page={p}&sort=name")
            except Exception:  # noqa: S112 - a page that fails is skipped; the seeded draw goes on
                continue
            out += [
                (x["name"], x.get("latest_stable_version") or x.get("latest_version")) for x in pk
            ]
        rng.shuffle(out)
        return out[:n]

    @staticmethod
    def nuget(rng, n):
        index = Http.json("https://api.nuget.org/v3/catalog0/index.json")["items"]
        seen, out = set(), []
        for page in rng.sample(index, min(len(index), n // 10 + 50)):
            try:
                items = Http.json(page["@id"])["items"]
            except Exception:  # noqa: S112 - a page that fails is skipped; the seeded draw goes on
                continue
            items = [i for i in items if i.get("@type") == "nuget:PackageDetails"]
            for i in rng.sample(items, min(10, len(items))):
                key = i["nuget:id"].lower()
                if key not in seen:
                    seen.add(key)
                    out.append((i["nuget:id"], i["nuget:version"]))
            if len(out) >= n:
                break
        return out[:n]

    @staticmethod
    def go(rng, n):
        start, end = time.mktime((2019, 4, 10, 0, 0, 0, 0, 0, 0)), time.time() - 86400
        seen, out = set(), []
        while len(out) < n:
            t = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(rng.uniform(start, end)))
            try:
                lines = (
                    Http.get(f"https://index.golang.org/index?since={t}&limit=200")
                    .decode()
                    .splitlines()
                )
            except Exception:  # noqa: S112 - a page that fails is skipped; the seeded draw goes on
                continue
            rows = [json.loads(x) for x in lines if x]
            for r in rng.sample(rows, min(8, len(rows))):
                if r["Path"] not in seen:
                    seen.add(r["Path"])
                    out.append((r["Path"], r["Version"]))
        return out[:n]

    @staticmethod
    def maven(rng, n):
        base = "https://search.maven.org/solrsearch/select?q=*:*&wt=json&rows=20&start="
        total = Http.json(base + "0")["response"]["numFound"]
        out = []
        while len(out) < n:
            try:
                docs = Http.json(base + str(rng.randrange(0, total - 20)))["response"]["docs"]
            except Exception:  # noqa: S112 - a page that fails is skipped; the seeded draw goes on
                continue
            out += [
                (d["g"], d["a"], d.get("latestVersion"))
                for d in rng.sample(docs, min(6, len(docs)))
                if d.get("p") in ("jar", "bundle", "maven-plugin")
            ]
        return out[:n]

    @staticmethod
    def openvsx(rng, n):
        total = Http.json("https://open-vsx.org/api/-/search?size=1")["totalSize"]
        out, seen = [], set()
        while len(out) < n:
            off = rng.randrange(0, max(1, total - 50))
            try:
                ext = Http.json(f"https://open-vsx.org/api/-/search?size=50&offset={off}")[
                    "extensions"
                ]
            except Exception:  # noqa: S112 - a page that fails is skipped; the seeded draw goes on
                continue
            for e in rng.sample(ext, min(5, len(ext))):
                key = (e["namespace"], e["name"])
                if key not in seen and (e.get("files") or {}).get("download"):
                    seen.add(key)
                    out.append(
                        (e["namespace"] + "." + e["name"], e["version"], e["files"]["download"])
                    )
        return out[:n]

    @staticmethod
    def helm(rng, n):
        total = int(
            Http.get("https://artifacthub.io/api/v1/packages/search?kind=0&limit=1", head=True).get(
                "Pagination-Total-Count", "20000"
            )
        )
        out, seen = [], set()
        while len(out) < n:
            off = rng.randrange(0, max(1, total - 60))
            try:
                pk = Http.json(
                    f"https://artifacthub.io/api/v1/packages/search?kind=0&limit=60&offset={off}"
                )["packages"]
            except Exception:  # noqa: S112 - a page that fails is skipped; the seeded draw goes on
                continue
            for p in rng.sample(pk, min(5, len(pk))):
                key = (p["repository"]["name"], p["name"])
                if key not in seen:
                    seen.add(key)
                    out.append(key)
        return out[:n]

    @staticmethod
    def galaxy(rng, n):
        base = (
            "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index/"
        )
        total = Http.json(base + "?limit=1")["meta"]["count"]
        out = []
        for off in rng.sample(range(0, total, 100), (total + 99) // 100):
            try:
                data = Http.json(f"{base}?limit=100&offset={off}")["data"]
            except Exception:  # noqa: S112 - a page that fails is skipped; the seeded draw goes on
                continue
            out += [
                (d["namespace"], d["name"], (d.get("highest_version") or {}).get("version"))
                for d in data
            ]
        rng.shuffle(out)
        return out[:n]

    @staticmethod
    def terraform(rng, n):
        out, seen = [], set()
        while len(out) < n:
            off = rng.randrange(0, 18000)
            try:
                mods = Http.json(f"https://registry.terraform.io/v1/modules?limit=50&offset={off}")[
                    "modules"
                ]
            except Exception:  # noqa: S112 - a page that fails is skipped; the seeded draw goes on
                continue
            for m in rng.sample(mods, min(5, len(mods))):
                if m["id"] not in seen:
                    seen.add(m["id"])
                    out.append(m["id"])
        return out[:n]

    @staticmethod
    def mcp(rng, n):
        out, cursor, seen = [], None, set()
        for _ in range(2000):
            url = "https://registry.modelcontextprotocol.io/v0/servers?limit=100" + (
                f"&cursor={urllib.parse.quote(cursor)}" if cursor else ""
            )
            try:
                d = Http.json(url)
            except Exception:
                break
            for s in d.get("servers", []):
                for p in (s.get("server") or {}).get("packages") or []:
                    kind, ident = p.get("registryType"), p.get("identifier")
                    if kind in ("npm", "pypi") and ident and (kind, ident) not in seen:
                        seen.add((kind, ident))
                        out.append((kind, ident))
            cursor = (d.get("metadata") or {}).get("nextCursor")
            if not cursor:
                break
        rng.shuffle(out)
        return out[:n]


# --- resolvers: draw item -> (name, version, url, digest "algo:hex" or "") -------------------------


class Resolve:
    @staticmethod
    def npm(name):
        m = Http.json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/latest")
        d = m.get("dist") or {}
        return name, m.get("version"), d["tarball"], "sha1:" + d["shasum"]

    @staticmethod
    def pypi(name):
        m = Http.json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
        files = m.get("urls") or []
        f = next((x for x in files if x["packagetype"] == "sdist"), None) or next(
            (x for x in files if x["packagetype"] == "bdist_wheel"), None
        )
        return name, m["info"]["version"], f["url"], "sha256:" + f["digests"]["sha256"]

    @staticmethod
    def rubygems(name):
        m = Http.json(f"https://rubygems.org/api/v1/gems/{urllib.parse.quote(name)}.json")
        return name, m["version"], m["gem_uri"], "sha256:" + (m.get("sha") or "")

    @staticmethod
    def packagist(name):
        m = Http.json(f"https://repo.packagist.org/p2/{name}.json")
        v = m["packages"][name][0]
        dist = v.get("dist") or {}
        url = dist["url"]
        g = re.match(r"https://api\.github\.com/repos/([^/]+/[^/]+)/zipball/(.+)$", url)
        if g:  # codeload serves the same archive without the API's unauthenticated rate limit
            url = f"https://codeload.github.com/{g.group(1)}/legacy.zip/{g.group(2)}"
        return name, v.get("version"), url, ("sha1:" + dist["shasum"]) if dist.get("shasum") else ""

    @staticmethod
    def pub(name):
        m = Http.json(f"https://pub.dev/api/packages/{name}")
        lt = m["latest"]
        return name, lt["version"], lt["archive_url"], "sha256:" + (lt.get("archive_sha256") or "")

    @staticmethod
    def hackage(name):
        pref = Http.json(f"https://hackage.haskell.org/package/{name}/preferred")
        versions = pref.get("normal-version") or []
        v = versions[0]
        return name, v, f"https://hackage.haskell.org/package/{name}-{v}/{name}-{v}.tar.gz", ""

    @staticmethod
    def cran(item):
        name, v, md5 = item
        return (
            name,
            v,
            f"https://cran.r-project.org/src/contrib/{name}_{v}.tar.gz",
            ("md5:" + md5) if md5 else "",
        )

    @staticmethod
    def conda(item):
        name, fn, sha, v = item
        return (
            name,
            v,
            f"https://conda.anaconda.org/conda-forge/noarch/{fn}",
            ("sha256:" + sha) if sha else "",
        )

    @staticmethod
    def crates(name):
        lower = name.lower()
        prefix = {1: "1", 2: "2", 3: f"3/{lower[0]}"}.get(len(lower), f"{lower[:2]}/{lower[2:4]}")
        lines = Http.get(f"https://index.crates.io/{prefix}/{lower}").decode().splitlines()
        rows = [json.loads(x) for x in lines if x]
        live = [r for r in rows if not r.get("yanked")] or rows
        row = live[-1]
        return (
            name,
            row["vers"],
            f"https://static.crates.io/crates/{name}/{name}-{row['vers']}.crate",
            "sha256:" + row["cksum"],
        )

    @staticmethod
    def hex(item):
        name, v = item
        return name, v, f"https://repo.hex.pm/tarballs/{name}-{v}.tar", ""

    @staticmethod
    def nuget(item):
        name, v = item
        low = name.lower()
        vl = v.lower().split("+")[0]
        return name, v, f"https://api.nuget.org/v3-flatcontainer/{low}/{vl}/{low}.{vl}.nupkg", ""

    @staticmethod
    def go(item):
        path, v = item
        esc = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)
        return path, v, f"https://proxy.golang.org/{esc}/@v/{v}.zip", ""

    @staticmethod
    def maven(item):
        g, a, v = item
        base = f"https://repo1.maven.org/maven2/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.jar"
        sha1 = Http.get(base + ".sha1").decode().split()[0].strip()
        return f"{g}:{a}", v, base, "sha1:" + sha1

    @staticmethod
    def openvsx(item):
        name, v, url = item
        return name, v, url, ""

    @staticmethod
    def helm(item):
        repo, name = item
        m = Http.json(f"https://artifacthub.io/api/v1/packages/helm/{repo}/{name}")
        url = m.get("content_url")
        if not url or not url.startswith("https://"):
            raise OSError("no https chart archive (oci or http)")
        # Artifact Hub's `digest` identifies the package version, not the archive: not checked.
        return f"{repo}/{name}", m.get("version"), url, ""

    @staticmethod
    def galaxy(item):
        ns, name, v = item
        m = Http.json(
            f"https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index/{ns}/{name}/versions/{v}/"
        )
        return (
            f"{ns}.{name}",
            v,
            m["download_url"],
            "sha256:" + ((m.get("artifact") or {}).get("sha256") or ""),
        )

    @staticmethod
    def terraform(mid):
        ns, name, provider, version = mid.split("/")
        h = Http.get(
            f"https://registry.terraform.io/v1/modules/{ns}/{name}/{provider}/{version}/download",
            head=True,
        )
        src = h.get("X-Terraform-Get") or ""
        g = re.match(r"(?:git::)?https://github\.com/([^/?]+/[^/?.]+)(?:\.git)?\?ref=([^&]+)", src)
        if not g:
            raise OSError("module source is not a github ref")
        return (
            f"{ns}/{name}/{provider}",
            version,
            f"https://codeload.github.com/{g.group(1)}/tar.gz/{g.group(2)}",
            "",
        )

    @staticmethod
    def mcp(item):
        kind, ident = item
        name, v, url, digest = (Resolve.npm if kind == "npm" else Resolve.pypi)(ident)
        return f"{kind}:{name}", v, url, digest


class Corpus:
    @staticmethod
    def fetch(eco, item, queue: Path):
        name, version, url, digest = getattr(Resolve, eco)(item)
        body = Http.get(url, MAX_ARCHIVE)
        if len(body) > MAX_ARCHIVE:
            raise OSError("archive over 32 MB")
        if digest and ":" in digest and digest.split(":", 1)[1]:
            algo, want = digest.split(":", 1)
            if hashlib.new(algo, body).hexdigest() != want.lower():
                raise OSError("digest mismatch")
        path = urllib.parse.urlsplit(url).path
        ext = next(
            (
                e
                for e in (
                    ".tar.gz",
                    ".tar.bz2",
                    ".tgz",
                    ".whl",
                    ".zip",
                    ".gem",
                    ".crate",
                    ".nupkg",
                    ".jar",
                    ".vsix",
                    ".tar",
                    ".egg",
                )
                if path.endswith(e)
            ),
            None,
        )
        if ext is None:
            ext = {"go": ".zip", "packagist": ".zip", "terraform": ".tar.gz"}.get(eco, ".tgz")
        safe = re.sub(r"[^\w.@+-]", "_", f"{name}-{version}")[:150]
        target = queue / eco / (safe + ext)
        target.parent.mkdir(parents=True, exist_ok=True)
        part = target.with_name(target.name + ".part")
        part.write_bytes(body)
        part.replace(target)
        return {
            "ecosystem": eco,
            "name": name,
            "version": version,
            "url": url,
            "digest": digest or "sha256:" + hashlib.sha256(body).hexdigest(),
            "digest_verified": bool(digest),
            "bytes": len(body),
            "file": f"{eco}/{target.name}",
        }

    @staticmethod
    def refetch(a) -> None:
        """Rebuild a previous corpus exactly: every manifest line's URL, its digest verified, written to
        the queue under the same relative path. Resumable: files already listed in --out's
        refetch.jsonl are skipped. A digest mismatch or a vanished archive is logged, never replaced."""
        a.out.mkdir(parents=True, exist_ok=True)
        log = a.out / "refetch.jsonl"
        done = (
            {json.loads(x)["file"] for x in log.read_text(encoding="utf-8").splitlines()}
            if log.exists()
            else set()
        )
        rows = [
            json.loads(x) for x in a.from_manifest.read_text(encoding="utf-8").splitlines() if x
        ]
        lock = threading.Lock()

        def queued() -> int:
            return sum(len(files) for _, _, files in os.walk(a.queue))

        def one(row):
            if row["file"] in done:
                return
            while queued() > a.max_queued:
                time.sleep(5)
            status = "ok"
            try:
                body = Http.get(row["url"], MAX_ARCHIVE)
                algo, want = row["digest"].split(":", 1)
                if hashlib.new(algo, body).hexdigest() != want.lower():
                    status = "digest-mismatch"
                else:
                    target = a.queue / row["file"]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    part = target.with_name(target.name + ".part")
                    part.write_bytes(body)
                    part.replace(target)
            except Exception as e:
                status = "error: " + repr(e)[:150]
            with lock, log.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"file": row["file"], "status": status}) + "\n")

        with ThreadPoolExecutor(a.workers) as pool:
            list(pool.map(one, rows))
        (a.queue / ".fetch-done").write_text("done", encoding="utf-8")

    @staticmethod
    def main():
        ap = argparse.ArgumentParser()
        ap.add_argument("--queue", type=Path, default=Path("/q"))
        ap.add_argument("--out", type=Path, default=Path("/out"))
        ap.add_argument("--only", nargs="*")
        ap.add_argument("--scale", type=float, default=1.0)
        ap.add_argument("--max-queued", type=int, default=3000)
        ap.add_argument("--workers", type=int, default=16)
        ap.add_argument(
            "--from-manifest",
            type=Path,
            help="re-fetch exactly the archives a previous run's manifest.jsonl lists "
            "(same URL, digest checked), instead of drawing names",
        )
        a = ap.parse_args()
        if a.from_manifest:
            Corpus.refetch(a)
            return
        a.out.mkdir(parents=True, exist_ok=True)
        manifest, failed = a.out / "manifest.jsonl", a.out / "failed.jsonl"
        done = set()
        for f in (manifest, failed):
            if f.exists():
                for line in f.read_text(encoding="utf-8").splitlines():
                    r = json.loads(line)
                    done.add((r["ecosystem"], r.get("draw") or r["name"]))
        lock = threading.Lock()
        ecos = a.only or list(TARGETS)
        # Phase 1: every registry's draw, cached so a restart draws the same names. Registries are
        # drawn concurrently (one thread each; per-host politeness still applies in Http.get).
        draws: dict[str, list] = {}

        def draw(eco: str) -> None:
            drawn_file = a.out / f"draw-{eco}.json"
            if drawn_file.exists():
                draws[eco] = json.loads(drawn_file.read_text(encoding="utf-8"))
                return
            try:
                rng = random.Random(f"{SEED}:{eco}")  # noqa: S311 - a reproducible draw
                items = getattr(Names, eco)(rng, int(TARGETS[eco] * a.scale * OVERDRAW))
                drawn_file.write_text(json.dumps(items), encoding="utf-8")
                draws[eco] = items
                print(f"{eco}: drawn {len(items)}", flush=True)
            except Exception as e:
                print(f"{eco}: name source failed: {e!r}", flush=True)

        with ThreadPoolExecutor(len(ecos)) as pool:
            list(pool.map(draw, ecos))
        draws = {eco: draws[eco] for eco in ecos if eco in draws}
        target = {eco: int(TARGETS[eco] * a.scale) for eco in draws}
        kept = dict.fromkeys(draws, 0)
        if manifest.exists():
            for line in manifest.read_text(encoding="utf-8").splitlines():
                e = json.loads(line)["ecosystem"]
                if e in kept:
                    kept[e] += 1
        for eco in draws:
            print(
                f"{eco}: {len(draws[eco])} drawn, {kept[eco]} already kept, target {target[eco]}",
                flush=True,
            )
        # Phase 2: interleaved, each registry advancing in proportion to its draw, so a partial run
        # is a representative sample of every ecosystem rather than all of npm first.
        order = sorted(
            (
                (i / len(items), eco, item)
                for eco, items in draws.items()
                for i, item in enumerate(items)
            ),
            key=lambda x: (x[0], x[1]),
        )

        def queued() -> int:
            return sum(len(files) for _, _, files in os.walk(a.queue))

        def one(job):
            _, eco, item = job
            key = (eco, json.dumps(item) if not isinstance(item, str) else item)
            if key in done or kept[eco] >= target[eco]:
                return
            while queued() > a.max_queued:
                time.sleep(5)
            try:
                rec = Corpus.fetch(eco, item, a.queue)
                rec["draw"] = key[1]
                with lock:
                    if kept[eco] < target[eco]:
                        kept[eco] += 1
                        with manifest.open("a", encoding="utf-8") as fh:
                            fh.write(json.dumps(rec) + "\n")
                    else:  # over target from a concurrent fetch: not part of the draw
                        (a.queue / rec["file"]).unlink(missing_ok=True)
            except Exception as e:
                with lock, failed.open("a", encoding="utf-8") as fh:
                    fh.write(
                        json.dumps(
                            {
                                "ecosystem": eco,
                                "name": key[1],
                                "draw": key[1],
                                "error": repr(e)[:200],
                            }
                        )
                        + "\n"
                    )

        with ThreadPoolExecutor(a.workers) as pool:
            list(pool.map(one, order))
        print("kept: " + json.dumps(kept), flush=True)
        (a.queue / ".fetch-done").write_text("done", encoding="utf-8")


if __name__ == "__main__":
    Corpus.main()
