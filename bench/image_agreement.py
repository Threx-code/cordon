"""How closely Cordon's reading of real container images agrees with Syft's, at scale.

Each image is pulled as a `docker save` tarball by crane, read by Syft (`syft docker-archive:`) and
by Cordon, and deleted before the next one. The two package sets are compared as purls -- type,
namespace, name and version, qualifiers dropped -- per package type, so an OS-package disagreement
and a language-package disagreement are told apart. Neither tool is the truth: every image's
differences are kept for examination. Run inside Docker only, from the image `Dockerfile.images`
builds (Cordon, Syft and crane at pinned versions):

    docker build -f bench/Dockerfile.images -t cordon-imgcmp:dev .
    docker run --rm -v "$PWD/bench/results/full-2026-10-07:/results" cordon-imgcmp:dev
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
import urllib.parse
from collections import defaultdict
from pathlib import Path
from typing import Any

#: Official and widely pulled images across every package manager and base family Cordon reads:
#: Debian/Ubuntu (dpkg), Alpine (apk), Red Hat family (rpm), distroless, Wolfi, and language
#: runtimes and applications whose layers carry npm, PyPI, Maven, Go, gem, Composer and Cargo
#: packages.
IMAGES = [
    # Bases
    *(f"debian:{t}" for t in ("bookworm", "bookworm-slim", "bullseye", "bullseye-slim", "trixie")),
    *(f"ubuntu:{t}" for t in ("20.04", "22.04", "24.04", "25.04")),
    *(f"alpine:{t}" for t in ("3.18", "3.19", "3.20", "3.21", "3.22")),
    "busybox:1.37", "fedora:41", "fedora:42", "rockylinux:9", "almalinux:9", "almalinux:8",
    "amazonlinux:2", "amazonlinux:2023", "oraclelinux:9", "registry.access.redhat.com/ubi9/ubi:latest",
    "registry.access.redhat.com/ubi9/ubi-minimal:latest", "registry.access.redhat.com/ubi8/ubi:latest",
    "photon:5.0", "archlinux:latest", "opensuse/leap:15.6", "gentoo/stage3:latest", "clearlinux:latest",
    "gcr.io/distroless/static-debian12:latest", "gcr.io/distroless/base-debian12:latest",
    "gcr.io/distroless/cc-debian12:latest", "gcr.io/distroless/python3-debian12:latest",
    "gcr.io/distroless/java17-debian12:latest", "gcr.io/distroless/nodejs22-debian12:latest",
    "cgr.dev/chainguard/wolfi-base:latest", "cgr.dev/chainguard/python:latest", "cgr.dev/chainguard/node:latest",
    "cgr.dev/chainguard/go:latest", "cgr.dev/chainguard/jdk:latest", "cgr.dev/chainguard/nginx:latest",
    # Language runtimes
    *(f"python:{t}" for t in ("3.9-slim", "3.10", "3.11-slim", "3.12", "3.12-alpine", "3.13-slim", "3.13-alpine")),
    *(f"node:{t}" for t in ("18", "20-slim", "20-alpine", "22", "22-alpine", "24-slim")),
    *(f"golang:{t}" for t in ("1.22", "1.23-alpine", "1.24", "1.25-alpine")),
    *(f"eclipse-temurin:{t}" for t in ("8-jre", "11-jdk", "17-jre", "21-jdk", "21-jre-alpine")),
    "openjdk:17-slim", "amazoncorretto:21", "maven:3.9-eclipse-temurin-21", "gradle:8-jdk21",
    *(f"ruby:{t}" for t in ("3.2", "3.3-slim", "3.4-alpine")),
    *(f"php:{t}" for t in ("8.2-apache", "8.3-fpm", "8.4-cli-alpine")), "composer:2",
    *(f"rust:{t}" for t in ("1.82", "1-slim", "1-alpine")),
    "elixir:1.18", "erlang:27", "haskell:9", "swift:6.0", "dart:stable", "julia:1.11", "r-base:4.4.2",
    "perl:5.40", "mcr.microsoft.com/dotnet/sdk:8.0", "mcr.microsoft.com/dotnet/aspnet:9.0",
    "mcr.microsoft.com/dotnet/runtime:8.0-alpine", "mono:6", "clojure:latest", "groovy:4.0",
    # Applications
    "nginx:1.27", "nginx:1.27-alpine", "httpd:2.4", "httpd:2.4-alpine", "traefik:v3.3", "caddy:2",
    "haproxy:3.1", "envoyproxy/envoy:v1.32-latest", "redis:7.4", "redis:7.4-alpine", "valkey/valkey:8",
    "memcached:1.6", "postgres:17", "postgres:16-alpine", "mysql:8.4", "mariadb:11", "mongo:8",
    "cassandra:5", "neo4j:5", "couchdb:3", "influxdb:2", "clickhouse/clickhouse-server:24",
    "elasticsearch:8.17.0", "kibana:8.17.0", "logstash:8.17.0", "opensearchproject/opensearch:2",
    "rabbitmq:4-management", "eclipse-mosquitto:2", "apache/kafka:3.9.0", "zookeeper:3.9", "nats:2",
    "grafana/grafana:11.4.0", "prom/prometheus:v3.1.0", "prom/alertmanager:v0.28.0",
    "prom/node-exporter:v1.8.2", "grafana/loki:3.3.2", "jaegertracing/all-in-one:1.65.0",
    "otel/opentelemetry-collector-contrib:0.116.0", "hashicorp/vault:1.18", "hashicorp/consul:1.20",
    "hashicorp/terraform:1.10", "jenkins/jenkins:lts", "sonarqube:community", "gitea/gitea:1.23",
    "nextcloud:30", "wordpress:6", "ghost:5", "drupal:11", "joomla:5", "mediawiki:1.43",
    "keycloak/keycloak:26.0", "minio/minio:latest", "registry:2", "portainer/portainer-ce:2.25.1",
    "tomcat:10.1", "jetty:12", "wildfly/wildfly:latest", "solr:9", "tensorflow/tensorflow:2.18.0",
    "jupyter/base-notebook:latest", "apache/airflow:2.10.4", "apache/superset:4.1.1",
    "metabase/metabase:v0.52.5", "n8nio/n8n:1.73.1", "nodered/node-red:4.0", "directus/directus:11",
    "strapi/strapi:latest", "mattermost/mattermost-team-edition:10.3", "rocket.chat:7",
    "ollama/ollama:0.5.4", "argoproj/argocd:v2.13.3", "bitnami/kubectl:1.32", "docker:27-cli",
    "amazon/aws-cli:2.22.0", "google/cloud-sdk:503.0.0-slim", "mcr.microsoft.com/azure-cli:2.67.0",
    "localstack/localstack:4.0", "selenium/standalone-chrome:131.0", "mcr.microsoft.com/playwright:v1.49.1",
    "cypress/included:13.17.0", "sonatype/nexus3:3.75.1", "jfrog/artifactory-oss:7.98.11",
    "quay.io/keycloak/keycloak:26.0", "quay.io/prometheus/blackbox-exporter:v0.25.0",
    "ghcr.io/home-assistant/home-assistant:2025.1", "ghcr.io/open-webui/open-webui:main",
    "ghcr.io/gethomepage/homepage:v0.10.9", "anchore/syft:v1.18.1", "aquasec/trivy:0.58.1",
]  # fmt: skip


class Purls:
    """A purl reduced to what both tools state: type, namespace, name and version."""

    #: Purl types Syft gives a name Cordon gives another for (the same package).
    TYPE_ALIASES = {"golang": "golang", "gem": "gem", "apk": "apk", "deb": "deb", "rpm": "rpm"}

    @staticmethod
    def key(purl: str) -> tuple[str, str] | None:
        if not purl.startswith("pkg:"):
            return None
        body = purl[4:].split("?", 1)[0].split("#", 1)[0]
        kind, _, rest = body.partition("/")
        if "@" not in rest:
            return None
        coordinate, _, version = rest.rpartition("@")
        coordinate = urllib.parse.unquote(coordinate)
        version = urllib.parse.unquote(version)
        kind = kind.lower()
        if kind in ("pypi",):
            coordinate = coordinate.lower().replace("_", "-").replace(".", "-")
        elif kind in ("npm", "maven", "deb", "apk", "rpm", "gem", "composer", "cargo", "nuget"):
            coordinate = coordinate.lower()
        if kind in ("deb", "apk", "rpm", "alpm"):
            # The distribution namespace differs between tools (debian vs ubuntu, alpine vs wolfi)
            # for the same installed package; the name and version are what the database states.
            coordinate = coordinate.rpartition("/")[2]
        if kind == "golang":
            # Cordon writes Go versions as OSV does (`1.8.1`), Syft as `go list` does (`v1.8.1`).
            version = version.removesuffix("+incompatible").removeprefix("v")
            if coordinate == "stdlib":
                # The standard library: Syft writes its version as the toolchain names it (`go1.24`).
                version = version.removeprefix("go")
        return kind, f"{coordinate}@{version}"

    #: Entries one tool lists that are not packages, each excluded from the ADJUSTED figures only
    #: and counted, so the raw agreement is never hidden: an RPM database's imported signing keys
    #: (`gpg-pubkey`), a Go binary built from a checkout (`(devel)` names no release), and a
    #: Windows launcher's PE version resource read as a NuGet package.
    @staticmethod
    def excluded(kind: str, entry: str) -> str | None:
        if kind.startswith("excluded:"):
            return kind.removeprefix("excluded:")
        if kind == "rpm" and entry.startswith("gpg-pubkey@"):
            return "rpm signing key"
        if kind == "golang" and entry.endswith("@(devel)"):
            return "go (devel) build"
        if kind == "nuget" and entry.startswith("simple launcher@"):
            return "windows launcher version resource"
        return None


class Image:
    """One image: pulled, read twice, compared, deleted."""

    @staticmethod
    def mirrors(reference: str) -> list[str]:
        """The reference, then Docker Hub's public mirrors for a Docker Hub image: anonymous pulls
        from Docker Hub are rate-limited, and the mirrors serve the same digests."""
        first = reference.split("/", 1)[0]
        if "." in first or ":" in first or first == "localhost":
            return [reference]
        path = reference if "/" in reference else f"library/{reference}"
        return [reference, f"mirror.gcr.io/{path}", f"public.ecr.aws/docker/{path}"]

    @staticmethod
    def pull(reference: str, into: Path) -> str | None:
        failure = ""
        for candidate in Image.mirrors(reference):
            completed = subprocess.run(  # noqa: S603 - fixed argv
                ["crane", "pull", "--platform", "linux/amd64", candidate, str(into)],
                capture_output=True, text=True, timeout=1800, check=False,
            )  # fmt: skip
            if completed.returncode == 0:
                return None
            failure = completed.stderr.strip()[-300:]
        return failure

    @staticmethod
    def syft(tarball: Path) -> dict[str, set[str]]:
        completed = subprocess.run(  # noqa: S603 - fixed argv
            ["syft", f"docker-archive:{tarball}", "-o", "json", "-q"],
            capture_output=True, text=True, timeout=3600, check=True,
        )  # fmt: skip
        out: dict[str, set[str]] = defaultdict(set)
        for artifact in json.loads(completed.stdout).get("artifacts") or []:
            if artifact.get("foundBy") == "dotnet-portable-executable-cataloger":
                # A .NET assembly's file version from its PE resources, one per DLL of the
                # framework: not a package version any advisory names. Listed, not compared.
                out["excluded:dotnet-assembly-file-version"].add(
                    f"{artifact.get('name')}@{artifact.get('version')}"
                )
                continue
            key = Purls.key(str(artifact.get("purl") or ""))
            if key and key[0] == "golang" and artifact.get("name"):
                # A long module path is split into a purl namespace, name and subpath; the
                # module path Syft reports is the comparable form.
                key = (
                    "golang",
                    f"{artifact['name']}@{str(artifact.get('version') or '').removeprefix('v').removesuffix('+incompatible')}",
                )
            if key:
                out[key[0]].add(key[1])
        return out

    @staticmethod
    def cordon(tarball: Path) -> tuple[dict[str, set[str]], float]:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        started = time.perf_counter()
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tarball)
        out: dict[str, set[str]] = defaultdict(set)
        for dependency in result.dependencies:
            if dependency.declared_in == "image-config/labels":
                continue  # the base image record: Syft does not list one
            key = Purls.key(str(dependency.purl or ""))
            if key:
                out[key[0]].add(key[1])
        return out, time.perf_counter() - started

    @staticmethod
    def compare(reference: str) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(dir="/scratch") as folder:
            tarball = Path(folder) / "image.tar"
            failed = Image.pull(reference, tarball)
            if failed:
                return {"image": reference, "error": f"pull: {failed}"}
            size = tarball.stat().st_size
            try:
                theirs = Image.syft(tarball)
                ours, seconds = Image.cordon(tarball)
            except Exception as exc:  # noqa: BLE001 - one image's failure is recorded, not fatal
                return {"image": reference, "error": f"{type(exc).__name__}: {exc}"[:400]}
        by_type: dict[str, Any] = {}
        for kind in sorted(set(ours) | set(theirs)):
            a, b = ours.get(kind, set()), theirs.get(kind, set())
            by_type[kind] = {
                "cordon": len(a), "syft": len(b), "agree": len(a & b),
                "only_cordon": sorted(a - b)[:20], "only_syft": sorted(b - a)[:20],
            }  # fmt: skip
        a_all = {(k, v) for k, vs in ours.items() for v in vs}
        b_all = {(k, v) for k, vs in theirs.items() for v in vs}
        both = len(a_all & b_all)
        precision = both / len(a_all) if a_all else float(not b_all)
        recall = both / len(b_all) if b_all else float(not a_all)
        f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
        exclusions: dict[str, int] = defaultdict(int)
        for kind, entry in a_all | b_all:
            why = Purls.excluded(kind, entry)
            if why:
                exclusions[why] += 1
        a_adj = {e for e in a_all if not Purls.excluded(*e)}
        b_adj = {e for e in b_all if not Purls.excluded(*e)}
        both_adj = len(a_adj & b_adj)
        p_adj = both_adj / len(a_adj) if a_adj else float(not b_adj)
        r_adj = both_adj / len(b_adj) if b_adj else float(not a_adj)
        f1_adj = 0.0 if p_adj + r_adj == 0 else 2 * p_adj * r_adj / (p_adj + r_adj)
        return {
            "image": reference, "bytes": size, "cordon_seconds": round(seconds, 1),
            "cordon": len(a_all), "syft": len(b_all), "agree": both,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "adjusted": {"cordon": len(a_adj), "syft": len(b_adj), "agree": both_adj, "f1": round(f1_adj, 4), "excluded": dict(exclusions)},
            "by_type": by_type,
        }  # fmt: skip

    @staticmethod
    def run(results: Path, only: list[str]) -> None:
        out_path = results / "image-agreement.json"
        rows: list[dict[str, Any]] = (
            json.loads(out_path.read_text())["images"] if out_path.exists() else []
        )
        done = {row["image"] for row in rows if "error" not in row}
        rows = [row for row in rows if row["image"] in done]
        for reference in only or IMAGES:
            if reference in done:
                continue
            row = Image.compare(reference)
            rows.append(row)
            print(
                json.dumps({k: row.get(k) for k in ("image", "cordon", "syft", "f1", "error")}),
                flush=True,
            )
            out_path.write_text(
                json.dumps({"summary": Image.summary(rows), "images": rows}, indent=1)
            )
        print(json.dumps(Image.summary(rows), indent=1))

    @staticmethod
    def summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
        compared = [r for r in rows if "f1" in r]
        types: dict[str, dict[str, int]] = defaultdict(lambda: {"cordon": 0, "syft": 0, "agree": 0})
        for row in compared:
            for kind, counts in row["by_type"].items():
                for field in ("cordon", "syft", "agree"):
                    types[kind][field] += counts[field]
        adjusted = [r["adjusted"] for r in compared if "adjusted" in r]
        excluded: dict[str, int] = defaultdict(int)
        for row in adjusted:
            for why, count in row["excluded"].items():
                excluded[why] += count
        return {
            "images": len(rows), "compared": len(compared), "errors": len(rows) - len(compared),
            "mean_f1": round(sum(r["f1"] for r in compared) / len(compared), 4) if compared else None,
            "images_at_or_above_98": sum(1 for r in compared if r["f1"] >= 0.98),
            "adjusted": {
                "mean_f1": round(sum(r["f1"] for r in adjusted) / len(adjusted), 4) if adjusted else None,
                "images_at_or_above_98": sum(1 for r in adjusted if r["f1"] >= 0.98),
                "packages": {"cordon": sum(r["cordon"] for r in adjusted), "syft": sum(r["syft"] for r in adjusted), "agree": sum(r["agree"] for r in adjusted)},
                "excluded": dict(excluded),
            },
            "packages": {"cordon": sum(r["cordon"] for r in compared), "syft": sum(r["syft"] for r in compared), "agree": sum(r["agree"] for r in compared)},
            "by_type": dict(sorted(types.items())),
        }  # fmt: skip


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--results", type=Path, default=Path("/results"))
    parser.add_argument("images", nargs="*", help="only these (default: the whole list)")
    arguments = parser.parse_args()
    Image.run(arguments.results, arguments.images)
