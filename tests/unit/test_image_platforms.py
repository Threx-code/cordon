"""A multi-platform image: every platform's operating-system packages, not only the first's.

The index of a multi-platform image lists one image per platform, and buildx adds attestation
manifests under `unknown/unknown`. Cordon read the first manifest and said the others were not
inventoried. Each platform is read now: a package on every platform is listed once, one on some
is labelled with those platforms, and an attestation manifest is never taken for a platform.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.images.oci import ImageLayers
from imagekit import ImageKit


class Layers:
    @staticmethod
    def dpkg(*packages: tuple[str, str]) -> bytes:
        status = "\n".join(ImageKit.dpkg_stanza(name, version) for name, version in packages)
        return ImageKit.layer(
            {
                "etc/os-release": b'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian 12"\n',
                "var/lib/dpkg/status": status.encode(),
            }
        )


IMAGE = ImageKit.oci_multi_platform(
    {
        "linux/amd64": [Layers.dpkg(("libc6", "2.36-9"), ("intel-microcode", "3.20240813.1"))],
        "linux/arm64/v8": [Layers.dpkg(("libc6", "2.36-9"), ("raspi-firmware", "1.20230405-1"))],
    }
)


class TestTheIndex:
    def test_every_real_platform_and_no_attestation(self) -> None:
        labels = [label for _, label in ImageLayers.platforms(IMAGE)]
        assert labels == ["linux/amd64", "linux/arm64/v8"]

    def test_each_platform_is_read_from_its_own_manifest(self) -> None:
        indices = {label: index for index, label in ImageLayers.platforms(IMAGE)}
        arm = ImageLayers.read_image(IMAGE, indices["linux/arm64/v8"])
        assert {p.name for p in arm.packages} == {"libc6", "raspi-firmware"}
        default = ImageLayers.read_image(IMAGE)
        assert {p.name for p in default.packages} == {"libc6", "intel-microcode"}

    def test_a_single_platform_image_has_no_platform_list(self) -> None:
        single = ImageKit.oci_layout([Layers.dpkg(("libc6", "2.36-9"))])
        assert ImageLayers.platforms(single) == []


class TestTheScan:
    @pytest.mark.conformance("image", "image.multi-platform")
    def test_every_platforms_packages_with_the_platforms_they_are_on(self, tmp_path) -> None:
        target = Path(tmp_path) / "image.tar"
        target.write_bytes(IMAGE)
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        found = {d.name: d.platform for d in result.dependencies if d.ecosystem == "deb"}
        assert found["libc6"] == ()  # on every platform: not labelled
        assert found["intel-microcode"] == ("platform linux/amd64",)
        assert found["raspi-firmware"] == ("platform linux/arm64/v8",)
        assert not [
            f
            for f in result.findings
            if f.rule_id == "OPERATIONAL.IMAGE.PARTIAL" and "platforms" in f.message
        ]
