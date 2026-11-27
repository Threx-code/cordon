"""docker and podman through Cordon (`sources/install/managers/image.py`, `cli/commands/install/image.py`).

The registry answers are the real ones for Docker Hub's `hello-world` (`images/hello-world/CAPTURES.md`): its index,
the linux/amd64 manifest, config and layer. The registry client is the real one with only its HTTP replaced, so
digest checks, size limits and the layout are the product's own.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cordon_scanner.cli.commands.install.image import ImageTools
from cordon_scanner.intel.registries.registry_image import RegistryImage, RegistryImageError
from cordon_scanner.sources.install.managers.image import ImagePlanner
from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused
from support import ROOT

CAPTURES = ROOT / "tests" / "unit" / "sources" / "install" / "images" / "hello-world"


class Captured:
    index = (CAPTURES / "index.json").read_bytes()
    manifest = (CAPTURES / "manifest.json").read_bytes()
    config = (CAPTURES / "config.json").read_bytes()
    layer = (CAPTURES / "layer.tar.gz").read_bytes()

    @classmethod
    def digest(cls, data: bytes) -> str:
        return f"sha256:{hashlib.sha256(data).hexdigest()}"

    @classmethod
    def blobs(cls) -> dict[str, bytes]:
        document = json.loads(cls.manifest)
        return {
            document["config"]["digest"]: cls.config,
            document["layers"][0]["digest"]: cls.layer,
        }


class Response(io.BytesIO):
    def __init__(self, data: bytes, media: str) -> None:
        super().__init__(data)
        self.headers = {"Content-Type": media}


class FakeHub(RegistryImage):
    """The real client; only the HTTP is replaced by what Docker Hub served."""

    def __init__(
        self, *, layer: bytes | None = None, other: dict[str, bytes] | None = None
    ) -> None:
        super().__init__(None, "library/hello-world")
        self.layer = layer
        self.other = other or {}
        self.asked: list[str] = []

    def _open(self, url: str, accept: str | None = None) -> Any:  # type: ignore[override]
        self.asked.append(url)
        tail = url.rsplit("/", 1)[-1]
        manifests = {
            "latest": (Captured.index, "application/vnd.oci.image.index.v1+json"),
            Captured.digest(Captured.manifest): (
                Captured.manifest,
                "application/vnd.oci.image.manifest.v1+json",
            ),
            **{d: (b, "application/vnd.oci.image.manifest.v1+json") for d, b in self.other.items()},
        }
        if "/manifests/" in url and tail in manifests:
            return Response(*manifests[tail])
        blobs = Captured.blobs()
        layer_digest = json.loads(Captured.manifest)["layers"][0]["digest"]
        if "/blobs/" in url and tail in blobs:
            return Response(self.layer if tail == layer_digest and self.layer else blobs[tail], "")
        raise RegistryImageError(f"unexpected request: {url}")


class Plans:
    @staticmethod
    def make(
        text: str = "hello-world",
        daemon: str = "linux/x86_64",
        wanted: str = "",
        hub: FakeHub | None = None,
        *,
        into: Path,
    ) -> tuple[InstallPlan, Any, str]:
        command = ImagePlanner.locate(["pull", *(["--platform", wanted] if wanted else []), text])
        client = hub or FakeHub()
        return ImagePlanner.plan(
            command, daemon, into / "layout", lambda registry, repository: client
        )


class TestFindingTheImage:
    @pytest.mark.parametrize(
        ("args", "position"),
        [
            (["pull", "hello-world"], 1),
            (["image", "pull", "hello-world:1"], 2),
            (["run", "hello-world"], 1),
            (["run", "--rm", "-it", "-p", "80:80", "--name=x", "nginx", "sleep", "1"], 6),
            (["run", "-itd", "nginx"], 2),
            (["run", "-e", "A=b", "nginx"], 3),
            (["run", "-eA=b", "nginx"], 2),
            (["container", "create", "--network", "host", "nginx"], 4),
            (["run", "--", "nginx"], 2),
            (["pull", "-q", "--disable-content-trust", "nginx"], 3),
        ],
    )
    def test_the_image_is_the_first_word_after_the_options(
        self, args: list[str], position: int
    ) -> None:
        assert ImagePlanner.installs(args)
        assert ImagePlanner.locate(args).position == position

    @pytest.mark.parametrize(
        "args",
        [["images"], ["ps", "-a"], ["build", "."], ["image", "ls"], ["version"], ["tag", "a", "b"]],
    )
    def test_other_commands_are_not_installs(self, args: list[str]) -> None:
        assert not ImagePlanner.installs(args)

    def test_an_option_it_does_not_know_could_hide_the_image_and_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match="does not know the option --frobnicate"):
            ImagePlanner.locate(["run", "--frobnicate", "nginx"])

    def test_an_unknown_short_option_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match="does not know the option -itz"):
            ImagePlanner.locate(["run", "-itz", "nginx"])

    def test_an_option_before_the_command_is_refused_not_skipped(self) -> None:
        args = ["-H", "tcp://example.invalid:2375", "run", "nginx"]
        assert ImagePlanner.installs(args)
        with pytest.raises(InstallRefused, match="DOCKER_HOST"):
            ImagePlanner.locate(args)

    def test_a_global_option_with_no_install_word_is_not_an_install(self) -> None:
        assert not ImagePlanner.installs(["--version"])

    def test_all_tags_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match="every tag"):
            ImagePlanner.locate(["pull", "-a", "nginx"])

    def test_a_command_with_no_image_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match="names no image"):
            ImagePlanner.locate(["pull", "-q"])

    def test_the_platform_asked_for_is_read_in_either_spelling(self) -> None:
        assert (
            ImagePlanner.locate(["pull", "--platform", "linux/arm64", "x"]).platform
            == "linux/arm64"
        )
        assert ImagePlanner.locate(["run", "--platform=linux/arm64", "x"]).platform == "linux/arm64"

    def test_only_the_image_word_is_replaced(self) -> None:
        args = ["run", "--rm", "nginx", "nginx", "-g"]
        command = ImagePlanner.locate(args)
        assert ImagePlanner.arguments(args, command, "nginx@sha256:ab") == [
            "run", "--rm", "nginx@sha256:ab", "nginx", "-g",
        ]  # fmt: skip


class TestTheName:
    def test_a_tag_and_a_digest_are_told_apart(self) -> None:
        digest = "sha256:" + "ab" * 32
        assert ImagePlanner.parse("nginx").reference == "latest"
        assert ImagePlanner.parse("nginx:1.27").reference == "1.27"
        pinned = ImagePlanner.parse(f"nginx@{digest}")
        assert (pinned.pinned, pinned.reference) == (True, digest)

    def test_a_registry_with_a_port_is_not_taken_for_a_tag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.intel.registries.archive_sources.hosts import PublicHost

        # A public host is one that resolves to a public address; the test has no network.
        monkeypatch.setattr(PublicHost, "ok", classmethod(lambda cls, host: True))
        image = ImagePlanner.parse("ghcr.io/acme/tool:2")
        assert (image.registry, image.repository, image.reference) == ("ghcr.io", "acme/tool", "2")

    def test_an_official_image_lives_under_library(self) -> None:
        assert ImagePlanner.parse("hello-world").repository == "library/hello-world"

    def test_a_short_digest_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match="sha256 digest"):
            ImagePlanner.parse("nginx@sha256:abc")

    def test_a_private_host_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match="not an image name"):
            ImagePlanner.parse("192.168.0.4/acme/tool")

    def test_a_pull_leaves_the_tag_that_was_asked_for(self) -> None:
        image = ImagePlanner.parse("hello-world")
        assert ImagePlanner.pinned(image, "sha256:ab") == "hello-world@sha256:ab"
        assert ImagePlanner.tagged(image) == "hello-world:latest"
        assert ImagePlanner.tagged(ImagePlanner.parse("hello-world@sha256:" + "ab" * 32)) is None


class TestThePlan:
    def test_the_manifest_for_the_runtimes_platform_is_the_one_pinned(self, tmp_path: Path) -> None:
        plan, image, digest = Plans.make(into=tmp_path)
        assert digest == Captured.digest(Captured.manifest)
        assert image.repository == "library/hello-world"
        assert plan.ecosystem == "image" and not plan.files
        assert [p.name for p in plan.local] == ["layout"]

    def test_the_layout_holds_the_manifest_config_and_layer_by_their_digests(
        self, tmp_path: Path
    ) -> None:
        plan, _, digest = Plans.make(into=tmp_path)
        with tarfile.open(plan.local[0] / "image.tar") as archive:
            names = set(archive.getnames())
            layout = json.loads(archive.extractfile("index.json").read())  # type: ignore[union-attr]
        expected = {"oci-layout", "index.json"} | {
            f"blobs/sha256/{d.partition(':')[2]}" for d in (digest, *Captured.blobs())
        }
        assert names == expected
        assert layout["manifests"][0]["digest"] == digest

    def test_only_the_chosen_platform_is_downloaded(self, tmp_path: Path) -> None:
        hub = FakeHub()
        Plans.make(hub=hub, into=tmp_path)
        assert sum("/blobs/" in url for url in hub.asked) == 2
        assert sum("/manifests/" in url for url in hub.asked) == 2

    def test_a_platform_asked_for_overrides_the_runtimes(self, tmp_path: Path) -> None:
        arm = next(
            d
            for d in json.loads(Captured.index)["manifests"]
            if d["platform"]["os"] == "linux" and d["platform"]["architecture"] == "arm64"
        )["digest"]
        hub = FakeHub(other={arm: Captured.manifest.replace(b"amd64", b"arm64")})
        with pytest.raises(InstallRefused, match="not that manifest"):
            Plans.make(wanted="linux/arm64", hub=hub, into=tmp_path)
        assert any(url.endswith(arm) for url in hub.asked)

    def test_an_image_with_no_build_for_the_platform_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match="no linux/sparc64 build"):
            Plans.make(daemon="linux/sparc64", into=tmp_path)

    def test_a_runtime_that_will_not_say_its_platform_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match="--platform"):
            Plans.make(daemon="", into=tmp_path)

    def test_a_layer_that_is_not_the_one_named_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match="do not match its digest"):
            Plans.make(hub=FakeHub(layer=Captured.layer + b"x"), into=tmp_path)

    def test_the_layout_is_private(self, tmp_path: Path) -> None:
        plan, _, _ = Plans.make(into=tmp_path)
        assert (plan.local[0] / "image.tar").stat().st_mode & 0o077 == 0


class FakeContext:
    """What the command layer gives the handler: it records what was checked and what was run."""

    def __init__(self, *, ok: bool = True) -> None:
        self.ok = ok
        self.checked: list[list[str]] = []
        self.ran: list[list[str]] = []
        self.blocked_with: list[object] = []

    def check(self, plan: InstallPlan, scratch: Path) -> Any:
        self.checked.append(sorted(p.name for p in plan.local[0].iterdir()))
        return SimpleNamespace(ok=self.ok)

    def blocked(self, verdict: object) -> int:
        self.blocked_with.append(verdict)
        return 2

    def run(
        self, argv: list[str], cwd: Path | None = None, env: dict[str, str] | None = None
    ) -> int:
        self.ran.append(list(argv))
        return 0


class TestTheCommand:
    DIGEST = Captured.digest(Captured.manifest)

    @pytest.fixture(autouse=True)
    def _hub(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            ImagePlanner, "registry", staticmethod(lambda registry, repository: FakeHub())
        )
        monkeypatch.setattr(ImageTools, "platform", classmethod(lambda cls, runtime: "linux/amd64"))

    def test_a_pull_pulls_the_digest_that_was_scanned_then_restores_the_tag(self) -> None:
        context = FakeContext()
        assert ImageTools.docker("/usr/bin/docker", ["pull", "hello-world"], context) == 0  # type: ignore[arg-type]
        assert context.checked == [["image.tar"]]
        assert context.ran == [
            ["/usr/bin/docker", "pull", f"hello-world@{self.DIGEST}"],
            ["/usr/bin/docker", "tag", f"hello-world@{self.DIGEST}", "hello-world:latest"],
        ]

    def test_a_run_runs_the_digest_that_was_scanned_with_its_other_words_untouched(self) -> None:
        context = FakeContext()
        args = ["run", "--rm", "-p", "80:80", "hello-world", "hello-world", "--flag"]
        ImageTools.docker("/usr/bin/docker", args, context)  # type: ignore[arg-type]
        assert context.ran == [
            ["/usr/bin/docker", "run", "--rm", "-p", "80:80", f"hello-world@{self.DIGEST}",
             "hello-world", "--flag"],
        ]  # fmt: skip

    def test_a_block_runs_nothing(self) -> None:
        context = FakeContext(ok=False)
        assert ImageTools.docker("/usr/bin/docker", ["pull", "hello-world"], context) == 2  # type: ignore[arg-type]
        assert context.ran == []

    def test_an_image_pulled_by_digest_is_not_retagged(self) -> None:
        context = FakeContext()
        ImageTools.docker("/usr/bin/docker", ["pull", f"hello-world@{self.DIGEST}"], context)  # type: ignore[arg-type]
        assert len(context.ran) == 1

    def test_a_refused_image_runs_nothing(self) -> None:
        context = FakeContext()
        with pytest.raises(InstallRefused):
            ImageTools.docker("/usr/bin/docker", ["run", "--frobnicate", "hello-world"], context)  # type: ignore[arg-type]
        assert context.ran == []


class TestTheScan:
    def test_the_scanner_reads_the_layout_and_the_real_image_passes(self, tmp_path: Path) -> None:
        from cordon_scanner.cli.commands.install.context import InstallContext
        from cordon_scanner.foundation.config.settings import Config

        plan, _, _ = Plans.make(into=tmp_path)
        assert InstallContext.scanner(Config.default())(plan.local[0]) == ()
