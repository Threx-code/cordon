"""Container images (`docker pull|run|create`, `podman` the same): the image's manifest, config and layers
scanned before the daemon pulls them.

An image is content-addressed, so what Cordon checks is exact. The image name is resolved against its
registry to one manifest (an index is narrowed to the daemon's platform), the manifest's config and every
layer are fetched and held to the sha256 the manifest names, the whole is laid out as an OCI image and
scanned, and only then is the command run -- with the image named by that manifest's digest, so the daemon
pulls the bytes that were scanned and nothing a tag moved to in between. `docker pull name:tag` is followed
by `docker tag` so the person still has the tag they asked for.

The image is found in the command line by a table of the options that take a value: an option Cordon does
not know could swallow the image's place, so it is refused rather than guessed at. Credentials are never
read: a registry that wants them is one the person pulls from themselves and scans with `docker save`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from cordon_scanner.intel.registries.registry_image import RegistryImage


@dataclass(frozen=True)
class ImageCommand:
    """A pull, run or create command line: where its image is, and what it asks for."""

    verb: str
    position: int
    text: str
    platform: str = ""


@dataclass(frozen=True)
class ImageName:
    registry: str | None
    repository: str
    #: A tag, or the digest the person pinned (`sha256:...`).
    reference: str
    pinned: bool
    #: The name as typed, without its tag or digest: what the digest is appended to.
    name: str


class ImagePlanner:
    #: `docker image pull`, `docker container run`: the group word, then the verb.
    GROUPS: ClassVar[dict[str, frozenset[str]]] = {
        "image": frozenset({"pull"}),
        "container": frozenset({"run", "create"}),
    }
    VERBS: ClassVar[frozenset[str]] = frozenset({"pull", "run", "create"})

    SHORT_FLAGS: ClassVar[frozenset[str]] = frozenset("diItPq")
    SHORT_VALUED: ClassVar[frozenset[str]] = frozenset("epvwuhmlaE")
    LONG_FLAGS: ClassVar[frozenset[str]] = frozenset(
        {
            "detach", "interactive", "tty", "rm", "publish-all", "init", "privileged", "read-only",
            "quiet", "disable-content-trust", "oom-kill-disable", "no-healthcheck", "sig-proxy",
            "help",
        }
    )  # fmt: skip
    LONG_VALUED: ClassVar[frozenset[str]] = frozenset(
        {
            "name", "env", "publish", "volume", "network", "net", "workdir", "user", "entrypoint",
            "hostname", "restart", "memory", "cpus", "env-file", "label", "label-file", "mount",
            "platform", "add-host", "dns", "dns-search", "dns-option", "cap-add", "cap-drop",
            "device", "pull", "security-opt", "tmpfs", "log-driver", "log-opt", "shm-size",
            "ulimit", "pid", "ipc", "uts", "gpus", "userns", "runtime", "stop-signal",
            "stop-timeout", "expose", "link", "group-add", "health-cmd", "health-interval",
            "health-retries", "health-timeout", "health-start-period", "memory-swap",
            "memory-reservation", "cpu-shares", "cpuset-cpus", "cgroupns", "ip", "ip6",
            "mac-address", "domainname", "volumes-from", "detach-keys", "attach", "annotation",
            "cidfile", "cgroup-parent", "pids-limit", "sysctl", "storage-opt", "isolation",
        }
    )  # fmt: skip
    #: Refused: it pulls every tag of a repository, and each would have to be checked.
    ALL_TAGS: ClassVar[frozenset[str]] = frozenset({"-a", "--all-tags"})

    @classmethod
    def installs(cls, args: Sequence[str]) -> bool:
        if args and args[0].startswith("-"):
            # A global option ahead of the command (`docker -H host run ...`): the command is somewhere
            # after it, and `locate` refuses rather than guess where.
            return any(a in cls.VERBS or a in cls.GROUPS for a in args)
        if len(args) >= 2 and args[0] in cls.GROUPS:
            return args[1] in cls.GROUPS[args[0]]
        return bool(args) and args[0] in cls.VERBS

    @classmethod
    def locate(cls, args: Sequence[str]) -> ImageCommand:
        """The verb, and where the image sits among the arguments. Fails closed on an option it does
        not know, since that option could take the image's place as its value."""
        if args[0].startswith("-"):
            raise InstallRefused(
                "an option before the command (`docker -H host run ...`) is not read by Cordon: set it "
                "in the environment instead (DOCKER_HOST, DOCKER_CONTEXT, DOCKER_CONFIG)"
            )
        start = 2 if len(args) >= 2 and args[0] in cls.GROUPS else 1
        verb = args[start - 1]
        platform = ""
        at = start
        while at < len(args):
            word = args[at]
            if word == "--":
                at += 1
                break
            if not word.startswith("-") or word == "-":
                break
            if word in cls.ALL_TAGS:
                raise InstallRefused(
                    "`pull --all-tags` fetches every tag of a repository; Cordon checks one image: "
                    "name the tag you want"
                )
            consumed, value = cls._option(word, args[at + 1 : at + 2])
            if value is not None and word.lstrip("-").split("=", 1)[0] == "platform":
                platform = value
            at += 1 + consumed
        if at >= len(args):
            raise InstallRefused(f"`{verb}` names no image Cordon can find in this command line")
        return ImageCommand(verb, at, args[at], platform)

    @classmethod
    def _option(cls, token: str, following: Sequence[str]) -> tuple[int, str | None]:
        """How many following arguments the option takes, and its value when it has one."""
        if token.startswith("--"):
            name, equals, value = token[2:].partition("=")
            if name in cls.LONG_FLAGS and not equals:
                return 0, None
            if name in cls.LONG_FLAGS and equals:
                return 0, value
            if name in cls.LONG_VALUED:
                if equals:
                    return 0, value
                return (1, following[0]) if following else (0, "")
            raise cls._unknown(token)
        letters = token[1:]
        for number, letter in enumerate(letters):
            if letter in cls.SHORT_FLAGS:
                continue
            if letter in cls.SHORT_VALUED:
                attached = letters[number + 1 :]
                if attached:
                    return 0, attached
                return (1, following[0]) if following else (0, "")
            raise cls._unknown(token)
        return 0, None

    @staticmethod
    def _unknown(token: str) -> InstallRefused:
        return InstallRefused(
            f"Cordon does not know the option {token.split('=')[0]}, and it could be taking the "
            "image's place on this command line, so it cannot say which image will be pulled. "
            "Write the option as --name=value, or pull the image first with `pull IMAGE` through Cordon"
        )

    @staticmethod
    def parse(text: str) -> ImageName:
        """`[registry/]repository[:tag][@sha256:digest]` as the registry client reads it."""
        from cordon_scanner.intel.registries.archive_sources.oci import ImageRef

        name, at, digest = text.partition("@")
        last = name.rpartition("/")[2]
        tag = ""
        if ":" in last:
            name, _, tag = name.rpartition(":")
        found = ImageRef.of(name)
        if found is None:
            raise InstallRefused(
                f"{text} is not an image name Cordon can check (a public registry's, in lower case)"
            )
        if at:
            if digest.partition(":")[0] != "sha256" or len(digest.partition(":")[2]) != 64:
                raise InstallRefused(f"{text}: only a sha256 digest can pin an image")
            return ImageName(found[0], found[1], digest, True, name)
        return ImageName(found[0], found[1], tag or "latest", False, name)

    @staticmethod
    def registry(registry: str | None, repository: str) -> RegistryImage:
        from cordon_scanner.intel.registries.registry_image import RegistryImage

        return RegistryImage(registry, repository)

    @classmethod
    def platform_of(cls, wanted: str, daemon: str) -> tuple[str, str, str]:
        """`(os, architecture, variant)` of the platform to pull: the one asked for, else the daemon's."""
        text = wanted or daemon
        parts = text.strip().lower().split("/")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            raise InstallRefused(
                "could not tell which platform the container runtime pulls for "
                f"({text!r}); name it with --platform os/arch"
            )
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(parts[1], parts[1])
        return parts[0], arch, parts[2] if len(parts) > 2 else ""

    @classmethod
    def plan(
        cls,
        command: ImageCommand,
        daemon: str,
        directory: Path,
        make: Callable[[str | None, str], RegistryImage] | None = None,
    ) -> tuple[InstallPlan, ImageName, str]:
        """The checked image as an OCI layout in `directory`, the name, and the manifest digest to pin."""
        from cordon_scanner.intel.registries.registry_image import (
            Pull,
            RegistryImage,
            RegistryImageError,
        )

        image = cls.parse(command.text)
        platform = cls.platform_of(command.platform, daemon)
        client = (make or cls.registry)(image.registry, image.repository)
        try:
            body, media = client.manifest(image.reference)
            document = json.loads(body)
            if "manifests" in document:
                digest = cls.choose(document, platform)
                body, media = client.manifest(digest)
                document = json.loads(body)
            else:
                digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
            if not isinstance(document.get("config"), dict) or "layers" not in document:
                raise InstallRefused(
                    f"{command.text} is an image manifest Cordon cannot read the layers of"
                )
            pull = Pull()
            pull.blobs[digest] = body
            client.image(body, pull)
        except RegistryImageError as exc:
            raise InstallRefused(str(exc)) from exc
        layout = RegistryImage.write_layout(
            {"schemaVersion": 2, "manifests": [{"digest": digest, "mediaType": media}]}, pull.blobs
        )
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = directory / "image.tar"
        target.write_bytes(layout)
        target.chmod(0o600)
        return InstallPlan("image", local=[directory]), image, digest

    @classmethod
    def choose(cls, index: dict[str, object], platform: tuple[str, str, str]) -> str:
        """The digest of the index's manifest for `platform`. Attestation manifests are not platforms."""
        wanted_os, wanted_arch, wanted_variant = platform
        entries = index.get("manifests")
        for entry in entries if isinstance(entries, list) else ():
            found = entry.get("platform") if isinstance(entry, dict) else None
            if not isinstance(found, dict):
                continue
            same = found.get("os") == wanted_os and found.get("architecture") == wanted_arch
            if same and (not wanted_variant or found.get("variant") == wanted_variant):
                return str(entry.get("digest", ""))
        raise InstallRefused(
            f"the image has no {wanted_os}/{wanted_arch} build, which is what the container runtime pulls"
        )

    @staticmethod
    def pinned(image: ImageName, digest: str) -> str:
        """The image named by the manifest that was scanned."""
        return f"{image.name}@{digest}"

    @staticmethod
    def tagged(image: ImageName) -> str | None:
        """The name a `pull` leaves on the machine (None for an image pulled by digest)."""
        return None if image.pinned else f"{image.name}:{image.reference}"

    @classmethod
    def arguments(cls, args: Sequence[str], command: ImageCommand, pinned: str) -> list[str]:
        """The command line, with the image named by the scanned manifest's digest."""
        out = list(args)
        out[command.position] = pinned
        return out


__all__ = ["ImageCommand", "ImageName", "ImagePlanner"]
