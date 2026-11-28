"""`docker run` (or `podman run`) read as the image it runs and what of the host it is given. Below both the MCP configuration checks
(`configuration.py`) and the launch declarations (`mcp_servers/declarations.py`), which each need it."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

_DOCKER_VALUE_FLAGS: Final = frozenset(
    {
        "-e", "--env", "-v", "--volume", "--mount", "-p", "--publish", "--name", "--network",
        "--net", "-w", "--workdir", "-u", "--user", "--entrypoint", "--platform", "-l", "--label",
        "--env-file", "--add-host", "--cap-add", "--cap-drop", "--device", "--pid", "--ipc",
        "--security-opt", "--tmpfs", "-h", "--hostname", "-m", "--memory", "--cpus", "--gpus",
        "--restart", "--log-driver", "--runtime", "--userns", "--uts", "--ulimit", "--shm-size",
        "--dns", "--expose", "--group-add", "--health-cmd", "--label-file", "--link", "--log-opt",
        "--stop-signal", "--volumes-from", "--cgroupns", "--pull",
    }
)  # fmt: skip
_HOST_PATHS: Final = re.compile(
    r"(?i)^(?:/|/etc|/root|/home|/users|/var/run/docker\.sock|/run/docker\.sock|/proc|/sys|/boot"
    r"|c:\\?|~|\$home|\$\{home\}|%userprofile%)(?:/|\\)?$"
    r"|(?:^|/)\.(?:ssh|aws|azure|kube|docker|gnupg|config/gcloud)(?:/|$)|docker\.sock$"
)
_SOCKET_ONLY: Final = re.compile(r"(?i)docker\.sock")
_ESCAPE_CAPS: Final = frozenset(
    {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "NET_ADMIN"}
)


@dataclass(frozen=True)
class DockerLaunch:
    image: str | None
    host_access: tuple[str, ...]
    """The flags that give the container the host: privilege, host namespaces, host paths."""

    @property
    def socket_only(self) -> bool:
        """Only the Docker socket is mounted: what a Docker-management server needs to work, and
        still root-equivalent, so reviewed rather than refused."""
        return bool(self.host_access) and all(_SOCKET_ONLY.search(a) for a in self.host_access)


class DockerRuns:
    @staticmethod
    def parse(args: list[str]) -> DockerLaunch | None:
        """`docker run ...` (or `podman run`), parsed: the image, and what of the host it is given."""
        if "run" not in args:
            return None
        rest = args[args.index("run") + 1 :]
        image: str | None = None
        access: list[str] = []
        index = 0
        while index < len(rest):
            word = rest[index]
            if not word.startswith("-"):
                image = word
                break
            flag, _, inline = word.partition("=")
            value = inline
            if flag in _DOCKER_VALUE_FLAGS and not inline:
                index += 1
                value = rest[index] if index < len(rest) else ""
            if flag == "--privileged":
                access.append("--privileged")
            elif (
                flag in ("--network", "--net", "--pid", "--ipc", "--uts", "--userns")
                and value == "host"
            ):
                access.append(f"{flag}={value}")
            elif flag == "--cap-add" and value.upper().removeprefix("CAP_") in _ESCAPE_CAPS:
                access.append(f"--cap-add={value}")
            elif flag == "--security-opt" and re.search(r"(?i)unconfined|label[=:]disable", value):
                access.append(f"--security-opt={value}")
            elif flag in ("-v", "--volume"):
                source = value.split(":", 1)[0]
                if _HOST_PATHS.search(source):
                    access.append(f"{flag} {value}")
            elif flag == "--mount":
                source = next(
                    (
                        p.split("=", 1)[1]
                        for p in value.split(",")
                        if p.startswith(("source=", "src="))
                    ),
                    "",
                )
                if source and _HOST_PATHS.search(source):
                    access.append(f"--mount {value}")
            index += 1
        return DockerLaunch(image, tuple(access))


__all__ = ["DockerLaunch", "DockerRuns"]
