"""The workload policies: Kubernetes and Compose workloads, Dockerfiles and deprecated runtimes --
what runs, with what privileges, on what base.
"""

from __future__ import annotations

from cordon_scanner.detect.infra.policy_terms import HIGH, LOW, MEDIUM
from cordon_scanner.foundation.models import Category, Severity

WORKLOAD_KINDS = (
    "k8s:Pod",
    "k8s:Deployment",
    "k8s:StatefulSet",
    "k8s:DaemonSet",
    "k8s:Job",
    "k8s:CronJob",
    "k8s:ReplicaSet",
    "k8s:ReplicationController",
)

K8S: tuple[tuple[str, str, str, Severity, Category, str, str, str, str], ...] = (
    (
        "HOST_NETWORK",
        "hostNetwork",
        r"hostNetwork:\s*true",
        HIGH,
        Category.SUSPICIOUS,
        "the pod shares the node's network namespace",
        "The pod sees and can bind every interface on the node, reach services that "
        "trust the node's address, and read traffic that was never meant to leave it. "
        "Network policy does not apply to it.",
        "Remove `hostNetwork: true`.",
        "hostNetwork",
    ),
    (
        "HOST_PID",
        "hostPID",
        r"hostPID:\s*true",
        HIGH,
        Category.SUSPICIOUS,
        "the pod shares the node's process namespace",
        "The container sees every process on the node, can read their memory and "
        "environment -- where credentials live -- and can signal them.",
        "Remove `hostPID: true`.",
        "hostPID",
    ),
    (
        "HOST_IPC",
        "hostIPC",
        r"hostIPC:\s*true",
        MEDIUM,
        Category.SUSPICIOUS,
        "the pod shares the node's IPC namespace",
        "Shared memory belonging to other workloads on the node is readable and "
        "writable from this one.",
        "Remove `hostIPC: true`.",
        "hostIPC",
    ),
    (
        "PRIVILEGED",
        "privileged",
        r"privileged:\s*true",
        HIGH,
        Category.SUSPICIOUS,
        "a container runs privileged",
        "A privileged container has the node's full capability set and access to its "
        "devices. It is a container boundary in name only: escaping to the node is a "
        "documented one-liner.",
        "Remove `privileged: true` and grant the specific capabilities the workload needs.",
        "privileged",
    ),
    (
        "PRIVILEGE_ESCALATION",
        "allowPrivilegeEscalation",
        r"allowPrivilegeEscalation:\s*true",
        MEDIUM,
        Category.SUSPICIOUS,
        "a container may gain more privileges than it started with",
        "A setuid binary or a file capability inside the image can raise the "
        "container's privileges at runtime, past whatever the manifest granted.",
        "Set `allowPrivilegeEscalation: false`.",
        "allowPrivilegeEscalation",
    ),
    (
        "RUN_AS_ROOT",
        "runAsUser",
        r"runAsUser:\s*0\b",
        MEDIUM,
        Category.SUSPICIOUS,
        "a container runs as uid 0",
        "Root in the container is root on the node for every resource the container "
        "boundary does not cover, and it removes the last barrier after a container "
        "escape.",
        "Run as a non-zero uid and set `runAsNonRoot: true`.",
        "runAsUser",
    ),
    (
        "DANGEROUS_CAPABILITY",
        "capabilities",
        r"add:[\s\S]{0,60}?\b(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|ALL)\b",
        HIGH,
        Category.SUSPICIOUS,
        "a container is granted a capability that defeats isolation",
        "SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE and DAC_READ_SEARCH each "
        "provide a documented path out of the container or into another workload's "
        "memory.",
        "Drop ALL and add back only the capabilities the workload cannot run without.",
        "capabilities",
    ),
    (
        "WRITABLE_ROOT",
        "readOnlyRootFilesystem",
        r"readOnlyRootFilesystem:\s*false",
        LOW,
        Category.POLICY,
        "the container's root filesystem is writable",
        "A writable root filesystem lets anything that executes in the container "
        "persist a payload for the life of the pod, and hides it from an image scan.",
        "Set `readOnlyRootFilesystem: true` and mount a volume for the paths that "
        "genuinely need writing.",
        "readOnlyRootFilesystem",
    ),
    (
        "LATEST_TAG",
        "image",
        r"image:\s*[^\s\"']+:latest\b",
        MEDIUM,
        Category.POLICY,
        "a container image is pinned to :latest",
        "What runs is whatever that tag pointed at when the node last pulled, which "
        "is not recorded anywhere and differs between nodes.",
        "Pin the image by digest, or at least by an immutable version tag.",
        "image",
    ),
    (
        "AUTOMOUNT_TOKEN",
        "automountServiceAccountToken",
        r"automountServiceAccountToken:\s*true",
        LOW,
        Category.POLICY,
        "the service account token is mounted into the pod",
        "Anything that executes in the pod can read the token and call the API server "
        "as the service account, which is the first step in most cluster-level "
        "escalations.",
        "Set `automountServiceAccountToken: false` for workloads that do not call the API server.",
        "automountServiceAccountToken",
    ),
    (
        "HOST_PATH",
        "hostPath",
        r"hostPath:",
        HIGH,
        Category.SUSPICIOUS,
        "a host directory is mounted into the pod",
        "The container reads and writes the node's own filesystem. A mount of `/`, "
        "`/etc`, `/var/run` or the kubelet's directory is a direct path to the node "
        "and to every other pod's secrets.",
        "Use a volume type that does not reach the node, or restrict the path and "
        "mount it read-only.",
        "hostPath",
    ),
)

COMPOSE: tuple[tuple[str, str, str, Severity, str, str, str, str], ...] = (
    (
        "PRIVILEGED",
        r"privileged:\s*true",
        "privileged: true",
        HIGH,
        "the service runs privileged",
        "A privileged container has the host's capabilities and its devices. On a "
        "developer machine that is the machine; in a pipeline it is the runner.",
        "Remove `privileged: true`.",
        "privileged: false",
    ),
    (
        "DOCKER_SOCKET",
        r"/var/run/docker\.sock",
        "- /var/run/docker.sock:/var/run/docker.sock",
        HIGH,
        "the Docker socket is mounted into the service",
        "Access to the daemon socket is equivalent to root on the host: a container "
        "with it can start another container that mounts the host filesystem.",
        "Do not mount the socket. If the service must orchestrate containers, give it "
        "a scoped API proxy instead.",
        "- ./data:/data",
    ),
    (
        "HOST_NETWORK",
        r"network_mode:\s*[\"']?host",
        "network_mode: host",
        MEDIUM,
        "the service shares the host network namespace",
        "The container binds and reads the host's interfaces directly, so published "
        "ports and network isolation both stop applying.",
        "Use the default bridge network and publish the ports the service needs.",
        "network_mode: bridge",
    ),
    (
        "DANGEROUS_CAPABILITY",
        r"cap_add:[\s\S]{0,60}?\b(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|ALL)\b",
        "cap_add:\n      - SYS_ADMIN",
        HIGH,
        "the service is granted a capability that defeats isolation",
        "SYS_ADMIN and its neighbours each provide a documented path out of the container.",
        "Drop all capabilities and add back only what the service cannot run without.",
        "cap_drop:\n      - ALL",
    ),
)

DEPRECATED_RUNTIMES: tuple[tuple[str, str, str, Severity, str, str], ...] = (
    (
        "aws_lambda_function",
        "runtime",
        r"runtime\s*=\s*\"(?:nodejs(?:|4\.3|6\.10|8\.10|10\.x|12\.x|14\.x|16\.x)"
        r"|python(?:2\.7|3\.6|3\.7|3\.8)|ruby2\.[57]|dotnetcore[0-9.]*|go1\.x)\"",
        MEDIUM,
        '  function_name = "example"\n  runtime = "python3.8"\n',
        '  function_name = "example"\n  runtime = "python3.12"\n',
    ),
    (
        "azurerm_linux_function_app",
        "python_version",
        r"python_version\s*=\s*\"3\.[678]\"",
        MEDIUM,
        '  name = "example"\n  site_config {\n    application_stack {\n      python_version = "3.8"\n    }\n  }\n',
        '  name = "example"\n  site_config {\n    application_stack {\n      python_version = "3.12"\n    }\n  }\n',
    ),
    (
        "google_cloudfunctions_function",
        "runtime",
        r"runtime\s*=\s*\"(?:nodejs(?:6|8|10|12|14)|python3[67]|go11[13])\"",
        MEDIUM,
        '  name = "example"\n  runtime = "python37"\n',
        '  name = "example"\n  runtime = "python312"\n',
    ),
    (
        "aws_elastic_beanstalk_environment",
        "solution_stack_name",
        r"solution_stack_name\s*=\s*\"[^\"]*(?:Node\.js 1[0-4]|Python 3\.[678]|PHP 7\.[0-4])",
        MEDIUM,
        '  name = "example"\n  solution_stack_name = "64bit Amazon Linux 2 v5.4.0 running Python 3.7"\n',
        '  name = "example"\n  solution_stack_name = "64bit Amazon Linux 2023 v4.0.0 running Python 3.12"\n',
    ),
)

DOCKERFILE: tuple[tuple[str, str, str, Severity, Category, str, str, str, str, str], ...] = (
    (
        "ROOT_USER",
        "USER",
        r"(?m)^\s*USER\s+(?:root|0)\s*$",
        MEDIUM,
        Category.POLICY,
        "the image runs as root",
        "Everything the container executes runs as uid 0. A container escape, a "
        "mounted volume or a shared kernel namespace then reaches the host as root, "
        "and nothing inside the image constrains it.",
        "Create a user and end the build with `USER app`.",
        'FROM debian:12\nUSER root\nCMD ["/app"]\n',
        'FROM debian:12\nRUN useradd -m app\nUSER app\nCMD ["/app"]\n',
    ),
    (
        "ADD_REMOTE",
        "ADD",
        r"(?m)^\s*ADD\s+https?://",
        MEDIUM,
        Category.SUSPICIOUS,
        "the build downloads a URL with ADD",
        "`ADD` with a URL fetches whatever the host serves at build time, with no "
        "digest and no record of what arrived. `COPY` cannot do this, which is the "
        "reason to prefer it.",
        "Download in a `RUN` step that verifies a checksum, or vendor the file and COPY it.",
        "FROM debian:12\nADD https://example.invalid/tool.tar.gz /tmp/\n",
        "FROM debian:12\nCOPY tool.tar.gz /tmp/\n",
    ),
    (
        "SUDO",
        "RUN",
        r"(?m)^\s*RUN\s+[^\n]*\bsudo\b",
        LOW,
        Category.POLICY,
        "the build uses sudo",
        "A build already runs as root unless told otherwise, so `sudo` in a Dockerfile "
        "means the image ships a setuid path that a compromised process inside it can "
        "use.",
        "Drop `sudo` and switch users with `USER` instead.",
        "FROM debian:12\nRUN sudo apt-get update\n",
        "FROM debian:12\nRUN apt-get update\n",
    ),
    (
        "SECRET_ARG",
        "ARG",
        # A whole-word secret name -- `TIKTOKEN_CACHE_DIR` is not a token -- given a literal value
        # on its own line: not empty, not a `$VARIABLE` handed through.
        r"(?mi)^[ \t]{0,16}(?:ARG|ENV)[ \t]{1,8}(?:[A-Z0-9]{1,40}_){0,6}"
        r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY)(?:_[A-Z0-9]{1,40}){0,6}"
        r"(?:[ \t]{0,4}=[ \t]{0,4}|[ \t]{1,4})[\"']?[^\s\"'$]{4,200}",
        HIGH,
        Category.SUSPICIOUS,
        "a credential is baked into the image",
        "A value passed as ARG or set as ENV is recorded in the image's layer history "
        "and is readable by anyone who can pull the image, whether or not the final "
        "stage still uses it.",
        "Use a build secret mount (`RUN --mount=type=secret`) or inject the value at run time.",
        "FROM debian:12\nENV API_KEY=sk-live-aaaaaaaaaaaa\n",
        'FROM debian:12\nENV OPENAI_API_KEY=""\nENV TIKTOKEN_CACHE_DIR=/app/.tiktoken\n'
        "ARG GITHUB_TOKEN\nENV TOKEN=$GITHUB_TOKEN\n",
    ),
    (
        "SECRET_ARG_DECLARED",
        "ARG",
        # Declared, not given: the value arrives with `--build-arg` and still lands in the
        # image's history. Docker's own build check reports this shape as a warning.
        r"(?mi)^[ \t]{0,16}ARG[ \t]{1,8}(?:[A-Z0-9]{1,40}_){0,6}"
        r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY)(?:_[A-Z0-9]{1,40}){0,6}[ \t]{0,8}$",
        MEDIUM,
        Category.POLICY,
        "a credential is passed as a build argument",
        "A `--build-arg` value is recorded in the image's build history, so a token passed "
        "this way is readable by anyone who can pull the image.",
        "Use a build secret mount (`RUN --mount=type=secret`) instead of an ARG.",
        "FROM debian:12\nARG GITHUB_TOKEN\nRUN git clone https://$GITHUB_TOKEN@example.invalid/r\n",
        "FROM debian:12\nARG VERSION\nRUN --mount=type=secret,id=gh git clone https://example.invalid/r\n",
    ),
    (
        "NO_HEALTHCHECK",
        "HEALTHCHECK",
        r"HEALTHCHECK",
        LOW,
        Category.POLICY,
        "the image serves a port and declares no health check",
        "An orchestrator cannot tell a hung container from a working one, so a "
        "process that has stopped serving keeps receiving traffic.",
        "Add a `HEALTHCHECK` instruction that exercises the service rather than the process.",
        'FROM debian:12\nEXPOSE 8080\nCMD ["/app"]\n',
        'FROM debian:12\nEXPOSE 8080\nHEALTHCHECK CMD curl -f http://localhost/health\nCMD ["/app"]\n',
    ),
)

K8S_EXTRA: tuple[tuple[str, str, str, Severity, Category, str, str, str, str], ...] = (
    (
        "NO_RESOURCE_LIMITS",
        "limits",
        r"limits:",
        LOW,
        Category.POLICY,
        "no resource limits are set",
        "A container with no limit can consume the node's whole CPU and memory. One "
        "workload -- or one runaway dependency inside it -- then evicts everything "
        "else scheduled there.",
        "Set `resources.limits` for cpu and memory.",
        "limits",
    ),
    (
        "DEFAULT_SERVICE_ACCOUNT",
        "serviceAccountName",
        r"serviceAccountName:",
        LOW,
        Category.POLICY,
        "the workload uses the namespace's default service account",
        "The default account is shared by everything in the namespace, so a "
        "permission granted for one workload is granted to all of them.",
        "Create a service account for this workload and name it here.",
        "serviceAccountName",
    ),
    (
        "HOST_PORT",
        "hostPort",
        r"hostPort:\s*\d+",
        MEDIUM,
        Category.SUSPICIOUS,
        "a container binds a port on the node",
        "A host port bypasses the Service layer and network policy, and it reserves "
        "that port on every node the pod can be scheduled to.",
        "Expose the container through a Service instead.",
        "hostPort",
    ),
    (
        "NO_RUN_AS_NON_ROOT",
        "runAsNonRoot",
        r"runAsNonRoot:\s*true",
        LOW,
        Category.POLICY,
        "nothing requires the container to run as a non-root user",
        "Without `runAsNonRoot: true` the kubelet accepts an image whose default user "
        "is root, so the manifest's intent depends on what the image happens to do.",
        "Set `runAsNonRoot: true` in the pod or container securityContext.",
        "runAsNonRoot",
    ),
    (
        "NO_SECCOMP",
        "seccompProfile",
        r"seccompProfile:",
        LOW,
        Category.POLICY,
        "no seccomp profile is applied",
        "Without a profile the container may issue any syscall the kernel offers, "
        "which is the surface most container escapes are written against.",
        "Set `seccompProfile.type: RuntimeDefault`.",
        "seccompProfile",
    ),
    (
        "SECRET_ENV_VALUE",
        "env",
        # Not a name for where the credential is: `POSTGRES_PASSWORD_FILE` is the convention for
        # "read it from this mounted file" (Docker's official images), and caveman's
        # `CAVEMAN_MIDDLEWARE_TOKEN_MAP_FILE: /etc/caveman/identity/tokens.yaml` was reported.
        r"(?mi)^\s*-?\s*name:\s*[A-Z_]*(?:PASSWORD|SECRET|TOKEN|API_KEY)[A-Z_]*"
        r"(?<!_FILE)(?<!_PATH)(?<!_DIR)\s*\n\s*value:\s*\S+",
        HIGH,
        Category.SUSPICIOUS,
        "a credential is written into the manifest",
        "An environment variable with a literal value lives in the manifest, in the "
        "repository and in every copy of both. It is readable by anyone who can read "
        "the cluster's resources, and rotating it is a code change.",
        "Reference a Secret with `valueFrom.secretKeyRef`, or an external secret store.",
        "env",
    ),
)


__all__ = ["COMPOSE", "DEPRECATED_RUNTIMES", "DOCKERFILE", "K8S", "K8S_EXTRA", "WORKLOAD_KINDS"]
