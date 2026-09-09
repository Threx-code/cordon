"""Software that legitimately adapts to running in a container.

This is the case the anti-analysis rule must not fire on. The check is real and
so is the branch, but nothing is decoded, spawned or sent anywhere: the result
only changes how many workers are started.
"""

import os
from pathlib import Path


def in_container() -> bool:
    return Path("/proc/self/cgroup").exists() and "docker" in Path("/proc/self/cgroup").read_text()


def worker_count() -> int:
    if in_container():
        return int(os.environ.get("WEB_CONCURRENCY", "2"))
    return os.cpu_count() or 4
