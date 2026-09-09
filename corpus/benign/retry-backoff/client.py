"""An ordinary retry loop.

Sleeps, and reaches the network, which is the pair the delay pattern would fire
on if it counted every sleep. The delays here are short because they are
backoff rather than an attempt to outlive an observer.
"""

import time
import urllib.request


def fetch(url: str, attempts: int = 3) -> bytes:
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                return response.read()
        except OSError:
            if attempt == attempts - 1:
                raise
            time.sleep(2**attempt)
    return b""
