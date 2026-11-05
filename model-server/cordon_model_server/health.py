"""The container's liveness probe: GET /healthz on the local listener, TLS or not.

The certificate is not checked: the probe connects to this container's own loopback address to ask
whether the process answers, and it sends nothing.
"""

from __future__ import annotations

import os
import ssl
import sys
import urllib.request


class Health:
    @staticmethod
    def check() -> int:
        port = os.environ.get("CORDON_MODEL_PORT", "8443")
        insecure = ssl.create_default_context()
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        for url in (f"https://127.0.0.1:{port}/healthz", f"http://127.0.0.1:{port}/healthz"):
            try:
                context = insecure if url.startswith("https") else None
                # Loopback only, and the scheme fixed above.
                with urllib.request.urlopen(url, timeout=5, context=context) as r:  # noqa: S310
                    if r.status == 200:
                        return 0
            except OSError:
                continue
        return 1


if __name__ == "__main__":
    sys.exit(Health.check())
