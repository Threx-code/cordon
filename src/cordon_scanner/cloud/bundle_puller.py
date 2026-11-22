"""How a point gets its policy bundle: pulled from the bundle store with an ETag and a version pin (row BP-6-12).

`BundlePuller.pull(runtime, now)` asks the bundle store for the bundles after the one the runtime holds, with the ETag of the last
answer in `If-None-Match`:

* `304`: nothing is new; the held bundle is the one in force, and the answer is `unchanged`;
* `200`: the bundles since the held one, oldest first, which the runtime takes through the bundle chain check (every link verified,
  all or nothing); the ETag of the answer is kept beside the bundle;
* anything else, or no answer at all: the store could not be reached, the answer is `unreachable`, and nothing changes: a bundle held
  and not yet expired still decides, as every point's degrade rows say.

The version pin is the highest bundle version this point may take (a rollout held at a version, or a point that must not move ahead of
the others): a bundle past it is not offered to the chain check, and an answer with nothing under the pin is `pinned`.

The HTTP call is the caller's (`fetch(url, headers) -> (status, headers, body)`), so the same puller serves the CLI, the hooks, the
firewall and the gates, and a test needs no network. The URL is asked with `?since=<held version>`.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any

from cordon_scanner.cloud.bundle_chain import BundleChain, BundleError

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from cordon_scanner.cloud.local_runtime import LocalRuntime
    from cordon_scanner.cloud.local_store import LocalStore


class BundlePuller:
    ETAG_NAME = "bundle"

    def __init__(
        self,
        url: str,
        fetch: Callable[[str, dict[str, str]], tuple[int, Mapping[str, str], bytes]],
        store: LocalStore,
        *,
        pin: int | None = None,
    ) -> None:
        self._url, self._fetch, self._store, self._pin = url, fetch, store, pin

    def pull(self, runtime: LocalRuntime, now: datetime) -> str:
        """`new`, `unchanged`, `pinned` or `unreachable`; a refused bundle raises `BundleError` (by name, `BundleRefused`) and
        leaves what the runtime holds as it was."""
        held = runtime.held["version"] if runtime.held else 0
        headers = {"Accept": "application/json"}
        etag = self._etag()
        if etag:
            headers["If-None-Match"] = etag
        try:
            status, answered, body = self._fetch(f"{self._url}?since={held}", headers)
        except Exception:  # noqa: BLE001 -- any failure to ask is a store that could not be reached
            return "unreachable"
        if status == 304:
            return "unchanged"
        if status != 200:
            return "unreachable"
        listed = self._listed(body)
        envelopes = self._offered(listed)
        held_back = len(envelopes) < len(listed)
        if not envelopes:
            return "pinned" if held_back else "unchanged"
        state = runtime.accept(envelopes, now)
        validator = {key.lower(): value for key, value in answered.items()}.get("etag")
        # An ETag stands for everything the store answered with; when the pin held bundles back it must not be kept, or a later
        # pull, with the pin lifted, would be told "not modified" about bundles this point never took.
        kept = validator if validator and not held_back else ""
        self._store.put_blob("etag", self.ETAG_NAME, kept.encode("utf-8"), now.isoformat())
        return state

    def _etag(self) -> str:
        kept = self._store.blob("etag", self.ETAG_NAME)
        return kept.data.decode("utf-8") if kept is not None else ""

    def _listed(self, body: bytes) -> list[Any]:
        try:
            document = json.loads(body)
        except ValueError as problem:
            raise BundleError("the bundle store's answer is not JSON") from problem
        bundles = document.get("bundles") if isinstance(document, dict) else None
        if not isinstance(bundles, list):
            raise BundleError("the bundle store's answer has no `bundles` list")
        return bundles

    def _offered(self, bundles: list[Any]) -> list[Any]:
        """The bundles of the answer up to the pin, in the order the store gave them."""
        if self._pin is None:
            return bundles
        return [item for item in bundles if self._version(item) <= self._pin]

    @staticmethod
    def _version(envelope: Any) -> int:
        version = BundleChain.unverified_payload_document(envelope).get("version")
        return version if isinstance(version, int) and not isinstance(version, bool) else 0


__all__ = ["BundlePuller"]
