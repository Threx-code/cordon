"""How a point gets its policy bundle: pulled from the bundle store with an ETag and a version pin (row BP-6-12).

The route is the platform's `GET /v1/bundles/<scope>?since=<held version>` (`wait=<seconds>` to long-poll, at most 30). It answers:

* `304` with no body, when nothing is newer than `since`: the held bundle is the one in force, `unchanged`;
* `200` with the API's standard envelope `{"status": true, "message": ..., "data": {scope, from_version, latest_version, etag,
  restart, bundles, latest?}}`: `bundles` are the envelopes since the held version, oldest first, and go through the bundle chain
  check (every link verified, all or nothing); when `restart` is true, `bundles` is empty and `latest` is the newest envelope
  alone, which the store sends when it no longer holds the bundles between: the runtime takes it as a fresh start
  (`LocalRuntime.restart`: verified like any other, never older than the one held);
* every answer carries `ETag: "<payload sha256>"` (quoted) and `X-Bundle-Version`; the ETag as the store wrote it, quotes included, is
  kept beside the bundle and sent back in `If-None-Match`;
* anything else (a refusal has `"status": false` and a 4xx), or no answer at all, is `unreachable`: nothing changes, and a bundle held
  and not yet expired still decides, as every point's degrade rows say.

The version pin is the highest bundle version this point may take (a rollout held at a version, or a point that must not move ahead
of the others): a bundle past it is not offered to the chain check, and an answer with nothing under the pin is `pinned`, and its ETag
is not kept (or a later pull, with the pin lifted, would be told "not modified" about bundles this point never took).

Under a root the customer holds, the platform also serves the decision delegation (`delegations`, a list of one or empty) and
tags every answer, the `304` too, with `X-Decision-Delegation-Sequence`. A puller given the root (`root_public`, `delegation`, `tenant`)
verifies the delegation it is sent (`DecisionDelegation.accept`), keeps the highest sequence it has accepted, and refuses a lower one; when
an answer's header is higher than the one held it asks once for the whole bundle (no `since`, no `If-None-Match`) to get the document,
even though the ETag says the bundle is unchanged. The header is only a reason to ask: the signed document's own sequence is what counts.

The HTTP call is the caller's (`fetch(url, headers) -> (status, headers, body)`), so the same puller serves the CLI, the hooks, the
firewall and the gates, and a test needs no network.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from cordon_scanner.cloud.agent.decision_delegation import DecisionDelegation
from cordon_scanner.cloud.bundle_chain import BundleChain, BundleError

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from datetime import datetime

    from cordon_scanner.cloud.local_runtime import LocalRuntime
    from cordon_scanner.cloud.local_store import LocalStore


class BundlePuller:
    ETAG_NAME = "bundle"
    MAX_WAIT_S = 30

    def __init__(
        self,
        url: str,
        fetch: Callable[[str, dict[str, str]], tuple[int, Mapping[str, str], bytes]],
        store: LocalStore,
        *,
        pin: int | None = None,
        wait_s: int = 0,
        root_public: bytes | None = None,
        delegation: object = None,
        tenant: str = "",
    ) -> None:
        if not 0 <= wait_s <= self.MAX_WAIT_S:
            raise ValueError(f"wait is 0 to {self.MAX_WAIT_S} seconds")
        self._url, self._fetch, self._store, self._pin, self._wait = url, fetch, store, pin, wait_s
        self._root, self._delegation, self._tenant = root_public, delegation, tenant

    def pull(self, runtime: LocalRuntime, now: datetime) -> str:
        """`new`, `unchanged`, `pinned` or `unreachable`; a refused bundle or an answer that is not the store's raises `BundleError`
        (`BundleRefused` by name for a refused one) and leaves what the runtime holds as it was."""
        held = runtime.held["version"] if runtime.held else 0
        headers = {"Accept": "application/json"}
        etag = self._etag()
        if etag:
            headers["If-None-Match"] = etag
        query = f"since={held}" + (f"&wait={self._wait}" if self._wait else "")
        try:
            status, answered, body = self._fetch(f"{self._url}?{query}", headers)
        except Exception:  # noqa: BLE001 -- any failure to ask is a store that could not be reached
            return "unreachable"
        if status == 304:
            self._follow_header(answered, headers, now)
            return "unchanged"
        if status != 200:
            return "unreachable"
        data = self._data(body)
        self._take(data.get("delegations"))
        self._follow_header(answered, headers, now)
        offered, held_back = self._offered(data)
        if not offered:
            return "pinned" if held_back else "unchanged"
        state = (
            runtime.restart(offered[0], now) if data["restart"] else runtime.accept(offered, now)
        )
        validator = {key.lower(): value for key, value in answered.items()}.get("etag", "")
        # An ETag stands for everything the store answered with; when the pin held bundles back it is not kept.
        kept = validator if validator and not held_back else ""
        self._store.put_blob("etag", self.ETAG_NAME, kept.encode("utf-8"), now.isoformat())
        return state

    DELEGATION_BLOB = "decision-delegation"
    HEADER = "x-decision-delegation-sequence"

    def decision_delegation(self) -> object:
        """The decision delegation last accepted, or None: what a decision under a customer root is verified with."""
        kept = self._store.blob("decision-delegation", self.DELEGATION_BLOB)
        if kept is None:
            return None
        try:
            return json.loads(kept.data)
        except ValueError:
            return None

    def held_sequence(self) -> int:
        """The highest decision delegation sequence accepted, or 0."""
        kept = self.decision_delegation()
        if kept is None:
            return 0
        sequence = BundleChain.unverified_payload_document(kept).get("sequence")
        return sequence if isinstance(sequence, int) and not isinstance(sequence, bool) else 0

    def _take(self, offered: object) -> None:
        """Verify and keep the decision delegation of an answer; a document that fails is refused (`BundleError`) and the one held stays."""
        if self._root is None or not isinstance(offered, list) or not offered:
            return
        held = self.held_sequence()
        envelope = offered[0]
        if DecisionDelegation.root_names_decision(self._root, self._delegation, self._tenant):
            return
        document = DecisionDelegation.accept(
            self._root, self._delegation, self._tenant, envelope, min_sequence=held
        )
        if document["sequence"] > held or self.decision_delegation() is None:
            self._store.put_blob(
                "decision-delegation",
                self.DELEGATION_BLOB,
                json.dumps(envelope, sort_keys=True).encode("utf-8"),
                str(document["issued_at"]),
            )

    def _follow_header(
        self, answered: Mapping[str, str], headers: dict[str, str], now: datetime
    ) -> None:
        """When the answer says the platform holds a higher decision delegation sequence than this point, ask once for the whole bundle."""
        if self._root is None:
            return
        said = {key.lower(): value for key, value in answered.items()}.get(self.HEADER, "")
        if not said.isdigit() or int(said) <= self.held_sequence():
            return
        try:
            status, _, body = self._fetch(self._url, {"Accept": headers["Accept"]})
        except Exception:  # noqa: BLE001 -- failing to ask leaves what is held
            return
        if status == 200:
            self._take(self._whole(body).get("delegations"))

    @staticmethod
    def _whole(body: bytes) -> dict[str, Any]:
        try:
            document = json.loads(body)
        except ValueError as problem:
            raise BundleError("the bundle store's answer is not JSON") from problem
        data = (
            document.get("data")
            if isinstance(document, dict) and document.get("status") is True
            else None
        )
        if not isinstance(data, dict):
            raise BundleError("the bundle store's answer is not a bundle answer")
        return data

    def _etag(self) -> str:
        kept = self._store.blob("etag", self.ETAG_NAME)
        return kept.data.decode("utf-8") if kept is not None else ""

    @staticmethod
    def _data(body: bytes) -> dict[str, Any]:
        """The `data` of the store's standard envelope, checked to be what it says it is."""
        try:
            document = json.loads(body)
        except ValueError as problem:
            raise BundleError("the bundle store's answer is not JSON") from problem
        data = (
            document.get("data")
            if isinstance(document, dict) and document.get("status") is True
            else None
        )
        if not isinstance(data, dict) or not isinstance(data.get("restart"), bool):
            raise BundleError("the bundle store's answer is not a bundle answer")
        if data["restart"]:
            if not isinstance(data.get("latest"), dict):
                raise BundleError("the bundle store asks for a restart and sends no bundle")
        elif not isinstance(data.get("bundles"), list):
            raise BundleError("the bundle store's answer has no `bundles` list")
        return data

    def _offered(self, data: dict[str, Any]) -> tuple[list[Any], bool]:
        """The bundles of the answer up to the pin, oldest first, and whether the pin held any back."""
        listed: list[Any] = [data["latest"]] if data["restart"] else list(data["bundles"])
        if self._pin is None:
            return listed, False
        kept = [item for item in listed if self._version(item) <= self._pin]
        return kept, len(kept) < len(listed)

    @staticmethod
    def _version(envelope: Any) -> int:
        version = BundleChain.unverified_payload_document(envelope).get("version")
        return version if isinstance(version, int) and not isinstance(version, bool) else 0


__all__ = ["BundlePuller"]
