"""What the code a consumer runs does with what it reads: the package verdict's flow facts.

The capability profile (`Engine._capability_profile`) says what the files an install or an import
runs can do -- reach the network, start a process. A library's entry point can do both and be
harmless; what it does with a secret is the question. These facts name each source a reached file
reads, the sink it reaches and the kind of destination (`JsFlow`): `import_flow_environment_
request_unknown` is the entry point sending the environment somewhere its file does not name.

Three places, each a key prefix, each read as JavaScript only:

- `install`: the hook scripts and the files they run;
- `import`: the package's own entry points (`main`, `bin`, `exports`);
- `closure`: the first-party files those entry points load, transitively, and are not entries.

The framework facts name what the capability primitives cannot see in a plugin: an n8n node
reads its credentials through `this.getCredentials()` and sends through `helpers.request`, so
a credential stealer written as a node shows no credential read and no egress (review 98: one
family of five releases). A legitimate node makes the same calls -- 115 of the npm work set's
318 n8n nodes, 52 of them to a host their own credential definition does not name -- so these
are facts for the verdict to weigh, never a rule.

Nothing here blocks. The keys are new, so a model trained without them ignores them, and every
fact is a function of the files' bytes alone.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.javascript.js_flow import JsFlow

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.detect.base import FileUnit, ScanContext


class ReachedFlows:
    """`of(units, ctx)`: the flow and framework facts of the files a consumer runs."""

    #: Per place, as many files as the capability profile reads (`Engine._PROFILE_FILES`).
    FILES: ClassVar[int] = 50
    #: The size past which a file is not read here: the profile's own limit.
    MAX_SIZE: ClassVar[int] = 1_000_000
    JS: ClassVar[tuple[str, ...]] = (".js", ".mjs", ".cjs")

    FRAMEWORK: ClassVar[dict[str, re.Pattern[str]]] = {
        "framework_credential": re.compile(r"\.getCredentials\s*\("),
        "framework_request": re.compile(
            r"\bhelpers\s*\.\s*(?:request|httpRequest|httpRequestWithAuthentication)\s*\("
        ),
    }

    @staticmethod
    def places(ctx: ScanContext) -> dict[str, frozenset[str]]:
        entries = ctx.import_entry_paths
        return {
            "install": ctx.install_hook_paths | ctx.install_entry_paths,
            "import": entries,
            "closure": ctx.library_closure_paths - entries,
        }

    @staticmethod
    def of(units: Sequence[FileUnit], ctx: ScanContext) -> dict[str, float]:
        out: dict[str, float] = {}
        for place, paths in ReachedFlows.places(ctx).items():
            read = 0
            for unit in units:
                if read >= ReachedFlows.FILES:
                    break
                path = unit.path
                if (
                    path not in paths
                    or unit.content.size > ReachedFlows.MAX_SIZE
                    or not path.rsplit("!", 1)[-1].lower().endswith(ReachedFlows.JS)
                ):
                    continue
                read += 1
                out.update(ReachedFlows.facts(place, unit.content.text))
        return out

    @staticmethod
    def facts(place: str, text: str) -> dict[str, float]:
        """One file's facts under `place`: each source, sink and destination kind it joins, and
        the framework calls it makes."""
        out = {
            f"{place}_can_{name}": 1.0
            for name, pattern in ReachedFlows.FRAMEWORK.items()
            if pattern.search(text)
        }
        try:
            flows = JsFlow.flows(text)
        except Exception:  # a fact is evidence, never a scan failure
            flows = []
        for flow in flows:
            for source in sorted(flow.sources):
                out[f"{place}_flow_{source}_{flow.sink}_{flow.destination}"] = 1.0
        return out


__all__ = ["ReachedFlows"]
