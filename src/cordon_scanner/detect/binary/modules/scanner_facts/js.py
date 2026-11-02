"""The `js` rule module: one JavaScript file's source-to-sink flows.

    js.flow(source, sink, destination)   a value from `source` reaches `sink` in this file, with a
                                         `destination` kind of destination; "" is any
    js.flows                             how many flows the file has
    js.sinks                             the sinks they reach, sorted, each once
    js.place                             where the file runs (as `package.place`)

The flows are `JsFlow.flows`, the reader `ReachedFlows` runs over the files a consumer reaches,
which keeps its answers by content, so a reached file is not read twice. A file that is not
JavaScript (.js, .mjs, .cjs, or a `node` script), past `ReachedFlows.MAX_SIZE`, or one the
reader gives up on has every field undefined, never false: a fact is evidence, never a failure.

    source        secret_file home_file network_response decoded environment identity browser
                  clipboard wallet_key
    sink          request connection dns process open execute
    destination   drop ip fixed unknown
"""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.detect.binary.modules.scanner_facts.facts import FileFlows


class Js(FileFlows):
    LANGUAGE: ClassVar[str] = "js"

    @staticmethod
    def read(text: str) -> list[tuple[str, str, str]]:
        from cordon_scanner.analysis.javascript.js_flow import JsFlow

        return sorted(
            (source, flow.sink, flow.destination)
            for flow in JsFlow.flows(text)
            for source in flow.sources
        )


__all__ = ["Js"]
