"""The JavaScript wasm-bindgen generates, which runs strings its own module hands it.

A Rust crate compiled with wasm-bindgen ships `<name>_bg.wasm` and a glue file. For
`js_sys::Function::new` the glue gets one import, generated as

    const ret = new Function(getStringFromWasm0(arg0, arg1));

and it loads the module it runs from beside itself (`new URL("<name>_bg.wasm", import.meta.url)`
fetched in `__wbg_init`). js_flow follows that fetch's response into the module's memory and out
through `getStringFromWasm0` into `new Function`, which is the shape of a dropper: the REMOTE_CODE
flow. What runs is the crate's own code, read by the binary rules; 15 npm releases were blocked for
it alone (review 98, npm work half), among them WebAssembly SDKs for Automerge, Kaspa and OPAQUE.

Only that generated line is set aside, and only in a file that names the runtime's hooks and its
own `_bg.wasm`. A compromised release that adds a dropper beside the glue is judged on that
dropper: the 32 DataDog npm samples carrying the glue stay blocked on their payloads.
"""

from __future__ import annotations

import re
from typing import Final

#: The generated import for `Function::new`: a string handed over by pointer and length, run
#: as a function body (one or two of them: arguments, then body).
_SHIM: Final = re.compile(
    r"[ \t]*(?:const|let|var)\s+ret\s*=\s*new\s+Function\(\s*getStringFromWasm0\(\s*arg\d\s*,"
    r"\s*arg\d\s*\)(?:\s*,\s*getStringFromWasm0\(\s*arg\d\s*,\s*arg\d\s*\))?\s*\)\s*;"
)


class WasmBindgenGlue:
    @staticmethod
    def generated(text: str) -> bool:
        """Whether the file is wasm-bindgen glue: it names the runtime's hooks and its module."""
        return "__wbindgen_" in text and "_bg.wasm" in text

    @staticmethod
    def shim_at(text: str, offset: int) -> bool:
        """Whether the line starting at `offset` is the generated `Function::new` import."""
        return _SHIM.match(text, offset) is not None


__all__ = ["WasmBindgenGlue"]
