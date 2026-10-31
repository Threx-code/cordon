"""The vt module's schema tables, generated from YARA-X 1.21.0's vt .proto files (R10).

    python scripts/reference/vt_schema.py tests/unit/data/vt_protos \
        src/cordon_scanner/detect/binary/modules/reports/vt_schema.py

The output is committed; tests/unit/detect/binary/modules/test_vt.py regenerates it and requires
the same file.

What a rule sees follows YARA-X's reading of the protos: a field's (yara.field_options) `name`
renames it, `ignore` drops it, `lowercase` lowercases its text; `repeated` is an array, `map<,>` a
dictionary, an enum field an integer; an enum's values are constants (renamed by
(yara.enum_options) `name`, valued by (yara.enum_value) where given) under the struct the enum is
declared in. The emitted module holds data only: FIELDS (message -> [rule name, json names, kind,
type, flags]), ENUMS (enum -> rule name, scope, {value name: value}) and ROOT.
"""

import json
import re
import sys
from pathlib import Path

SCALARS = {
    "int32": "int",
    "int64": "int",
    "uint32": "int",
    "uint64": "int",
    "sint32": "int",
    "sint64": "int",
    "fixed32": "int",
    "fixed64": "int",
    "sfixed32": "int",
    "sfixed64": "int",
    "bool": "bool",
    "float": "float",
    "double": "float",
    "string": "text",
    "bytes": "text",
}


class ProtoText:
    """A .proto file's text: comments removed, then split into tokens."""

    @staticmethod
    def strip_comments(text):
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        return re.sub(r"//[^\n]*", "", text)

    @staticmethod
    def tokens(text):
        return re.findall(
            r'"(?:[^"\\]|\\.)*"|[A-Za-z_][\w.]*|-?\d+(?:\.\d+)?|[{}\[\]();=<>,:]', text
        )


class Parser:
    def __init__(self, toks, package):
        self.t, self.i, self.package = toks, 0, package
        self.messages, self.enums = {}, {}

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def skip_block(self):
        depth = 0
        while True:
            tok = self.take()
            if tok in "{[(":
                depth += 1
            elif tok in "}])":
                depth -= 1
                if depth == 0:
                    return

    def options_text(self):
        """The raw tokens of a [ ... ] or { ... } option block, as text."""
        start, depth = self.i, 0
        while True:
            tok = self.take()
            if tok in "[{(":
                depth += 1
            elif tok in "]})":
                depth -= 1
                if depth == 0:
                    return " ".join(self.t[start : self.i])

    def file(self):
        while self.peek() is not None:
            tok = self.take()
            if tok == "message":
                self.message(self.package)
            elif tok == "enum":
                self.enum(self.package)
            elif tok in ("syntax", "package", "import"):
                while self.take() != ";":
                    pass
            elif tok == "option":
                while self.peek() != ";":
                    if self.peek() == "{":
                        self.skip_block()
                    else:
                        self.take()
                self.take()

    def message(self, scope):
        name = self.take()
        full = f"{scope}.{name}"
        self.take()  # {
        info = {"fields": [], "rule_name": name, "scope": scope}
        self.messages[full] = info
        while (tok := self.take()) != "}":
            if tok == "message":
                self.message(full)
            elif tok == "enum":
                self.enum(full)
            elif tok == "oneof":
                self.take()
                self.take()  # name {
                while self.peek() != "}":
                    self.field(info, None, full)
                self.take()
            elif tok == "option":
                opts = []
                while self.peek() != ";":
                    opts.append(self.options_text() if self.peek() == "{" else self.take())
                self.take()
                text = " ".join(opts)
                if "yara.message_options" in text and (
                    m := re.search(r'name\s*:\s*"([^"]+)"', text)
                ):
                    info["rule_name"] = m.group(1)
            elif tok in ("reserved", "extensions"):
                while self.take() != ";":
                    pass
            else:
                self.field(info, tok, full)

    def field(self, info, first, scope):
        label = None
        tok = first if first is not None else self.take()
        if tok in ("repeated", "optional", "required"):
            label, tok = tok, self.take()
        if tok == "map":
            self.take()
            key = self.take()
            self.take()
            value = self.take()
            self.take()
            kind, ftype = "map", (key, value)
        else:
            kind, ftype = ("repeated" if label == "repeated" else "single"), tok
        name = self.take()
        self.take()
        number = int(self.take())
        opts = self.options_text() if self.peek() == "[" else ""
        self.take()  # ;
        rename = re.search(r'yara\.field_options \) = \{[^}]*?name : "([^"]+)"', opts)
        info["fields"].append(
            {
                "proto": name,
                "number": number,
                "rule": rename.group(1) if rename else name,
                "kind": kind,
                "type": ftype,
                "scope": scope,
                "ignore": bool(re.search(r"ignore : true", opts)),
                "lowercase": bool(re.search(r"lowercase : true", opts)),
                "files_only": "accept_if" in opts and '"file"' in opts,
                "not_for_files": "accept_if" in opts and '"file"' not in opts,
            }
        )

    def enum(self, scope):
        name = self.take()
        full = f"{scope}.{name}"
        self.take()
        info = {"rule_name": name, "scope": scope, "values": {}, "numbers": {}, "inline": False}
        self.enums[full] = info
        while (tok := self.take()) != "}":
            if tok == "option":
                text = []
                while self.peek() != ";":
                    text.append(self.options_text() if self.peek() == "{" else self.take())
                self.take()
                text = " ".join(text)
                if m := re.search(r'name : "([^"]+)"', text):
                    info["rule_name"] = m.group(1)
                info["inline"] = info["inline"] or bool(re.search(r"inline : true", text))
            elif tok == "reserved":
                while self.take() != ";":
                    pass
            else:
                self.take()  # =
                number = int(self.take())
                opts = self.options_text() if self.peek() == "[" else ""
                self.take()
                m = re.search(r"i64 : (-?\d+)", opts)
                info["values"][tok] = int(m.group(1)) if m else number
                info["numbers"][tok] = number


class Names:
    """Type names as protobuf resolves them."""

    @staticmethod
    def resolve(name, scope, known):
        """A type name as protobuf resolves it: innermost scope outwards, then as written."""
        if name in SCALARS:
            return name
        parts = scope.split(".")
        for i in range(len(parts), 0, -1):
            cand = ".".join(parts[:i]) + "." + name
            if cand in known:
                return cand
        return name if name in known else None


class VtSchemaFile:
    """The generated tables as JSON text, sorted and indented, so a regeneration from the same
    protos is the same file."""

    @staticmethod
    def render(data):
        return json.dumps(data, indent=1, sort_keys=True) + "\n"


class Generate:
    """The generator's run: the protos read, the tables written."""

    @staticmethod
    def main(protos, out):
        messages, enums = {}, {}
        for path in sorted(Path(protos, "vt").rglob("*.proto")):
            text = ProtoText.strip_comments(path.read_text(encoding="utf-8"))
            pkg = re.search(r"package\s+([\w.]+)\s*;", text).group(1)
            p = Parser(ProtoText.tokens(text), pkg)
            p.file()
            messages.update(p.messages)
            enums.update(p.enums)
        # protobuf's well-known types, as their .proto declares them
        for wkt in ("google.protobuf.Timestamp", "google.protobuf.Duration"):
            messages[wkt] = {
                "rule_name": wkt.rsplit(".", 1)[1],
                "scope": "google.protobuf",
                "fields": [
                    {
                        "proto": "seconds",
                        "number": 1,
                        "rule": "seconds",
                        "kind": "single",
                        "type": "int64",
                        "scope": wkt,
                        "ignore": False,
                        "lowercase": False,
                        "files_only": False,
                        "not_for_files": False,
                    },
                    {
                        "proto": "nanos",
                        "number": 2,
                        "rule": "nanos",
                        "kind": "single",
                        "type": "int32",
                        "scope": wkt,
                        "ignore": False,
                        "lowercase": False,
                        "files_only": False,
                        "not_for_files": False,
                    },
                ],
            }
        known = set(messages) | set(enums)
        fields = {}
        for full, info in messages.items():
            rows = []
            for f in info["fields"]:
                if f["ignore"]:
                    continue
                if f["kind"] == "map":
                    key, value = f["type"]
                    target = Names.resolve(value, f["scope"], known)
                    rows.append(
                        [
                            f["rule"],
                            f["proto"],
                            "map",
                            target,
                            key,
                            f["lowercase"],
                            f["files_only"],
                            f["not_for_files"],
                            f["number"],
                        ]
                    )
                    continue
                target = Names.resolve(f["type"], f["scope"], known)
                if target is None:
                    raise SystemExit(f"unresolved type {f['type']} in {full}")
                rows.append(
                    [
                        f["rule"],
                        f["proto"],
                        f["kind"],
                        target,
                        None,
                        f["lowercase"],
                        f["files_only"],
                        f["not_for_files"],
                        f["number"],
                    ]
                )
            fields[full] = {"rule_name": info["rule_name"], "scope": info["scope"], "fields": rows}
        root = "vt.titan.LiveHuntData"
        data = {"ROOT": root, "MESSAGES": fields, "ENUMS": enums}
        Path(out).write_text(VtSchemaFile.render(data), encoding="utf-8")
        print(
            len(fields),
            "messages",
            len(enums),
            "enums",
            sum(len(m["fields"]) for m in fields.values()),
            "fields",
        )


if __name__ == "__main__":
    Generate.main(sys.argv[1], sys.argv[2])
