"""The strings a JavaScript expression can spell, when only literals in the file decide them.

`JsFlow` follows labels: which sources reach a sink. A label says nothing about a literal's text, and
a fixed host carries none, so a decision that rests on what a URL IS -- a download pinned to an
official tool's own release path -- cannot be read from labels. This reads the expression's value
set instead: every string it can take, through the forms a bundler writes a platform-specific asset
URL in (review 98 #28, positron-stata's uv download):

    literals, `+` and template literals         `https://.../uv-${target}.${ext}`
    ternaries and `||` / `??` / `&&`            each branch's strings, the condition ignored
    names bound by a plain `=`                  every binding of the name in the file
    a call of a function in the file            what its `return`s spell
    a field of an object literal                `asset.url`, `asset = uvAsset(...)` returning `{url}`

It fails closed. A parameter, a call of anything not in the file, a number, a destructured name, a
loop variable, `+=`, a member of anything but an object literal the file builds, an object that
escapes (passed to a call, aliased, returned, written through a member), a spread or computed key in
that literal: any of these makes the whole set unknown (None), and so does a set past `LIMIT`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from cordon_scanner.analysis.javascript.js_flow import _Analysis

Key = tuple[int, str]


class JsValues:
    #: Distinct strings a value set may hold before it is unknown.
    LIMIT: ClassVar[int] = 64
    #: Hops (a name to its binding, a call to its returns, a field to its value) before unknown.
    DEPTH: ClassVar[int] = 8
    #: What `undefined` and `null` (and `void 0`, which is `undefined`) read as in a string.
    NOTHING: ClassVar[dict[str, frozenset[str]]] = {
        "undefined": frozenset({"undefined"}),
        "null": frozenset({"null"}),
    }
    #: Operators a ternary or a logical join is split at; each side is one of the values.
    _EITHER: ClassVar[frozenset[str]] = frozenset({"||", "??", "&&"})
    #: Tokens that, after an object's name, mean it is read where it stands and not handed on.
    _TESTED: ClassVar[frozenset[str]] = frozenset(
        {")", ";", "&&", "||", "?", "===", "!==", "==", "!="}
    )
    #: Tokens after a member read that make it a write or a call through the object.
    _WRITES: ClassVar[frozenset[str]] = frozenset(
        {"=", "+=", "-=", "||=", "??=", "&&=", "(", "[", "++", "--"}
    )

    def __init__(self, analysis: _Analysis) -> None:
        """`analysis` after `_Analysis.run`: its scopes, `bound` bindings and `fn_by_name`."""
        self.a = analysis
        self._opaque = self._opaque_names()
        self._sealed: dict[Key, bool] = {}

    # -- strings ---------------------------------------------------------------------------------

    def strings(self, s: int, e: int, scope: int, depth: int = 0) -> frozenset[str] | None:
        """Every string tokens [s, e) can evaluate to, or None when the file does not decide it."""
        a = self.a
        if depth > self.DEPTH or s >= e:
            return None
        while a.is_p(s, "(") and a.match[s] == e - 1:
            s, e = s + 1, e - 1
        if s >= e:
            return None
        either = self._either(s, e)
        if either is not None:
            parts = [self.strings(x, y, scope, depth) for x, y in either]
            return self._union(parts)
        joined = self._top_level(s, e, "+")
        if len(joined) > 1:
            return self._product([self.strings(x, y, scope, depth) for x, y in joined])
        return self._operand(s, e, scope, depth)

    def _operand(self, s: int, e: int, scope: int, depth: int) -> frozenset[str] | None:
        a, t = self.a, self.a.t
        if e - s == 1:
            if t[s].kind == "str":
                return frozenset({str(t[s].value)})
            if a.is_name(s) and str(t[s].value) in self.NOTHING:
                return self.NOTHING[str(t[s].value)]
            if a.is_name(s):
                return self._name_strings(a.resolve(str(t[s].value), scope), depth + 1)
            return None
        if e - s == 2 and a.is_name(s, "void") and t[s + 1].kind == "num":
            return self.NOTHING["undefined"]
        if a.is_name(s) and a.is_p(s + 1, "(") and a.match[s + 1] == e - 1:
            fid = self._callee(s, scope)
            if fid is None:
                return None
            return self._union(
                [self.strings(x, y, fid, depth + 1) for x, y in self._returns(fid)] or [None]
            )
        if e - s == 3 and a.is_name(s) and a.is_p(s + 1, ".") and a.is_name(s + 2):
            objects = self._objects_of_name(a.resolve(str(t[s].value), scope), depth + 1)
            if objects is None:
                return None
            got: list[frozenset[str] | None] = []
            for brace, where in objects:
                value = self._field(brace, str(t[s + 2].value))
                if value is None:
                    return None
                got.append(self.strings(*value, where, depth + 1))
            return self._union(got or [None])
        return None

    def _name_strings(self, key: Key, depth: int) -> frozenset[str] | None:
        sites = self._sites(key)
        if sites is None:
            return None
        return self._union([self.strings(x, y, self.a.scope_of(x), depth) for x, y in sites])

    # -- objects ---------------------------------------------------------------------------------

    def _objects_of_name(self, key: Key, depth: int) -> list[tuple[int, int]] | None:
        """(opening brace, scope) of every object literal the name can hold."""
        sites = self._sites(key)
        if sites is None or not self._only_read(key):
            return None
        out: list[tuple[int, int]] = []
        for x, y in sites:
            got = self._objects(x, y, self.a.scope_of(x), depth)
            if got is None:
                return None
            out += got
        return out

    def _objects(self, s: int, e: int, scope: int, depth: int) -> list[tuple[int, int]] | None:
        """Object literals [s, e) evaluates to: itself, or what the function it calls returns.
        `undefined` and `null` are no object (reading a field of one throws) and add none."""
        a, t = self.a, self.a.t
        if depth > self.DEPTH or s >= e:
            return None
        while a.is_p(s, "(") and a.match[s] == e - 1:
            s, e = s + 1, e - 1
        if a.is_p(s, "{") and a.match[s] == e - 1:
            return [(s, scope)]
        if (e - s == 1 and (a.is_name(s, "undefined") or a.is_name(s, "null"))) or (
            e - s == 2 and a.is_name(s, "void")
        ):
            return []
        if a.is_name(s) and a.is_p(s + 1, "(") and a.match[s + 1] == e - 1:
            fid = self._callee(s, scope)
            if fid is None:
                return None
            out: list[tuple[int, int]] = []
            for x, y in self._returns(fid):
                got = self._objects(x, y, fid, depth + 1)
                if got is None:
                    return None
                out += got
            return out
        if e - s == 1 and a.is_name(s):
            # A returned name: the object literal it holds, inside the function that built it.
            return self._objects_of_name(a.resolve(str(t[s].value), scope), depth + 1)
        return None

    def _field(self, brace: int, name: str) -> tuple[int, int] | None:
        """The value range of `name` in the object literal at `brace`; None when it is absent or
        something else may set it (a spread, a computed key, a method or accessor of that name)."""
        a, t = self.a, self.a.t
        found: tuple[int, int] | None = None
        for x, y in self._top_level(brace + 1, a.match[brace], ","):
            if x >= y:
                continue
            if a.is_p(x, "...") or a.is_p(x, "["):
                return None
            if y - x == 1 and a.is_name(x):
                if t[x].value == name:
                    found = (x, y)  # shorthand: the name's own value
                continue
            if (a.is_name(x) or t[x].kind == "str") and a.is_p(x + 1, ":"):
                if str(t[x].value) == name:
                    found = (x + 2, y)
                continue
            if any(a.is_name(k, name) for k in range(x, min(y, x + 3))):
                return None  # `url() {...}`, `get url() {...}`
        return found

    def _only_read(self, key: Key) -> bool:
        """Whether every use of an object's name reads it where it stands: a field read, or a test
        (`if (!asset)`). Passed to a call, aliased, returned, spread or written through a member,
        the object may be changed where this does not look."""
        got = self._sealed.get(key)
        if got is not None:
            return got
        a, t = self.a, self.a.t
        ok = True
        for k in range(a.n):
            if not (a.is_name(k, key[1]) and a.resolve(key[1], a.scope_of(k)) == key):
                continue
            if (
                a.is_p(k - 1, ".")
                or a.is_p(k - 1, "?.")
                or (a.is_p(k + 1, ":") and a.is_p(k - 1, "{"))
            ):
                continue  # another object's member of the same name, or a key
            if a.is_p(k + 1, "=") and self._plain_target(k):
                continue
            if (a.is_p(k + 1, ".") or a.is_p(k + 1, "?.")) and a.is_name(k + 2):
                after = t[k + 3] if k + 3 < a.n else None
                if after is None or after.kind != "punct" or after.value not in self._WRITES:
                    continue
            elif (
                k + 1 < a.n
                and t[k + 1].kind == "punct"
                and t[k + 1].value in self._TESTED
                and not (a.is_p(k - 1, ",") or a.is_p(k - 1, "=") or a.is_name(k - 1, "return"))
                and not (a.is_p(k - 1, "(") and (a.is_name(k - 2) or a.is_p(k - 2, ")")))
            ):
                continue
            ok = False
            break
        self._sealed[key] = ok
        return ok

    # -- helpers ---------------------------------------------------------------------------------

    def _sites(self, key: Key) -> list[tuple[int, int]] | None:
        """The right-hand sides bound to `key`, or None for a name the file does not decide: a
        parameter, a name written any way but a plain `=`, or one never bound here."""
        a = self.a
        if key in self._opaque or (key[0] > 0 and key[1] in a.fns[key[0] - 1].params):
            return None
        return a.bound.get(key) or None

    def _opaque_names(self) -> set[Key]:
        a = self.a
        return {key for key, sites in a.bound.items() if not all(self._plain(s) for s, _ in sites)}

    def _plain(self, rhs: int) -> bool:
        """Whether the binding whose right-hand side starts at `rhs` is `name = ...` itself, not a
        destructuring, a member write (`asset.url = x`), a loop's `of`/`in` or a compound `+=`."""
        return self.a.is_p(rhs - 1, "=") and self._plain_target(rhs - 2)

    def _plain_target(self, k: int) -> bool:
        a = self.a
        return a.is_name(k) and not (a.is_p(k - 1, ".") or a.is_p(k - 1, "?."))

    def _callee(self, k: int, scope: int) -> int | None:
        """The function in the file a call by name at `k` runs; None when there is none, or when
        the name is also bound to anything but that function's own literal (`f = other`)."""
        a = self.a
        key = a.resolve(str(a.t[k].value), scope)
        fid = a.fn_by_name.get(key)
        if fid is None:
            return None
        for s, _ in a.bound.get(key, ()):
            if (a.fn_at_token.get(s) or a.fn_at_token.get(s + 1)) != fid:
                return None
        return fid

    def _returns(self, fid: int) -> list[tuple[int, int]]:
        a = self.a
        fn = a.fns[fid - 1]
        if fn.expression_body:
            return [(fn.start, fn.end)]
        return [
            (k + 1, a.expr_end(k + 1))
            for k in range(fn.start, min(fn.end, a.n))
            if a.is_name(k, "return") and a.scope_of(k) == fid
        ]

    def _top_level(self, s: int, e: int, sep: str) -> list[tuple[int, int]]:
        """[s, e) split at `sep` where it is not inside brackets."""
        a = self.a
        out, start, k = [], s, s
        while k < e:
            tok = a.t[k]
            if tok.kind == "punct" and tok.value in ("(", "[", "{") and a.match[k] > k:
                k = a.match[k] + 1
                continue
            if tok.kind == "punct" and tok.value == sep:
                out.append((start, k))
                start = k + 1
            k += 1
        out.append((start, e))
        return out

    def _either(self, s: int, e: int) -> list[tuple[int, int]] | None:
        """The alternatives of a ternary (its two branches) or of a top-level `||`/`??`/`&&` join
        (every side); None when [s, e) is neither."""
        a = self.a
        k, question = s, -1
        sides: list[int] = []
        while k < e:
            tok = a.t[k]
            if tok.kind == "punct" and tok.value in ("(", "[", "{") and a.match[k] > k:
                k = a.match[k] + 1
                continue
            if tok.kind == "punct" and tok.value == "?":
                question = k
                break
            if tok.kind == "punct" and tok.value in self._EITHER:
                sides.append(k)
            k += 1
        if question >= 0:
            nested, k = 0, question + 1
            while k < e:
                tok = a.t[k]
                if tok.kind == "punct" and tok.value in ("(", "[", "{") and a.match[k] > k:
                    k = a.match[k] + 1
                    continue
                if tok.kind == "punct" and tok.value == "?":
                    nested += 1
                elif tok.kind == "punct" and tok.value == ":":
                    if not nested:
                        return [(question + 1, k), (k + 1, e)]
                    nested -= 1
                k += 1
            return None
        if not sides:
            return None
        bounds = [s, *(x + 1 for x in sides)]
        ends = [*sides, e]
        return list(zip(bounds, ends, strict=True))

    def _union(self, parts: list[frozenset[str] | None]) -> frozenset[str] | None:
        out: set[str] = set()
        for part in parts:
            if part is None:
                return None
            out |= part
            if len(out) > self.LIMIT:
                return None
        return frozenset(out)

    def _product(self, parts: list[frozenset[str] | None]) -> frozenset[str] | None:
        out: set[str] = {""}
        for part in parts:
            if part is None:
                return None
            out = {x + y for x in out for y in part}
            if len(out) > self.LIMIT:
                return None
        return frozenset(out)


__all__ = ["JsValues"]
