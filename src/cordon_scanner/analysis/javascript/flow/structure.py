"""A JavaScript file's structure as the flow analysis reads it: its tokens and brackets, where an
expression ends, its functions and their parameters, scopes and classes, and the scope a name
resolves to."""

from __future__ import annotations

import bisect
from collections.abc import Callable

from cordon_scanner.analysis.javascript.flow.vocabulary import (
    _CLOSE,
    _CONTEXTUAL,
    _KEYWORDS,
    _OPEN,
    _TS_MODIFIERS,
    Flow,
    Label,
    _Fn,
)
from cordon_scanner.analysis.javascript.js_eval import JsEval, Tok


class Structure:
    """The lowest layer of `js_flow._Analysis`: the token stream, the functions and scopes found in
    it, and name resolution. Every layer above reads the file through these."""

    def __init__(self, text: str, seed: Callable[[str], str | None] | None = None) -> None:
        self.text = text
        #: Opt-in: a label for a string literal, ahead of every other fact about it -- what a caller
        #: follows that no rule reads (`js_persist.py`). None for every analysis the rules run.
        self.seed = seed
        self.t: list[Tok] = Structure._uncomma(JsEval.tokens(text, templates=True))
        self.n = len(self.t)
        self.newlines = [i for i, c in enumerate(text) if c == "\n"]
        self.match = self._brackets()
        self.fns: list[_Fn] = []
        self.scope_at: list[int] = []
        self.declared: dict[int, set[str]] = {}
        self.parent: dict[int, int] = {}
        self.vars: dict[tuple[int, str], set[Label]] = {}
        self.aliases: dict[str, str] = {}  # local name -> "module" or "module.member"
        self.connections: set[tuple[int, str]] = set()  # names bound to an open connection
        self.raw_connections: set[tuple[int, str]] = set()  # ... to a raw socket among them
        self.bound: dict[tuple[int, str], list[tuple[int, int]]] = {}  # name -> what it is bound to
        self.instance_of: dict[tuple[int, str], int] = {}  # name bound to `new C()` -> C
        #: names bound to a messaging client -> (host, destination kind) of what it sends to
        self.bot_clients: dict[tuple[int, str], tuple[str | None, str]] = {}
        self.archives: set[tuple[int, str]] = set()  # names bound to an archive being built
        self.registry_parts: set[str] = set()  # literal parts of registry tarball URLs
        self.flows: dict[tuple[int, str], Flow] = {}
        self.fn_by_name: dict[tuple[int, str], int] = {}
        self.fn_at_token: dict[int, int] = {}
        #: Range taints are cached until any binding or return value grows.
        self.version = 0
        #: Work done (label growth and range evaluations), bounded so no file can run long.
        self.work = 0
        self.budget = 8 * self.n + 100_000
        self._args_cache: dict[int, list[tuple[int, int]]] = {}
        self._file_destination: tuple[str | None, str] | None = None
        self._cache: dict[tuple[int, int, int], tuple[int, set[Label]]] = {}
        self._compiled: dict[
            tuple[int, int, int],
            tuple[
                frozenset[Label],
                tuple[tuple[int, str], ...],
                tuple[tuple[int, int], ...],
                tuple[tuple[int, int], ...],
            ],
        ] = {}

    # -- structure -------------------------------------------------------------------------------

    @staticmethod
    def _uncomma(t: list[Tok]) -> list[Tok]:
        """`(0, os_1.hostname)(...)` -- how TypeScript and Babel call an imported function -- read
        as the call it is, `os_1.hostname(...)`: the parenthesis, `0` and comma are dropped."""
        drop: set[int] = set()
        for i in range(len(t) - 4):
            if not (
                t[i].kind == "punct"
                and t[i].value == "("
                and t[i + 1].kind == "num"
                and t[i + 1].value == 0
                and t[i + 2].kind == "punct"
                and t[i + 2].value == ","
                and t[i + 3].kind == "name"
            ):
                continue
            k = i + 3
            while k + 2 < len(t) and t[k + 1].value == "." and t[k + 2].kind == "name":
                k += 2
            if (
                k + 2 < len(t)
                and t[k + 1].kind == "punct"
                and t[k + 1].value == ")"
                and t[k + 2].kind == "punct"
                and t[k + 2].value == "("
            ):
                drop.update((i, i + 1, i + 2, k + 1))
        return [tok for i, tok in enumerate(t) if i not in drop] if drop else t

    def _brackets(self) -> list[int]:
        match = [-1] * self.n
        stack: list[int] = []
        for i, tok in enumerate(self.t):
            if tok.kind != "punct":
                continue
            if tok.value in _OPEN:
                stack.append(i)
            elif tok.value in _CLOSE and stack:
                j = stack.pop()
                match[i], match[j] = j, i
        return match

    def line(self, i: int) -> int:
        return bisect.bisect_right(self.newlines, self.t[min(i, self.n - 1)].start) + 1

    def is_p(self, i: int, value: str) -> bool:
        return 0 <= i < self.n and self.t[i].kind == "punct" and self.t[i].value == value

    def is_name(self, i: int, value: str | None = None) -> bool:
        return (
            0 <= i < self.n
            and self.t[i].kind == "name"
            and (value is None or self.t[i].value == value)
        )

    def _new_line_between(self, i: int, j: int) -> bool:
        return "\n" in self.text[self.t[i].end : self.t[j].start]

    def expr_end(self, j: int) -> int:
        """One past the last token of the expression starting at `j` (statement-level)."""
        k = j
        while k < self.n:
            tok = self.t[k]
            if tok.kind == "punct":
                if tok.value in _OPEN:
                    close = self.match[k]
                    if close < 0:
                        return k  # unbalanced: the expression is not known to go further
                    k = close + 1
                    continue
                if tok.value in (";", ",") or tok.value in _CLOSE:
                    return k
            if k > j and self._asi(k):
                return k
            k += 1
        return k

    def _asi(self, k: int) -> bool:
        """A line break that ends the previous statement (automatic semicolon insertion)."""
        prev, tok = self.t[k - 1], self.t[k]
        if not self._new_line_between(k - 1, k):
            return False
        ends = prev.kind in ("name", "str", "num") or (
            prev.kind == "punct" and prev.value in (")", "]", "}", "++", "--")
        )
        if not ends or (
            prev.kind == "name"
            and prev.value in _KEYWORDS - {"this", "null", "true", "false", "undefined"}
        ):
            return False
        if tok.kind == "punct":
            return tok.value in ("++", "--", "!", "~")
        return tok.kind in ("name", "str", "num") and tok.value not in ("in", "of", "instanceof")

    def _params(self, open_i: int) -> list[str]:
        close = self.match[open_i]
        names: list[str] = []
        depth = 0
        k = open_i + 1
        while k < close:
            tok = self.t[k]
            if tok.kind == "punct" and tok.value in _OPEN:
                depth += 1
            elif tok.kind == "punct" and tok.value in _CLOSE:
                depth -= 1
            elif tok.kind == "punct" and tok.value == "=" and depth == 0:
                k = self.expr_end(k + 1)
                continue
            elif tok.kind == "punct" and tok.value == ":" and depth == 0:
                # A TypeScript parameter type (`p: Record<string, any>`): no names in it. Read as
                # names, `any` became a parameter and every later one moved along.
                k = self._type_end(k + 1, close, (",", "="))
                continue
            elif (
                tok.kind == "name"
                and tok.value not in _KEYWORDS
                and not (depth == 0 and tok.value in _TS_MODIFIERS and self.is_name(k + 1))
                and (depth == 0 or not self.is_p(k + 1, ":"))
            ):
                names.append(tok.value)
            k += 1
        return names

    def _type_end(self, k: int, stop: int, ends: tuple[str, ...]) -> int:
        """Where a TypeScript type starting at `k` ends: the first of `ends` outside its brackets
        and angle brackets, or `stop`. An object type before a body (`): { a: T } {`) is part of
        the type."""
        angle = 0
        while k < stop:
            tok = self.t[k]
            if tok.kind == "punct":
                v = str(tok.value)
                if v == "<":
                    angle += 1
                elif v in (">", ">>", ">>>"):
                    angle = max(0, angle - len(v))
                elif (
                    angle == 0
                    and v in ends
                    and not (v == "{" and self.match[k] > 0 and self.is_p(self.match[k] + 1, "{"))
                ):
                    return k
                elif v in _OPEN and self.match[k] > 0:
                    k = self.match[k] + 1
                    continue
            k += 1
        return stop

    def _past_return_type(self, close: int) -> int:
        """The token after the parameter list closing at `close`, past a TypeScript return type
        (`): Promise<string> {`, `): void =>`): where the body or the `=>` is."""
        if not self.is_p(close + 1, ":"):
            return close + 1
        stop = min(self.n, close + 80)
        end = self._type_end(close + 2, stop, ("{", "=>", ";"))
        return end if end < stop and not self.is_p(end, ";") else close + 1

    def _find_functions(self) -> None:
        t, n = self.t, self.n
        for i in range(n):
            tok = t[i]
            fn: _Fn | None = None
            if tok.kind == "name" and tok.value == "function":
                k = i + 1
                if self.is_p(k, "*"):
                    k += 1
                name = None
                if self.is_name(k):
                    name, k = t[k].value, k + 1
                if self.is_p(k, "<"):  # `function f<T>(...)`
                    k = self._type_end(k, min(n, k + 40), ("(",))
                if self.is_p(k, "(") and self.match[k] > 0:
                    body = self._past_return_type(self.match[k])
                    if self.is_p(body, "{") and self.match[body] > 0:
                        fn = _Fn(
                            len(self.fns) + 1,
                            self._params(k),
                            body + 1,
                            self.match[body],
                            False,
                            name,
                        )
                        self.fn_at_token[i] = fn.fid
            elif tok.kind == "punct" and tok.value == "=>":
                p = i - 1
                if not self.is_p(p, ")"):
                    # `(a: T): Promise<R> => ...`: back past the return type to the parameters.
                    for j in range(i - 2, max(i - 60, 0), -1):
                        if self.is_p(j, ")") and self._past_return_type(j) == i:
                            p = j
                            break
                if self.is_p(p, ")") and self.match[p] >= 0:
                    params = self._params(self.match[p])
                    head = self.match[p]
                elif self.is_name(p):
                    params, head = [t[p].value], p
                else:
                    continue
                if self.is_name(head - 1, "async"):
                    head -= 1
                if self.is_p(i + 1, "{") and self.match[i + 1] > 0:
                    fn = _Fn(len(self.fns) + 1, params, i + 2, self.match[i + 1], False, arrow=True)
                else:
                    fn = _Fn(
                        len(self.fns) + 1, params, i + 1, self.expr_end(i + 1), True, arrow=True
                    )
                self.fn_at_token[head] = fn.fid
            elif (
                tok.kind == "name"
                # A method may be named `get`, `set` or `from` (`set(key, value) {`): those are
                # keywords only before another name.
                and (tok.value not in _KEYWORDS or tok.value in _CONTEXTUAL)
                and self.is_p(i + 1, "(")
                and self.match[i + 1] > 0
                and self.is_p(self._past_return_type(self.match[i + 1]), "{")
                and (
                    i == 0
                    or (t[i - 1].kind == "punct" and t[i - 1].value in ("{", "}", ",", ";", "*"))
                    or self.is_name(i - 1, "async")
                    or self.is_name(i - 1, "static")
                    or self.is_name(i - 1, "get")
                    or self.is_name(i - 1, "set")
                    or (t[i - 1].kind == "name" and t[i - 1].value in _TS_MODIFIERS)
                )
            ):
                body = self._past_return_type(self.match[i + 1])
                if self.match[body] > 0:
                    fn = _Fn(
                        len(self.fns) + 1,
                        self._params(i + 1),
                        body + 1,
                        self.match[body],
                        False,
                        tok.value,
                        method=True,
                    )
                    self.fn_at_token[i] = fn.fid
            if fn is not None:
                self.fns.append(fn)

    def _scopes(self) -> None:
        self.scope_at = [0] * self.n
        for fn in sorted(self.fns, key=lambda f: f.start - f.end):  # widest first
            outer = self.scope_at[fn.start] if fn.start < self.n else 0
            self.parent[fn.fid] = outer
            for k in range(fn.start, min(fn.end, self.n)):
                self.scope_at[k] = fn.fid
        self.declared = {0: set()}
        for fn in self.fns:
            self.declared.setdefault(fn.fid, set()).update(fn.params)
            for idx, p in enumerate(fn.params):
                self.vars[(fn.fid, p)] = {("P", fn.fid, idx)}

    def scope_of(self, i: int) -> int:
        return self.scope_at[i] if 0 <= i < self.n else 0

    def _classes(self) -> None:
        """Each token's innermost class body (`class_at`, 0 for none) and the scope each class
        body sits in."""
        self.class_at = [0] * self.n
        self.class_scope: dict[int, int] = {}
        self.class_by_name: dict[str, int] = {}
        ambiguous: set[str] = set()
        spans: list[tuple[int, int]] = []
        for i in range(self.n):
            if not self.is_name(i, "class") or self.is_p(i - 1, "."):
                continue
            # `class Client`, or `var Client = class {...}` as bundlers write it.
            if self.is_name(i + 1) and self.t[i + 1].value != "extends":
                named: str | None = str(self.t[i + 1].value)
            elif self.is_p(i - 1, "=") and self.is_name(i - 2):
                named = str(self.t[i - 2].value)
            else:
                named = None
            k = i + 1
            while k < min(self.n, i + 200) and not self.is_p(k, "{"):
                if (
                    self.t[k].kind == "punct"
                    and self.t[k].value in ("(", "[")
                    and self.match[k] > 0
                ):
                    k = self.match[k]
                elif self.t[k].kind == "punct" and self.t[k].value in (";", ")", "}", "=>"):
                    break
                k += 1
            if self.is_p(k, "{") and self.match[k] > 0:
                spans.append((k, self.match[k]))
                if named:
                    # A name declared by more than one class is ambiguous: `C.m()` and `new C()`
                    # cannot be resolved to one of them. Minifiers reuse short class names across
                    # a bundle, so dispatching by such a name links unrelated code (review 98: a
                    # SheetJS-bundling extension's fetch reached a spawn through two classes that
                    # shared a mangled name). Only a name one class declares is dispatchable.
                    if named in self.class_by_name:
                        ambiguous.add(named)
                    else:
                        self.class_by_name[named] = len(spans)
        for name in ambiguous:
            self.class_by_name.pop(name, None)
        for c, (open_i, close) in sorted(
            enumerate(spans, 1), key=lambda item: item[1][0] - item[1][1]
        ):  # widest first, so an inner class wins
            self.class_scope[c] = self.scope_at[open_i]
            for k in range(open_i + 1, close):
                self.class_at[k] = c

    def this_of(self, scope: int) -> tuple[int, str]:
        """Whose `this` a function sees: in a class's method, or any function inside one, that
        class's instance (`(-class, "this")`); anywhere else the one file-wide `this` as before,
        so prototype-style code (`C.prototype.m = function () { this.x }`) still shares its
        fields. Any function inside, not only an arrow: compiled async methods run their body in
        `__awaiter(this, ..., function* () {...})`, whose `this` is the method's. One file-wide
        `this` for classes let a response one class stored reach every other class in a bundle
        (review 98 P1 A/B)."""
        s, seen = scope, 0
        while s and seen < 200:
            fn = self.fns[s - 1]
            if fn.method:
                c = self.class_at[fn.start] if fn.start < self.n else 0
                if c and self.class_scope.get(c) == self.parent.get(s, 0):
                    return (-c, "this")
            s, seen = self.parent.get(s, 0), seen + 1
        return (0, "this")

    def _on_class(self, k: int) -> bool:
        """Whether name token `k` is `m` in `C.m`, `C` a class of this file."""
        return (
            self.is_p(k - 1, ".")
            and self.is_name(k - 2)
            and not self.is_p(k - 3, ".")
            and str(self.t[k - 2].value) in self.class_by_name
        )

    def _static_call(self, k: int) -> int | None:
        """The method `C.m(...)` at name token `k` calls, when `C` is a class of this file."""
        if not self._on_class(k):
            return None
        c = self.class_by_name[str(self.t[k - 2].value)]
        return self.fn_by_name.get((-c, str(self.t[k].value)))

    def method_of(self, name: str, scope: int) -> int | None:
        """The function `this.name(...)` calls: the method of the caller's own class when it has
        one, otherwise the file-wide lookup."""
        owner = self.this_of(scope)
        if owner[0] < 0:
            return self.fn_by_name.get((owner[0], name))
        return self.fn_by_name.get(self.resolve(name, scope))

    def resolve(self, name: str, scope: int) -> tuple[int, str]:
        if name == "this":
            return self.this_of(scope)
        s = scope
        seen = 0
        while s and seen < 200:
            if name in self.declared.get(s, ()):
                return (s, name)
            s = self.parent.get(s, 0)
            seen += 1
        return (0, name)

    def _folded(self, a: int, b: int) -> str | None:
        """The string [a, b) spells when it is only literals joined by `+`, else None."""
        parts: list[str] = []
        for i in range(a, b):
            tok = self.t[i]
            if tok.kind == "str":
                parts.append(str(tok.value))
            elif not (tok.kind == "punct" and tok.value in ("+", "(", ")")):
                return None
        return "".join(parts) if parts else None

    def _args(self, open_i: int) -> list[tuple[int, int]]:
        got = self._args_cache.get(open_i)
        if got is None:
            got = self._args_cache[open_i] = self._split_args(open_i)
        return got

    def _split_args(self, open_i: int) -> list[tuple[int, int]]:
        close = self.match[open_i]
        if close < 0:
            return []
        out, k = [], open_i + 1
        start = k
        while k < close:
            if self.t[k].kind == "punct" and self.t[k].value in _OPEN and self.match[k] > 0:
                k = self.match[k] + 1
                continue
            if self.is_p(k, ","):
                out.append((start, k))
                start = k + 1
            k += 1
        if start < close:
            out.append((start, close))
        return out
