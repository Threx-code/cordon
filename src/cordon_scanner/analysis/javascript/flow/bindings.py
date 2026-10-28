"""What a JavaScript file binds its names to: declarations and assignments, including destructuring,
the modules it imports under an alias, and the member chains those aliases begin."""

from __future__ import annotations

from cordon_scanner.analysis.javascript.flow.structure import Structure
from cordon_scanner.analysis.javascript.flow.vocabulary import (
    _DECLARE,
    _HOST_OBJECTS,
    _IMPORT_HELPERS,
    _KEYWORDS,
    _REQUEST_MODULES,
)


class Bindings(Structure):
    """The bindings layer of `js_flow._Analysis`: every name's bindings, and the module or member
    each import alias stands for."""

    def _bindings(self) -> list[tuple[list[tuple[int, str]], int, int]]:
        """(targets, rhs_start, rhs_end): every binding site, with the names it writes."""
        t, out = self.t, []
        for i in range(self.n):
            tok = t[i]
            if tok.kind == "name" and tok.value in _DECLARE:
                k = i + 1
                while k < self.n:
                    scope = self.scope_of(k)
                    if self.is_name(k) and t[k].value not in _KEYWORDS:
                        targets = [t[k].value]
                        k += 1
                    elif self.is_p(k, "{") or self.is_p(k, "["):
                        close = self.match[k]
                        if close < 0:
                            break
                        targets = [
                            t[m].value
                            for m in range(k + 1, close)
                            if t[m].kind == "name"
                            and t[m].value not in _KEYWORDS
                            and not self.is_p(m + 1, ":")
                        ]
                        k = close + 1
                    else:
                        break
                    self.declared.setdefault(scope, set()).update(targets)
                    if self.is_p(k, ":"):  # `const t: string = ...`: past the TypeScript type
                        k = self._type_end(k + 1, min(self.n, k + 80), ("=", ",", ";"))
                    if self.is_p(k, "=") or (self.is_name(k, "of") or self.is_name(k, "in")):
                        end = self.expr_end(k + 1)
                        out.append(([(scope, x) for x in targets], k + 1, end))
                        k = end
                    if self.is_p(k, ","):
                        k += 1
                        continue
                    break
            elif tok.kind == "punct" and tok.value in ("=", "+=", "||=", "??="):
                if i == 0 or t[i - 1].kind not in ("name", "punct"):
                    continue
                base = self._assign_base(i - 1)
                if base is None:
                    continue
                scope = self.scope_of(i)
                out.append(([self.resolve(base, scope)], i + 1, self.expr_end(i + 1)))
            elif tok.kind == "name" and tok.value == "function" and self.is_name(i + 1):
                self.declared.setdefault(self.scope_of(i), set()).add(t[i + 1].value)
        return out

    def _assign_base(self, k: int) -> str | None:
        """The name at the root of an assignment target ending at token `k`: `a`, `a.b.c`, `a[x]`.
        None for a member of the runtime's own objects: `process.exitCode = ok ? 0 : 1` stores
        nothing the file reads back as `process.platform`, and taking `process` as the store let
        one response reach every child process the file starts (review 98 P1 A/B)."""
        end = k
        while k >= 0:
            tok = self.t[k]
            if tok.kind == "punct" and tok.value == "]" and self.match[k] >= 0:
                k = self.match[k] - 1
                continue
            if tok.kind == "name":
                if self.is_p(k - 1, "."):
                    k -= 2
                    continue
                if k != end and tok.value in _HOST_OBJECTS:
                    return None
                return None if tok.value in _KEYWORDS and tok.value != "this" else tok.value
            return None
        return None

    def _modules(self) -> None:
        """`const h = require("https")`, `import axios from "axios"`, `const {request} = require(...)`."""
        t = self.t
        for i in range(self.n):
            if (
                self.is_name(i, "require")
                and self.is_p(i + 1, "(")
                and self.match[i + 1] > i + 2
                # `require("child_" + "process")`: the name its literals spell.
                and (spelled := self._folded(i + 2, self.match[i + 1])) is not None
            ):
                module = spelled.removeprefix("node:")
                close = self.match[i + 1]
                k = i - 1
                if self.is_p(k, "(") and self.is_name(k - 1) and t[k - 1].value in _IMPORT_HELPERS:
                    k -= 2  # `os_1 = __importDefault(require("os"))`: the helper hands it back
                member = None
                if self.is_p(close + 1, ".") and self.is_name(close + 2):
                    member = t[close + 2].value
                if self.is_p(k, "="):
                    k -= 1
                    if self.is_name(k):
                        self.aliases[t[k].value] = module + (f".{member}" if member else "")
                    elif self.is_p(k, "}") and self.match[k] >= 0:
                        self._destructured(self.match[k], k, module)
            elif self.is_name(i, "import") and not self.is_p(i + 1, "("):
                k = i + 1
                end = min(self.n, i + 200)
                while k < end and not self.is_name(k, "from"):
                    k += 1
                if k + 1 < self.n and t[k + 1].kind == "str":
                    module = str(t[k + 1].value).removeprefix("node:")
                    j = i + 1
                    if self.is_name(j) and t[j].value not in _KEYWORDS:
                        self.aliases[t[j].value] = module
                    for m in range(i + 1, k):
                        if self.is_name(m, "as") and self.is_name(m + 1):
                            prev = t[m - 1]
                            self.aliases[t[m + 1].value] = (
                                module
                                if prev.kind == "punct" and prev.value == "*"
                                else f"{module}.{prev.value}"
                            )
                    for m in range(i + 1, k):
                        if self.is_p(m, "{") and self.match[m] > 0:
                            self._destructured(m, self.match[m], module)
        # `const api = axios.create({...})`, `got.extend(...)`: an instance sends as the module does.
        for i in range(2, self.n - 3):
            if (
                self.is_p(i - 1, "=")
                and self.is_name(i - 2)
                and self.is_name(i)
                and self.is_p(i + 1, ".")
                and self.is_name(i + 2)
                and t[i + 2].value in ("create", "extend")
                and self.is_p(i + 3, "(")
            ):
                root = self.aliases.get(str(t[i].value), str(t[i].value)).split(".")[0]
                if root in _REQUEST_MODULES:
                    self.aliases[str(t[i - 2].value)] = root

    def _destructured(self, open_i: int, close_i: int, module: str) -> None:
        t = self.t
        for m in range(open_i + 1, close_i):
            if t[m].kind != "name" or t[m].value in _KEYWORDS:
                continue
            if (self.is_p(m + 1, ":") or self.is_name(m + 1, "as")) and self.is_name(m + 2):
                self.aliases[t[m + 2].value] = f"{module}.{t[m].value}"
            elif not self.is_p(m - 1, ":") and not self.is_name(m - 1, "as"):
                self.aliases[t[m].value] = f"{module}.{t[m].value}"

    def _chain(self, i: int) -> tuple[list[str], int]:
        """The dotted callee ending at token `i` (`a.b.c` -> ["a","b","c"]) and its first token."""
        parts = [str(self.t[i].value)]
        k = i
        while self.is_p(k - 1, ".") and self.is_name(k - 2):
            parts.append(str(self.t[k - 2].value))
            k -= 2
        if self.is_p(k - 1, "?.") and self.is_name(k - 2):
            parts.append(str(self.t[k - 2].value))
            k -= 2
        # `require("axios").post(...)`: the module itself, inline.
        if (
            self.is_p(k - 1, ".")
            and self.is_p(k - 2, ")")
            and self.match[k - 2] >= 1  # `require(` may open the file
            and self.is_name(self.match[k - 2] - 1, "require")
            and self.t[self.match[k - 2] + 1].kind == "str"
        ):
            parts.append(str(self.t[self.match[k - 2] + 1].value).removeprefix("node:"))
            k = self.match[k - 2] - 1
        parts.reverse()
        # A property of something that is not a name (`/re/.exec(line)`, `f().exec(x)`) is not
        # the import of that name: `exec` destructured from child_process made every regex's
        # `.exec` a command run.
        if (
            parts
            and parts[0] in self.aliases
            and not (self.is_p(k - 1, ".") or self.is_p(k - 1, "?."))
        ):
            parts = (
                self.aliases[parts[0]].split(".", 1)[:1]
                + (
                    self.aliases[parts[0]].split(".", 1)[1:]
                    if "." in self.aliases[parts[0]]
                    else []
                )
                + parts[1:]
            )
        if len(parts) > 2 and parts[1] == "default":
            del parts[1]  # `os_1.default.hostname`: a module's default export is the module
        return parts, k
