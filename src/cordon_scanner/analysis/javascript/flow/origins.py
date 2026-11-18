"""Where a file's requests go, as the class of each request site: an external literal host, a loopback or
private one, or a host nothing in the file decides. The worker states the counts and whether a decoded value reaches a
process or an evaluator (`flow/summaries.py`, the `js.request` and `js.decoded` facts); the parent reads them across the
package (`CrossFileJoin.unexternal`) to grade the two REMOTE_CODE composites.

The class is read at the request, from the first argument's text: a literal or a constant folded from literals, a
template or concatenation that starts with a scheme and a host, a name bound to one of those (followed three bindings),
an options object with a literal `host` or `hostname`. A host written by a parameter, a variable, a property, an
environment variable or a configuration is `unresolved`: nothing in the file says where the request goes, and a
literal such a value is later given is another request, in another place. Never a host name in a fact: only its class.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Final

EXTERNAL: Final = "external"
LOCAL: Final = "local"
UNRESOLVED: Final = "unresolved"
UNREAD: Final = "unread"
#: Reading the file's origins cost more steps than one file may spend (`RequestOrigins.STEP_FLOOR`): nothing is
#: known of where it requests, and the package keeps its block, as for a file not read.
OVER_BUDGET: Final = "over_budget"
CLASSES: Final = (EXTERNAL, LOCAL, UNRESOLVED, UNREAD, OVER_BUDGET)


class OverBudget(Exception):
    """A file's origins cost more steps than the limit allows."""


class Steps:
    """The steps spent reading one file's origins: a token read, a value set evaluated, a pass over the file's
    tokens. Counted, never timed: the same file costs the same steps on any machine at any load. `limit` None
    only counts (the measurement)."""

    __slots__ = ("limit", "used")

    def __init__(self, limit: int | None = None) -> None:
        self.limit = limit
        self.used = 0

    def spend(self, n: int = 1) -> None:
        self.used += n
        if self.limit is not None and self.used > self.limit:
            raise OverBudget


class RequestOrigins:
    """The class of each request site of an analysed file, and its decoded flows."""

    #: The steps one file's origins may cost: this floor and `STEPS_PER_TOKEN` for each token of the file. A step
    #: is one token read or one value set evaluated (counted, never timed), so a file costs the same on any
    #: machine at any load. Set from what real files need: across 101,553 JavaScript files, bundles of up to 11
    #: million tokens among them, the median is 0.15 steps per token, the 99.9th percentile 1.47 and the largest
    #: 15.36; no file reaches the limit, and the floor keeps a small file from a limit of a few steps. A name read
    #: again for every path that reaches it can cost thousands of steps per token; that is what the limit stops.
    STEP_FLOOR: ClassVar[int] = 100_000
    STEPS_PER_TOKEN: ClassVar[int] = 16

    #: The host in a URL a constant folds to: after a scheme and `//` (credentials skipped), or after a bare `//`.
    _URL_HOST: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:[A-Za-z][A-Za-z0-9+.-]*:)?//(?:[^@/\s]*@)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9._-]+)"
    )
    #: A host written without a scheme (`api.x.invalid/v1`, `localhost:3000`): a dotted name or `localhost`, so a
    #: bare word or a relative path (`/api/v1`, `update`) is no host.
    _BARE_HOST: ClassVar[re.Pattern[str]] = re.compile(
        r"^(\[[0-9a-fA-F:]{2,45}\]|[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}|localhost)(?=[:/?#]|$)",
        re.IGNORECASE,
    )
    #: The scheme and host a template or concatenation starts with, up to a delimiter or the end.
    _PREFIX_HOST: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:https?|wss?)://(\[[0-9a-fA-F:]+\]|[A-Za-z0-9._-]+)(?=[:/?#]|$)", re.IGNORECASE
    )
    #: A host on this machine or inside a private network: loopback, the private IPv4 ranges, `.local`.
    _PRIVATE: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:localhost|0\.0\.0\.0|\[?::1\]?|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}"
        r"|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|[A-Za-z0-9.-]+\.local)$",
        re.IGNORECASE,
    )
    #: A string that starts with a scheme and `//`.
    _SCHEMED: ClassVar[re.Pattern[str]] = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
    #: Token kinds that hold literal text: a string, and the pieces of a template.
    _LITERAL_KINDS: ClassVar[frozenset[str]] = frozenset(
        {"str", "template", "template_head", "template_middle", "template_tail"}
    )
    #: Bindings followed from a name to the literal behind it.
    _DEPTH: ClassVar[int] = 3

    @classmethod
    def host_of(cls, text: str) -> str | None:
        """The host a URL string names, or None where it names none."""
        found = cls._URL_HOST.match(text) or cls._BARE_HOST.match(text)
        return found.group(1) if found else None

    @classmethod
    def external_url(cls, text: str) -> bool:
        """Whether a string is a URL with a scheme and a host that is not loopback or private."""
        if not cls._SCHEMED.match(text):
            return False
        host = cls.host_of(text)
        return host is not None and not cls._PRIVATE.match(host)

    @classmethod
    def handed_on(cls, a: Any, values: Any) -> int:
        """Calls of a function of this file, or of another module of the package, that are handed an external
        literal URL: a helper that requests whatever it is given (`fetchRun(url)`) goes where its callers say.
        Every call is read, not only those of a file with `://` in a literal: the scheme and the host may be two
        strings joined where the helper is called (`"https:" + "//h/x"`)."""
        steps = values.steps
        if steps is not None:
            steps.spend(a.n // 8)  # the pass over the tokens below
        count = 0
        for k in range(a.n - 1):
            if not (a.t[k].kind == "name" and a.is_p(k + 1, "(") and a.match[k + 1] > 0):
                continue
            scope = a.scope_of(k)
            if not (
                a.local_callee(k) is not None or a.resolve(str(a.t[k].value), scope) in a.fn_by_name
            ):
                continue
            if steps is not None:
                steps.spend()
            for begin, end in (a._args(k + 1) or [])[:8]:
                strings = values.strings(begin, end, scope)
                count += bool(strings) and any(cls.external_url(s) for s in strings)
        return count

    @staticmethod
    def _prefix_host(a: Any, begin: int, end: int) -> list[str] | None:
        """The host a template or concatenation starts with, when its first string spells a scheme and a
        host and the host is not cut short by the next part (`https://api.x/${id}` is one, `https://${h}` not)."""
        i = begin
        while i < end and a.t[i].kind == "punct":
            i += 1
        if i < end and a.t[i].kind == "str":
            text = str(a.t[i].value)
            found = RequestOrigins._PREFIX_HOST.match(text)
            if found and (found.end() < len(text) or i + 1 >= end or a.t[i + 1].kind == "punct"):
                return [found.group(1)]
        return None

    @classmethod
    def literal_hosts(
        cls, a: Any, begin: int, end: int, scope: int, depth: int = 0, steps: Steps | None = None
    ) -> list[str] | None:
        """Every host the argument can name when the file's literals decide it, or None."""
        if steps is not None:
            steps.spend(1 + (end - begin) // 8)
        folded = a._folded(begin, end)
        if folded is not None:
            host = cls.host_of(folded)
            return [host] if host else None
        prefix = cls._prefix_host(a, begin, end)
        if prefix is not None:
            return prefix
        if end == begin + 1 and a.t[begin].kind == "name" and depth < cls._DEPTH:
            hosts: list[str] = []
            for first, last in a.bound.get(a.resolve(str(a.t[begin].value), scope)) or []:
                sub = cls.literal_hosts(a, first, last, a.scope_of(first), depth + 1, steps)
                if sub is None:
                    return None
                hosts += sub
            return hosts or None
        if a.is_p(begin, "{") and a.match[begin] > 0:
            for i in range(begin + 1, a.match[begin]):
                if (
                    a.t[i].kind == "name"
                    and str(a.t[i].value) in ("host", "hostname")
                    and a.is_p(i + 1, ":")
                    and a.t[i + 2].kind == "str"
                ):
                    return [str(a.t[i + 2].value)]
        return None

    #: The sinks a response comes back through: a request, a raw connection, a DNS lookup (a TXT record).
    SITES: ClassVar[frozenset[str]] = frozenset({"request", "connection", "dns"})

    @classmethod
    def site_hosts(cls, a: Any, values: Any, k: int, kind: str, scope: int) -> list[str] | None:
        """Every host the request, connection or lookup at name token `k` can name when the file's literals
        decide it (a constant, a template, a field of an object the file builds, a returned value: `JsValues`;
        or the prefix and option forms of `literal_hosts`), or None. A request names its host in its first
        argument; a socket or a lookup may name it in any of the first four (`connect(port, host)`)."""
        args = a._args(k + 1)
        if not args:
            return None
        found: list[str] = []
        for begin, end in args[:1] if kind == "request" else args[:4]:
            if values.steps is not None:
                values.steps.spend(end - begin)  # the scan of the argument's tokens below
            strings = values.strings(begin, end, scope)
            if strings:
                found += [host for host in map(cls.host_of, strings) if host]
            else:
                found += cls.literal_hosts(a, begin, end, scope, 0, values.steps) or []
            # A URL written in the expression is where the request goes by default, whatever a variable beside
            # it may override (`process.env.MIRROR || "https://h/x"`): an external one counts.
            found += [
                host
                for i in range(begin, end)
                if a.t[i].kind in cls._LITERAL_KINDS
                and cls.external_url(str(a.t[i].value))
                and (host := cls.host_of(str(a.t[i].value)))
            ]
        return found or None

    @classmethod
    def names_an_external_literal(
        cls,
        a: Any,
        begin: int,
        end: int,
        scope: int,
        steps: Steps,
        depth: int = 0,
        seen: dict[tuple[int, int, int, int], bool] | None = None,
    ) -> bool:
        """Whether the tokens [begin, end), what the names in them are bound to and the bodies of the functions
        of this file they call hold an external literal URL: where a request goes by default when the value that
        reaches it is unknown (`process.env.MIRROR || "https://h/x"` returned by a helper, then fetched). Each
        token read is a step; past the limit the whole file is `over_budget`. `seen` holds the answer for each
        range at each depth, so a range reached by many paths, or by many requests, is read once."""
        if seen is not None and (key := (begin, end, scope, depth)) in seen:
            return seen[key]
        found = cls._names_literal(a, begin, end, scope, steps, depth, seen)
        if seen is not None:
            seen[(begin, end, scope, depth)] = found
        return found

    @classmethod
    def _names_literal(
        cls,
        a: Any,
        begin: int,
        end: int,
        scope: int,
        steps: Steps,
        depth: int,
        seen: dict[tuple[int, int, int, int], bool] | None,
    ) -> bool:
        for i in range(begin, end):
            token = a.t[i]
            steps.spend()
            if token.kind in cls._LITERAL_KINDS and cls.external_url(str(token.value)):
                return True
            if token.kind != "name" or depth >= cls._DEPTH:
                continue
            key = a.resolve(str(token.value), scope)
            for first, last in a.bound.get(key) or []:
                if cls.names_an_external_literal(
                    a, first, last, a.scope_of(first), steps, depth + 1, seen
                ):
                    return True
            fid = a.fn_by_name.get(key) if a.is_p(i + 1, "(") else None
            if fid and cls.names_an_external_literal(
                a,
                a.fns[fid - 1].start,
                a.fns[fid - 1].end,
                a.scope_of(a.fns[fid - 1].start),
                steps,
                depth + 1,
                seen,
            ):
                return True
        return False

    @classmethod
    def limit(cls, a: Any) -> int:
        """The steps one file's origins may cost: a floor and a share for each token of the file."""
        return cls.STEP_FLOOR + cls.STEPS_PER_TOKEN * int(a.n)

    @classmethod
    def classes(cls, a: Any) -> dict[str, int]:
        """The sites of an analysed file a response comes back through, by class: `external`, `local`,
        `unresolved`; `over_budget` alone when reading them cost more than `limit` steps, or when the analysis
        did not reach every call (the sites it recorded are then not the file's whole set)."""
        return cls.measure(a, cls.limit(a))[0]

    @classmethod
    def measure(cls, a: Any, limit: int | None = None) -> tuple[dict[str, int], int]:
        """`classes` and the steps it cost, with `limit` steps allowed (none: only counted)."""
        from cordon_scanner.analysis.javascript.js_values import JsValues

        steps = Steps(limit)
        if not a.sites_complete:
            return {OVER_BUDGET: 1}, 0
        out = {EXTERNAL: 0, LOCAL: 0, UNRESOLVED: 0}
        searched: dict[tuple[int, int, int, int], bool] = {}
        try:
            values = JsValues(a, steps)
            # The sites are the call pass's own (`_apply_sink` records each request, connection and DNS call
            # it classes), not a second walk over every token.
            for k, kind in sorted(a.sink_sites.items()):
                if not a._called(k):
                    continue
                steps.spend()
                scope = a.scope_of(k)
                hosts = cls.site_hosts(a, values, k, kind, scope)
                if hosts is None:
                    args = a._args(k + 1) or []
                    default = any(
                        cls.names_an_external_literal(a, begin, end, scope, steps, 0, searched)
                        for begin, end in (args[:1] if kind == "request" else args[:4])
                    )
                    out[EXTERNAL if default else UNRESOLVED] += 1
                elif all(cls._PRIVATE.match(host) for host in hosts):
                    out[LOCAL] += 1
                else:
                    out[EXTERNAL] += 1
            # A helper that requests whatever it is given goes where its callers say: an external literal URL
            # handed to a function of the package counts as an external request (the helper's own site is
            # `unresolved`, its parameter being all the file says of it).
            out[EXTERNAL] += cls.handed_on(a, values)
        except OverBudget:
            return {OVER_BUDGET: 1}, steps.used
        return {name: n for name, n in out.items() if n}, steps.used

    @staticmethod
    def decoded(a: Any) -> bool:
        """Whether a decoded value reaches a process or an evaluator in the file (`decoded` to `execute` or
        `process`: the flows `CAP.JS.FLOW.DECODED_RUN` reports)."""
        return any(
            "decoded" in flow.sources and flow.sink in ("execute", "process")
            for flow in a.flows.values()
        )


__all__ = [
    "CLASSES",
    "EXTERNAL",
    "LOCAL",
    "OVER_BUDGET",
    "UNREAD",
    "UNRESOLVED",
    "OverBudget",
    "RequestOrigins",
    "Steps",
]
