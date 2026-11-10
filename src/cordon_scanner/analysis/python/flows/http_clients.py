"""HTTP client objects and the methods on them that send a request (group A (a)). Moved out of
`pyfacts.py` (its length limit); `pyfacts` folds `CLIENT_REQUESTS` into `PRIMITIVES` as egress."""

from __future__ import annotations

#: Constructors of an HTTP client object, and the methods on it that send a request. A request sent
#: through a client (`client = httpx.Client(); client.post(url, json=data)`, `with requests.Session()
#: as s`, `self._session = requests.Session()`) is a request as `requests.post` is: group A (a),
#: 2026-11-10, where 13 of 17 PyPI units sent what they gathered through one and no flow fact fired.
HTTP_CLIENTS: frozenset[str] = frozenset(
    {
        "requests.Session",
        "requests.session",
        "requests.sessions.Session",
        "httpx.Client",
        "httpx.AsyncClient",
        "urllib3.PoolManager",
        "urllib3.HTTPConnectionPool",
        "urllib3.HTTPSConnectionPool",
        "aiohttp.ClientSession",
    }
)
HTTP_CLIENT_METHODS: frozenset[str] = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request", "send", "stream",
     "urlopen"}
)  # fmt: skip

#: `<client>.<method>` for every client and request method: the dotted names a call resolves to.
CLIENT_REQUESTS: frozenset[str] = frozenset(
    f"{client}.{method}" for client in HTTP_CLIENTS for method in HTTP_CLIENT_METHODS
)

__all__ = ["CLIENT_REQUESTS", "HTTP_CLIENTS", "HTTP_CLIENT_METHODS"]
