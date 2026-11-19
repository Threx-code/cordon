"""The name a private package leaves the tenant under (design spec 22.2 Q1, settled by cordon-a0).

`canonical_id` is plain and never changes. A name that belongs to one tenant (an internal
namespace, a private registry, an unpublished package) must not leave that tenant in the clear, so
anything sent out of the tenant -- to Cordon's shared evidence, a feed, a customer-facing export --
carries `outbound`'s form: the plain id for a public name, and for a private one a keyed hash,

```
  hash:<id prefix>/<hmac-sha256 over the plain canonical id, key = the tenant's key for this purpose>
  pkg:npm/%40acme/billing   ->   hash:pkg/9f2c...   (64 hex)
```

The key comes from the tenant's key hierarchy (spec 15.3) through `TenantKeys`; this module only
asks for it, so the console, the backend and a test use the one function. A tenant may opt in to
plain private names; the default is hashed. Two tenants' hashes of one name differ, and the hash
does not give the name back.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Collection
from typing import ClassVar, Protocol


class TenantKeys(Protocol):
    """The tenant's key hierarchy as this module needs it: one secret per tenant and purpose."""

    def key(self, tenant: str, purpose: str) -> bytes: ...


class PrivateNames:
    """Decide whether a name is private, and write the form that may leave the tenant."""

    PURPOSE: ClassVar[str] = "subject-name-v1"
    PREFIX: ClassVar[str] = "hash:"
    MIN_KEY_BYTES: ClassVar[int] = 16
    #: Registries open to everyone. A package named by any other registry is private to whoever runs it.
    PUBLIC_REGISTRIES: ClassVar[frozenset[str]] = frozenset(
        [
            "registry.npmjs.org",
            "pypi.org",
            "files.pythonhosted.org",
            "crates.io",
            "index.crates.io",
            "rubygems.org",
            "repo.maven.apache.org",
            "repo1.maven.org",
            "api.nuget.org",
            "nuget.org",
            "packagist.org",
            "proxy.golang.org",
            "pkg.go.dev",
            "docker.io",
            "registry-1.docker.io",
            "ghcr.io",
            "quay.io",
            "mcr.microsoft.com",
            "gcr.io",
            "registry.k8s.io",
        ]
    )

    @classmethod
    def is_private(
        cls,
        *,
        registry: str | None = None,
        namespace: str | None = None,
        published: bool | None = None,
        internal_namespaces: Collection[str] = (),
    ) -> bool:
        """Whether a name is private: it is known to be unpublished, it is served by a registry that is
        not a public one, or it sits in one of the tenant's internal namespaces."""
        if published is False:
            return True
        if registry and registry.strip().lower().rstrip("/") not in cls.PUBLIC_REGISTRIES:
            return True
        folded = {item.strip().lower() for item in internal_namespaces}
        return bool(namespace and namespace.strip().lower() in folded)

    @classmethod
    def hashed(cls, subject_id: str, tenant: str, keys: TenantKeys) -> str:
        """The keyed hash of a plain canonical id: `hash:<prefix>/<64 hex>`, the id's own prefix
        (the text before its first `:`) kept so a view can group by kind."""
        if cls.is_hashed(subject_id):
            raise ValueError("a hashed id is not hashed again")
        prefix, separator, _ = subject_id.partition(":")
        if not separator or not prefix:
            raise ValueError(f"{subject_id!r} is not a canonical subject id")
        secret = keys.key(tenant, cls.PURPOSE)
        if len(secret) < cls.MIN_KEY_BYTES:
            raise ValueError("the tenant's key is too short to hash names with")
        digest = hmac.new(secret, subject_id.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{cls.PREFIX}{prefix}/{digest}"

    @classmethod
    def is_hashed(cls, text: str) -> bool:
        return text.startswith(cls.PREFIX)

    @classmethod
    def outbound(
        cls,
        subject_id: str,
        tenant: str,
        keys: TenantKeys,
        *,
        private: bool,
        plain_opt_in: bool = False,
    ) -> str:
        """The form of `subject_id` that may leave the tenant: plain for a public name, or when the
        tenant opted in to plain private names; the keyed hash otherwise."""
        if not private or plain_opt_in:
            return subject_id
        return cls.hashed(subject_id, tenant, keys)


__all__ = ["PrivateNames", "TenantKeys"]
