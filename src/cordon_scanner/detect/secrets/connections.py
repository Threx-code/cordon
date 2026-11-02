"""A credential written into a connection string (`scheme://user:secret@host`), and the hosts such a
string can name without leaving the machine: the shapes `SECRET.URL.CREDENTIAL.001` reads.
"""

from __future__ import annotations

import re

from cordon_scanner.detect.secrets.patterns import SecretPattern

CONNECTION_STRING = SecretPattern._p(
    r"""(?ix)
    \b[a-z][a-z0-9+.\-]{1,30}://
    [^\s:@/]{1,64} : ([^\s:@/]{6,120}) @
    (
        # An IPv6 literal, which is the one host form that carries colons.
        \[[0-9a-f:.]{2,45}\]
        # Or a dot-separated sequence of letter-digit-hyphen labels, which is
        # every other host there is.
      | [a-z0-9](?:[a-z0-9.\-]{0,120})?
    )
    """
)
r"""A password embedded in a URL's userinfo.

A database URL that carries userinfo -- a user name and a password, separated by
a colon, before the host -- holds a live credential in a form no assignment
pattern sees, and that is the conventional way such URLs are written.

The host is captured as well as the password, because where the URL points
decides whether the value is a credential at all. See `LOCAL_OR_RESERVED_HOST`.

**Matched as a host, not as "everything up to a delimiter."** The host group was
`[^\s@/?\#]{1,120}`, which excludes whitespace and the characters that end the
authority component of a URL -- and not the quote that ends the STRING the URL
is written inside. A URL in source code is nearly always quoted, so the captured
host came back as `my.example.com")`, and `LOCAL_OR_RESERVED_HOST` is anchored at
both ends: every reserved-host exclusion it makes silently failed for any URL
inside a quoted expression. Ruby's own `lib/uri/generic.rb` documents `uri.user=`
with `URI.parse("http://john:S3nsit1ve@my.example.com")` in an RDoc comment, and
that was reported at high severity -- a credential for the domain RFC 2606
reserves so that documentation can do exactly this.

A consequence worth naming: a host written as a template expression -- Docker
Swarm's `@{{ index .Service.Labels ... }}_postgres` -- no longer matches at all,
where before it matched as an opaque run of characters. That is the same
judgement in a different place. A host nothing can resolve is not a host a
credential authenticates to, and the template has to be rendered before there is
anything to point at.

Described rather than shown. This project scans itself, and a complete example
here would be a true positive: the tool should not need an exception for its own
source."""

LOCAL_OR_RESERVED_HOST = re.compile(
    rb"""(?ix)
    ^\[?(?:
        localhost
      | 127\.[0-9.]{1,11}
      | 0\.0\.0\.0
      | ::1
      | [a-z0-9-]{1,60}\.(?:localhost|local|test|invalid|example)
      | (?:[a-z0-9-]{1,60}\.){0,4}example\.(?:com|net|org)
      # A SINGLE-LABEL host, which on the public internet does not resolve. A name with
      # no dot in it is a Compose service, a Kubernetes service or an `/etc/hosts`
      # entry -- something reachable only from inside the thing that defines it.
      # SQLAlchemy's `setup.cfg` declares a connection URL per driver against
      # `mssql2022`, which is the name of the container its own test suite starts, and
      # the credential in them is `scott:tiger` -- Oracle's demonstration account since
      # 1979. Its loopback variants were already excused by the line above and these
      # were not, which is the same fixture written for a container instead of a port.
      | [a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?
    )\]?(?::[0-9]{1,5})?$
    """
)
"""Hosts nobody's production credential authenticates to.

Loopback, the `.test`/`.invalid`/`.example`/`.localhost` names RFC 6761 reserves
for exactly this, and the `example.com` family RFC 2606 reserves for
documentation. A URL pointing at one of them is a test fixture or a manual
page, and axios alone had a dozen of them -- `http://urluser:urlpass@127.0.0.1`
appears in its adapter tests because testing basic auth requires a URL with
basic auth in it.

Deliberately not extended to private ranges. A credential for `10.0.0.5` is a
credential for something real, and treating an internal address as a
documentation address is how an internal leak goes unreported."""


__all__ = ["CONNECTION_STRING", "LOCAL_OR_RESERVED_HOST"]
