"""The `vt` module's functions on network names: `vt.net.IP.in_range(cidr)` and
`vt.net.Domain.permutation_of(target[, kinds])`, as YARA-X 1.21.0 answers them.

`in_range` is whether the IP address (its `raw` text) lies in a CIDR range written `address/prefix`.
`permutation_of` is whether the domain is a lookalike of `target`: the same public suffix, a different
name, and the registrable label related to the target's by one of the permutation kinds, the bits of
`kinds` (31, every kind, when not given):

- TYPO (1): one key's neighbour inserted, a letter left out, one replaced by a QWERTY neighbour, a
  letter doubled, two adjacent letters swapped once, one vowel for another;
- HOMOGLYPH (2): letters replaced by look-alikes (`rn`-style shapes are not included, as the
  reference does not include them);
- HYPHENATION (4): hyphens inserted between letters of the registrable label;
- SUBDOMAIN (8): dots inserted between letters of the name before the suffix;
- BITSQUATTING (16): one ASCII letter one bit away.

Where each comparison resumes after a difference is the reference's: the checks compare what follows,
not the letter skipped (`insertion("ab", "aqb")` holds because "b" follows in both). The tables (QWERTY
neighbours, look-alike letters) are the reference's, since they are what a rule's answer depends on.

The public suffix is the Public Suffix List snapshot the reference was built with (psl 2.1.238,
data/public_suffix_list.dat, MPL-2.0), read with the list's own algorithm: labels matched from the
right, byte for byte, an exception rule ending the suffix before its label, a wildcard taking any one
label, and the last label alone when no rule matches. Common hosts (www, ftp, m, mail, webmail, ns1,
ns2) are read as subdomains, as the reference reads them.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any, ClassVar

KINDS = {"ALL": 31, "TYPO": 1, "HOMOGLYPH": 2, "HYPHENATION": 4, "SUBDOMAIN": 8, "BITSQUATTING": 16}


class PublicSuffix:
    """The Public Suffix List as a trie of labels from the right."""

    _root: ClassVar[dict[Any, Any] | None] = None
    #: The key marking where a rule ends: a str, so no label (bytes) can be it.
    END: ClassVar[str] = "end"

    @staticmethod
    def _trie() -> dict[Any, Any]:
        if PublicSuffix._root is None:
            root: dict[Any, Any] = {}
            text = resources.files(__package__).joinpath("data/public_suffix_list.dat").read_bytes()
            for line in text.splitlines():
                rule = line.strip()
                if not rule or rule.startswith(b"//"):
                    continue
                node = root
                for label in reversed(rule.split(b".")):
                    node = node.setdefault(label, {})
                node[PublicSuffix.END] = {}
            PublicSuffix._root = root
        return PublicSuffix._root

    @staticmethod
    def length(name: bytes) -> int | None:
        """The suffix's length in bytes (a trailing dot counted), or None when there is none."""
        labels = name.split(b".")
        fqdn = name.endswith(b".")
        if fqdn:
            labels.pop()
        labels.reverse()
        if not labels:
            return None
        node = PublicSuffix._trie()
        matched = 0  # labels the prevailing rule covers
        for depth, label in enumerate(labels, 1):
            if b"!" + label in node:
                break  # an exception: the suffix stops before this label
            following: dict[Any, Any] | None = node.get(label, node.get(b"*"))
            if following is None:
                break
            node = following
            if PublicSuffix.END in node:
                matched = depth
        if matched == 0:
            matched = 1  # no rule: the last label alone
        size = sum(len(x) for x in labels[:matched]) + matched - 1
        size += 1 if fqdn else 0
        return size or None


@dataclass(frozen=True)
class DomainParts:
    prefix: str | None
    subdomain: str | None
    domain: str | None
    tld: str


class VtNet:
    """The two `vt.net` functions."""

    HOSTS: ClassVar[frozenset[str]] = frozenset(
        {"www", "ftp", "m", "mail", "webmail", "ns1", "ns2"}
    )
    VOWELS: ClassVar[frozenset[str]] = frozenset("aeiou")
    QWERTY: ClassVar[dict[str, str]] = {
        "1": "2q", "2": "13qw", "3": "24we", "4": "35er", "5": "46rt", "6": "57ty", "7": "68yu",
        "8": "79ui", "9": "80io", "0": "9op", "q": "12wa", "w": "qeas23", "e": "wrsd34",
        "r": "etdf45", "t": "ryfg56", "y": "tugh67", "u": "yihj78", "i": "uojk89", "o": "ipkl90",
        "p": "ol0", "a": "qwsz", "s": "awedzx", "d": "serfxc", "f": "drtgcv", "g": "ftyhvb",
        "h": "gyujbn", "j": "huiknm", "k": "jiolm", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv",
        "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
    }  # fmt: skip
    LOOKALIKES: ClassVar[dict[str, str]] = {
        "a": "\u00e0\u00e1\u00e2\u00e3\u00e4\u00e5\u0251\u1ea1\u01ce\u0103\u0227\u0105", "b": "d\u0299\u0253\u1e03\u1e05\u1e07\u0185", "c": "e\u0188\u010b\u0107\u00e7\u010d\u0109o", "d": "b\u0257\u0111\u010f\u0256\u1e11\u1e0b\u1e0d\u1e0f\u1e13",
        "e": "c\u00e9\u00e8\u00ea\u00eb\u0113\u0115\u011b\u0117\u1eb9\u0119\u0229\u0247\u1e1b", "f": "\u0192\u1e1f", "g": "q\u0262\u0261\u0121\u011f\u01f5\u0123\u011d\u01e7\u01e5", "h": "\u0125\u021f\u0127\u0266\u1e27\u1e29\u2c68\u1e23\u1e25\u1e2b\u1e96",
        "i": "1l\u00ed\u00ec\u00ef\u0131\u0269\u01d0\u012d\u1ec9\u1ecb\u0268\u020b\u012b", "j": "\u029d\u0249", "k": "\u1e33\u1e35\u2c6a\u0137", "l": "1i\u026b\u0142", "m": "n\u1e41\u1e43\u1d0d\u0271\u1e3f",
        "n": "mr\u0144\u1e45\u1e47\u1e49\u00f1\u0146\u01f9\u0148\ua791", "o": "0\u022f\u1ecd\u1ecf\u01a1\u00f3\u00f6\u0151", "p": "\u01bf\u01a5\u1e55\u1e57", "q": "g\u02a0",
        "r": "\u0280\u027c\u027d\u0155\u0157\u0159\u024d\u027e\u0213\u0211\u1e59\u1e5b\u1e5f", "s": "\u0282\u015b\u1e63\u1e61\u0219\u015d\u0161", "t": "\u0163\u0167\u1e6b\u1e6d\u021b\u01ab",
        "u": "\u1d1c\u01d4\u016d\u00fc\u0289\u00f9\u00fa\u00fb\u0169\u016b\u0173\u01b0\u016f\u0171\u0215\u0217\u1ee5", "v": "\u1e7f\u2c71\u1d8c\u1e7d\u2c74", "w": "\u0175\u1e81\u1e83\u1e85\u2c73\u1e87\u1e89\u1e98", "y": "\u028f\u00fd\u00ff\u0177\u01b4\u0233\u024f\u1eff\u1e8f\u1ef5",
        "z": "\u0290\u017c\u017a\u1d22\u01b6\u1e93\u1e95\u2c6c",
    }  # fmt: skip

    @staticmethod
    def in_range(raw: bytes, cidr: bytes) -> bool:
        try:
            text = cidr.decode("utf-8")
            if "/" not in text or "%" in text:
                return False
            network = ipaddress.ip_network(text, strict=False)
            address_text = raw.decode("utf-8")
            if "%" in address_text:
                return False
            address = ipaddress.ip_address(address_text)
        except (UnicodeDecodeError, ValueError):
            return False
        return address.version == network.version and address in network

    @staticmethod
    @lru_cache(maxsize=4096)
    def parse_domain(name: bytes) -> DomainParts | None:
        size = PublicSuffix.length(name)
        if size is None:
            return None
        try:
            tld = name[len(name) - size :].decode("utf-8")
        except UnicodeDecodeError:
            return None
        if len(name) <= size + 1:
            return DomainParts(None, None, None, tld)
        try:
            prefix = name[: len(name) - size - 1].decode("utf-8")
        except UnicodeDecodeError:
            return None
        sub, dot, dom = prefix.rpartition(".")
        subdomain: str | None = sub if dot else None
        domain: str | None = dom if dot else prefix
        if domain in VtNet.HOSTS:
            subdomain, domain = domain, None
        return DomainParts(prefix, subdomain, domain, tld)

    @staticmethod
    def permutation_of(raw: bytes, target: bytes, kinds: int = 31) -> bool:
        scanned, legit = VtNet.parse_domain(raw), VtNet.parse_domain(target)
        if scanned is None or legit is None or scanned == legit or scanned.tld != legit.tld:
            return False
        if scanned.domain is None or legit.domain is None:
            return False
        a, b = legit.domain, scanned.domain
        if kinds & 1 and Typos.any(a, b):
            return True
        if kinds & 2 and Typos.homoglyph(a, b):
            return True
        if kinds & 16 and Typos.bitsquatting(a, b):
            return True
        if (
            kinds & 8
            and legit.prefix is not None
            and scanned.prefix is not None
            and Typos.interleaved(legit.prefix, scanned.prefix, ".")
        ):
            return True
        return bool(kinds & 4 and Typos.interleaved(a, b, "-"))


class Typos:
    """Each permutation check, over code points, comparing what follows a difference."""

    @staticmethod
    def any(a: str, b: str) -> bool:
        return (
            Typos.insertion(a, b)
            or Typos.omission(a, b)
            or Typos.replacement(a, b)
            or Typos.doubling(a, b)
            or Typos.swap(a, b)
            or Typos.vowel_swap(a, b)
        )

    @staticmethod
    def neighbours(x: str, y: str) -> bool:
        return y in VtNet.QWERTY.get(x, "")

    @staticmethod
    def first_difference(a: str, b: str) -> int:
        """The first index where the two differ, or the shorter length."""
        i = 0
        while i < len(a) and i < len(b) and a[i] == b[i]:
            i += 1
        return i

    @staticmethod
    def insertion(a: str, b: str) -> bool:
        i = Typos.first_difference(a, b)
        if i >= len(b):
            return False
        if i < len(a) and Typos.neighbours(a[i], b[i]):
            return a[i + 1 :] == b[i + 2 :]
        if i > 0 and Typos.neighbours(a[i - 1], b[i]):
            return a[i + 1 :] == b[i + 2 :]
        return False

    @staticmethod
    def omission(a: str, b: str) -> bool:
        i = Typos.first_difference(a, b)
        if i < len(a) and i < len(b):
            return i + 1 < len(a) and a[i + 1] == b[i] and a[i + 2 :] == b[i + 1 :]
        return i < len(a) and i == len(b) and len(a) == i + 1

    @staticmethod
    def replacement(a: str, b: str) -> bool:
        i = Typos.first_difference(a, b)
        if i < len(a) and i < len(b):
            return Typos.neighbours(a[i], b[i]) and a[i + 1 :] == b[i + 1 :]
        return False

    @staticmethod
    def vowel_swap(a: str, b: str) -> bool:
        i = Typos.first_difference(a, b)
        if i < len(a) and i < len(b):
            return a[i] in VtNet.VOWELS and b[i] in VtNet.VOWELS and a[i + 1 :] == b[i + 1 :]
        return False

    @staticmethod
    def doubling(a: str, b: str) -> bool:
        i = Typos.first_difference(a, b)
        if i == 0 or i >= len(b):
            return False
        if b[i] != a[i - 1]:
            return False
        if i < len(a):
            return a[i + 1 :] == b[i + 2 :]
        return b[i + 1 :] == ""

    @staticmethod
    def swap(a: str, b: str) -> bool:
        """Equal but for one adjacent pair written in the other order."""
        swaps, i, n, m = 0, 0, len(a), len(b)
        prev: tuple[str, str] | None = None
        while True:
            if i >= n or i >= m:
                if i >= n and i >= m:
                    return swaps == 1 and (prev is None or prev[0] == prev[1])
                return False
            x, y = a[i], b[i]
            if x == y or prev is None:
                prev = (x, y)
            elif x == prev[1] and y == prev[0]:
                swaps += 1
                prev = None
            else:
                return False
            i += 1

    @staticmethod
    def bitsquatting(a: str, b: str) -> bool:
        i = Typos.first_difference(a, b)
        if i >= len(a) or i >= len(b):
            return False
        x, y = a[i], b[i]
        if not (x.isascii() and y.isascii()):
            return False
        return bin(ord(x) ^ ord(y)).count("1") == 1 and a[i + 1 :] == b[i + 1 :]

    @staticmethod
    def interleaved(a: str, b: str, c: str) -> bool:
        found, i, j = False, 0, 0
        while True:
            if i >= len(a) or j >= len(b):
                return i >= len(a) and j >= len(b) and found
            if a[i] != b[j]:
                if i == 0 or b[j] != c or j + 1 >= len(b) or b[j + 1] != a[i]:
                    return False
                found = True
                j += 1
            i += 1
            j += 1

    @staticmethod
    def homoglyph(a: str, b: str) -> bool:
        if len(a) != len(b):
            return False
        found = False
        for x, y in zip(a, b, strict=True):
            if x == y:
                continue
            if y not in VtNet.LOOKALIKES.get(x, "") and x not in VtNet.LOOKALIKES.get(y, ""):
                return False
            found = True
        return found


__all__ = ["KINDS", "PublicSuffix", "Typos", "VtNet"]
