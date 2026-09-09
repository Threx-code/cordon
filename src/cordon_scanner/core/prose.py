"""Small grammar helpers for the sentences findings are written in.

A finding is prose that somebody reads under time pressure, and prose that
trips them costs more than the character it saves. "A ELF executable" and "A
npm access token" both read as typos, and a reader who trips over the grammar
of a finding trusts the rest of it less -- which is a real cost for a tool
whose only output is assertions about their code.
"""

from __future__ import annotations

SPOKEN_AS_VOWEL = frozenset("AEFHILMNORSX")
"""Letters whose *name* begins with a vowel sound.

An initialism takes its article from how it is said rather than how it is
spelled: an ELF executable, an npm token, an S3 bucket, an HTTP header. F, H,
L, M, N, R, S and X are the consonants whose letter-names open with a vowel
("eff", "aitch", "ell", "em", "en", "ar", "ess", "ex")."""

VOWELS = frozenset("AEIOU")


def article(word: str) -> str:
    """ "a" or "an", by how the following word is said.

    A word is treated as an initialism when its first two characters are the
    same case and at least one is a letter that is not spoken as a word --
    which covers `ELF`, `AWS` and `npm`, and leaves `Java`, `Mach-O` and
    `shell` to the ordinary vowel test.
    """
    head = word.strip()[:2]
    if len(head) < 2 or not head[0].isalpha():
        return "an" if head[:1].upper() in VOWELS else "a"

    initialism = head.isupper() or (head.islower() and _is_initialism(word))
    letters = SPOKEN_AS_VOWEL if initialism else VOWELS
    return "an" if head[0].upper() in letters else "a"


def _is_initialism(word: str) -> bool:
    """Whether a lower-case word is said letter by letter.

    There is no rule for this, only a list. `npm` is "en-pee-em" and takes
    "an"; `nginx` is "engine-x" and takes "an" as well; `shell` is a word. The
    list is short because the alternative -- guessing -- gets it wrong in both
    directions, and being wrong here is more visible than being silent.
    """
    return word.split()[0].lower() in {"npm", "nginx", "ssh", "sql", "xml", "html", "ssl", "rsa"}


__all__ = ["SPOKEN_AS_VOWEL", "VOWELS", "article"]
