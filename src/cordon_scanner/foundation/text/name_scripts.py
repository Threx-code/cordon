"""The writing systems a package name mixes: a Latin name with a Cyrillic or Greek letter reads as a name it is not."""

from __future__ import annotations

import unicodedata


class NameScripts:
    """Which non-Latin script a mostly Latin name borrows a letter from, or None."""

    #: Scripts whose letters render like Latin ones in a package name.
    LOOKALIKE_SCRIPTS = ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE")

    @classmethod
    def mixed(cls, name: str) -> str | None:
        """The other script when a name mixes Latin letters with Cyrillic or Greek ones.

        `Micr\u043esoft.EntetyFrameworkCore` on NuGet spells its `o` as Cyrillic U+043E: it reads as
        Microsoft's and sorts beside it, and no one types it by accident. A name written wholly in
        another script is that script's, and is not this."""
        latin = other = False
        found = ""
        for char in name:
            if not char.isalpha():
                continue
            script = unicodedata.name(char, "").split(" ", 1)[0]
            if script == "LATIN":
                latin = True
            elif script in cls.LOOKALIKE_SCRIPTS:
                other, found = True, script.capitalize()
        return found if latin and other else None
