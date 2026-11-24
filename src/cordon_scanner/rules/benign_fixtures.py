"""Benign text a delivered rule must not fire on.

Some invented, ordinary code and prose ships with the scanner: a few short programs of the kind any package holds (reading its own config, printing, parsing JSON, listing a folder) and the first
files of the calibration corpus. A delivered text rule that matches any of them is wrong about ordinary code, and `FeedPacks` demotes it when its pack loads.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.rules.calibration import CalibrationCorpus

if TYPE_CHECKING:
    from cordon_scanner.rules.pack import RulePack


class BenignFixtures:
    PROGRAMS: ClassVar[tuple[bytes, ...]] = (
        b"const fs = require('fs');\nconst path = require('path');\nconst config = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));\nconsole.log(config.name);\n",
        b"import os\nimport json\n\ndef main():\n    with open(os.path.join(os.getcwd(), 'settings.json')) as handle:\n        print(json.load(handle)['title'])\n\nif __name__ == '__main__':\n    main()\n",
        b"function add(a, b) {\n  return a + b;\n}\nmodule.exports = { add };\n",
        b"# A small library\n\nInstall it, import it and call `add(1, 2)`. It has no dependencies and reads no files.\n",
        b'{"name": "tiny", "version": "1.0.0", "main": "index.js", "scripts": {"test": "node test.js"}}\n',
    )
    CORPUS_FILES: ClassVar[int] = 4

    @classmethod
    def files(cls) -> tuple[bytes, ...]:
        return cls.PROGRAMS + CalibrationCorpus.files()[: cls.CORPUS_FILES]

    @classmethod
    def firing(cls, pack: RulePack) -> tuple[str, ...]:
        """The ids of the pack's text rules that match any benign fixture."""
        files, fired = cls.files(), []
        for compiled in pack.rules:
            match = compiled.match
            if match.regex is None:
                continue
            for data in files:
                regex = match.regex_for(data)
                if regex is not None and match.search(regex, data) is not None:
                    fired.append(compiled.rule.id)
                    break
        return tuple(fired)


__all__ = ["BenignFixtures"]
