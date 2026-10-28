#!/usr/bin/env python3
"""Point every documentation link at this release's tag instead of a moving branch.

The README is also the PyPI page, and docs and tutorials link to one another by absolute GitHub URL.
A link to `main` shows whatever `main` says today, so a user of 0.5.0 following one would read
0.6.0's instructions. Run at release time:

    python3 scripts/release/pin_doc_links.py            # rewrite to the version in cordon_scanner/version.py
    python3 scripts/release/pin_doc_links.py --check    # exit 1 if any link is not pinned to it

Images are pinned too, when the links are: in the repository the README names its images by a
relative path (`docs/assets/...`), which GitHub resolves on every branch and pull request, and PyPI
cannot resolve at all. Pinning turns each into the raw file at the release tag, as is any raw URL
naming a branch. `--check` is about links only, so a branch's relative images never fail it.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = next(
    (p for p in (Path.cwd(), *Path.cwd().parents) if (p / "src" / "cordon_scanner").is_dir()), None
) or sys.exit("run this from inside the Cordon repository")
REPOSITORY = "https://github.com/Threx-code/cordon"
LINK = re.compile(re.escape(REPOSITORY) + r"/(blob|tree)/([^/\s)\"'>]+)/")
RAW = "https://raw.githubusercontent.com/Threx-code/cordon"
#: An image the README names by a path in the repository, or by a raw URL on some ref.
IMAGE = re.compile(r'src="(?:' + re.escape(RAW) + r'/[^"\s]+?/)?(docs/assets/[^"\s]+)"')
FILES = ("README.md", "CHANGELOG.md", "docs/*.md", "tutorials/*.md", "editors/vscode/README.md")


class DocLinks:
    """Pinning documentation links to the release tag."""

    @staticmethod
    def version() -> str:
        text = (ROOT / "src" / "cordon_scanner" / "version.py").read_text(encoding="utf-8")
        found = re.search(r'__version__\s*=\s*"([^"]+)"', text)
        if found is None:
            raise SystemExit("no __version__ in version.py")
        return found.group(1)

    @staticmethod
    def documents() -> list[Path]:
        return sorted({p for pattern in FILES for p in ROOT.glob(pattern)})

    @staticmethod
    def pinned(text: str, tag: str, *, images: bool) -> str:
        """`text` with every repository link, and with `images` every image, naming `tag`."""
        text = LINK.sub(lambda m: f"{REPOSITORY}/{m.group(1)}/{tag}/", text)
        if images:
            text = IMAGE.sub(lambda m: f'src="{RAW}/{tag}/{m.group(1)}"', text)
        return text

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--check", action="store_true")
        args = parser.parse_args()
        tag = f"v{DocLinks.version()}"
        stale: list[str] = []
        for path in DocLinks.documents():
            text = path.read_text(encoding="utf-8")
            pinned = DocLinks.pinned(text, tag, images=not args.check)
            if pinned != text:
                if args.check:
                    stale.append(path.relative_to(ROOT).as_posix())
                else:
                    path.write_text(pinned, encoding="utf-8")
                    print(f"pinned {path.relative_to(ROOT)} to {tag}")
        if stale:
            print(f"links not pinned to {tag}: " + ", ".join(stale), file=sys.stderr)
            return 1
        return 0


if __name__ == "__main__":
    sys.exit(DocLinks.main())
