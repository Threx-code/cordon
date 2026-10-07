# Maintaining the tutorials

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

The tutorials are the scanner's documentation. They live here, as Markdown, and nowhere
else: the website's Learn section (`cordon.dev/learn`) is built from these files at each
release tag, so editing a tutorial here is the only edit there is.

```
   tutorials/*.md  (this directory)
        │
        ├──► GitHub: read as they are, at the release tag
        │
        └──► the website: frontend/scripts/tutorials/build.mjs reads each release's copy,
             draws every box diagram in 2D, links every section to its heading here,
             and serves one set per minor release (/learn/0.6, /learn/0.5, ...)
```

## Two kinds of tutorial

```
   01 to 24    written by hand: one use case each, diagram first
   25 to 28    GENERATED from the code: never edit them by hand
                 25  every ecosystem         python tests/tutorial_reference.py ecosystems
                 26  every command           python tests/tutorial_reference.py commands
                 27  every agent location    python tests/tutorial_reference.py agents
                 28  every rule              python tests/tutorial_reference.py rules
```

`tests/unit/test_tutorial_reference.py` fails when a generated tutorial disagrees with the
code: add an ecosystem, a flag, an agent path or a rule, and the test tells you which file
to regenerate, with the command. Regenerate inside the project's container:

```bash
python tests/tutorial_reference.py ecosystems > tutorials/25-every-ecosystem.md
python tests/tutorial_reference.py commands   > tutorials/26-every-command.md
python tests/tutorial_reference.py agents     > tutorials/27-every-agent-location.md
python tests/tutorial_reference.py rules      > tutorials/28-every-rule.md
```

A new ecosystem also needs its display name in `NAMES` in `tests/tutorial_reference.py`;
the generator stops and says so if it is missing.

## Adding a hand-written tutorial

1. Name it `NN-short-name.md`, the next number. Start it with `# NN · Title`, then the
   version banner every tutorial carries (copy it from another), then one paragraph saying
   what the tutorial is for: the site uses that paragraph as its summary.
2. Put it on **the map** in `README.md`, under its group, as
   `├─ NN  Title ........ one line`. The site builds its navigation from the map, and the
   build refuses a tutorial that is not on it.
3. End it with a `Next:` line linking the tutorial after it, as every tutorial does, and
   point the previous tutorial's `Next:` line at the new one.

## What the site understands

Only what these files already use, so a page never renders differently from GitHub:

```
   # ## ###          headings: ## and ### become sections, each linked to GitHub
   paragraphs, - lists, | tables |, > quotes, ---
   `code` **bold** *italic* and links
   fenced blocks     a fence drawn with box characters (┌ ─ ┐ │ └ ┘ ├ ┤ ┬ ┴ ┼ ► ▼)
                     becomes a 2D figure; any other fence stays a code block
```

Links: another tutorial (`18-agents-and-mcp.md`) becomes its page on the site; a file in
the repository (`../docs/08-ACCURACY.md`) and an inline `path/that/exists` become GitHub
links at the release tag. A link to a file that does not exist stops the build.

Draw diagrams 76 columns wide at most, with whole boxes (every corner present), so they
read the same in a terminal, on GitHub and on the site.

## Versions

Each minor release keeps its own tutorials, read from its latest patch tag, the way
Laravel versions its documentation. After tagging a release, rebuild the site's content
with the new version first; see `frontend/scripts/tutorials/README.md`.
