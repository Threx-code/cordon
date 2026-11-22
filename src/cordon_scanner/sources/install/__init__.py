"""Packages checked before they are installed: `cordon npm|pnpm|yarn|pip|uv|poetry|cargo|go|gem|bundle`.

Each planner resolves the install with the package manager's own resolver and nothing run; `guard`
fetches, verifies and scans the files; the command (`cli/commands/install/`) installs exactly them.
Design: package `reviews/install-guard/01-DESIGN.md`.
"""
