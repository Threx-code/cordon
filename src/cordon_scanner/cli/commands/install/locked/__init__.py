"""The lock-driven install tools: each reads a lock file the package manager keeps (`cordon bazel`, `pod`, `Rscript`, `cabal`, ...) and holds every pin to its hash (`command.py` runs them)."""
