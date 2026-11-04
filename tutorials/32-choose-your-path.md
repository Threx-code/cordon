# 32 · Putting Cordon to work: choose your path

> **For Cordon 0.7.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

The tutorials from here on are ready-made implementations: each one is something you copy
into a machine, a repository or a pipeline and it works. They start with one developer's
laptop and end with an organisation-wide rollout, and each level adds to the one before
rather than replacing it.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  LEVEL 1  one machine                                                    │
│    33  On your laptop ........ vet a package before you install it,      │
│                                scan a project, git hooks that fail closed│
│    34  Guard your installs ... pnpm, npm and pip: checked before fetch,  │
│                                read before anything runs                 │
├──────────────────────────────────────────────────────────────────────────┤
│  LEVEL 2  every repository's pipeline                                    │
│    35  GitHub Actions ........ the action, SARIF, dependency review      │
│    36  GitLab CI ............. the template, code quality, merge gate    │
│    37  Other CI systems ...... Jenkins, Azure, Bitbucket, CircleCI,      │
│                                Buildkite, and any shell                  │
│    38  Containers and images . an image before it is pushed or deployed  │
├──────────────────────────────────────────────────────────────────────────┤
│  LEVEL 3  the organisation                                               │
│    39  Rolling out ........... one policy ceiling, baselines, expiring   │
│                                suppressions, notifications               │
│    40  Air-gapped ............ mirrored intel, offline scans, a verified │
│                                install                                   │
│    41  AI agents ............. the MCP server for each coding agent      │
│    42  From your own code .... the Python API and the JSON result        │
└──────────────────────────────────────────────────────────────────────────┘
```

## Which one first

```
   Do you run code from a package registry on this machine?
      │
      ├── yes ──► 33, then 34: nothing new lands unread
      │
   Does a pipeline build or deploy what you write?
      │
      ├── yes ──► 35, 36 or 37, whichever runs your pipeline; 38 if it ships images
      │
   Are there many repositories, or rules you must prove you follow?
      │
      └── yes ──► 39 for the policy; 40 if the machines are offline; 41 if
                  coding agents install things for you; 42 to wire results
                  into your own systems
```

## What stays the same at every level

```
   Cordon READS. It never runs the code it is scanning, and nothing about
   your code leaves the machine:

     default    asks OSV for advisories published since this release: the
                same requests for everyone, naming nothing you scan
     --offline  no request at all (an air-gap; tutorial 40)
     --online   also fetches the packages being checked, from their own
                registries, to read them

   Every level uses the same exit codes, so a script, a hook and a pipeline
   all decide the same way:

     0  clean          1  findings at or above --fail-on
     2  scanner error  3  configuration error  4  incomplete
```

An incomplete scan is never a pass: a file that could not be read, or intel older than
its limit, is said, and with `--fail-on-incomplete` it fails the step. Tutorial 29 explains
each coverage note and what to do about it.

Next: **[33 · On your laptop](33-on-your-laptop.md)**.
