# 22 · Code arriving from someone else

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

A repository is most dangerous the moment it lands on your machine. Nobody has to run
it on purpose: an editor opens its tasks, a shell loads its `.envrc`, a coding agent
reads its instruction files and MCP config, `npm install` runs its hooks. A teammate
whose machine was compromised pushes, you pull, and the same thing happens to you.

So Cordon checks code **before** it reaches your working tree.

```
   CLONE                                  PULL
   ─────                                  ────
   git clone --no-checkout                git fetch
     history only; working tree empty       new commits arrive, nothing merged
            │                                      │
   scan the commit from git's objects     scan the incoming commit from git's objects
     nothing written to disk                findings your checkout already had
            │                                are not counted again
      ┌─────┴──────┐                         ┌────┴─────┐
    passes       blocked                   passes     blocked
      │            │                         │          │
   check out    remove the clone          merge      stop: your checkout
                (objects and all)         (ff-only)  is exactly as it was
```

## Run it

```
   cordon-scanner clone https://github.com/acme/app.git
   cordon-scanner clone git@github.com:acme/app.git app --branch release

   cordon-scanner pull                     # the branch's upstream
   cordon-scanner pull origin main --merge # allow a merge commit
```

Both use your own git for the network step, with your credentials, so private
repositories work. Reading the commit uses Cordon's hardened git, which runs no
program a repository's configuration names.

## What blocks

```
┌──────────────────────────────────────────────────────────────────────────┐
│  always       anything MALICIOUS: a known-malicious release in a         │
│               lockfile, malware in the source, a poisoned agent config   │
│  by default   anything CRITICAL                                          │
│  --fail-on    lower the bar:  --fail-on high                             │
└──────────────────────────────────────────────────────────────────────────┘
```

The default is lower than a commit or push gate on purpose. Those judge your own
change; this judges a whole repository someone else wrote, and almost every real
project carries an old HIGH advisory somewhere. The question here is whether the
code is compromised.

**The code under check cannot configure its own check.** No `cordon.yaml`, policy
file or baseline inside the incoming commit is read. A repository that could
suppress its own finding would switch the check off exactly when it matters. Your
own settings come only from `--config PATH`.

## Plain git clone and git pull, too

People will not always type `cordon-scanner clone`. Install the hooks once, and
every repository you clone or create from then on carries them:

```
   cordon-scanner guard install --global     # every future clone and git init
   cordon-scanner guard install              # a repository you already have
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│  post-checkout   after git clone, git checkout, git switch               │
│  post-merge      after git pull, git merge                               │
│                                                                          │
│  Git has written the files when these run, so they cannot refuse.        │
│  They UNDO, before anything has acted on the code:                       │
│                                                                          │
│    blocked pull or merge   git reset --merge ORIG_HEAD                   │
│                            (your uncommitted work is kept)               │
│    blocked branch switch   back to the branch you were on                │
│    blocked clone           its files removed from the working tree;      │
│                            the objects stay, readable with git show      │
└──────────────────────────────────────────────────────────────────────────┘
```

`--global` uses git's `init.templateDir`, not a global `core.hooksPath`. A global
hooks path would replace every repository's own hooks (husky's, pre-commit's, your
team's); a template only seeds new repositories. An existing template directory is
used, and hooks already in it are kept, with a backup written beside them.

If `cordon-scanner` is missing when a hook runs, the hook says so loudly: the code
was not checked, and should not be opened or built until it is.

## A teammate who is already compromised

Hooks on their laptop can be skipped with `--no-verify`, or removed by the malware
itself. The control they cannot get around is on the server:

```
   ┌─────────────┐   push   ┌──────────────────────────────┐   pull   ┌──────────┐
   │  teammate   │ ───────► │  protected branch            │ ───────► │   you    │
   │ (hooks can  │          │  Cordon as a REQUIRED check  │          │ clone /  │
   │  be skipped)│          │  (GitHub Action, Cloud PR    │          │ pull and │
   └─────────────┘          │   check): it cannot merge    │          │ hooks    │
                            └──────────────────────────────┘          └──────────┘
```

Make the Cordon check required on protected branches (tutorial 10), and run `pull`
or the hooks on your own machine for everything else: their other branches, forks,
and anything you clone.

Next: **[23 · Machines and vendor SBOMs](23-machines-and-sboms.md)**.
