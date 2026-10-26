# 13 · AST rules & capabilities

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

This is how Cordon sees through obfuscation, and how you extend it.

## The tiers, cheapest first

```
   ┌───────────┐   most files stop here
   │  literal  │   exact bytes
   ├───────────┤
   │  regex    │   safe subset
   ├───────────┤
   │ structural│   parsed manifests/config
   ├───────────┤
   │   ast     │   RESOLVED calls — sees through aliases, folding, getattr
   ├───────────┤
   │  graph    │   over the dependency graph
   ├───────────┤
   │ composite │   boolean over the above, within a scope
   └───────────┘
```

## What the AST tier catches that regex cannot

```
   SOURCE                                      RESOLVES TO
   ──────                                      ──────────
   os.system("id")                             os.system
   f = os.system ; f("id")                     os.system     (bound name)
   getattr(os, "sys"+"tem")("id")              os.system     (folded + getattr)
   const { exec } = require('child_process')   child_process.exec
   import { exec as e } from 'child_process'   child_process.exec   (renamed import)
```

## One rule, every language

```
              ┌─────────────────────────────────────────────┐
   kind: ast  │  callee = child_process.exec  (or spawn…)   │
              │  argument is CONSTRUCTED (not a literal)    │
              └─────────────────────────────────────────────┘
                     │ Python           │ JS / TS
                     ▼                  ▼
              stdlib `ast`         Cordon's own parser
              (always on)          (always on)
```

## Nothing to install

```
   JS/TS calls are resolved by Cordon's own front end -- real scopes, aliases
   through require, every import form, createRequire, dynamic import(),
   TypeScript `import =`, computed members and bundler calls -- in every install.
   No parser written elsewhere ever reads a scanned file.
```

## Capabilities compose (recap from 02)

```
   CAP.*.DECODE  ┐
   CAP.*.EXECUTE ├─▶ composite: "decode → execute within N lines"  = second-stage loader
   CAP.*.SPAWN   ┘
```

## Check the rules yourself

```
   cordon-scanner rules test     # every rule with an inline sample must still fire
```

Next: **[14 · Config, policy & baselines](14-config-policy-baselines.md)**.
