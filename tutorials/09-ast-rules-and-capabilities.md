# 09 · AST rules & capabilities

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
                     ▼                   ▼
              stdlib `ast`         tree-sitter  ([ast-js])
              (always on)          (opt-in extra)
```

## The extra, and honest degradation

```
   pip install cordon-scanner[ast-js]
```

```
   WITH [ast-js]                       WITHOUT it
   ────────────                        ──────────
   JS/TS calls resolved by the AST     JS/TS still scanned by the regex tier;
   tier, same rules as Python          the AST tier reports the language as
                                       NOT ANALYSED — never pretends it was
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

Next: **10 — config, policy & baselines**.
