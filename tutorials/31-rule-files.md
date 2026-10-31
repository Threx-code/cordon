# 31 · Rule files: your own signatures, matched against every file

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

A security team keeps the signatures it trusts -- its own, its vendor's, a feed's -- in rule files.
`--rule-file` matches every file of a scan against one, with cordon-rule, Cordon's own rule engine.
cordon-rule reads rule files in the YARA format (`.yar`).

```bash
cordon-scanner scan . --rule-file ./signatures.yar
cordon-scanner scan . --rule-file builtin      # the pack shipped with Cordon
CORDON_RULE_FILE=./signatures.yar cordon-scanner scan .
```

The rules are the operator's choice, never the repository's: a repository's own configuration
cannot name a rule file, because a scan target that chose the rules run against it would choose
rules that never match.

## What a match reports

| Rule | When |
|------|------|
| `SUSPECT.RULEFILE.MATCH.001` | a rule matched a file (HIGH, or the rule's `severity` meta) |
| `MALWARE.RULEFILE.MATCH.001` | a rule whose meta says `category = "malicious"` matched (CRITICAL) |
| `OPERATIONAL.RULEFILE.STATUS` | the rule file ran over the scan's files |
| `OPERATIONAL.RULEFILE.UNAVAILABLE` | the rule file was asked for and could not be used |

A rule's `path_include` meta (`"*.py,*.js"`) limits which files its match counts for.

A rule whose meta says `layers = "decoded"` also reads what each file carries under a wrapper:
`atob("...")`, `Buffer.from(..., "base64")` or `"hex"`, Python's `b64decode`, `bytes.fromhex` and
`unhexlify` over a literal, and zlib or gzip data inside any of them, peeled up to four layers deep.
The layers are decoded to bytes, so a rule finds an executable under base64 as readily as a script.
A match on a layer names it ("matched this file's layer decoded from atob (layer 2)"), and a rule
that matched the raw bytes is not reported again for a layer. Every other rule reads the raw bytes
only, as YARA does, so a rule file without the meta answers exactly as it did. Nothing is run, a
layer is at most 1 MiB, and compressed data is inflated only that far.

A rule file
that does not compile, or that imports a module cordon-rule does not provide, is reported as
`OPERATIONAL.RULEFILE.UNAVAILABLE` and marks the scan incomplete: "no rule matched" and "no rule
ran" never look alike.

## Rules over what the scanner knows: `package`, `js`, `python`

Three modules read what Cordon has already worked out about the package a file is in, so a rule can
say "the install hook sends the environment somewhere it does not name" rather than only "these
bytes occur":

```
import "package"
import "js"

rule install_hook_sends_environment {
  condition:
    package.place == "install" and js.flow("environment", "request", "unknown")
}

rule first_release_with_a_new_hook {
  condition:
    package.registry.known and package.registry.first_release and package.install_time
}
```

| Field | What it reads |
|-------|---------------|
| `package.ecosystem`, `name`, `version` | the release the scan names (its manifest) |
| `package.place` | where this file runs: `install`, `import`, `closure`, `agent`, `ci`, or `""` |
| `package.install_time` | the package has an install hook or a file one runs |
| `package.can(place, capability)` | the capability profile of the code run at `place` |
| `package.flow(place, source, sink, destination)` | a reached file's flow; `""` is any |
| `package.flows` | how many flows the reached code has |
| `package.campaign.siblings`, `shared` | condemned releases sharing two facets with this one (npm) |
| `package.registry.known`, `age_days`, `first_release`, `prior_versions`, `prior_24h`, `new_publisher`, `maintainers`, `hooks`, `hooks_added`, `dependencies_added`, `confusion_version`, `prerelease_build` | the registry's record of the release, from `cordon-scanner intel acquire` |
| `js.flow(source, sink, destination)`, `js.flows`, `js.sinks`, `js.place` | this JavaScript file's own flows |
| `python.flow(...)`, `python.flows`, `python.sinks`, `python.place` | this Python file's own flows |

Sources are `secret_file`, `home_file`, `network_response`, `decoded`, `environment`, `identity`,
`browser`, `clipboard` and `wallet_key`; sinks `request`, `connection`, `dns`, `process`, `open` and
`execute`; destinations `drop`, `ip`, `fixed` and `unknown`.

Each value is a fact the package verdict reads; nothing is analysed for the rule. Those facts exist
only once every detector has run, so a rule file importing one of these modules is matched after
detection, in a pass of its own, and its matches then go through everything any finding goes
through (the ceilings, suppressions, folds and verdict):

```
  detection ──► the verdict's facts ──► the rule file, with the facts ──► ceilings, suppressions,
  (every          profile, flows,          (same worker pool;              folds, verdict
   detector)      registry, campaigns       each file's own place)          (facts reused)
```

A rule file importing none of the three is matched during detection exactly as before. Where
there is no fact, a field is undefined, never false or 0: with no registry record acquired,
`package.registry.known` is false and every other registry field undefined; a non-npm package has no
`campaign`; a file of another language, or over 1 MB, has every `js` or `python` field undefined.
A measurement run (`CORDON_MEASURE_FEATURES=1`) is content-only: the registry record is never read
there, so no rule carries registry knowledge into a content-only number. These answers depend on
more than a file's bytes, so they are never kept in the match cache.

## What the language covers

- **Rules**: `global` and `private` rules, tags, `meta`, `strings`, `condition`, references to
  other rules and `prefix*` sets of them. `include "name"` reads another file, named relative to
  the file that includes it, and only from under the directory of the rule file you passed to
  `--rule-file`: a collection's index file loads its members, and nothing outside that directory
  is read (an absolute name, a `..` that leaves it, or a link pointing out of it is refused, as is
  a cycle or nesting deeper than 32). All the files together stay within the 16 MiB limit. The
  built-in pack (`--rule-file builtin`) never includes. A change to an included file is seen by
  the scan cache, as a change to the rule file itself is.
- **Strings**: text with `nocase`, `wide`, `ascii`, `fullword`, `private`, `xor`, `base64` and
  `base64wide`; hex patterns with wildcards, nibble masks, `~` negation, jumps and alternatives;
  regular expressions with `i` and `s`.
- **Conditions**: counts, offsets and lengths of matches (`#a`, `@a[i]`, `!a[i]`), `at` and `in`,
  string sets and quantifiers, both `for` loops, arithmetic and bitwise operators, the integer
  readers, `defined`, and the string operators including `matches`.
- **Modules**: `math`, `hash`, `string`, `console` and `time`; `pe`, `elf`, `dotnet`, `macho` and
  `dex` for executables; `olecf`, `msi` and `vba` for compound files, installers and macros; `lnk`,
  `zip` and `crx` for shortcuts, archives and browser extensions; `magic` for a file's type;
  `androguard` for Android packages;
  `cuckoo` for what a sandbox run did (below); `package`, `js` and `python` for what the scanner
  knows of the package (above).

## Giving a module data: `cuckoo`

`cuckoo`'s functions (`network.dns_lookup`, `network.http_get`, `network.http_post`,
`network.http_request`, `network.http_user_agent`, `network.host`, `network.tcp`, `network.udp`,
`registry.key_access`, `filesystem.file_access`, `sync.mutex`) answer from a Cuckoo sandbox report
given to the scan, as `yara -x cuckoo=report.json` gives one:

```
cordon-scanner scan . --rule-file rules.yar --rule-module-data cuckoo=report.json
```

The report is read once and every file of the scan is matched against the same run. A report
that is not JSON, or that holds an integer outside 64 bits, makes the rule file unavailable for the
scan (`OPERATIONAL.RULEFILE.UNAVAILABLE`). Without a report the functions answer 0, and
`OPERATIONAL.RULEFILE.STATUS` says the rules import `cuckoo` and none was given. An item of
`hosts`, `keys`, `files` or `mutexes` that is not text is skipped (the reference engine crashes on
one).

## How it is held to its behaviour

cordon-rule is Cordon's own code: no native library reads a scanned file, and nothing is
installed. Its results are held to the reference behaviour of the format by a conformance suite of
cases, by a differential over generated rules (100,000 random rules over random data, every match
compared offset by offset) and by the built-in pack over the measured package corpus. Where a rule
would make another engine crash or hang -- a repeat of nothing, a zero-width loop -- cordon-rule
returns a defined result instead.

Every run is bounded: a pattern reads at most 4,096 bytes from where it starts, holds at most 1,024
threads, and each file is matched under a timeout, so a pathological rule cannot hold a scan.

Next: back to **[the tutorial map](README.md)**.

## Android packages: `androguard`

`androguard` answers the Koodous rule collections' functions (`package_name`, `app_name`,
`main_activity`, `activity`, `service`, `receiver`, `permission`, `permissions_number`, `url`,
`certificate.sha1`, `certificate.subject`, `certificate.issuer`, `min_sdk`, `max_sdk`, `target_sdk`)
from the APK itself: the compiled manifest, the resource table, the signer's certificate (v1 or the v2
and v3 signing block) and the URLs in the dex string tables. No report is needed. A Koodous report can
be given instead, and every file of the scan answers from it:

```
cordon-scanner scan . --rule-file rules.yar --rule-module-data androguard=report.json
```
