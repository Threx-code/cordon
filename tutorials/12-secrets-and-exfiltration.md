# 12 · Secrets, credentials and exfiltration

The largest domain in the rule pack: **59 secret rules and 8 exfiltration
rules**, 47% of everything Cordon ships. This is the one where the tool that
finds the problem must not become the problem.

```
┌──────────────────────────────────────────────────────────────────────────┐
│ A credential is two findings, never one.                                 │
│                                                                          │
│    WHAT IT IS ......... a token was committed, so it is public now       │
│    WHAT IT DOES ....... something reads it and sends it somewhere        │
│                                                                          │
│ The first is a leak. The second is exfiltration. Cordon reports          │
│ them separately because they have different owners and different         │
│ urgencies -- rotate the key, versus treat the host as compromised.       │
└──────────────────────────────────────────────────────────────────────────┘
```

## The pipeline

```
┌──────────────────────────────────────────────────────────────────────────┐
│ file bytes                                                               │
│     │                                                                    │
│     ├─ 1. PATTERN ....... 58 provider shapes: AWS, GitHub, Stripe,       │
│     │                     Slack, OpenAI, npm, PyPI, Vault, ...           │
│     │                     each anchored to that issuer's real format     │
│     │                                                                    │
│     ├─ 2. ENTROPY ....... a high-entropy run where a name says           │
│     │                     'secret' -- SECRET.GENERIC.ASSIGNMENT.001      │
│     │                                                                    │
│     ├─ 3. STRUCTURE ..... PEM blocks, JWTs, URLs with inline             │
│     │                     credentials -- shape, not vocabulary           │
│     │                                                                    │
│     └─ 4. CONTEXT ....... is this file an install hook? is there         │
│                           egress nearby? that decides the severity       │
└──────────────────────────────────────────────────────────────────────────┘
```

## Redaction: the part that matters most

A scanner reports into CI logs, pull-request comments and SARIF files uploaded
to third parties. All three outlive the repository and are read more widely.

```
┌──────────────────────────────────────────────────────────────────────────┐
│   RedactionMode          what reaches the report                         │
├──────────────────────────────────────────────────────────────────────────┤
│   none          raw matched text      refused for every SECRET.* rule    │
│   masked        structure kept,       the default for everything else    │
│                 entropy masked                                           │
│   hash_only     the match hash only   MANDATORY for SECRET.* rules       │
├──────────────────────────────────────────────────────────────────────────┤
│   So a leaked key is reported by its sha256, never by its value.         │
│   You cannot configure your way out of this: `evidence_policy:           │
│   none` on a secret rule is refused at rule-load time, not at            │
│   report time.                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

Verify it yourself — the value never appears:

```bash
cordon-scanner scan . -f json:out.json
jq '.findings[] | select(.rule_id|startswith("SECRET")) | .evidence' out.json
```

## Why it does not drown you

Sixty rules over a real repository would be unusable without these. Each one is
a **ceiling**, not a suppression — the finding stays in the report.

```
┌──────────────────────────────────────────────────────────────────────────┐
│   a directory of 5+ private keys                                         │
│      └─▶ one finding, severity capped at MEDIUM                          │
│          a CA + intermediate + client + server is a generated            │
│          hierarchy far more often than a disclosure                      │
│                                                                          │
│   3+ private keys in ONE file                                            │
│      └─▶ one finding, capped         a per-algorithm test table          │
│                                                                          │
│   the same credential NAME in 10+ files                                  │
│      └─▶ one finding, capped         one decision, not ten leaks         │
│                                                                          │
│   byte-identical file in N places                                        │
│      └─▶ one finding                 one thing to fix, not N             │
└──────────────────────────────────────────────────────────────────────────┘
```

Every one of them still says *every value is committed*: if one protects
something live, all of them are in git history and in every clone.

## Pairing: a secret plus egress is not a leak, it is theft

```
┌──────────────────────────────────────────────────────────────────────────┐
│   reads ~/.npmrc          ─┐                                             │
│                            ├──▶  MALWARE.EXFIL.CREDENTIAL_STORE.001      │
│   posts to a webhook      ─┘     critical · treat the host as breached   │
│                                                                          │
│   reads os.environ        ─┐                                             │
│                            ├──▶  SUSPECT.EXFIL.001                       │
│   urlopen(host, data=..)  ─┘     high · in an install hook: critical     │
│                                                                          │
│   hostname + user + cwd   ─┐                                             │
│                            ├──▶  MALWARE.EXFIL.BEACON.001                │
│   GET with them as params ─┘     the install-time beacon shape           │
│                                                                          │
│   base64 chunks           ─┐                                             │
│                            ├──▶  SUSPECT.EXFIL.DNS.001                   │
│   as DNS subdomains       ─┘     tunnelling out where HTTP is blocked    │
└──────────────────────────────────────────────────────────────────────────┘
```

The eight exfiltration rules divide on **where the data goes**:

| rule | the channel |
|---|---|
| `MALWARE.EXFIL.001` / `SUSPECT.EXFIL.001` | any outbound send of read data |
| `*.EXFIL.CREDENTIAL_STORE.001` | `~/.npmrc`, `~/.aws`, keychains, `.env` |
| `*.EXFIL.DROP_POINT.001` | paste sites, Discord/Telegram webhooks |
| `SUSPECT.EXFIL.DNS.001` | data encoded into DNS lookups |
| `MALWARE.EXFIL.BEACON.001` | hostname/user/cwd sent at install time |

## The .env problem

```
┌──────────────────────────────────────────────────────────────────────────┐
│   .env is gitignored, so it is not committed, so there is nothing        │
│   to find -- right?                                                      │
│                                                                          │
│   Cordon scans the WORKING TREE, not the index. A gitignored .env        │
│   sitting on disk is read and reported, because:                         │
│                                                                          │
│     · it is on the machine running the scan                              │
│     · `git add -f` happens                                               │
│     · a Docker COPY . ignores .gitignore entirely                        │
│     · the file lands in the image layer, which ships                     │
│                                                                          │
│   If you want it excluded, exclude it deliberately and see the           │
│   POLICY.COVERAGE.TARGET_EXCLUSION finding that records you did.         │
└──────────────────────────────────────────────────────────────────────────┘
```

## Tuning, least-blunt first

**1. Is it real?** The hash lets you confirm without the value leaving.

```bash
cordon-scanner scan . -f json:out.json
```

**2. A whole class you do not use.** In `cordon.yaml` -- there is no CLI flag
for this, deliberately, so the decision is committed and reviewable:

```yaml
rules:
  disabled:
    - SECRET.AIRTABLE.TOKEN.001
```

If that config lives in the repository *being scanned*, Cordon reports
`POLICY.COVERAGE.RULE_DISABLED` at HIGH -- a scan target does not get to
quietly switch off checks. In an operator's own `--config` file it is silent.

**3. One path that is genuinely test material** -- with an expiry and an owner.
See tutorial 10: suppressions expire so the decision gets re-examined while
somebody still remembers why.

> **Never** lower `evidence_policy` on a secret rule to see the value. The rule
> loader refuses it, and that refusal is the feature.

---

Next: **[13 · CI/CD pipeline attacks](13-cicd-attacks.md)** — the seven rules
for attacks *on* your pipeline, as opposed to running Cordon *in* it.
