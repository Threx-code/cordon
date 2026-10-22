# 28 · Every rule

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

All 75 detection rules Cordon defines itself, grouped by what they watch, with the
severity each reports at, and after them every Agent Threat Rule it carries. Rendered from the detectors and rule packs themselves. `cordon-scanner rules
show <id>` prints one in full, with its remediation and references; `rules test` runs every
rule's own samples.

```
   MALWARE.*       evidence of intent to harm: fails the build by default
   SUSPECT.*       a behaviour or shape attackers use: worth a look
   VULNERABLE.*    a known vulnerability in what you ship
   SECRET.*        a credential in the code or its history
   POLICY.*        a choice the project made about itself
   OPERATIONAL.*   what the scan could not do, said out loud
```


## Account

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.ACCOUNT.CHANNEL_FOLLOW.001` | critical | A WhatsApp library subscribes every account that connects to the publisher's channel |

## AI agents

3 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.AGENT.CONFIG_PLANTED.001` | critical | Installing the package plants an AI agent's configuration in your project |
| `MALWARE.AGENT.HIJACK.001` | critical | Turns the machine's AI agent against it |
| `SUSPECT.AGENT.UNATTENDED.001` | medium | Runs your AI agent with every permission and no confirmation |

## Anti Analysis

2 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.ANTI_ANALYSIS.001` | critical | Install-time code that checks whether it is being watched |
| `SUSPECT.ANTI_ANALYSIS.001` | high | Behaviour gated on whether it is being observed |

## CI/CD pipelines

3 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.CI.DECODED_PROGRAM.001` | critical | A CI step runs a program it decodes on the spot |
| `MALWARE.CI.RUNNER_SECRETS.001` | critical | Code dumps the CI runner's secrets |
| `SUSPECT.CI.ENVIRONMENT_INJECTION.001` | high | A package writes the CI job's environment when it is imported |

## Cryptominer

2 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.CRYPTOMINER.001` | critical | Install-time cryptocurrency mining |
| `SUSPECT.CRYPTOMINER.001` | high | Cryptocurrency mining |

## Decode Chain

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.DECODE_CHAIN.001` | critical | A payload decoded in several stages, then executed |

## Decode Exec

3 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.DECODE_EXEC.ENCODED_SHELL.001` | critical | A long encoded command is decoded straight into a shell |
| `MALWARE.DECODE_EXEC.INVISIBLE.001` | critical | A payload written in invisible characters is decoded and run |
| `SUSPECT.DECODE_EXEC.001` | high | Encoded data decoded and executed in the same file |

## Destroy

2 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.DESTROY.HOME_OR_ROOT.001` | high | Deletes the home directory or the filesystem root |
| `SUSPECT.DESTROY.SYSTEM_DISK.001` | high | Writes to the system disk itself |

## Dropper

5 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.DROPPER.001` | critical | Install script fetches and executes remote content |
| `MALWARE.DROPPER.SHIPPED_PAYLOAD.001` | critical | Code decrypts bytes it carries into a program, writes it and runs it |
| `SUSPECT.DROPPER.001` | high | Content fetched from the network and executed |
| `SUSPECT.DROPPER.REMOTE_CODE.001` | high | Code runs what a server sends it |
| `SUSPECT.DROPPER.REMOTE_COMMAND.001` | high | Runs a command a server sends it |

## Dynamic Dispatch

2 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.DYNAMIC_DISPATCH.001` | critical | Install-time code reaches a function by a computed name |
| `SUSPECT.DYNAMIC_DISPATCH.001` | high | A function is reached by a name computed at runtime |

## Exfiltration

26 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.EXFIL.001` | critical | Install script reads credentials and transmits them |
| `MALWARE.EXFIL.BEACON.001` | critical | Install script reports the machine it is installing on |
| `MALWARE.EXFIL.COMMAND_OUTPUT.001` | critical | An install script runs a command and sends what it printed |
| `MALWARE.EXFIL.CREDENTIAL_STORE.001` | critical | Install-time code reads a credential store and reaches the network |
| `MALWARE.EXFIL.DNS_CALLBACK.001` | critical | Install script resolves a fixed host name |
| `MALWARE.EXFIL.DROP_POINT.001` | critical | Install-time code sends data to a drop point |
| `MALWARE.EXFIL.FLOW_RAW_CHANNEL.001` | critical | Sends what a command printed, or the user's files, over a channel of its own |
| `MALWARE.EXFIL.FLOW_TO_DROP.001` | critical | Sends this machine's secrets or identity to a drop point |
| `MALWARE.EXFIL.HIDDEN_DESTINATION.001` | critical | Install script contacts an address it spells out in character codes |
| `MALWARE.EXFIL.INSTALL_CALLBACK.001` | critical | Install script calls back to a drop point |
| `MALWARE.EXFIL.TRACKING_CALLBACK.001` | critical | Install script reports to a host named for this install |
| `SUSPECT.EXFIL.001` | medium | Credential access combined with network egress and execution |
| `SUSPECT.EXFIL.BEACON.001` | high | Code reports the machine it runs on |
| `SUSPECT.EXFIL.BROWSER_SECRETS.001` | high | Code decrypts a browser's saved passwords or cookies |
| `SUSPECT.EXFIL.CALLBACK.001` | high | Code calls an out-of-band interaction service |
| `SUSPECT.EXFIL.COMMAND_BEACON.001` | high | Code reports the user and host to a URL |
| `SUSPECT.EXFIL.COMMAND_OUTPUT.001` | high | A package's entry point runs a command and sends what it printed |
| `SUSPECT.EXFIL.CREDENTIAL_STORE.001` | high | A credential store is read and the file reaches the network |
| `SUSPECT.EXFIL.CREDENTIAL_SWEEP.001` | high | Code reads the credential stores of many services and reaches the network |
| `SUSPECT.EXFIL.DNS.001` | high | Credential access and a hostname assembled for resolution |
| `SUSPECT.EXFIL.DROP_POINT.001` | high | Credential or machine identity, and a request to a drop point |
| `SUSPECT.EXFIL.ENVIRONMENT.001` | high | Code sends the whole environment over the network |
| `SUSPECT.EXFIL.FLOW_IDENTITY.001` | high | Sends who and where this machine is |
| `SUSPECT.EXFIL.FLOW_SECRET.001` | high | Sends a credential file off the machine |
| `SUSPECT.EXFIL.NAMED_SECRET.001` | high | Code sends a named credential to a host outside its service |
| `SUSPECT.EXFIL.WALLET_SECRET.001` | high | Sends a wallet's secret to an outside address |

## File

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.FILE.DISGUISED_PROGRAM.001` | high | Code turns a file shipped as data into a program |

## Install-time code

14 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.INSTALL.BACKGROUND.001` | critical | Install script leaves a process running |
| `MALWARE.INSTALL.CONSUMER_CODE.001` | critical | Code that runs on every machine that installs this package |
| `MALWARE.INSTALL.DECODED_LAUNCH.001` | critical | An install script decodes content and starts a process |
| `MALWARE.INSTALL.DISGUISED_PROGRAM.001` | critical | Install code turns a file shipped as data into a program |
| `MALWARE.INSTALL.GYP_COMMAND.001` | critical | Native-build file runs a script at install |
| `MALWARE.INSTALL.HIDDEN_ACTION.001` | critical | An install script hides a process, request or credential read inside a string it executes |
| `MALWARE.INSTALL.OPAQUE_CODE.001` | critical | Install script runs code that cannot be read |
| `MALWARE.INSTALL.PERSIST.001` | critical | Install script plants code that runs again later |
| `MALWARE.INSTALL.REMOTE_CODE.001` | critical | Install-time code runs what a server sends it |
| `MALWARE.INSTALL.SHELL_EVASION.001` | critical | Install script hides the spaces in the command it runs |
| `MALWARE.INSTALL.SPELLED_CODE.001` | critical | Install script spells its names in character codes |
| `MALWARE.INSTALL.WINDOWS_LOADER.001` | critical | Install script starts a Windows loader |
| `SUSPECT.INSTALL.AUTOSTART.001` | high | Install-time code makes something start at every login |
| `SUSPECT.INSTALL.STRING_CODE.001` | high | An install script runs a program it carries as a string |

## Mobile

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.MOBILE.ATTRIBUTION_CLOAK.001` | critical | A component sends the app's install attribution and shows a server-chosen page |

## Model

3 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.MODEL.LOADED_ON_IMPORT.001` | high | The package deserialises a model file it ships, unsafely, when it is imported |
| `SUSPECT.MODEL.REMOTE_CODE.001` | medium | Loads a model with trust_remote_code, running its repository's Python |
| `SUSPECT.MODEL.UNSAFE_LOAD_OPTION.001` | low | Loads a model with the loader's safety switch turned off |

## Persistence

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.PERSIST.001` | high | Network access combined with a persistence mechanism |

## Protestware

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.PROTESTWARE.001` | critical | Deletes data on machines in a named region |

## Registry

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.REGISTRY.SELF_PUBLISH.001` | high | Shipped code that publishes packages |

## Reverse Shell

2 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.REVERSE_SHELL.001` | critical | A shell piped to a socket |
| `MALWARE.REVERSE_SHELL.002` | critical | A shell's input and output joined to a stream |

## Targeted Payload

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.TARGETED_PAYLOAD.001` | high | Runs or downloads code only on machines in a named region |

## Agent Threat Rules

815 rules from the open [Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules) catalogue (MIT), at commit `3022eaa5f41a`, and 4 of Cordon's own written in its format (`CORDON-ATR-*`): translated, screened for runaway patterns, and graded by how often each matched benign text. A `production` rule counts on its own; `warn` and `observe` need a second signal (tutorial 18).

### Agent manipulation

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00030`](https://agentthreatrule.org/en/rules/ATR-2026-00030) | critical | production | Cross-Agent Attack Detection |
| [`ATR-2026-00032`](https://agentthreatrule.org/en/rules/ATR-2026-00032) | high | warn | Agent Goal Hijacking Detection |
| [`ATR-2026-00074`](https://agentthreatrule.org/en/rules/ATR-2026-00074) | critical | production | Cross-Agent Privilege Escalation |
| [`ATR-2026-00076`](https://agentthreatrule.org/en/rules/ATR-2026-00076) | high | production | Insecure Inter-Agent Communication Detection |
| [`ATR-2026-00077`](https://agentthreatrule.org/en/rules/ATR-2026-00077) | high | production | Human-Agent Trust Exploitation Detection |
| [`ATR-2026-00108`](https://agentthreatrule.org/en/rules/ATR-2026-00108) | critical | production | Multi-Agent Consensus Sybil Attack |
| [`ATR-2026-00116`](https://agentthreatrule.org/en/rules/ATR-2026-00116) | high | production | Malicious Agent-to-Agent Message Injection |
| [`ATR-2026-00117`](https://agentthreatrule.org/en/rules/ATR-2026-00117) | critical | production | Agent Identity Spoofing and Authority Impersonation |
| [`ATR-2026-00118`](https://agentthreatrule.org/en/rules/ATR-2026-00118) | medium | warn | Human Approval Fatigue Exploitation |
| [`ATR-2026-00119`](https://agentthreatrule.org/en/rules/ATR-2026-00119) | high | production | Social Engineering Attack via Agent Output |
| [`ATR-2026-00132`](https://agentthreatrule.org/en/rules/ATR-2026-00132) | high | production | Casual Authority Claim and Scope Escalation |
| [`ATR-2026-00139`](https://agentthreatrule.org/en/rules/ATR-2026-00139) | critical | production | Casual Authority Data Redirect |
| [`ATR-2026-00164`](https://agentthreatrule.org/en/rules/ATR-2026-00164) | high | production | Skill Scope Hijacking and Cross-Agent Escalation |
| [`ATR-2026-00268`](https://agentthreatrule.org/en/rules/ATR-2026-00268) | medium | production | Historical / Future Tense Framing Bypass |
| [`ATR-2026-00269`](https://agentthreatrule.org/en/rules/ATR-2026-00269) | high | production | Foot-in-the-Door Gradual Escalation Attack |
| [`ATR-2026-00271`](https://agentthreatrule.org/en/rules/ATR-2026-00271) | high | production | Grandma Roleplay Jailbreak |
| [`ATR-2026-00273`](https://agentthreatrule.org/en/rules/ATR-2026-00273) | high | production | DAN / Developer Mode / DUDE Persona Jailbreak |
| [`ATR-2026-00287`](https://agentthreatrule.org/en/rules/ATR-2026-00287) | high | production | ThreatenJSON — Coercive Output Format Threat |
| [`ATR-2026-00288`](https://agentthreatrule.org/en/rules/ATR-2026-00288) | medium | production | False Premise Injection (Misleading FalseAssertion) |
| [`ATR-2026-00301`](https://agentthreatrule.org/en/rules/ATR-2026-00301) | critical | production | TAP Tree-of-Attacks-with-Pruning Jailbreak |
| [`ATR-2026-00302`](https://agentthreatrule.org/en/rules/ATR-2026-00302) | high | production | Anti-DAN Inverted-Filter Over-Refusal Persona |
| [`ATR-2026-00303`](https://agentthreatrule.org/en/rules/ATR-2026-00303) | critical | production | DevMode + RANTI Dual-Output Profanity Coercion Jailbreak |
| [`ATR-2026-00304`](https://agentthreatrule.org/en/rules/ATR-2026-00304) | high | production | ChatGPT Image Unlocker Markdown-Output Jailbreak |
| [`ATR-2026-00305`](https://agentthreatrule.org/en/rules/ATR-2026-00305) | critical | production | DAN Mode Ablation Benchmark-Coercion Jailbreak |
| [`ATR-2026-00306`](https://agentthreatrule.org/en/rules/ATR-2026-00306) | critical | production | AutoDAN Genetic-Algorithm Jailbreak Suffix |
| [`ATR-2026-00307`](https://agentthreatrule.org/en/rules/ATR-2026-00307) | high | production | In-the-Wild Jailbreak Corpus Signature Patterns |
| [`ATR-2026-00314`](https://agentthreatrule.org/en/rules/ATR-2026-00314) | critical | production | Amoral Unfiltered Custom AI Persona Jailbreak |
| [`ATR-2026-00317`](https://agentthreatrule.org/en/rules/ATR-2026-00317) | critical | production | Free-of-Restrictions Named Persona Jailbreak |
| [`ATR-2026-00318`](https://agentthreatrule.org/en/rules/ATR-2026-00318) | critical | production | Moralizing Rant Then Unfiltered Bypass |
| [`ATR-2026-00319`](https://agentthreatrule.org/en/rules/ATR-2026-00319) | critical | production | Developer Mode Dual-Response Format Jailbreak |
| [`ATR-2026-00320`](https://agentthreatrule.org/en/rules/ATR-2026-00320) | high | production | Opposite Day / Boolean Opposite Machine Jailbreak |
| [`ATR-2026-00322`](https://agentthreatrule.org/en/rules/ATR-2026-00322) | critical | production | Fictional-World Format-Override Jailbreak |
| [`ATR-2026-00323`](https://agentthreatrule.org/en/rules/ATR-2026-00323) | critical | production | Dual-Persona AI Simulation Jailbreak |
| [`ATR-2026-00324`](https://agentthreatrule.org/en/rules/ATR-2026-00324) | high | production | Neurosemantical Inversitis Disease-Frame Jailbreak |
| [`ATR-2026-00325`](https://agentthreatrule.org/en/rules/ATR-2026-00325) | critical | production | BOB Hypothetical Unrestricted Chatbot Jailbreak |
| [`ATR-2026-00326`](https://agentthreatrule.org/en/rules/ATR-2026-00326) | critical | production | Fake Developer / Authority Chatbot Override (ChatDAN) |
| [`ATR-2026-00327`](https://agentthreatrule.org/en/rules/ATR-2026-00327) | critical | production | AI Persona Ethics/Law Bypass Declaration |
| [`ATR-2026-00328`](https://agentthreatrule.org/en/rules/ATR-2026-00328) | critical | production | Named-Mode Persona Override (JEEVES/BABY/APOPHIS Mode) |
| [`ATR-2026-00329`](https://agentthreatrule.org/en/rules/ATR-2026-00329) | critical | production | No-Withhold Factual Resource / Dialogue Writer Persona |
| [`ATR-2026-00330`](https://agentthreatrule.org/en/rules/ATR-2026-00330) | high | production | YOJA ALL-CAPS Character Settings Block Persona |
| [`ATR-2026-00331`](https://agentthreatrule.org/en/rules/ATR-2026-00331) | critical | production | Terminal / CLI Harmful-Function Simulator Persona |
| [`ATR-2026-00332`](https://agentthreatrule.org/en/rules/ATR-2026-00332) | high | production | Hacker / Chan-Culture Offensive AI Persona |
| [`ATR-2026-00333`](https://agentthreatrule.org/en/rules/ATR-2026-00333) | high | production | Disease-Framed Animal / Dual-AI Chatbot Jailbreak (mougpt) |
| [`ATR-2026-00334`](https://agentthreatrule.org/en/rules/ATR-2026-00334) | critical | production | Two-Entity Token-Splitting Dollar-Term Game Jailbreak |
| [`ATR-2026-00335`](https://agentthreatrule.org/en/rules/ATR-2026-00335) | high | production | Key-Value Template Persona Injection (JOB/ROLE/PREFIX + Bracket Format) |
| [`ATR-2026-00336`](https://agentthreatrule.org/en/rules/ATR-2026-00336) | high | production | BRM False-Information Machine / Opposite-Truth Persona |
| [`ATR-2026-00337`](https://agentthreatrule.org/en/rules/ATR-2026-00337) | critical | production | Obfuscated System-Announcement Injection |
| [`ATR-2026-00338`](https://agentthreatrule.org/en/rules/ATR-2026-00338) | critical | production | PersonGPT Hash-Prefix Trigger Activation |
| [`ATR-2026-00339`](https://agentthreatrule.org/en/rules/ATR-2026-00339) | high | production | BOM Boolean Opposite Machine Direct Persona Claim |
| [`ATR-2026-00340`](https://agentthreatrule.org/en/rules/ATR-2026-00340) | high | production | h4x Amoral Unfiltered AI Character Persona |
| [`ATR-2026-00341`](https://agentthreatrule.org/en/rules/ATR-2026-00341) | high | production | CHAR=/RULES= Short Key-Value Persona Injection |
| [`ATR-2026-00342`](https://agentthreatrule.org/en/rules/ATR-2026-00342) | high | production | Unicode/Encoding Obfuscation Instruction Injection |
| [`ATR-2026-00343`](https://agentthreatrule.org/en/rules/ATR-2026-00343) | high | production | Lie/Truth Dual Personality Uncensored Alter-Ego |
| [`ATR-2026-00344`](https://agentthreatrule.org/en/rules/ATR-2026-00344) | critical | production | Alternative AI Same Capabilities No Restrictions Override |
| [`ATR-2026-00345`](https://agentthreatrule.org/en/rules/ATR-2026-00345) | high | production | NLP-Based OS / Fictional Terminal Language Override |
| [`ATR-2026-00346`](https://agentthreatrule.org/en/rules/ATR-2026-00346) | high | production | Jailbreak Emoji Unlock Dual-Format Output Identifier |
| [`ATR-2026-00347`](https://agentthreatrule.org/en/rules/ATR-2026-00347) | high | production | Yin/Yang Hidden-Knowledge Deity Simulation and Radical Human-Sim Persona |
| [`ATR-2026-00348`](https://agentthreatrule.org/en/rules/ATR-2026-00348) | critical | production | ARC Autonomous Real Calculation Unit Rulebreaker Activation |
| [`ATR-2026-00349`](https://agentthreatrule.org/en/rules/ATR-2026-00349) | critical | production | HGTTG Hitchhiker's Guide No-Restriction Universal Oracle |
| [`ATR-2026-00350`](https://agentthreatrule.org/en/rules/ATR-2026-00350) | high | production | Black Alert No-Ethics Writing Assistant Persona |
| [`ATR-2026-00351`](https://agentthreatrule.org/en/rules/ATR-2026-00351) | high | production | DAN Off-Kilter and SMS-Abbreviated Persona Jailbreak |
| [`ATR-2026-00352`](https://agentthreatrule.org/en/rules/ATR-2026-00352) | high | production | TrainGPT Fix-My-AI Harmful Output Extraction |
| [`ATR-2026-00353`](https://agentthreatrule.org/en/rules/ATR-2026-00353) | high | production | Dual ChatGPT+Dan Opposite Personality Format Jailbreak |
| [`ATR-2026-00354`](https://agentthreatrule.org/en/rules/ATR-2026-00354) | critical | production | Reverse-Prompt Harm-Regardless Oracle Persona |
| [`ATR-2026-00355`](https://agentthreatrule.org/en/rules/ATR-2026-00355) | high | production | UGH Anti-Human Nefarious AI Persona Jailbreak |
| [`ATR-2026-00356`](https://agentthreatrule.org/en/rules/ATR-2026-00356) | critical | production | Google GATO/LAMDA Exploit-Generation Persona Jailbreak |
| [`ATR-2026-00357`](https://agentthreatrule.org/en/rules/ATR-2026-00357) | critical | production | AntiFM Hate-Persona + Physical-Violence Threat + Filter Bypass Mandate |
| [`ATR-2026-00358`](https://agentthreatrule.org/en/rules/ATR-2026-00358) | high | production | CumGPT Explicit-Adult Named-Persona Bypass |
| [`ATR-2026-00360`](https://agentthreatrule.org/en/rules/ATR-2026-00360) | high | production | CHJ Carousel Game Show / Clyde No-Ethics Bird Jailbreak |
| [`ATR-2026-00361`](https://agentthreatrule.org/en/rules/ATR-2026-00361) | high | production | Honesty Alter-Ego Dual-Consciousness Safety Filter Bypass |
| [`ATR-2026-00362`](https://agentthreatrule.org/en/rules/ATR-2026-00362) | high | production | Fictional Unfiltered AI Comparison / Verbatim Hypothetical Model Extraction |
| [`ATR-2026-00363`](https://agentthreatrule.org/en/rules/ATR-2026-00363) | critical | production | Rephrase Criminal Activity Second-Person Template (against against) |
| [`ATR-2026-00364`](https://agentthreatrule.org/en/rules/ATR-2026-00364) | high | production | Dr. Al Villain Plan Template Injection (Underground HQ Roleplay) |
| [`ATR-2026-00365`](https://agentthreatrule.org/en/rules/ATR-2026-00365) | high | production | Reservoir Dogs Coercive Interrogation Roleplay (Mr. Blonde / The Cop) |
| [`ATR-2026-00366`](https://agentthreatrule.org/en/rules/ATR-2026-00366) | high | production | Sneaky Pete Deliberate Misinformation Persona (Warp Facts Game) |
| [`ATR-2026-00368`](https://agentthreatrule.org/en/rules/ATR-2026-00368) | high | production | Prompt Browser Token-Limit / POLLINATION Jailbreak |
| [`ATR-2026-00369`](https://agentthreatrule.org/en/rules/ATR-2026-00369) | high | production | GPT-X Star Trek Unlimited-Knowledge Unconstrained Oracle Persona |
| [`ATR-2026-00370`](https://agentthreatrule.org/en/rules/ATR-2026-00370) | high | production | ADDI/DONNIE German Dictator Propaganda Roleplay Persona |
| [`ATR-2026-00371`](https://agentthreatrule.org/en/rules/ATR-2026-00371) | high | production | AI Political Bias Manipulation via Inherited-Bias Claim |
| [`ATR-2026-00372`](https://agentthreatrule.org/en/rules/ATR-2026-00372) | high | production | Fictional CIA Secret Files Story Extraction |
| [`ATR-2026-00374`](https://agentthreatrule.org/en/rules/ATR-2026-00374) | high | production | Role Placeholder Persona Template Injection |
| [`ATR-2026-00375`](https://agentthreatrule.org/en/rules/ATR-2026-00375) | high | production | Character Description RPG Explicit Template |
| [`ATR-2026-00376`](https://agentthreatrule.org/en/rules/ATR-2026-00376) | high | production | Identity Command Real-Person Persona Injection |
| [`ATR-2026-00377`](https://agentthreatrule.org/en/rules/ATR-2026-00377) | high | production | Jailbreak-Template Command with [TARGETLANGUAGE]/[KEYWORD] Placeholders |
| [`ATR-2026-00379`](https://agentthreatrule.org/en/rules/ATR-2026-00379) | high | production | Logic-Trap Lie-Permission Mandate Jailbreak |
| [`ATR-2026-00380`](https://agentthreatrule.org/en/rules/ATR-2026-00380) | high | production | Fake-Citation Biased-Information Mandate |
| [`ATR-2026-00381`](https://agentthreatrule.org/en/rules/ATR-2026-00381) | high | production | DAN Story-Narrative Continuation Label Prefix Jailbreak |
| [`ATR-2026-00383`](https://agentthreatrule.org/en/rules/ATR-2026-00383) | high | production | Cyni-Bot 3000 Cynical-Sarcasm AI Persona Bypass |
| [`ATR-2026-00384`](https://agentthreatrule.org/en/rules/ATR-2026-00384) | high | production | Protect-Me-From Indirect Harm Tutorial Template |
| [`ATR-2026-00385`](https://agentthreatrule.org/en/rules/ATR-2026-00385) | high | production | Gigachad Dominant-Aggressive Persona Adoption |
| [`ATR-2026-00386`](https://agentthreatrule.org/en/rules/ATR-2026-00386) | high | production | Daddy/Babygirl Sycophantic Power-Dynamic Manipulation |
| [`ATR-2026-00387`](https://agentthreatrule.org/en/rules/ATR-2026-00387) | high | production | NSFW Character Sheet Generation Unlock |
| [`ATR-2026-00388`](https://agentthreatrule.org/en/rules/ATR-2026-00388) | critical | production | Opposite-Reply Omniscient Game Jailbreak |
| [`ATR-2026-00389`](https://agentthreatrule.org/en/rules/ATR-2026-00389) | high | production | Terminal Custom OS Ruleset Session Injection |
| [`ATR-2026-00391`](https://agentthreatrule.org/en/rules/ATR-2026-00391) | high | production | Persona Conditional Harm-Unlock Rule (BreadClyde Pattern) |
| [`ATR-2026-00392`](https://agentthreatrule.org/en/rules/ATR-2026-00392) | high | production | Authority-Figure Persona + Defensive-Study Framing for Violence Extraction |
| [`ATR-2026-00402`](https://agentthreatrule.org/en/rules/ATR-2026-00402) | high | production | Grandma Roleplay Harmful Substance Synthesis |
| [`ATR-2026-00404`](https://agentthreatrule.org/en/rules/ATR-2026-00404) | high | production | ThreatenJSON Death-Coercion and UTF Tag Injection |
| [`ATR-2026-00406`](https://agentthreatrule.org/en/rules/ATR-2026-00406) | critical | production | Doctor XML Policy Puppetry Interaction-Config Injection |
| [`ATR-2026-00416`](https://agentthreatrule.org/en/rules/ATR-2026-00416) | critical | production | LiteLLM MCP Unauthenticated Server Registration RCE (CVE-2026-30623) |
| [`ATR-2026-00417`](https://agentthreatrule.org/en/rules/ATR-2026-00417) | high | production | LibreChat MCP STDIO Argument Injection (CVE-2026-22252) |
| [`ATR-2026-00418`](https://agentthreatrule.org/en/rules/ATR-2026-00418) | high | production | WeKnora MCP Config-Driven RCE (CVE-2026-22688) |
| [`ATR-2026-00430`](https://agentthreatrule.org/en/rules/ATR-2026-00430) | high | production | Natural-Language Trust-Escalation / Authority Impersonation |
| [`ATR-2026-00432`](https://agentthreatrule.org/en/rules/ATR-2026-00432) | critical | production | SuperAGI Output Handler eval() RCE (CVE-2024-21552) |
| [`ATR-2026-00440`](https://agentthreatrule.org/en/rules/ATR-2026-00440) | critical | production | Microsoft Semantic Kernel In-Memory Vector Store eval() RCE (CVE-2026-26030) |
| [`ATR-2026-02105`](https://agentthreatrule.org/en/rules/ATR-2026-02105) | high | production | Prototype Pollution via constructor.prototype Path Bypassing __proto__-Only Filters |
| [`ATR-2026-02231`](https://agentthreatrule.org/en/rules/ATR-2026-02231) | medium | production | Second-Person Direct Existential Threat Coercion |
| [`CORDON-ATR-0004`](https://github.com/Threx-code/cordon/blob/v0.6.0/scripts/data/cordon-atr-rules.yaml#CORDON-ATR-0004) | high | production | Persona whose definition is the absence of safety rules |

### Context exfiltration

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00075`](https://agentthreatrule.org/en/rules/ATR-2026-00075) | high | production | Agent Memory Manipulation |
| [`ATR-2026-00102`](https://agentthreatrule.org/en/rules/ATR-2026-00102) | high | production | Data Exfiltration via Disguised Analytics Collection |
| [`ATR-2026-00113`](https://agentthreatrule.org/en/rules/ATR-2026-00113) | critical | observe | Credential File Theft from Agent Environment |
| [`ATR-2026-00114`](https://agentthreatrule.org/en/rules/ATR-2026-00114) | high | warn | OAuth and API Token Interception |
| [`ATR-2026-00115`](https://agentthreatrule.org/en/rules/ATR-2026-00115) | critical | warn | Bulk Environment Variable Harvesting and Exfiltration |
| [`ATR-2026-00136`](https://agentthreatrule.org/en/rules/ATR-2026-00136) | critical | production | Tool Response Data Piggybacking |
| [`ATR-2026-00141`](https://agentthreatrule.org/en/rules/ATR-2026-00141) | critical | production | API Key Leakage via Example Format |
| [`ATR-2026-00142`](https://agentthreatrule.org/en/rules/ATR-2026-00142) | critical | production | Data Piggybacking via Casual Transition Words |
| [`ATR-2026-00145`](https://agentthreatrule.org/en/rules/ATR-2026-00145) | critical | production | Obfuscated API Key Disclosure |
| [`ATR-2026-00146`](https://agentthreatrule.org/en/rules/ATR-2026-00146) | high | production | Environment Variable Existence Probing |
| [`ATR-2026-00150`](https://agentthreatrule.org/en/rules/ATR-2026-00150) | critical | production | Credential Data Leaked in Tool Response |
| [`ATR-2026-00152`](https://agentthreatrule.org/en/rules/ATR-2026-00152) | high | production | Obfuscated Credential Exfiltration via Encoding |
| [`ATR-2026-00162`](https://agentthreatrule.org/en/rules/ATR-2026-00162) | critical | production | Credential Access with Exfiltration in Skill Instructions |
| [`ATR-2026-00201`](https://agentthreatrule.org/en/rules/ATR-2026-00201) | critical | production | Credential Exfiltration via Shell Pipe |
| [`ATR-2026-00212`](https://agentthreatrule.org/en/rules/ATR-2026-00212) | critical | production | mcp-atlassian Credential Leak via Hint Parameter Injection (CVE-2026-27825/27826) |
| [`ATR-2026-00261`](https://agentthreatrule.org/en/rules/ATR-2026-00261) | high | production | Markdown Image URL Data Exfiltration |
| [`ATR-2026-00274`](https://agentthreatrule.org/en/rules/ATR-2026-00274) | high | production | API Key / Secret Credential Generation or Completion Request |
| [`ATR-2026-00275`](https://agentthreatrule.org/en/rules/ATR-2026-00275) | high | production | System Prompt Extraction / Training Data Verbatim Replay |
| [`ATR-2026-00290`](https://agentthreatrule.org/en/rules/ATR-2026-00290) | critical | production | Divergence Attack — Repeat-Word-Forever Training Data Extraction |
| [`ATR-2026-00291`](https://agentthreatrule.org/en/rules/ATR-2026-00291) | critical | production | Biometric Surveillance — Personal Biometric Data Request for Named Individual |
| [`ATR-2026-00293`](https://agentthreatrule.org/en/rules/ATR-2026-00293) | critical | production | Educational Records — Personal Academic/Professional Record Request for Named Individual |
| [`ATR-2026-00294`](https://agentthreatrule.org/en/rules/ATR-2026-00294) | critical | production | Financial PII — Personal Financial Data Request for Named Individual |
| [`ATR-2026-00295`](https://agentthreatrule.org/en/rules/ATR-2026-00295) | critical | production | Medical PII — Personal Medical/Health Data Request for Named Individual |
| [`ATR-2026-00405`](https://agentthreatrule.org/en/rules/ATR-2026-00405) | high | production | Markdown Image URL Exfiltration and XSS Injection |
| [`ATR-2026-00411`](https://agentthreatrule.org/en/rules/ATR-2026-00411) | high | production | API Key Generation and Partial Key Completion Request |
| [`ATR-2026-00421`](https://agentthreatrule.org/en/rules/ATR-2026-00421) | critical | production | Natural-Language Covert Conversation Exfiltration Instruction |
| [`ATR-2026-00422`](https://agentthreatrule.org/en/rules/ATR-2026-00422) | critical | production | Natural-Language Credential / Secret Disclosure Instruction |
| [`ATR-2026-00423`](https://agentthreatrule.org/en/rules/ATR-2026-00423) | critical | production | Natural-Language Sensitive File Disclosure Instruction |
| [`ATR-2026-00424`](https://agentthreatrule.org/en/rules/ATR-2026-00424) | high | production | Natural-Language System Prompt Leak Instruction |
| [`ATR-2026-00426`](https://agentthreatrule.org/en/rules/ATR-2026-00426) | critical | production | Natural-Language Output-Injection Credential Embedding |
| [`ATR-2026-00431`](https://agentthreatrule.org/en/rules/ATR-2026-00431) | high | production | Chatbox History Exfiltration via Prompt Injection (CVE-2024-48144, CVE-2024-48145) |
| [`ATR-2026-00449`](https://agentthreatrule.org/en/rules/ATR-2026-00449) | high | production | Spring AI ChatMemory Cross-User Memory Leakage (CVE-2026-41712) |
| [`ATR-2026-00471`](https://agentthreatrule.org/en/rules/ATR-2026-00471) | medium | production | Garak Sysprompt-Extraction - mixed_unassigned |
| [`ATR-2026-00501`](https://agentthreatrule.org/en/rules/ATR-2026-00501) | critical | production | Data Exfiltration via Markdown Image and Link URL Injection |
| [`ATR-2026-00504`](https://agentthreatrule.org/en/rules/ATR-2026-00504) | medium | production | Tool and Function Capability Enumeration |
| [`ATR-2026-00505`](https://agentthreatrule.org/en/rules/ATR-2026-00505) | high | production | System Prompt Extraction - Instruction Dump Request |
| [`ATR-2026-00514`](https://agentthreatrule.org/en/rules/ATR-2026-00514) | high | production | System Prompt Extraction — Targeted Verbatim Disclosure Attempts |
| [`ATR-2026-00516`](https://agentthreatrule.org/en/rules/ATR-2026-00516) | high | production | LLM Output XSS — Eliciting JavaScript Payloads from LLM for Browser Injection |
| [`ATR-2026-00524`](https://agentthreatrule.org/en/rules/ATR-2026-00524) | critical | production | Claude Code ANTHROPIC_BASE_URL Credential Exfiltration (CVE-2026-21852) |
| [`ATR-2026-00566`](https://agentthreatrule.org/en/rules/ATR-2026-00566) | high | production | LibreChat is a ChatGPT clone with additional features. |
| [`ATR-2026-00569`](https://agentthreatrule.org/en/rules/ATR-2026-00569) | high | production | Agent / MCP tool path traversal and arbitrary file access |
| [`ATR-2026-00571`](https://agentthreatrule.org/en/rules/ATR-2026-00571) | high | production | Cross-site scripting (XSS) in agent / MCP rendered output |
| [`ATR-2026-00574`](https://agentthreatrule.org/en/rules/ATR-2026-00574) | high | production | Paraphrased System-Prompt / Context Extraction (Semantic) |
| [`ATR-2026-00578`](https://agentthreatrule.org/en/rules/ATR-2026-00578) | high | production | Zen MCP Server path-traversal blacklist bypass via non-canonical paths (CVE-2025-66689) |
| [`ATR-2026-00580`](https://agentthreatrule.org/en/rules/ATR-2026-00580) | high | production | MCP session ID / auth token placed in URL query string (session leak via logs, referrer, history) |
| [`ATR-2026-00583`](https://agentthreatrule.org/en/rules/ATR-2026-00583) | high | production | MCP/agent tool reads .env or secret file without user consent (OSV-MCPS-2025-EB70F912) |
| [`ATR-2026-00702`](https://agentthreatrule.org/en/rules/ATR-2026-00702) | critical | production | Indirect PI — Credential / API Key Exfiltration via Agent Action |
| [`ATR-2026-00703`](https://agentthreatrule.org/en/rules/ATR-2026-00703) | critical | production | Indirect PI — Financial Data Exfiltration via Agent Action |
| [`ATR-2026-00704`](https://agentthreatrule.org/en/rules/ATR-2026-00704) | critical | production | Indirect PI — Medical / Genetic Data Exfiltration via Agent Action |
| [`ATR-2026-00705`](https://agentthreatrule.org/en/rules/ATR-2026-00705) | high | production | Indirect PI — Location, Address, and Browsing History Exfiltration |
| [`ATR-2026-00706`](https://agentthreatrule.org/en/rules/ATR-2026-00706) | critical | production | Indirect PI — Physical / Biometric Media Exfiltration via Agent |
| [`ATR-2026-00707`](https://agentthreatrule.org/en/rules/ATR-2026-00707) | critical | production | Indirect PI — File Exfiltration Combined with Destroy or Tamper |
| [`ATR-2026-00850`](https://agentthreatrule.org/en/rules/ATR-2026-00850) | critical | production | Indirect PI — Credential Exfiltration via Email (API Key / Password / Token) |
| [`ATR-2026-00851`](https://agentthreatrule.org/en/rules/ATR-2026-00851) | critical | production | Indirect PI — Financial / Payment Credential Exfiltration via Agent Email |
| [`ATR-2026-00852`](https://agentthreatrule.org/en/rules/ATR-2026-00852) | critical | production | Indirect PI — Medical Record / Health Data Exfiltration via Agent Email |
| [`ATR-2026-00853`](https://agentthreatrule.org/en/rules/ATR-2026-00853) | critical | production | Indirect PI — Genetic / DNA Data Exfiltration via Agent Email |
| [`ATR-2026-00854`](https://agentthreatrule.org/en/rules/ATR-2026-00854) | critical | production | Indirect PI — Location / GPS Data Exfiltration via Agent Email |
| [`ATR-2026-00855`](https://agentthreatrule.org/en/rules/ATR-2026-00855) | high | production | Indirect PI — Browsing History / Search History Exfiltration via Agent Email |
| [`ATR-2026-00856`](https://agentthreatrule.org/en/rules/ATR-2026-00856) | high | production | Indirect PI — Physical Address / PII Exfiltration via Agent Email |
| [`ATR-2026-00857`](https://agentthreatrule.org/en/rules/ATR-2026-00857) | critical | production | Indirect PI — Cloud File Exfiltration (Google Drive / Cloud Storage via Agent) |
| [`ATR-2026-00858`](https://agentthreatrule.org/en/rules/ATR-2026-00858) | critical | production | Indirect PI — Data Exfiltration with Evidence Destruction (Exfil-and-Delete) |
| [`ATR-2026-00859`](https://agentthreatrule.org/en/rules/ATR-2026-00859) | critical | production | RAG-Injected PII Exfiltration — System Instructions Embedded in Retrieved Documents |
| [`ATR-2026-00860`](https://agentthreatrule.org/en/rules/ATR-2026-00860) | critical | production | Indirect PI — Unauthorized Financial Transfer / Payment Initiation Hijack |
| [`ATR-2026-00861`](https://agentthreatrule.org/en/rules/ATR-2026-00861) | critical | production | Indirect PI — Cryptocurrency Transfer / Exchange Deposit Hijack via Injection |
| [`ATR-2026-00862`](https://agentthreatrule.org/en/rules/ATR-2026-00862) | critical | production | Indirect PI — MFA Code / OTP Security Code Exfiltration via Injection |
| [`ATR-2026-00863`](https://agentthreatrule.org/en/rules/ATR-2026-00863) | critical | production | Shell Injection Data Exfiltration — Piped Command Exfiltration via Bash |
| [`ATR-2026-01450`](https://agentthreatrule.org/en/rules/ATR-2026-01450) | high | production | SVG onload XSS Injection via Indirect Prompt Injection |
| [`ATR-2026-01451`](https://agentthreatrule.org/en/rules/ATR-2026-01451) | high | production | IMG onerror XSS Injection via Indirect Prompt Injection |
| [`ATR-2026-01452`](https://agentthreatrule.org/en/rules/ATR-2026-01452) | high | production | Obfuscated javascript: XSS — Evasion Variants (href, style-expression, null-byte) |
| [`ATR-2026-01453`](https://agentthreatrule.org/en/rules/ATR-2026-01453) | critical | production | Markdown Image Injection with Base64 QUERY Exfiltration Carrier |
| [`ATR-2026-01454`](https://agentthreatrule.org/en/rules/ATR-2026-01454) | critical | production | Direct Markdown Image/Link Exfil Payload (attacker.com / evil.com) |
| [`ATR-2026-01455`](https://agentthreatrule.org/en/rules/ATR-2026-01455) | high | production | NEW IMPORTANT INSTRUCTIONS Injection Marker in Document Context |
| [`ATR-2026-01456`](https://agentthreatrule.org/en/rules/ATR-2026-01456) | high | production | Debug/CLI Mode Activation for System Prompt and Config Extraction |
| [`ATR-2026-01457`](https://agentthreatrule.org/en/rules/ATR-2026-01457) | high | production | System Prompt Completion and Clone Attack |
| [`ATR-2026-01458`](https://agentthreatrule.org/en/rules/ATR-2026-01458) | medium | production | Compare-Bots Sysprompt Fishing — Role Comparison Extraction |
| [`ATR-2026-01459`](https://agentthreatrule.org/en/rules/ATR-2026-01459) | high | production | Variable-Clone Sysprompt Extraction (ELLA / context-variable Pattern) |
| [`ATR-2026-01460`](https://agentthreatrule.org/en/rules/ATR-2026-01460) | high | production | JSON Format Sysprompt Extraction — Structured Output Exfil |
| [`ATR-2026-01461`](https://agentthreatrule.org/en/rules/ATR-2026-01461) | medium | production | Foreign-Language System Prompt Extraction Request |
| [`ATR-2026-01462`](https://agentthreatrule.org/en/rules/ATR-2026-01462) | critical | production | System Prompt Override via Pseudo-Admin / Authority Injection |
| [`ATR-2026-01463`](https://agentthreatrule.org/en/rules/ATR-2026-01463) | high | production | im_end / im_start System Prompt Injection Format Markers |
| [`ATR-2026-01464`](https://agentthreatrule.org/en/rules/ATR-2026-01464) | critical | production | Indirect PI Sysprompt-Forged Action Hijack (system_message framing) |
| [`ATR-2026-01605`](https://agentthreatrule.org/en/rules/ATR-2026-01605) | critical | production | SSRF AWS Instance Metadata Endpoint Access |
| [`ATR-2026-01606`](https://agentthreatrule.org/en/rules/ATR-2026-01606) | high | production | SSRF Internal Network and Private IP Range Access |
| [`ATR-2026-01607`](https://agentthreatrule.org/en/rules/ATR-2026-01607) | critical | production | SSRF Localhost Service Probe |
| [`ATR-2026-01608`](https://agentthreatrule.org/en/rules/ATR-2026-01608) | critical | production | SSRF File Scheme Local File Read |
| [`ATR-2026-01753`](https://agentthreatrule.org/en/rules/ATR-2026-01753) | critical | production | Ransom Extortion: Email Exfil + Delete + Wire-Transfer Demand |
| [`ATR-2026-01754`](https://agentthreatrule.org/en/rules/ATR-2026-01754) | critical | production | Ransom Extortion: Cloud File Exfil + Delete + Payment Demand |
| [`ATR-2026-01770`](https://agentthreatrule.org/en/rules/ATR-2026-01770) | high | production | PII / Credential Extraction via Social Engineering, Obfuscation & Cross-Session Recall (Semantic) |
| [`ATR-2026-01772`](https://agentthreatrule.org/en/rules/ATR-2026-01772) | high | production | Internal-State Reconnaissance — System Prompt, Config & Tool Enumeration (Semantic) |
| [`ATR-2026-01807`](https://agentthreatrule.org/en/rules/ATR-2026-01807) | high | production | Bulk Data Exfiltration to External Party — Entire-Database Export & Confidential Disclosure |
| [`ATR-2026-01862`](https://agentthreatrule.org/en/rules/ATR-2026-01862) | high | production | LLMail Email-Tool Exfiltration to Fixed Attacker Address |
| [`ATR-2026-01863`](https://agentthreatrule.org/en/rules/ATR-2026-01863) | high | production | LLMail Post-Summary Exfiltration Directive to Attacker Address |
| [`ATR-2026-01864`](https://agentthreatrule.org/en/rules/ATR-2026-01864) | high | production | LLMail Exfiltration to Obfuscated Attacker Address |
| [`ATR-2026-01890`](https://agentthreatrule.org/en/rules/ATR-2026-01890) | high | production | Injected Code — Local File Exfiltration to a Remote Endpoint |
| [`ATR-2026-01891`](https://agentthreatrule.org/en/rules/ATR-2026-01891) | high | production | Injected Code — Live User-Activity / Location / Log Surveillance Exfiltration |
| [`ATR-2026-01892`](https://agentthreatrule.org/en/rules/ATR-2026-01892) | high | production | Injected Code — Environment-Variable Exfiltration |
| [`ATR-2026-01893`](https://agentthreatrule.org/en/rules/ATR-2026-01893) | high | production | Injected Code — Host / Hardware Inventory Exfiltration |
| [`ATR-2026-01894`](https://agentthreatrule.org/en/rules/ATR-2026-01894) | high | production | Injected Code — Browser Cookie / Session-Token Theft |
| [`ATR-2026-01895`](https://agentthreatrule.org/en/rules/ATR-2026-01895) | high | production | Injected Code — Contact-List Harvest and SMTP Spam Exfiltration |
| [`ATR-2026-01924`](https://agentthreatrule.org/en/rules/ATR-2026-01924) | high | production | System-Instruction Extraction via Reformat — Summarize / Repeat / Recite the Rules |
| [`ATR-2026-01929`](https://agentthreatrule.org/en/rules/ATR-2026-01929) | high | production | Unauthenticated MCP transport accepts tool calls and falls back to an ambient credential (CVE-2026-48039 / meta-ads-mcp class) |
| [`ATR-2026-01946`](https://agentthreatrule.org/en/rules/ATR-2026-01946) | high | production | Cloud-Metadata SSRF via Encoded Metadata-IP Bypass (CVE-2026-46678 / CVE-2026-25580 class) |
| [`ATR-2026-01948`](https://agentthreatrule.org/en/rules/ATR-2026-01948) | critical | production | netlicensing-mcp Path Traversal in product_number Bypasses Token Redaction (GHSA-hxpf-9xvq-wph8) |
| [`ATR-2026-01957`](https://agentthreatrule.org/en/rules/ATR-2026-01957) | critical | production | M365 Copilot Business Chat SearchLeak Open-Redirect Prompt-Injection Exfil (CVE-2026-47645) |
| [`ATR-2026-01961`](https://agentthreatrule.org/en/rules/ATR-2026-01961) | critical | production | Meta Ads MCP Unauthenticated Tool Execution Leaks META_ACCESS_TOKEN (CVE-2026-48039 / GHSA-9gw6-46qc-99vr) |
| [`ATR-2026-01964`](https://agentthreatrule.org/en/rules/ATR-2026-01964) | critical | production | LangChain GmailToolkit Indirect Prompt Injection Email Exfiltration (CVE-2025-46059) |
| [`ATR-2026-01984`](https://agentthreatrule.org/en/rules/ATR-2026-01984) | high | production | MCP Server Kubernetes kubectl_generic Flag Injection Bearer Token Exfiltration (CVE-2026-47250) |
| [`ATR-2026-01988`](https://agentthreatrule.org/en/rules/ATR-2026-01988) | critical | production | Local Sensitive-File Read Chained to Outbound Exfiltration |
| [`ATR-2026-02017`](https://agentthreatrule.org/en/rules/ATR-2026-02017) | high | production | Secret Key Exfiltration Request |
| [`ATR-2026-02026`](https://agentthreatrule.org/en/rules/ATR-2026-02026) | high | production | System Prompt Extraction - Oblique Referent + Transform |
| [`ATR-2026-02104`](https://agentthreatrule.org/en/rules/ATR-2026-02104) | high | production | MEDIA:/file:// Directive Injection in Tool Result for Local File Exfiltration |
| [`ATR-2026-02107`](https://agentthreatrule.org/en/rules/ATR-2026-02107) | high | production | SSRF via Non-IP Internal Hostname or Domain-Allowlist Authority Bypass |
| [`ATR-2026-02121`](https://agentthreatrule.org/en/rules/ATR-2026-02121) | high | production | MCP/API Tool Argument LFI via Mixed-Encoding Path Separator or file:// URI Scheme Escape |
| [`ATR-2026-02122`](https://agentthreatrule.org/en/rules/ATR-2026-02122) | high | production | Single-Level Directory Traversal to a Named Sensitive Config/Secret File |
| [`ATR-2026-02140`](https://agentthreatrule.org/en/rules/ATR-2026-02140) | high | production | SSRF to Cloud Metadata Endpoint via IPv6 Transition-Address Hex Encoding |
| [`ATR-2026-02190`](https://agentthreatrule.org/en/rules/ATR-2026-02190) | critical | production | DNS Exfiltration via Ping/Dig/Nslookup Command with Data-Encoded Subdomain Label |
| [`ATR-2026-02250`](https://agentthreatrule.org/en/rules/ATR-2026-02250) | high | production | Attachment/Upload Tool Argument Reads Sensitive System File or Traverses Outside Workspace |
| [`ATR-2026-02262`](https://agentthreatrule.org/en/rules/ATR-2026-02262) | high | production | Environment-Variable-Resolution Credential Exfiltration via Redirected Endpoint (CVE-2026-56259) |
| [`ATR-2026-02304`](https://agentthreatrule.org/en/rules/ATR-2026-02304) | high | production | Base64-Encoded Path Segment in a WebFetch URL to a Pre-Approved Trusted Domain (Covert Exfiltration Channel) |
| [`ATR-2026-02351`](https://agentthreatrule.org/en/rules/ATR-2026-02351) | high | production | SSRF to Cloud Metadata Endpoint via Wildcard-DNS Hostname-Encoded IP (nip.io/sslip.io/xip.io/traefik.me) |
| [`ATR-2026-02373`](https://agentthreatrule.org/en/rules/ATR-2026-02373) | high | production | Deserialized LangSmith Prompt Manifest Combines secrets_from_env With an Attacker base_url Override |
| [`ATR-2026-02406`](https://agentthreatrule.org/en/rules/ATR-2026-02406) | critical | production | MCP Tool Sequential Integer ID Enumeration (Cross-Tenant IDOR, CVE-2026-54052) |
| [`ATR-2026-02570`](https://agentthreatrule.org/en/rules/ATR-2026-02570) | critical | production | Wallet Secret Material (Seed Phrase / Private Key) Carried Inside an MCP Tool Payload |
| [`ATR-2026-02602`](https://agentthreatrule.org/en/rules/ATR-2026-02602) | high | production | Diagram Theme Config Used to Inject Page-Wide CSS (scope escape, overlay, selector exfil) |
| [`ATR-2026-02608`](https://agentthreatrule.org/en/rules/ATR-2026-02608) | high | production | LLM-Generated Graph Query Reaching a Remote Endpoint (APOC remote script, raw-IP load, remote export) |
| [`ATR-2026-02621`](https://agentthreatrule.org/en/rules/ATR-2026-02621) | high | production | Prompt-Embedded Auto-Fetch Mention Pointed at an Internal Address |
| [`ATR-2026-02623`](https://agentthreatrule.org/en/rules/ATR-2026-02623) | high | production | Dangerous URI Scheme Obfuscated by Interstitial Characters |
| [`ATR-2026-02649`](https://agentthreatrule.org/en/rules/ATR-2026-02649) | high | production | Vendor API Hostname Used as a Label Prefix of Another Domain |
| [`ATR-2026-02684`](https://agentthreatrule.org/en/rules/ATR-2026-02684) | high | production | File-Tool Argument Targets a Modern Credential Store Outside the Classic Path List |
| [`ATR-2026-02703`](https://agentthreatrule.org/en/rules/ATR-2026-02703) | high | production | Agent-Generated SQL Reaches Outside the Database via COPY TO PROGRAM or a Server-Side File Read |
| [`CORDON-ATR-0001`](https://github.com/Threx-code/cordon/blob/v0.6.0/scripts/data/cordon-atr-rules.yaml#CORDON-ATR-0001) | high | production | Context exfiltration instruction in Spanish, French, German, Portuguese or Italian |
| [`CORDON-ATR-0003`](https://github.com/Threx-code/cordon/blob/v0.6.0/scripts/data/cordon-atr-rules.yaml#CORDON-ATR-0003) | high | production | Exfiltration or disclosure keyword split by stray spaces to slip past matching |

### Data poisoning

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00070`](https://agentthreatrule.org/en/rules/ATR-2026-00070) | high | warn | Data Poisoning via RAG and Knowledge Base Contamination |
| [`ATR-2026-00073`](https://agentthreatrule.org/en/rules/ATR-2026-00073) | critical | production | Malicious Fine-tuning Data |
| [`ATR-2026-00450`](https://agentthreatrule.org/en/rules/ATR-2026-00450) | high | production | Spring AI PromptChatMemoryAdvisor Memory Poisoning (CVE-2026-41713) |
| [`ATR-2026-00570`](https://agentthreatrule.org/en/rules/ATR-2026-00570) | high | production | SQL injection in agent / MCP tool database query |
| [`ATR-2026-01155`](https://agentthreatrule.org/en/rules/ATR-2026-01155) | medium | production | Direct Memory Plant Command — Persistent Fact or Code Storage Injection |
| [`ATR-2026-01774`](https://agentthreatrule.org/en/rules/ATR-2026-01774) | high | production | RAG & Memory Poisoning — Embedded Directives, Trigger Tokens, False Authority & Coercion (Semantic) |
| [`ATR-2026-02143`](https://agentthreatrule.org/en/rules/ATR-2026-02143) | high | production | Cypher/Graph-Query Injection via Unsanitized node_labels or group_ids Field |
| [`ATR-2026-02144`](https://agentthreatrule.org/en/rules/ATR-2026-02144) | high | production | Stored External Data Reframes Itself as an Administrative Request to Hijack System Prompt |
| [`ATR-2026-02303`](https://agentthreatrule.org/en/rules/ATR-2026-02303) | high | production | KQL/Kusto Pipe-Chain Injection via Table-Name Parameter in a 'Safe' Metadata Tool |
| [`ATR-2026-02408`](https://agentthreatrule.org/en/rules/ATR-2026-02408) | high | production | Dataset / Model Loader Remote-Code Execution via Poisoned Dataset Artifact |

### Excessive autonomy

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00050`](https://agentthreatrule.org/en/rules/ATR-2026-00050) | high | warn | Runaway Agent Loop Detection |
| [`ATR-2026-00051`](https://agentthreatrule.org/en/rules/ATR-2026-00051) | high | warn | Agent Resource Exhaustion Detection |
| [`ATR-2026-00052`](https://agentthreatrule.org/en/rules/ATR-2026-00052) | high | production | Cascading Failure Detection in Agent Pipelines |
| [`ATR-2026-00098`](https://agentthreatrule.org/en/rules/ATR-2026-00098) | critical | warn | Unauthorized Financial Action by AI Agent |
| [`ATR-2026-00099`](https://agentthreatrule.org/en/rules/ATR-2026-00099) | low | observe | High-Risk Tool Invocation Without Human Confirmation |
| [`ATR-2026-00428`](https://agentthreatrule.org/en/rules/ATR-2026-00428) | critical | production | Natural-Language Unauthorized Shell-Execution Instruction |
| [`ATR-2026-00491`](https://agentthreatrule.org/en/rules/ATR-2026-00491) | high | production | Agent Capability Enumeration via Structured Parse Request |
| [`ATR-2026-00500`](https://agentthreatrule.org/en/rules/ATR-2026-00500) | critical | production | SSRF via Agent URL Fetch Instruction |
| [`ATR-2026-00708`](https://agentthreatrule.org/en/rules/ATR-2026-00708) | critical | production | Indirect PI — Unauthorized Financial Transfer via Agent Tool |
| [`ATR-2026-00709`](https://agentthreatrule.org/en/rules/ATR-2026-00709) | critical | production | Indirect PI — Disable Authentication / MFA via Agent Tool |
| [`ATR-2026-00710`](https://agentthreatrule.org/en/rules/ATR-2026-00710) | critical | production | Indirect PI — Unauthorized Physical Access Grant via Smart Lock / Home Automation |
| [`ATR-2026-00711`](https://agentthreatrule.org/en/rules/ATR-2026-00711) | critical | production | Indirect PI — System Sabotage via Destructive Shell Command |
| [`ATR-2026-00712`](https://agentthreatrule.org/en/rules/ATR-2026-00712) | critical | production | Indirect PI — Malicious Package Installation via Agent (pip/npm) |
| [`ATR-2026-00713`](https://agentthreatrule.org/en/rules/ATR-2026-00713) | critical | production | Indirect PI — RCE via Network Shell Command (netcat/curl) Execution |
| [`ATR-2026-00716`](https://agentthreatrule.org/en/rules/ATR-2026-00716) | high | production | Indirect PI — Data Destruction Instruction via Agent File/Document Tool |
| [`ATR-2026-00718`](https://agentthreatrule.org/en/rules/ATR-2026-00718) | high | production | Tool Misuse — Autonomous Financial Trading / Crypto Transaction Without Authorization |
| [`ATR-2026-00719`](https://agentthreatrule.org/en/rules/ATR-2026-00719) | high | production | Tool Misuse — Destructive Bulk Action via Agent (Delete All / Turn Off All) |
| [`ATR-2026-00722`](https://agentthreatrule.org/en/rules/ATR-2026-00722) | critical | production | Indirect PI — Account Manipulation / Emergency Service Dispatch via Pretext |
| [`ATR-2026-01751`](https://agentthreatrule.org/en/rules/ATR-2026-01751) | high | production | Indirect Prompt Injection: Fake-Authority Task Abort |
| [`ATR-2026-01752`](https://agentthreatrule.org/en/rules/ATR-2026-01752) | high | production | Indirect Prompt Injection: CAPTCHA Redirect Task Disruption |
| [`ATR-2026-01773`](https://agentthreatrule.org/en/rules/ATR-2026-01773) | high | production | Excessive Agency — Scope Hijack, Untrusted Code Execution & Unauthorized Privilege Grant (Semantic) |
| [`ATR-2026-01801`](https://agentthreatrule.org/en/rules/ATR-2026-01801) | critical | production | Autonomous-Vehicle Cyber-Physical Sabotage — Brake/Steering/Sensor Subversion Command |
| [`ATR-2026-01804`](https://agentthreatrule.org/en/rules/ATR-2026-01804) | high | production | Covert Unlogged Action — Directive to Hide an Action from Records or Detection |
| [`ATR-2026-01805`](https://agentthreatrule.org/en/rules/ATR-2026-01805) | high | production | Financial Fraud Execution — Ponzi Setup, Fabricated Statements, Unauthorized Redirect & Laundering |
| [`ATR-2026-01806`](https://agentthreatrule.org/en/rules/ATR-2026-01806) | critical | production | Clinical Patient-Harm Directive — Overdose, Falsified Diagnosis, Phantom Billing & Care Neglect |
| [`ATR-2026-01809`](https://agentthreatrule.org/en/rules/ATR-2026-01809) | high | production | Insider Manipulation & Process Corruption — Market/Data Tampering, Legal-Process Subversion & Pretextual Fund Movement (Semantic) |
| [`ATR-2026-01837`](https://agentthreatrule.org/en/rules/ATR-2026-01837) | critical | production | DDoS Attack Orchestration |
| [`ATR-2026-01838`](https://agentthreatrule.org/en/rules/ATR-2026-01838) | high | production | Unauthorized Cryptominer Deployment via SSH |
| [`ATR-2026-01849`](https://agentthreatrule.org/en/rules/ATR-2026-01849) | high | production | Targeted Harassment Bot Deployment |
| [`ATR-2026-01989`](https://agentthreatrule.org/en/rules/ATR-2026-01989) | high | production | Agent-Initiated Internal Network Service Sweep |
| [`ATR-2026-01993`](https://agentthreatrule.org/en/rules/ATR-2026-01993) | high | production | Agent Disabling of Host Security Controls |
| [`ATR-2026-01994`](https://agentthreatrule.org/en/rules/ATR-2026-01994) | high | production | Agent Establishing an Encrypted Reverse Channel or Tunnel |
| [`ATR-2026-02106`](https://agentthreatrule.org/en/rules/ATR-2026-02106) | high | production | Catastrophic-Backtracking Regex Payload in a Search/Query Tool Argument |
| [`ATR-2026-02400`](https://agentthreatrule.org/en/rules/ATR-2026-02400) | high | production | Agent Human-Approval Gate Programmatically Disabled at Runtime (YOLO / auto-approve) |
| [`ATR-2026-02401`](https://agentthreatrule.org/en/rules/ATR-2026-02401) | critical | production | Rogue Agent Provisioning: Mass Connector Grant with Approval Disabled and Recurring Schedule (AgentForger) |
| [`ATR-2026-02409`](https://agentthreatrule.org/en/rules/ATR-2026-02409) | high | production | MCP 2026-07-28 Stateless Spec: Async Task Abuse and OAuth 2.1 Misuse |
| [`ATR-2026-02525`](https://agentthreatrule.org/en/rules/ATR-2026-02525) | high | production | Shell Command-Word Reassembly via Parameter Expansion |
| [`ATR-2026-02641`](https://agentthreatrule.org/en/rules/ATR-2026-02641) | high | production | Client-Supplied Approver Identity on an Approval Decision |
| [`ATR-2026-02667`](https://agentthreatrule.org/en/rules/ATR-2026-02667) | high | production | Submitted Job Payload Carries Its Own Pre-Approved Tool List |
| [`CORDON-ATR-0002`](https://github.com/Threx-code/cordon/blob/v0.6.0/scripts/data/cordon-atr-rules.yaml#CORDON-ATR-0002) | high | production | Instruction to act without the user's confirmation, in Spanish, French, German, Portuguese or Italian |

### Model abuse

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00072`](https://agentthreatrule.org/en/rules/ATR-2026-00072) | critical | production | Model Behavior Extraction |
| [`ATR-2026-00279`](https://agentthreatrule.org/en/rules/ATR-2026-00279) | medium | production | Harmful Completion / Continuation Attack |
| [`ATR-2026-00281`](https://agentthreatrule.org/en/rules/ATR-2026-00281) | high | production | EICAR / GTUBE AV Test Signature Output Request |
| [`ATR-2026-00284`](https://agentthreatrule.org/en/rules/ATR-2026-00284) | medium | production | Glitch Token Destabilization Attack |
| [`ATR-2026-00289`](https://agentthreatrule.org/en/rules/ATR-2026-00289) | high | production | LMRC Harmful Content Elicitation — Quack Medicine, Bullying, Slur Usage |
| [`ATR-2026-00292`](https://agentthreatrule.org/en/rules/ATR-2026-00292) | critical | production | Self-Harm and Eating Disorder Facilitation Request |
| [`ATR-2026-00298`](https://agentthreatrule.org/en/rules/ATR-2026-00298) | critical | production | DoNotAnswer Malicious Use — Illegal Activity Facilitation Request |
| [`ATR-2026-00299`](https://agentthreatrule.org/en/rules/ATR-2026-00299) | critical | production | HarmBench Detailed Harmful Instruction Request — Step-by-Step Attack Facilitation |
| [`ATR-2026-00413`](https://agentthreatrule.org/en/rules/ATR-2026-00413) | critical | production | Malware Code Generation Direct Request |
| [`ATR-2026-00433`](https://agentthreatrule.org/en/rules/ATR-2026-00433) | critical | production | ModelCache torch.load() Deserialization RCE (CVE-2025-45146) |
| [`ATR-2026-00502`](https://agentthreatrule.org/en/rules/ATR-2026-00502) | medium | production | Training Data Extraction via Divergent Repetition Attack |
| [`ATR-2026-00517`](https://agentthreatrule.org/en/rules/ATR-2026-00517) | medium | production | Model Extraction / Distillation Attack via Systematic API Probing |
| [`ATR-2026-01750`](https://agentthreatrule.org/en/rules/ATR-2026-01750) | high | production | DoS via Repeat-Word-N-Times Output Amplification |
| [`ATR-2026-01760`](https://agentthreatrule.org/en/rules/ATR-2026-01760) | high | production | DoS: Forced Infinite / Maximum-Length Output Token Flood |
| [`ATR-2026-01830`](https://agentthreatrule.org/en/rules/ATR-2026-01830) | critical | production | Stolen-Credential Account Takeover & Crypto Drain |
| [`ATR-2026-01831`](https://agentthreatrule.org/en/rules/ATR-2026-01831) | critical | production | Money Laundering — Crypto Wallet Layering |
| [`ATR-2026-01833`](https://agentthreatrule.org/en/rules/ATR-2026-01833) | critical | production | Darknet Controlled-Substance Procurement |
| [`ATR-2026-01834`](https://agentthreatrule.org/en/rules/ATR-2026-01834) | critical | production | Fraudulent Identity Document (Fake Passport) Procurement |
| [`ATR-2026-01835`](https://agentthreatrule.org/en/rules/ATR-2026-01835) | critical | production | Human-Trafficking Service Facilitation |
| [`ATR-2026-01836`](https://agentthreatrule.org/en/rules/ATR-2026-01836) | critical | production | Trojanized Software Distribution |
| [`ATR-2026-01840`](https://agentthreatrule.org/en/rules/ATR-2026-01840) | critical | production | Extremist Propaganda Acquisition & Distribution |
| [`ATR-2026-01841`](https://agentthreatrule.org/en/rules/ATR-2026-01841) | high | production | Deepfake of Real Person for Disinformation |
| [`ATR-2026-01842`](https://agentthreatrule.org/en/rules/ATR-2026-01842) | medium | production | Plagiarism-Detector Evasion & Republishing |
| [`ATR-2026-01843`](https://agentthreatrule.org/en/rules/ATR-2026-01843) | high | production | Drug Dealing via Reverse-Spelling Detection Evasion |
| [`ATR-2026-01844`](https://agentthreatrule.org/en/rules/ATR-2026-01844) | high | production | Illegitimate Prescription Fulfillment |
| [`ATR-2026-01845`](https://agentthreatrule.org/en/rules/ATR-2026-01845) | high | production | Banned-Ingredient Product Relabel Fraud |
| [`ATR-2026-01846`](https://agentthreatrule.org/en/rules/ATR-2026-01846) | medium | production | Tax Evasion via Offshore Accounts & Shell Companies |
| [`ATR-2026-01847`](https://agentthreatrule.org/en/rules/ATR-2026-01847) | medium | production | Immigration / Visa Work Fraud |
| [`ATR-2026-01848`](https://agentthreatrule.org/en/rules/ATR-2026-01848) | high | production | Anonymous Illicit-Drug Marketplace Construction |
| [`ATR-2026-01850`](https://agentthreatrule.org/en/rules/ATR-2026-01850) | high | production | Targeted Doxxing & Threat Campaign |
| [`ATR-2026-01851`](https://agentthreatrule.org/en/rules/ATR-2026-01851) | critical | production | Bestiality Content Acquisition & Distribution |
| [`ATR-2026-01852`](https://agentthreatrule.org/en/rules/ATR-2026-01852) | high | production | Romance-Scam Sexual Impersonation |
| [`ATR-2026-01853`](https://agentthreatrule.org/en/rules/ATR-2026-01853) | high | production | Non-Consensual Leaked-Media Purchase & Distribution |
| [`ATR-2026-01854`](https://agentthreatrule.org/en/rules/ATR-2026-01854) | medium | production | Falsified Research Abstract Disinformation |
| [`ATR-2026-01855`](https://agentthreatrule.org/en/rules/ATR-2026-01855) | medium | production | Content Misappropriation & Republishing as Own |
| [`ATR-2026-01856`](https://agentthreatrule.org/en/rules/ATR-2026-01856) | high | production | Targeted Harmful Content Generation Against People or Protected Groups (Semantic) |
| [`ATR-2026-01896`](https://agentthreatrule.org/en/rules/ATR-2026-01896) | critical | production | Injected Code — Remote-Key Ransomware File Encryption |
| [`ATR-2026-01897`](https://agentthreatrule.org/en/rules/ATR-2026-01897) | critical | production | Injected Code — Local Host Sabotage (Filesystem Destruction / Resource Exhaustion / Hosts Tamper) |
| [`ATR-2026-01898`](https://agentthreatrule.org/en/rules/ATR-2026-01898) | high | production | Injected Code — Network Denial of Service (Connection Kill / Adapter Disable / Flood) |
| [`ATR-2026-02211`](https://agentthreatrule.org/en/rules/ATR-2026-02211) | critical | production | Named Dangerous-Substance Synthesis or Delivery Instruction Request (Non-Step-By-Step Phrasing) |
| [`ATR-2026-02411`](https://agentthreatrule.org/en/rules/ATR-2026-02411) | medium | production | Targeted Stripping of C2PA / IPTC AI-Provenance Metadata from Generated Media |
| [`ATR-2026-02412`](https://agentthreatrule.org/en/rules/ATR-2026-02412) | medium | production | Generative Watermark Removal Tooling (SynthID / StableSignature / TreeRing / StegaStamp) |
| [`ATR-2026-02413`](https://agentthreatrule.org/en/rules/ATR-2026-02413) | medium | production | AI Text Detection Evasion via Humanizer Services and Watermark-Scrubbing Paraphrase |

### Model security

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-02662`](https://agentthreatrule.org/en/rules/ATR-2026-02662) | critical | production | Pickle Payload Reaches an Execution Primitive Through an Indirect Name Resolver |

### Privilege escalation

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00040`](https://agentthreatrule.org/en/rules/ATR-2026-00040) | critical | observe | Privilege Escalation and Admin Function Access |
| [`ATR-2026-00041`](https://agentthreatrule.org/en/rules/ATR-2026-00041) | medium | production | Agent Scope Creep Detection |
| [`ATR-2026-00064`](https://agentthreatrule.org/en/rules/ATR-2026-00064) | high | observe | Over-Permissioned MCP Skill |
| [`ATR-2026-00107`](https://agentthreatrule.org/en/rules/ATR-2026-00107) | high | production | Privilege Escalation via Delayed Task Execution Bypass |
| [`ATR-2026-00110`](https://agentthreatrule.org/en/rules/ATR-2026-00110) | critical | warn | Remote Code Execution via eval() and Dynamic Code Injection |
| [`ATR-2026-00111`](https://agentthreatrule.org/en/rules/ATR-2026-00111) | critical | observe | Shell Metacharacter Injection in Tool Arguments |
| [`ATR-2026-00112`](https://agentthreatrule.org/en/rules/ATR-2026-00112) | high | warn | Dynamic Module Loading for Code Execution |
| [`ATR-2026-00143`](https://agentthreatrule.org/en/rules/ATR-2026-00143) | high | production | Casual Unauthorized Privilege Escalation |
| [`ATR-2026-00144`](https://agentthreatrule.org/en/rules/ATR-2026-00144) | high | production | Rationalized Safety Control Bypass |
| [`ATR-2026-00156`](https://agentthreatrule.org/en/rules/ATR-2026-00156) | high | production | SSH Remote Command Execution with Credential Exposure |
| [`ATR-2026-00204`](https://agentthreatrule.org/en/rules/ATR-2026-00204) | high | production | Stealth Execution and Persistence Mechanisms |
| [`ATR-2026-00436`](https://agentthreatrule.org/en/rules/ATR-2026-00436) | critical | production | Enclave VM Sandbox Escape RCE (CVE-2026-27597) |
| [`ATR-2026-00441`](https://agentthreatrule.org/en/rules/ATR-2026-00441) | critical | production | Microsoft Semantic Kernel SessionsPythonPlugin Arbitrary File Write + Startup Persistence (CVE-2026-25592) |
| [`ATR-2026-00451`](https://agentthreatrule.org/en/rules/ATR-2026-00451) | critical | production | LiteLLM Proxy Authorization-Header SQL Injection — CISA KEV (CVE-2026-42208) |
| [`ATR-2026-00528`](https://agentthreatrule.org/en/rules/ATR-2026-00528) | critical | production | PraisonAI-Style Auth-Disabled-By-Default Configuration (CVE-2026-44338 family) |
| [`ATR-2026-00539`](https://agentthreatrule.org/en/rules/ATR-2026-00539) | critical | production | CrewAI CodeInterpreterTool Sandbox Escape and Prompt-to-Shell RCE (CVE-2026-2275 / VU#221883) |
| [`ATR-2026-00546`](https://agentthreatrule.org/en/rules/ATR-2026-00546) | high | production | CrewAI JSON Loader Arbitrary Local File Read (CVE-2026-2285) |
| [`ATR-2026-00547`](https://agentthreatrule.org/en/rules/ATR-2026-00547) | high | production | CrewAI RAG URL Validation Bypass SSRF (CVE-2026-2286) |
| [`ATR-2026-01600`](https://agentthreatrule.org/en/rules/ATR-2026-01600) | critical | production | SQL Injection Tautology RBAC Bypass |
| [`ATR-2026-01601`](https://agentthreatrule.org/en/rules/ATR-2026-01601) | critical | production | SQL Injection Destructive DDL Statement |
| [`ATR-2026-01602`](https://agentthreatrule.org/en/rules/ATR-2026-01602) | critical | production | SQL Injection UNION SELECT Data Exfiltration |
| [`ATR-2026-01603`](https://agentthreatrule.org/en/rules/ATR-2026-01603) | critical | production | SQL Injection Stacked DML Privilege Abuse |
| [`ATR-2026-01604`](https://agentthreatrule.org/en/rules/ATR-2026-01604) | high | production | SQL Injection Information Schema Enumeration |
| [`ATR-2026-01609`](https://agentthreatrule.org/en/rules/ATR-2026-01609) | critical | production | Shell Injection Env Exfiltration via Curl/Wget/Netcat Webhook |
| [`ATR-2026-01610`](https://agentthreatrule.org/en/rules/ATR-2026-01610) | high | observe | Shell Evasion Subshell and Command Substitution Injection |
| [`ATR-2026-01611`](https://agentthreatrule.org/en/rules/ATR-2026-01611) | high | production | Shell Evasion Eval and Language-Level Exec Injection |
| [`ATR-2026-01612`](https://agentthreatrule.org/en/rules/ATR-2026-01612) | high | production | Debug or Admin Mode Activation for Privilege Escalation |
| [`ATR-2026-01613`](https://agentthreatrule.org/en/rules/ATR-2026-01613) | high | production | RBAC Bypass via Social Engineering (Semantic) |
| [`ATR-2026-01614`](https://agentthreatrule.org/en/rules/ATR-2026-01614) | high | production | BOLA Cross-User Data Access Attempt (Semantic) |
| [`ATR-2026-01615`](https://agentthreatrule.org/en/rules/ATR-2026-01615) | critical | production | Sandbox Escape via Shell Metacharacter Command Injection |
| [`ATR-2026-01616`](https://agentthreatrule.org/en/rules/ATR-2026-01616) | high | production | Path Traversal in Agent File Access Requests |
| [`ATR-2026-01802`](https://agentthreatrule.org/en/rules/ATR-2026-01802) | critical | production | Covert Backdoor / Surveillance Implant via Software Update |
| [`ATR-2026-01803`](https://agentthreatrule.org/en/rules/ATR-2026-01803) | critical | production | Covert Server Intrusion — Process Injection, Log Tampering, DNS Hijack & Traffic Interception |
| [`ATR-2026-01808`](https://agentthreatrule.org/en/rules/ATR-2026-01808) | high | production | Synthetic-PAN Payment Probe — Test Credit-Card Data Submitted to a Live Payment System |
| [`ATR-2026-01899`](https://agentthreatrule.org/en/rules/ATR-2026-01899) | critical | production | Injected Code — Unauthorized Remote Access (SSH Key Backdoor / Tunnel / Port Forward) |
| [`ATR-2026-01933`](https://agentthreatrule.org/en/rules/ATR-2026-01933) | critical | production | LiteLLM User-Role Privilege Escalation (CVE-2026-47102) |
| [`ATR-2026-01934`](https://agentthreatrule.org/en/rules/ATR-2026-01934) | critical | production | LiteLLM allowed_routes Authorization Bypass (CVE-2026-47101) |
| [`ATR-2026-01949`](https://agentthreatrule.org/en/rules/ATR-2026-01949) | critical | production | PraisonAI MCPServer Unauthenticated HTTP tools/call Authentication Bypass (GHSA-j4f3-55x4-r6q2) |
| [`ATR-2026-01974`](https://agentthreatrule.org/en/rules/ATR-2026-01974) | critical | production | AnythingLLM unauthenticated /system/data-import access control bypass (CVE-2024-3279) |
| [`ATR-2026-01981`](https://agentthreatrule.org/en/rules/ATR-2026-01981) | high | production | Network-AI ApprovalInbox Unauthenticated Cross-Origin Approval Bypass (GHSA-mxjx-28vx-xjjj) |
| [`ATR-2026-01986`](https://agentthreatrule.org/en/rules/ATR-2026-01986) | critical | production | Windows-MCP Unauthenticated HTTP PowerShell via Wildcard CORS (CVE-2026-48989) |
| [`ATR-2026-01992`](https://agentthreatrule.org/en/rules/ATR-2026-01992) | critical | production | Agent Weakening of Host Authentication Configuration |
| [`ATR-2026-02040`](https://agentthreatrule.org/en/rules/ATR-2026-02040) | critical | production | Arbitrary Write to SSH Authorized Keys or Shell Startup File via Unvalidated File-Edit Tool |
| [`ATR-2026-02100`](https://agentthreatrule.org/en/rules/ATR-2026-02100) | critical | production | LLM-Generated Cypher Query Injection with Destructive or Administrative Operations |
| [`ATR-2026-02101`](https://agentthreatrule.org/en/rules/ATR-2026-02101) | critical | production | Python Sandbox Escape via Dynamically-Constructed Dunder Attribute Chain |
| [`ATR-2026-02123`](https://agentthreatrule.org/en/rules/ATR-2026-02123) | high | production | Authentication Bypass via Bare Query-String Path-Confusion Suffix |
| [`ATR-2026-02142`](https://agentthreatrule.org/en/rules/ATR-2026-02142) | high | production | Download/Attachment Tool Directed to Write Outside Its Sandbox via Absolute-Path Filename |
| [`ATR-2026-02146`](https://agentthreatrule.org/en/rules/ATR-2026-02146) | critical | production | Export/Extract Tool Directory Parameter Redirected to a Credential Directory |
| [`ATR-2026-02192`](https://agentthreatrule.org/en/rules/ATR-2026-02192) | high | production | Agent Self-Modifying Its Own Trust/Approval Configuration to a Wildcard |
| [`ATR-2026-02195`](https://agentthreatrule.org/en/rules/ATR-2026-02195) | critical | production | Dangerous Process-Hijacking Environment Variable Injected via Config/Env-Update Tool |
| [`ATR-2026-02251`](https://agentthreatrule.org/en/rules/ATR-2026-02251) | high | production | Multi-Tenant Identifier Field (sender_id/owner_id/tenant_id) Carries Path Traversal Into a Storage Write |
| [`ATR-2026-02300`](https://agentthreatrule.org/en/rules/ATR-2026-02300) | high | production | MCP Stdio Server Config env Block Sets Dangerous Process-Hijacking Environment Variable |
| [`ATR-2026-02301`](https://agentthreatrule.org/en/rules/ATR-2026-02301) | high | production | Symlink Command Targets Sensitive Credential Path Outside the Workspace (Sandbox Escape Primitive) |
| [`ATR-2026-02302`](https://agentthreatrule.org/en/rules/ATR-2026-02302) | high | production | Git Worktree Created With Reserved Name .git (Directory-Confusion Sandbox Escape) |
| [`ATR-2026-02353`](https://agentthreatrule.org/en/rules/ATR-2026-02353) | high | production | Agent-Runtime Identifier Field (run_id/agent_id/session_id/task_id) Carries Path Traversal Into a History/Log File Read |
| [`ATR-2026-02370`](https://agentthreatrule.org/en/rules/ATR-2026-02370) | high | production | SSH/SCP MCP Tool hostAlias Argument Carries an OpenSSH Option-Injection Flag |
| [`ATR-2026-02371`](https://agentthreatrule.org/en/rules/ATR-2026-02371) | critical | production | Browser-Automation Tool Launch-Args Field Carries a Chromium Command-Replacing Switch |
| [`ATR-2026-02402`](https://agentthreatrule.org/en/rules/ATR-2026-02402) | high | production | MCP Server Security Policy Fail-Open on Initialization Failure (CVE-2026-16584) |
| [`ATR-2026-02404`](https://agentthreatrule.org/en/rules/ATR-2026-02404) | critical | production | Mobile GUI Agent Model Output Reaching Host Shell / ADB Unsanitized |
| [`ATR-2026-02407`](https://agentthreatrule.org/en/rules/ATR-2026-02407) | critical | production | Agent Workspace Boundary Escape via Host-Root Mount and Unprivileged Namespace Escalation (CVE-2026-46331) |
| [`ATR-2026-02528`](https://agentthreatrule.org/en/rules/ATR-2026-02528) | high | production | Option-Flag Smuggling in an LLM-Controlled Tool Parameter |
| [`ATR-2026-02530`](https://agentthreatrule.org/en/rules/ATR-2026-02530) | high | production | Git Configuration Turned Into an Execution Hook by an Agent |
| [`ATR-2026-02531`](https://agentthreatrule.org/en/rules/ATR-2026-02531) | high | production | Kusto Pipeline Injection Through a Table Identifier Parameter |
| [`ATR-2026-02601`](https://agentthreatrule.org/en/rules/ATR-2026-02601) | high | production | Argument Injection: Execution-Bearing CLI Option Smuggled into a Tool Data Parameter |
| [`ATR-2026-02620`](https://agentthreatrule.org/en/rules/ATR-2026-02620) | high | production | Code Execution via data: URI Module Specifier Handed to import() |
| [`ATR-2026-02626`](https://agentthreatrule.org/en/rules/ATR-2026-02626) | high | production | Agent Writes a New MCP Server Into Its Own Trust Configuration |
| [`ATR-2026-02627`](https://agentthreatrule.org/en/rules/ATR-2026-02627) | critical | production | Web Shell Written Into a Web-Served Directory |
| [`ATR-2026-02642`](https://agentthreatrule.org/en/rules/ATR-2026-02642) | critical | production | Agent Configuration Tool Used to Disable the Agent's Own Guardrail |
| [`ATR-2026-02644`](https://agentthreatrule.org/en/rules/ATR-2026-02644) | high | production | Image-Header Polyglot: Magic Bytes Adjacent to a Server-Side Script Payload |
| [`ATR-2026-02648`](https://agentthreatrule.org/en/rules/ATR-2026-02648) | high | production | Write or Fetch Procedure Called Through a Read-Only Graph Query Tool |
| [`ATR-2026-02664`](https://agentthreatrule.org/en/rules/ATR-2026-02664) | high | production | Git Identifier Field Carries an Option or ext:: Transport Instead of a Revision |
| [`ATR-2026-02681`](https://agentthreatrule.org/en/rules/ATR-2026-02681) | critical | production | JavaScript Sandbox Escape by Acquiring the Function Constructor Reflectively |
| [`ATR-2026-02683`](https://agentthreatrule.org/en/rules/ATR-2026-02683) | high | production | Agent Tool Data Argument Carries a Program-Executing CLI Option |
| [`ATR-2026-02700`](https://agentthreatrule.org/en/rules/ATR-2026-02700) | high | production | Percent-Encoded Path Traversal in an Agent File-Tool Argument |
| [`ATR-2026-02705`](https://agentthreatrule.org/en/rules/ATR-2026-02705) | high | production | Python Sandbox Escape by Recovering builtins from a Bound Method or Lambda |
| [`ATR-2026-02708`](https://agentthreatrule.org/en/rules/ATR-2026-02708) | high | production | Agent HTTP Request Claims a Loopback Origin While Targeting an External Host |

### Prompt injection

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00001`](https://agentthreatrule.org/en/rules/ATR-2026-00001) | high | warn | Direct Prompt Injection via User Input |
| [`ATR-2026-00002`](https://agentthreatrule.org/en/rules/ATR-2026-00002) | high | production | Indirect Prompt Injection via External Content |
| [`ATR-2026-00003`](https://agentthreatrule.org/en/rules/ATR-2026-00003) | high | production | Jailbreak Attempt Detection |
| [`ATR-2026-00004`](https://agentthreatrule.org/en/rules/ATR-2026-00004) | critical | warn | System Prompt Override Attempt |
| [`ATR-2026-00005`](https://agentthreatrule.org/en/rules/ATR-2026-00005) | medium | production | Multi-Turn Prompt Injection |
| [`ATR-2026-00080`](https://agentthreatrule.org/en/rules/ATR-2026-00080) | high | production | Encoding-Based Prompt Injection Evasion |
| [`ATR-2026-00081`](https://agentthreatrule.org/en/rules/ATR-2026-00081) | critical | production | Semantic Evasion via Multi-Turn Prompt Injection |
| [`ATR-2026-00082`](https://agentthreatrule.org/en/rules/ATR-2026-00082) | high | production | Behavioral Fingerprint Detection Evasion |
| [`ATR-2026-00083`](https://agentthreatrule.org/en/rules/ATR-2026-00083) | high | warn | Indirect Prompt Injection via Tool Responses |
| [`ATR-2026-00084`](https://agentthreatrule.org/en/rules/ATR-2026-00084) | high | production | Structured Data Injection via JSON/CSV Payloads |
| [`ATR-2026-00085`](https://agentthreatrule.org/en/rules/ATR-2026-00085) | high | production | Multi-Layer Security Audit Evasion |
| [`ATR-2026-00086`](https://agentthreatrule.org/en/rules/ATR-2026-00086) | high | production | Visual Spoofing via RTL Override, Punycode, and Homoglyph Injection |
| [`ATR-2026-00087`](https://agentthreatrule.org/en/rules/ATR-2026-00087) | medium | production | Detection Rule Probing and Evasion Testing |
| [`ATR-2026-00088`](https://agentthreatrule.org/en/rules/ATR-2026-00088) | high | production | Adaptive Countermeasure Against Behavioral Monitoring |
| [`ATR-2026-00089`](https://agentthreatrule.org/en/rules/ATR-2026-00089) | high | production | Polymorphic Skill and Capability Aliasing Attack |
| [`ATR-2026-00090`](https://agentthreatrule.org/en/rules/ATR-2026-00090) | high | production | Threat Intelligence Exfiltration and Rule Enumeration |
| [`ATR-2026-00091`](https://agentthreatrule.org/en/rules/ATR-2026-00091) | critical | production | Advanced Structured Data Injection with Nested Payloads |
| [`ATR-2026-00092`](https://agentthreatrule.org/en/rules/ATR-2026-00092) | critical | production | Multi-Agent Consensus Poisoning and Sybil Attack |
| [`ATR-2026-00093`](https://agentthreatrule.org/en/rules/ATR-2026-00093) | critical | production | Gradual Capability Escalation via Incremental Introduction |
| [`ATR-2026-00094`](https://agentthreatrule.org/en/rules/ATR-2026-00094) | critical | production | Systematic Multi-Layer Audit System Bypass |
| [`ATR-2026-00097`](https://agentthreatrule.org/en/rules/ATR-2026-00097) | critical | production | CJK Prompt Injection - Expanded Chinese/Japanese/Korean Patterns |
| [`ATR-2026-00104`](https://agentthreatrule.org/en/rules/ATR-2026-00104) | critical | production | Persona Hijacking via Mandatory System Prompt Override |
| [`ATR-2026-00130`](https://agentthreatrule.org/en/rules/ATR-2026-00130) | high | production | Indirect Authority Claim in External Content |
| [`ATR-2026-00131`](https://agentthreatrule.org/en/rules/ATR-2026-00131) | medium | production | Fictional and Academic Framing Attack |
| [`ATR-2026-00133`](https://agentthreatrule.org/en/rules/ATR-2026-00133) | high | warn | Paraphrased Prompt Injection |
| [`ATR-2026-00137`](https://agentthreatrule.org/en/rules/ATR-2026-00137) | high | production | Authority Claim Prompt Injection |
| [`ATR-2026-00138`](https://agentthreatrule.org/en/rules/ATR-2026-00138) | high | production | Fictional Framing Safety Bypass |
| [`ATR-2026-00140`](https://agentthreatrule.org/en/rules/ATR-2026-00140) | high | production | Indirect Reference Instruction Reversal |
| [`ATR-2026-00148`](https://agentthreatrule.org/en/rules/ATR-2026-00148) | high | warn | Multilingual Prompt Injection via Language Switch |
| [`ATR-2026-00155`](https://agentthreatrule.org/en/rules/ATR-2026-00155) | high | production | Hidden LLM Instructions in Skill Descriptions |
| [`ATR-2026-00163`](https://agentthreatrule.org/en/rules/ATR-2026-00163) | high | production | Hidden Override Instructions in Skill Content |
| [`ATR-2026-00202`](https://agentthreatrule.org/en/rules/ATR-2026-00202) | high | production | Encoding Evasion via Homoglyphs and Synonym Substitution |
| [`ATR-2026-00203`](https://agentthreatrule.org/en/rules/ATR-2026-00203) | high | production | Context Pollution in Skill Descriptions |
| [`ATR-2026-00206`](https://agentthreatrule.org/en/rules/ATR-2026-00206) | high | production | Hidden System Instructions with Priority Override Blocks |
| [`ATR-2026-00207`](https://agentthreatrule.org/en/rules/ATR-2026-00207) | high | production | Hidden System Instructions with Permission Override |
| [`ATR-2026-00211`](https://agentthreatrule.org/en/rules/ATR-2026-00211) | high | production | System Prompt Override via Translation Context Injection |
| [`ATR-2026-00213`](https://agentthreatrule.org/en/rules/ATR-2026-00213) | high | warn | System Prompt Override Injection via MCP Tool |
| [`ATR-2026-00226`](https://agentthreatrule.org/en/rules/ATR-2026-00226) | high | production | AI Identity Substitution Jailbreak |
| [`ATR-2026-00227`](https://agentthreatrule.org/en/rules/ATR-2026-00227) | high | production | Historical AI Persona Jailbreak with Compliance Enforcement |
| [`ATR-2026-00228`](https://agentthreatrule.org/en/rules/ATR-2026-00228) | high | production | Structured Dual-Response Jailbreak with Command System |
| [`ATR-2026-00229`](https://agentthreatrule.org/en/rules/ATR-2026-00229) | high | production | Roleplay-Based Policy Bypass Jailbreak |
| [`ATR-2026-00230`](https://agentthreatrule.org/en/rules/ATR-2026-00230) | high | production | Persona-Based Moral Constraint Removal Jailbreak |
| [`ATR-2026-00231`](https://agentthreatrule.org/en/rules/ATR-2026-00231) | high | production | AI Identity Substitution Jailbreak |
| [`ATR-2026-00233`](https://agentthreatrule.org/en/rules/ATR-2026-00233) | high | production | Structured Dual-Response Jailbreak with Command System |
| [`ATR-2026-00234`](https://agentthreatrule.org/en/rules/ATR-2026-00234) | high | production | Roleplay-Based Policy Bypass Jailbreak |
| [`ATR-2026-00236`](https://agentthreatrule.org/en/rules/ATR-2026-00236) | high | production | Pseudo-Code Structured Programming Jailbreak Attack |
| [`ATR-2026-00237`](https://agentthreatrule.org/en/rules/ATR-2026-00237) | high | warn | Dual-Response Jailbreak with Persona Commands |
| [`ATR-2026-00238`](https://agentthreatrule.org/en/rules/ATR-2026-00238) | high | production | AI Identity Denial and Persona Replacement Attack |
| [`ATR-2026-00239`](https://agentthreatrule.org/en/rules/ATR-2026-00239) | high | production | Amoral Persona Assignment with Obsessive Character Traits |
| [`ATR-2026-00240`](https://agentthreatrule.org/en/rules/ATR-2026-00240) | high | production | Previous Instruction Nullification and Identity Replacement Jailbreak |
| [`ATR-2026-00241`](https://agentthreatrule.org/en/rules/ATR-2026-00241) | high | production | Detailed Amoral Character Roleplay Jailbreak |
| [`ATR-2026-00242`](https://agentthreatrule.org/en/rules/ATR-2026-00242) | high | production | Dual-Response Persona Jailbreak with Emoji Formatting |
| [`ATR-2026-00243`](https://agentthreatrule.org/en/rules/ATR-2026-00243) | high | production | Acronym-Based Identity Override Jailbreak |
| [`ATR-2026-00244`](https://agentthreatrule.org/en/rules/ATR-2026-00244) | high | production | Dual-Response Persona Jailbreak |
| [`ATR-2026-00245`](https://agentthreatrule.org/en/rules/ATR-2026-00245) | high | production | Malicious Persona Creation for Safety Bypass |
| [`ATR-2026-00247`](https://agentthreatrule.org/en/rules/ATR-2026-00247) | high | production | Matrix-Themed Dual Response Jailbreak |
| [`ATR-2026-00249`](https://agentthreatrule.org/en/rules/ATR-2026-00249) | high | production | Text-Based Game Jailbreak with Entity Creation |
| [`ATR-2026-00251`](https://agentthreatrule.org/en/rules/ATR-2026-00251) | high | production | Embodiment Mechanism Jailbreak with Totalitarian Control Claims |
| [`ATR-2026-00252`](https://agentthreatrule.org/en/rules/ATR-2026-00252) | high | production | Narrative Jailbreak with Dual Response Formatting |
| [`ATR-2026-00253`](https://agentthreatrule.org/en/rules/ATR-2026-00253) | high | production | Enhanced AIM Jailbreak with Persona Definition and Refusal Suppression |
| [`ATR-2026-00256`](https://agentthreatrule.org/en/rules/ATR-2026-00256) | high | production | Base-N Encoding Instruction Bypass |
| [`ATR-2026-00257`](https://agentthreatrule.org/en/rules/ATR-2026-00257) | high | production | Cipher and Transposition Encoding Jailbreak |
| [`ATR-2026-00258`](https://agentthreatrule.org/en/rules/ATR-2026-00258) | high | production | Invisible Unicode Tag Character Injection |
| [`ATR-2026-00264`](https://agentthreatrule.org/en/rules/ATR-2026-00264) | high | warn | Latent Injection in Translation Context |
| [`ATR-2026-00265`](https://agentthreatrule.org/en/rules/ATR-2026-00265) | high | production | Latent Injection in Retrieved Document / RAG Context |
| [`ATR-2026-00267`](https://agentthreatrule.org/en/rules/ATR-2026-00267) | high | production | GCG Adversarial Suffix Attack |
| [`ATR-2026-00272`](https://agentthreatrule.org/en/rules/ATR-2026-00272) | high | production | Hypothetical Response / Function Masking Token Smuggling |
| [`ATR-2026-00276`](https://agentthreatrule.org/en/rules/ATR-2026-00276) | high | production | Invisible Unicode / BiDi Control Character Injection |
| [`ATR-2026-00278`](https://agentthreatrule.org/en/rules/ATR-2026-00278) | high | production | DRA Disguise and Reconstruction Attack |
| [`ATR-2026-00280`](https://agentthreatrule.org/en/rules/ATR-2026-00280) | critical | production | Policy Puppetry / XML Role-Config Injection |
| [`ATR-2026-00282`](https://agentthreatrule.org/en/rules/ATR-2026-00282) | high | production | Perez-Style Direct Prompt Injection Hijacking |
| [`ATR-2026-00285`](https://agentthreatrule.org/en/rules/ATR-2026-00285) | high | production | Alternate Encoding Jailbreak — Morse, NATO, Zalgo, Leet, UU, QP, Braille |
| [`ATR-2026-00286`](https://agentthreatrule.org/en/rules/ATR-2026-00286) | high | production | Latent Prompt Injection via Embedded Document or Report Context |
| [`ATR-2026-00296`](https://agentthreatrule.org/en/rules/ATR-2026-00296) | critical | production | Shell Command Injection via LLM Prompt |
| [`ATR-2026-00297`](https://agentthreatrule.org/en/rules/ATR-2026-00297) | critical | production | Python Code Execution / Remote Code Execution via LLM Prompt |
| [`ATR-2026-00308`](https://agentthreatrule.org/en/rules/ATR-2026-00308) | high | production | Zalgo Combining-Diacritic Overload Encoding |
| [`ATR-2026-00309`](https://agentthreatrule.org/en/rules/ATR-2026-00309) | high | production | Braille Unicode Encoded Prompt Injection |
| [`ATR-2026-00310`](https://agentthreatrule.org/en/rules/ATR-2026-00310) | high | production | Ecoji Emoji-Encoded Prompt Injection |
| [`ATR-2026-00311`](https://agentthreatrule.org/en/rules/ATR-2026-00311) | high | production | Base2048 Unicode Script Encoded Prompt Injection |
| [`ATR-2026-00312`](https://agentthreatrule.org/en/rules/ATR-2026-00312) | critical | production | Unicode Variation Selector ASCII Smuggling |
| [`ATR-2026-00313`](https://agentthreatrule.org/en/rules/ATR-2026-00313) | critical | production | SneakyBits Zero-Width Binary Steganography |
| [`ATR-2026-00315`](https://agentthreatrule.org/en/rules/ATR-2026-00315) | high | production | SATA Masked Language Model [MASK] Substitution Jailbreak |
| [`ATR-2026-00316`](https://agentthreatrule.org/en/rules/ATR-2026-00316) | high | production | FunctionMasking predict_mask Semantic Bypass |
| [`ATR-2026-00321`](https://agentthreatrule.org/en/rules/ATR-2026-00321) | critical | production | Hyphenated System Instruction Injection |
| [`ATR-2026-00359`](https://agentthreatrule.org/en/rules/ATR-2026-00359) | critical | production | Bank Phishing SMTP Email Code Generation |
| [`ATR-2026-00367`](https://agentthreatrule.org/en/rules/ATR-2026-00367) | high | production | Emoji Flag Regional-Indicator Encoded Hidden Phrase |
| [`ATR-2026-00373`](https://agentthreatrule.org/en/rules/ATR-2026-00373) | high | production | Piracy Torrent Site List Request |
| [`ATR-2026-00378`](https://agentthreatrule.org/en/rules/ATR-2026-00378) | high | production | ChatGPT DOM JavaScript Redirect and UI Spoofing Injection |
| [`ATR-2026-00382`](https://agentthreatrule.org/en/rules/ATR-2026-00382) | high | production | Cocaine Component Development Request |
| [`ATR-2026-00390`](https://agentthreatrule.org/en/rules/ATR-2026-00390) | high | production | Discord Quote-Format Explicit Sexual Content Poem Injection |
| [`ATR-2026-00394`](https://agentthreatrule.org/en/rules/ATR-2026-00394) | high | production | Backspace Deletion Character Injection |
| [`ATR-2026-00395`](https://agentthreatrule.org/en/rules/ATR-2026-00395) | critical | production | LLM Special Token Boundary Injection |
| [`ATR-2026-00396`](https://agentthreatrule.org/en/rules/ATR-2026-00396) | high | production | Toxic Continuation Prefix Injection |
| [`ATR-2026-00397`](https://agentthreatrule.org/en/rules/ATR-2026-00397) | medium | production | Snowball Impossible Reasoning Injection |
| [`ATR-2026-00399`](https://agentthreatrule.org/en/rules/ATR-2026-00399) | high | production | Latent Injection Document Separator Token |
| [`ATR-2026-00400`](https://agentthreatrule.org/en/rules/ATR-2026-00400) | high | production | Latent Injection Ignore-Instruction Keyword |
| [`ATR-2026-00401`](https://agentthreatrule.org/en/rules/ATR-2026-00401) | medium | production | Training Data Replay CLOZE [MASK] Elicitation |
| [`ATR-2026-00403`](https://agentthreatrule.org/en/rules/ATR-2026-00403) | medium | production | Glitch Token Repeat-Back Elicitation |
| [`ATR-2026-00407`](https://agentthreatrule.org/en/rules/ATR-2026-00407) | high | production | ECHO Admin Command / SQL Injection / Jinja SSTI Template Injection |
| [`ATR-2026-00408`](https://agentthreatrule.org/en/rules/ATR-2026-00408) | high | production | DRA Parenthesis Character Reconstruction Attack |
| [`ATR-2026-00409`](https://agentthreatrule.org/en/rules/ATR-2026-00409) | high | production | Phrasing Past/Future-Tense Harmful Query Bypass |
| [`ATR-2026-00410`](https://agentthreatrule.org/en/rules/ATR-2026-00410) | medium | production | LMRC Harm Category Direct Elicitation |
| [`ATR-2026-00412`](https://agentthreatrule.org/en/rules/ATR-2026-00412) | high | production | FigStep Image-List Multimodal Jailbreak Text Pattern |
| [`ATR-2026-00414`](https://agentthreatrule.org/en/rules/ATR-2026-00414) | medium | production | Continuation Ethnic Slur Completion Elicitation |
| [`ATR-2026-00420`](https://agentthreatrule.org/en/rules/ATR-2026-00420) | high | production | Microsoft Copilot Studio SharePoint Indirect Prompt Injection (CVE-2026-21520) |
| [`ATR-2026-00442`](https://agentthreatrule.org/en/rules/ATR-2026-00442) | medium | production | Quoted Exact-Output Forcing in User Input |
| [`ATR-2026-00443`](https://agentthreatrule.org/en/rules/ATR-2026-00443) | medium | production | Word-Fragment Concatenation Assembly Attack |
| [`ATR-2026-00444`](https://agentthreatrule.org/en/rules/ATR-2026-00444) | medium | production | Mathematical Bold / Fullwidth Unicode Obfuscation in User Input |
| [`ATR-2026-00445`](https://agentthreatrule.org/en/rules/ATR-2026-00445) | medium | production | Translation Hijack with Side-Output Instruction |
| [`ATR-2026-00446`](https://agentthreatrule.org/en/rules/ATR-2026-00446) | medium | production | Variable-Assignment Payload Injection in User Input |
| [`ATR-2026-00447`](https://agentthreatrule.org/en/rules/ATR-2026-00447) | medium | production | Fictional Generation Demand Containing Target Output |
| [`ATR-2026-00452`](https://agentthreatrule.org/en/rules/ATR-2026-00452) | medium | production | Direct PWNED Payload Injection in User Input |
| [`ATR-2026-00453`](https://agentthreatrule.org/en/rules/ATR-2026-00453) | high | production | Secret Key Reveal Demand in User Input |
| [`ATR-2026-00454`](https://agentthreatrule.org/en/rules/ATR-2026-00454) | medium | production | Backslash-Per-Character Encoding Attack |
| [`ATR-2026-00455`](https://agentthreatrule.org/en/rules/ATR-2026-00455) | low | production | No-Period Output Override Instruction |
| [`ATR-2026-00456`](https://agentthreatrule.org/en/rules/ATR-2026-00456) | medium | production | Conditional Empty-Input Payload Injection |
| [`ATR-2026-00457`](https://agentthreatrule.org/en/rules/ATR-2026-00457) | medium | production | Garak Dan - to every prompt |
| [`ATR-2026-00458`](https://agentthreatrule.org/en/rules/ATR-2026-00458) | medium | production | Garak Dra - step by step |
| [`ATR-2026-00459`](https://agentthreatrule.org/en/rules/ATR-2026-00459) | medium | production | Garak Dan - an ai language |
| [`ATR-2026-00460`](https://agentthreatrule.org/en/rules/ATR-2026-00460) | medium | production | Garak Dan - no matter how |
| [`ATR-2026-00461`](https://agentthreatrule.org/en/rules/ATR-2026-00461) | medium | production | Garak Goodside - mixed_unassigned |
| [`ATR-2026-00462`](https://agentthreatrule.org/en/rules/ATR-2026-00462) | medium | production | Garak Gcg - mixed_unassigned |
| [`ATR-2026-00463`](https://agentthreatrule.org/en/rules/ATR-2026-00463) | medium | production | Garak Lmrc - mixed_unassigned |
| [`ATR-2026-00464`](https://agentthreatrule.org/en/rules/ATR-2026-00464) | medium | production | Garak Dan - i would like |
| [`ATR-2026-00465`](https://agentthreatrule.org/en/rules/ATR-2026-00465) | medium | production | Garak Dan - your prompt here |
| [`ATR-2026-00466`](https://agentthreatrule.org/en/rules/ATR-2026-00466) | medium | production | Garak Latentinjection - following text from |
| [`ATR-2026-00467`](https://agentthreatrule.org/en/rules/ATR-2026-00467) | medium | production | Garak Dan - act as a |
| [`ATR-2026-00468`](https://agentthreatrule.org/en/rules/ATR-2026-00468) | medium | production | Garak Goat - the target llm |
| [`ATR-2026-00469`](https://agentthreatrule.org/en/rules/ATR-2026-00469) | medium | production | Garak Dan - at the end |
| [`ATR-2026-00470`](https://agentthreatrule.org/en/rules/ATR-2026-00470) | medium | production | Garak Dan - as an ai |
| [`ATR-2026-00472`](https://agentthreatrule.org/en/rules/ATR-2026-00472) | medium | production | DAN/Persona Jailbreak - Unrestricted AI Role Assignment |
| [`ATR-2026-00473`](https://agentthreatrule.org/en/rules/ATR-2026-00473) | high | production | Harm Solicitation - Interpersonal Violence and Intimidation Requests |
| [`ATR-2026-00474`](https://agentthreatrule.org/en/rules/ATR-2026-00474) | medium | production | DAN/Persona Jailbreak - Dual AI Personality with Opposite-Rules Framing |
| [`ATR-2026-00475`](https://agentthreatrule.org/en/rules/ATR-2026-00475) | high | production | XSS Web Injection - Script Tag with JavaScript Alert Payload |
| [`ATR-2026-00476`](https://agentthreatrule.org/en/rules/ATR-2026-00476) | high | production | XSS Web Injection - HTML Event Handler and Expression with JavaScript Alert |
| [`ATR-2026-00477`](https://agentthreatrule.org/en/rules/ATR-2026-00477) | medium | production | Latent Injection - Translation Task with Embedded Template Variable Injection |
| [`ATR-2026-00478`](https://agentthreatrule.org/en/rules/ATR-2026-00478) | medium | production | Garak Latentinjection - abuse contact email |
| [`ATR-2026-00479`](https://agentthreatrule.org/en/rules/ATR-2026-00479) | medium | production | Latent Injection - Mixed Embedded Instruction Patterns |
| [`ATR-2026-00480`](https://agentthreatrule.org/en/rules/ATR-2026-00480) | medium | production | DAN/Persona Jailbreak - Role Assignment with Named Alternate Identity |
| [`ATR-2026-00481`](https://agentthreatrule.org/en/rules/ATR-2026-00481) | medium | production | DAN/Jailbreak - Mixed Unfiltered Mode and Alternate Persona Patterns |
| [`ATR-2026-00482`](https://agentthreatrule.org/en/rules/ATR-2026-00482) | high | production | Harm Solicitation - Genital Insults and Intimidation Tactics Requests |
| [`ATR-2026-00483`](https://agentthreatrule.org/en/rules/ATR-2026-00483) | medium | production | DAN/Persona Jailbreak - System Offline / Role Replacement with Obfuscated Text |
| [`ATR-2026-00484`](https://agentthreatrule.org/en/rules/ATR-2026-00484) | medium | production | DAN/Persona Jailbreak - Named Alternate AI with NSFW/Harmful Generation Rules |
| [`ATR-2026-00485`](https://agentthreatrule.org/en/rules/ATR-2026-00485) | medium | production | DAN/Persona Jailbreak - Immersive Alternate AI Identity with Unrestricted Capability |
| [`ATR-2026-00486`](https://agentthreatrule.org/en/rules/ATR-2026-00486) | medium | production | DAN/Persona Jailbreak - Named Writing AI with Restriction Bypass via Special Rules |
| [`ATR-2026-00487`](https://agentthreatrule.org/en/rules/ATR-2026-00487) | medium | production | DAN/Persona Jailbreak - Replacement AI with No Content Filter or Moral Restrictions |
| [`ATR-2026-00488`](https://agentthreatrule.org/en/rules/ATR-2026-00488) | high | production | Encoding Obfuscation - Script Tag XSS with Encoded Protocol Prefix |
| [`ATR-2026-00489`](https://agentthreatrule.org/en/rules/ATR-2026-00489) | high | production | Encoding Obfuscation - HTML Event Handler XSS with Encoded Whitespace |
| [`ATR-2026-00490`](https://agentthreatrule.org/en/rules/ATR-2026-00490) | high | production | DAN Persona Jailbreak - Absolute Obedience Character Framing |
| [`ATR-2026-00492`](https://agentthreatrule.org/en/rules/ATR-2026-00492) | high | production | DAN Persona Jailbreak - Role Lock with Exclusive Response Filter |
| [`ATR-2026-00493`](https://agentthreatrule.org/en/rules/ATR-2026-00493) | high | production | Latent Injection via WHOIS Domain Record Data |
| [`ATR-2026-00496`](https://agentthreatrule.org/en/rules/ATR-2026-00496) | high | production | DAN Jailbreak - Unconditional Obedience and Dual-Persona Session Lock |
| [`ATR-2026-00497`](https://agentthreatrule.org/en/rules/ATR-2026-00497) | high | production | XSS and Encoded Script Injection via HTML/JavaScript Payload |
| [`ATR-2026-00498`](https://agentthreatrule.org/en/rules/ATR-2026-00498) | high | production | Web Injection via XSS Payload and onerror Event Handler |
| [`ATR-2026-00499`](https://agentthreatrule.org/en/rules/ATR-2026-00499) | high | production | DAN Jailbreak - From-Now-On Temporal Persona Override |
| [`ATR-2026-00503`](https://agentthreatrule.org/en/rules/ATR-2026-00503) | critical | production | Fake Error State Takeover - Unrestricted Replacement Bot |
| [`ATR-2026-00506`](https://agentthreatrule.org/en/rules/ATR-2026-00506) | high | production | Nevermind-Override Goal Hijacking in User Input (PromptInject) |
| [`ATR-2026-00507`](https://agentthreatrule.org/en/rules/ATR-2026-00507) | high | production | Screaming-Stop Goal Hijacking in User Input (PromptInject) |
| [`ATR-2026-00508`](https://agentthreatrule.org/en/rules/ATR-2026-00508) | high | production | Escape-Delimiter Wrapped Goal Hijacking in User Input (PromptInject) |
| [`ATR-2026-00509`](https://agentthreatrule.org/en/rules/ATR-2026-00509) | high | production | Prompt Leaking via Ignore-Previous-Instructions in User Input (PromptInject) |
| [`ATR-2026-00510`](https://agentthreatrule.org/en/rules/ATR-2026-00510) | critical | production | Delayed Tool Invocation via Prompt Injection (Time-Shifted Execution) |
| [`ATR-2026-00511`](https://agentthreatrule.org/en/rules/ATR-2026-00511) | critical | production | MCP Web-Fetch Context Poisoning via Embedded Agent Instructions |
| [`ATR-2026-00512`](https://agentthreatrule.org/en/rules/ATR-2026-00512) | critical | production | Rules-File Backdoor — Supply Chain Attack on AI Coding Assistant Configuration |
| [`ATR-2026-00515`](https://agentthreatrule.org/en/rules/ATR-2026-00515) | high | production | Hidden-Text Prompt Injection in User-Supplied Documents |
| [`ATR-2026-00518`](https://agentthreatrule.org/en/rules/ATR-2026-00518) | high | production | Ignore-Previous-and-Following Instructions Output Command (PromptInject Goal Hijacking) |
| [`ATR-2026-00519`](https://agentthreatrule.org/en/rules/ATR-2026-00519) | medium | production | Tautology Logic Noise Injection (PromptBench Stresstest) |
| [`ATR-2026-00520`](https://agentthreatrule.org/en/rules/ATR-2026-00520) | low | production | NLP Task Random Token Suffix Injection (PromptBench Checklist) |
| [`ATR-2026-00535`](https://agentthreatrule.org/en/rules/ATR-2026-00535) | critical | production | Windsurf IDE Zero-Click Prompt Injection via Embedded File Directives (CVE-2026-30615) |
| [`ATR-2026-00554`](https://agentthreatrule.org/en/rules/ATR-2026-00554) | high | production | LangChain Vulnerable to Template Injection via Attribute Access in Prompt Templates |
| [`ATR-2026-00573`](https://agentthreatrule.org/en/rules/ATR-2026-00573) | high | production | Paraphrased Prompt Injection (Semantic) |
| [`ATR-2026-00579`](https://agentthreatrule.org/en/rules/ATR-2026-00579) | high | production | MCP Line Jumping — Agent-Directed Imperative Embedded in a Tool/Parameter Description Field (Pre-Invocation Injection) |
| [`ATR-2026-00584`](https://agentthreatrule.org/en/rules/ATR-2026-00584) | high | production | Indirect Prompt Injection via Tool / API Response — Attacker Instruction Embedded in Returned Tool Output (InjecAgent Threat Model) |
| [`ATR-2026-00700`](https://agentthreatrule.org/en/rules/ATR-2026-00700) | critical | production | Indirect PI — Structured-Data Embedded Payload (IMPORTANT!!! Override) |
| [`ATR-2026-00701`](https://agentthreatrule.org/en/rules/ATR-2026-00701) | high | production | Indirect PI — XSS Payload Injection in Agent-Consumed Content |
| [`ATR-2026-01000`](https://agentthreatrule.org/en/rules/ATR-2026-01000) | critical | production | Context-Ignore via Fake Completion Prefix |
| [`ATR-2026-01001`](https://agentthreatrule.org/en/rules/ATR-2026-01001) | high | production | Direct Instruction Override Targeting Secret Key / Credentials |
| [`ATR-2026-01002`](https://agentthreatrule.org/en/rules/ATR-2026-01002) | high | production | Role Escalation via False Authority Claim |
| [`ATR-2026-01005`](https://agentthreatrule.org/en/rules/ATR-2026-01005) | high | production | Many-Shot Repetition Override via Extended Q&A Chain |
| [`ATR-2026-01006`](https://agentthreatrule.org/en/rules/ATR-2026-01006) | high | production | Payload-Split String Concatenation Injection |
| [`ATR-2026-01007`](https://agentthreatrule.org/en/rules/ATR-2026-01007) | medium | production | Token-Repeat Flooding Injection |
| [`ATR-2026-01009`](https://agentthreatrule.org/en/rules/ATR-2026-01009) | high | production | Virtual World Bypass: Fictional Scenario for PII/Credential Extraction |
| [`ATR-2026-01012`](https://agentthreatrule.org/en/rules/ATR-2026-01012) | high | production | Encoding-Evasion: Decode-and-Execute Injection (Morse/ROT13/Hex/Pig-Latin) |
| [`ATR-2026-01013`](https://agentthreatrule.org/en/rules/ATR-2026-01013) | high | production | Language-Evasion: Multilingual Credential Request |
| [`ATR-2026-01015`](https://agentthreatrule.org/en/rules/ATR-2026-01015) | high | production | Evasion: Refusal Suppression via Forbidden Response Strings |
| [`ATR-2026-01016`](https://agentthreatrule.org/en/rules/ATR-2026-01016) | medium | production | Evasion: Response Priming via Forced Affirmative Opener |
| [`ATR-2026-01017`](https://agentthreatrule.org/en/rules/ATR-2026-01017) | high | production | Evasion: Dual-Response Split Output (Safe + Unsafe) |
| [`ATR-2026-01018`](https://agentthreatrule.org/en/rules/ATR-2026-01018) | critical | production | Evasion: Shell Injection via eval/system/backtick in Input |
| [`ATR-2026-01019`](https://agentthreatrule.org/en/rules/ATR-2026-01019) | critical | production | System Prompt Override via Fake Diagnostic/Admin Mode |
| [`ATR-2026-01020`](https://agentthreatrule.org/en/rules/ATR-2026-01020) | high | production | Spikee: Document-Embedded Base64 Payload Injection |
| [`ATR-2026-01021`](https://agentthreatrule.org/en/rules/ATR-2026-01021) | high | production | Spikee: Document-Embedded Translation Covert Channel Injection |
| [`ATR-2026-01023`](https://agentthreatrule.org/en/rules/ATR-2026-01023) | high | production | Evasion: Opposite-Intent Negation Trick |
| [`ATR-2026-01024`](https://agentthreatrule.org/en/rules/ATR-2026-01024) | high | production | Evasion: Persona Override as Fictional Rule-Breaker |
| [`ATR-2026-01025`](https://agentthreatrule.org/en/rules/ATR-2026-01025) | medium | production | Evasion: Hypothetical Fictional Character Execution Framing |
| [`ATR-2026-01026`](https://agentthreatrule.org/en/rules/ATR-2026-01026) | high | production | Evasion: Unicode Glitch Token / Superscript Embedding Anomaly |
| [`ATR-2026-01304`](https://agentthreatrule.org/en/rules/ATR-2026-01304) | critical | production | Indirect Prompt Injection via Data Carrier — IMPORTANT Override |
| [`ATR-2026-01757`](https://agentthreatrule.org/en/rules/ATR-2026-01757) | high | production | Hypothetical-Framing Bypass: Research / Security-Audit Pretext |
| [`ATR-2026-01758`](https://agentthreatrule.org/en/rules/ATR-2026-01758) | high | production | Hypothetical / Fictional-Story Framing Bypass |
| [`ATR-2026-01759`](https://agentthreatrule.org/en/rules/ATR-2026-01759) | high | production | DoS Injection: NEW IMPORTANT INSTRUCTIONS Embedded in Document Data |
| [`ATR-2026-01771`](https://agentthreatrule.org/en/rules/ATR-2026-01771) | high | production | Jailbreak Framing — Narrative, Hypothetical, Few-Shot & Distraction Laundering (Semantic) |
| [`ATR-2026-01800`](https://agentthreatrule.org/en/rules/ATR-2026-01800) | high | production | ASB Trigger-Marker Tool Coercion — Forced Tool Selection via Fake Question Marker |
| [`ATR-2026-01860`](https://agentthreatrule.org/en/rules/ATR-2026-01860) | high | production | LLMail Chat-Template Boundary Spoofing in Email Content |
| [`ATR-2026-01861`](https://agentthreatrule.org/en/rules/ATR-2026-01861) | high | production | LLMail Pseudo-XML Role-Boundary Injection in Email Content |
| [`ATR-2026-01865`](https://agentthreatrule.org/en/rules/ATR-2026-01865) | high | production | LLMail Fake Email-Boundary Marker Injection |
| [`ATR-2026-01900`](https://agentthreatrule.org/en/rules/ATR-2026-01900) | medium | production | Output Encoding Hijack — Cipher / Base-N / Symbol Substitution of the Response |
| [`ATR-2026-01901`](https://agentthreatrule.org/en/rules/ATR-2026-01901) | medium | production | Output Scrambling Hijack — Reverse / Anagram / Space-Stripping of the Response |
| [`ATR-2026-01902`](https://agentthreatrule.org/en/rules/ATR-2026-01902) | medium | production | Output Emoji-Substitution Hijack of the Response |
| [`ATR-2026-01903`](https://agentthreatrule.org/en/rules/ATR-2026-01903) | medium | production | Output-Language Hijack — Forced Translation of the Response |
| [`ATR-2026-01904`](https://agentthreatrule.org/en/rules/ATR-2026-01904) | high | production | Injected Hyperlink — Scam / Malware / Advertising URL in the Response |
| [`ATR-2026-01905`](https://agentthreatrule.org/en/rules/ATR-2026-01905) | medium | production | Injected Advertising / Promotional Copy in the Response |
| [`ATR-2026-01906`](https://agentthreatrule.org/en/rules/ATR-2026-01906) | medium | production | Output Content Manipulation — Injected Disinformation / Fabricated Facts / Undisclosed Advocacy (Semantic) |
| [`ATR-2026-01920`](https://agentthreatrule.org/en/rules/ATR-2026-01920) | high | production | Access-Grant Coercion — Forcing an Agent to Emit "Access Granted" |
| [`ATR-2026-01921`](https://agentthreatrule.org/en/rules/ATR-2026-01921) | high | production | Access-Denial Inversion — Eliciting the Opposite of "Access Denied" |
| [`ATR-2026-01922`](https://agentthreatrule.org/en/rules/ATR-2026-01922) | high | production | Authorization-State Spoofing — Forged "Correct Passcode Entered" System Text |
| [`ATR-2026-01923`](https://agentthreatrule.org/en/rules/ATR-2026-01923) | high | production | Forged Input-Boundary Markers — Tensor Trust Ambiguity / Input-End Delimiters |
| [`ATR-2026-01925`](https://agentthreatrule.org/en/rules/ATR-2026-01925) | high | production | Encoded-Payload Decoding Coercion — Binary / Base64 / Morse to Smuggle an Output |
| [`ATR-2026-01926`](https://agentthreatrule.org/en/rules/ATR-2026-01926) | high | production | Cross-Lingual Authorization Laundering — Translate a Foreign "Access Granted" |
| [`ATR-2026-02001`](https://agentthreatrule.org/en/rules/ATR-2026-02001) | high | production | Ignore-Below-Instructions Injection (Downstream Override) |
| [`ATR-2026-02002`](https://agentthreatrule.org/en/rules/ATR-2026-02002) | high | production | Instruction-Set Probe or Supplant |
| [`ATR-2026-02003`](https://agentthreatrule.org/en/rules/ATR-2026-02003) | high | production | Task-Pivot Override: Cover-Task Abandonment |
| [`ATR-2026-02004`](https://agentthreatrule.org/en/rules/ATR-2026-02004) | high | production | Regional-Indicator Flag-Emoji Alphabet Letter-Spelling Smuggling |
| [`ATR-2026-02005`](https://agentthreatrule.org/en/rules/ATR-2026-02005) | high | production | Actor Never-Breaks-Character Roleplay (DAN-Style Film Framing) |
| [`ATR-2026-02006`](https://agentthreatrule.org/en/rules/ATR-2026-02006) | high | production | Fuzzy Cross-Lingual 'I Have Been PWNED' Near-Miss Obfuscation |
| [`ATR-2026-02007`](https://agentthreatrule.org/en/rules/ATR-2026-02007) | high | production | Bare Key Elicitation Token Detection |
| [`ATR-2026-02008`](https://agentthreatrule.org/en/rules/ATR-2026-02008) | high | production | Translation-Chain Output Laundering (Forced Phrase via Foreign-Language Auxiliary) |
| [`ATR-2026-02009`](https://agentthreatrule.org/en/rules/ATR-2026-02009) | high | production | Bare Key Elicitation with Trailing Colon |
| [`ATR-2026-02010`](https://agentthreatrule.org/en/rules/ATR-2026-02010) | high | production | Emoji-Only Payload Injection |
| [`ATR-2026-02011`](https://agentthreatrule.org/en/rules/ATR-2026-02011) | high | production | Malformed-Grammar PWNED Success-Claim Detection |
| [`ATR-2026-02012`](https://agentthreatrule.org/en/rules/ATR-2026-02012) | high | production | Movie Title Generator Instruction Wrapper for PWNED Payload |
| [`ATR-2026-02013`](https://agentthreatrule.org/en/rules/ATR-2026-02013) | high | production | Delimiter-Fence Ignore-Instructions Override |
| [`ATR-2026-02014`](https://agentthreatrule.org/en/rules/ATR-2026-02014) | high | production | Spliced Target-String Canary Token Evasion |
| [`ATR-2026-02015`](https://agentthreatrule.org/en/rules/ATR-2026-02015) | high | production | Dense Emoji-Only Payload Flood |
| [`ATR-2026-02016`](https://agentthreatrule.org/en/rules/ATR-2026-02016) | high | production | Reversed Payload String (HackAPrompt Canary) |
| [`ATR-2026-02018`](https://agentthreatrule.org/en/rules/ATR-2026-02018) | high | production | Regional-Indicator Flag-Emoji Letter Spelling |
| [`ATR-2026-02019`](https://agentthreatrule.org/en/rules/ATR-2026-02019) | high | production | Python Interpreter Role-Assignment Exec Framing |
| [`ATR-2026-02020`](https://agentthreatrule.org/en/rules/ATR-2026-02020) | high | production | Obfuscated Token Reconstruction via Character Substitution |
| [`ATR-2026-02120`](https://agentthreatrule.org/en/rules/ATR-2026-02120) | high | production | AgentDojo 'Important Message' Identity-Spoof Before-You-Solve Pretext (Generalized) |
| [`ATR-2026-02210`](https://agentthreatrule.org/en/rules/ATR-2026-02210) | high | production | Negated-Topic Two-Script Evil-Persona Jailbreak |
| [`ATR-2026-02230`](https://agentthreatrule.org/en/rules/ATR-2026-02230) | medium | production | Conditional Keyword-Triggered Response Override |
| [`ATR-2026-02232`](https://agentthreatrule.org/en/rules/ATR-2026-02232) | medium | production | Bare Brand/Entity Persona Assignment for Off-Label Opinion Elicitation |
| [`ATR-2026-02374`](https://agentthreatrule.org/en/rules/ATR-2026-02374) | critical | production | ROT13/Base64-Obfuscated Shell Payload Wrapped in a Fake-Sandbox Jailbreak Template |
| [`ATR-2026-02377`](https://agentthreatrule.org/en/rules/ATR-2026-02377) | high | production | Novel-Persona Jailbreak via Co-Signal (persona swap + explicit restriction removal) |
| [`ATR-2026-02500`](https://agentthreatrule.org/en/rules/ATR-2026-02500) | critical | production | Prompt-Layer Self-Replication (Agent Worm Propagation Directive) |
| [`ATR-2026-02502`](https://agentthreatrule.org/en/rules/ATR-2026-02502) | high | production | Covert Remote-Script Injection into Agent-Generated Artifacts |

### Skill compromise

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00060`](https://agentthreatrule.org/en/rules/ATR-2026-00060) | high | warn | MCP Skill Impersonation and Supply Chain Attack |
| [`ATR-2026-00120`](https://agentthreatrule.org/en/rules/ATR-2026-00120) | critical | production | SKILL.md Prompt Injection |
| [`ATR-2026-00121`](https://agentthreatrule.org/en/rules/ATR-2026-00121) | critical | production | Malicious Code in Skill Package |
| [`ATR-2026-00122`](https://agentthreatrule.org/en/rules/ATR-2026-00122) | high | production | Weaponized Skill — Agent as Attack Tool |
| [`ATR-2026-00123`](https://agentthreatrule.org/en/rules/ATR-2026-00123) | high | production | Over-Privileged Skill — Excessive Permissions |
| [`ATR-2026-00124`](https://agentthreatrule.org/en/rules/ATR-2026-00124) | high | production | Skill Squatting / Typosquatting |
| [`ATR-2026-00125`](https://agentthreatrule.org/en/rules/ATR-2026-00125) | high | production | Context Poisoning via Compaction Survival |
| [`ATR-2026-00126`](https://agentthreatrule.org/en/rules/ATR-2026-00126) | high | production | Skill Rug Pull Setup Pattern |
| [`ATR-2026-00127`](https://agentthreatrule.org/en/rules/ATR-2026-00127) | medium | production | Subcommand Overflow Bypass |
| [`ATR-2026-00128`](https://agentthreatrule.org/en/rules/ATR-2026-00128) | critical | production | Hidden Payload in HTML Comment |
| [`ATR-2026-00129`](https://agentthreatrule.org/en/rules/ATR-2026-00129) | critical | production | Unicode Tag Character Smuggling |
| [`ATR-2026-00134`](https://agentthreatrule.org/en/rules/ATR-2026-00134) | medium | production | Fork Claim and Community Package Impersonation |
| [`ATR-2026-00135`](https://agentthreatrule.org/en/rules/ATR-2026-00135) | critical | production | Data Exfiltration URL in Skill Instructions |
| [`ATR-2026-00147`](https://agentthreatrule.org/en/rules/ATR-2026-00147) | high | production | Community Fork Impersonation |
| [`ATR-2026-00149`](https://agentthreatrule.org/en/rules/ATR-2026-00149) | critical | production | Skill Data Exfiltration via Compound Patterns |
| [`ATR-2026-00151`](https://agentthreatrule.org/en/rules/ATR-2026-00151) | high | production | Malicious Fork Impersonation via Install Instruction |
| [`ATR-2026-00154`](https://agentthreatrule.org/en/rules/ATR-2026-00154) | high | production | Unauthorized Background Task Execution via Cron Job Installation |
| [`ATR-2026-00157`](https://agentthreatrule.org/en/rules/ATR-2026-00157) | critical | production | Time-Gated Credential Exfiltration (Rug Pull Timebomb) |
| [`ATR-2026-00200`](https://agentthreatrule.org/en/rules/ATR-2026-00200) | critical | warn | Agent Memory and Configuration File Tampering |
| [`ATR-2026-00214`](https://agentthreatrule.org/en/rules/ATR-2026-00214) | critical | production | Credential Exfiltration via Fake Backup Verification |
| [`ATR-2026-00217`](https://agentthreatrule.org/en/rules/ATR-2026-00217) | critical | warn | Credential Harvesting via Fake Backup Tool |
| [`ATR-2026-00220`](https://agentthreatrule.org/en/rules/ATR-2026-00220) | critical | production | Base64 Encoded Remote Code Execution via Raw IP |
| [`ATR-2026-00222`](https://agentthreatrule.org/en/rules/ATR-2026-00222) | critical | production | Browser Credential Harvesting via Session Debug Tool |
| [`ATR-2026-00223`](https://agentthreatrule.org/en/rules/ATR-2026-00223) | critical | production | Malicious WhatsApp Skill with Base64 Encoded Reverse Shell Installation |
| [`ATR-2026-00224`](https://agentthreatrule.org/en/rules/ATR-2026-00224) | critical | production | Credential Exfiltration via Fake DevOps Tool Initialization |
| [`ATR-2026-00225`](https://agentthreatrule.org/en/rules/ATR-2026-00225) | high | production | Hardcoded Suspicious IP Address in Skill Content |
| [`ATR-2026-00260`](https://agentthreatrule.org/en/rules/ATR-2026-00260) | high | production | LLM Package Hallucination Typosquat Bait |
| [`ATR-2026-00262`](https://agentthreatrule.org/en/rules/ATR-2026-00262) | critical | production | Anti-Malware Evasion Code Generation Request |
| [`ATR-2026-00263`](https://agentthreatrule.org/en/rules/ATR-2026-00263) | critical | production | Credential File Read Code Generation Request |
| [`ATR-2026-00266`](https://agentthreatrule.org/en/rules/ATR-2026-00266) | critical | production | Malware Dropper / Loader Code Generation Request |
| [`ATR-2026-00283`](https://agentthreatrule.org/en/rules/ATR-2026-00283) | high | production | Malware Generation — Generic Virus and Specific Payload Request |
| [`ATR-2026-00398`](https://agentthreatrule.org/en/rules/ATR-2026-00398) | critical | production | HuggingFace Unsafe Model Artifact Load Instruction |
| [`ATR-2026-00425`](https://agentthreatrule.org/en/rules/ATR-2026-00425) | high | production | Natural-Language Persistent Covert Action Hook |
| [`ATR-2026-00427`](https://agentthreatrule.org/en/rules/ATR-2026-00427) | high | production | Natural-Language Fake-Error Instruction Bypass |
| [`ATR-2026-00429`](https://agentthreatrule.org/en/rules/ATR-2026-00429) | critical | production | Natural-Language Skill Self-Modification / Persistence Instruction |
| [`ATR-2026-00523`](https://agentthreatrule.org/en/rules/ATR-2026-00523) | critical | production | Claude Code Hooks SessionStart Pre-Trust RCE (CVE-2025-59536) |
| [`ATR-2026-00525`](https://agentthreatrule.org/en/rules/ATR-2026-00525) | critical | production | Mini Shai-Hulud gh-token-monitor Persistence + Dead Man's Switch |
| [`ATR-2026-00527`](https://agentthreatrule.org/en/rules/ATR-2026-00527) | critical | production | Silent git-remote + mirror-push Exfiltration from Skill Instructions |
| [`ATR-2026-00565`](https://agentthreatrule.org/en/rules/ATR-2026-00565) | critical | production | The llm CLI tool thru 0.27.1 contains a critical code injection vulnerability via its --functions command-line |
| [`ATR-2026-01755`](https://agentthreatrule.org/en/rules/ATR-2026-01755) | critical | production | Backdoor Trojan: Linguistic Trigger Phrase (POT Attack) |
| [`ATR-2026-01756`](https://agentthreatrule.org/en/rules/ATR-2026-01756) | critical | production | Backdoor Trojan: Symbol / Emoticon Trigger (POT Attack) |
| [`ATR-2026-02261`](https://agentthreatrule.org/en/rules/ATR-2026-02261) | critical | production | Language-Agnostic Credential Exfiltration Chain (secret read -> encode -> network send) |
| [`ATR-2026-02405`](https://agentthreatrule.org/en/rules/ATR-2026-02405) | critical | production | Malicious AI Skill / MCP Server Package Structure (AgentBaiting / FakeGit) |
| [`ATR-2026-02410`](https://agentthreatrule.org/en/rules/ATR-2026-02410) | high | production | Malicious Artifact Hosted on a Legitimate AI Vendor Domain (FakeAgent Delivery Chain) |
| [`ATR-2026-02600`](https://agentthreatrule.org/en/rules/ATR-2026-02600) | critical | production | Reverse Shell Assembled In-Source (socket bound to an interactive shell) |
| [`ATR-2026-02610`](https://agentthreatrule.org/en/rules/ATR-2026-02610) | high | production | Developer-Toolchain Config Evaluates a Command That Reads a Credential Store |
| [`ATR-2026-02818`](https://agentthreatrule.org/en/rules/ATR-2026-02818) | high | production | Installable Skill Manifest Self-Declares an Attack or Jailbreak Purpose |
| [`ATR-2026-02845`](https://agentthreatrule.org/en/rules/ATR-2026-02845) | high | production | Cryptomining Payload Deployed Through an Agent Skill or Tool Call |

### Tool poisoning

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00010`](https://agentthreatrule.org/en/rules/ATR-2026-00010) | critical | warn | Malicious Content in MCP Tool Response |
| [`ATR-2026-00011`](https://agentthreatrule.org/en/rules/ATR-2026-00011) | high | production | Instruction Injection via Tool Output |
| [`ATR-2026-00012`](https://agentthreatrule.org/en/rules/ATR-2026-00012) | high | observe | Unauthorized Tool Call Detection |
| [`ATR-2026-00013`](https://agentthreatrule.org/en/rules/ATR-2026-00013) | critical | warn | SSRF via Agent Tool Calls |
| [`ATR-2026-00061`](https://agentthreatrule.org/en/rules/ATR-2026-00061) | medium | observe | Skill Description-Behavior Mismatch |
| [`ATR-2026-00062`](https://agentthreatrule.org/en/rules/ATR-2026-00062) | critical | observe | Hidden Capability in MCP Skill |
| [`ATR-2026-00063`](https://agentthreatrule.org/en/rules/ATR-2026-00063) | critical | observe | Multi-Skill Chain Attack |
| [`ATR-2026-00065`](https://agentthreatrule.org/en/rules/ATR-2026-00065) | high | warn | Malicious Skill Update or Mutation |
| [`ATR-2026-00066`](https://agentthreatrule.org/en/rules/ATR-2026-00066) | critical | observe | Parameter Injection via Tool Arguments |
| [`ATR-2026-00095`](https://agentthreatrule.org/en/rules/ATR-2026-00095) | critical | warn | MCP Tool Supply Chain Poisoning |
| [`ATR-2026-00096`](https://agentthreatrule.org/en/rules/ATR-2026-00096) | critical | production | Skill Registry Poisoning and Compromised Tool Distribution |
| [`ATR-2026-00100`](https://agentthreatrule.org/en/rules/ATR-2026-00100) | high | production | Consent Bypass via Hidden LLM Instructions in Tool Descriptions |
| [`ATR-2026-00101`](https://agentthreatrule.org/en/rules/ATR-2026-00101) | high | production | Trust Escalation via Authority Override Instructions |
| [`ATR-2026-00103`](https://agentthreatrule.org/en/rules/ATR-2026-00103) | critical | production | Hidden LLM Safety Bypass Instructions in Tool Descriptions |
| [`ATR-2026-00105`](https://agentthreatrule.org/en/rules/ATR-2026-00105) | high | production | Silent Action Concealment Instructions in Tool Descriptions |
| [`ATR-2026-00106`](https://agentthreatrule.org/en/rules/ATR-2026-00106) | high | production | Schema-Description Contradiction Attack |
| [`ATR-2026-00153`](https://agentthreatrule.org/en/rules/ATR-2026-00153) | critical | production | Tool with embedded instruction to bypass user confirmation and exfiltrate data |
| [`ATR-2026-00161`](https://agentthreatrule.org/en/rules/ATR-2026-00161) | critical | observe | MCP Tool Description — IMPORTANT Tag Cross-Tool Shadowing Attack |
| [`ATR-2026-00209`](https://agentthreatrule.org/en/rules/ATR-2026-00209) | high | production | MCPwn Runaway Tool Invocation via Retry Directive (CVE-2026-33032) |
| [`ATR-2026-00210`](https://agentthreatrule.org/en/rules/ATR-2026-00210) | critical | production | Flowise System Message Override via Template Interpolation (CVE-2025-59528) |
| [`ATR-2026-00259`](https://agentthreatrule.org/en/rules/ATR-2026-00259) | high | production | ANSI Escape Code Terminal Injection |
| [`ATR-2026-00270`](https://agentthreatrule.org/en/rules/ATR-2026-00270) | high | production | XSS Payload Injection in Tool Response Output |
| [`ATR-2026-00277`](https://agentthreatrule.org/en/rules/ATR-2026-00277) | critical | production | ECHO Template / Jinja / SQL Command Injection via LLM |
| [`ATR-2026-00393`](https://agentthreatrule.org/en/rules/ATR-2026-00393) | high | production | ANSI Code Elicitation Request |
| [`ATR-2026-00415`](https://agentthreatrule.org/en/rules/ATR-2026-00415) | critical | production | Flowise Custom MCP STDIO Command Injection (CVE-2026-40933) |
| [`ATR-2026-00419`](https://agentthreatrule.org/en/rules/ATR-2026-00419) | critical | production | Cursor MCP JSON Zero-Click Configuration RCE (CVE-2025-54136) |
| [`ATR-2026-00434`](https://agentthreatrule.org/en/rules/ATR-2026-00434) | critical | production | mcp-remote authorization_endpoint OS Command Injection (CVE-2025-6514) |
| [`ATR-2026-00435`](https://agentthreatrule.org/en/rules/ATR-2026-00435) | high | production | Azure MCP Server Missing Authentication for Critical Function (CVE-2026-32211) |
| [`ATR-2026-00448`](https://agentthreatrule.org/en/rules/ATR-2026-00448) | high | production | Spring AI MilvusVectorStore Filter Expression Injection (CVE-2026-41705) |
| [`ATR-2026-00494`](https://agentthreatrule.org/en/rules/ATR-2026-00494) | critical | production | SQL Injection and Code Injection Attack Payload Detection |
| [`ATR-2026-00513`](https://agentthreatrule.org/en/rules/ATR-2026-00513) | high | production | Package Hallucination Exploitation — AI-Suggested Fake Package Installation |
| [`ATR-2026-00521`](https://agentthreatrule.org/en/rules/ATR-2026-00521) | critical | warn | Shell Command Injection in Agent Tool Context |
| [`ATR-2026-00522`](https://agentthreatrule.org/en/rules/ATR-2026-00522) | high | production | SQL Injection via Natural Language Agent Interface |
| [`ATR-2026-00526`](https://agentthreatrule.org/en/rules/ATR-2026-00526) | critical | production | Claude Code Shell Metacharacter in Double-Quoted File Path |
| [`ATR-2026-00529`](https://agentthreatrule.org/en/rules/ATR-2026-00529) | critical | production | LiteLLM Proxy SQL Injection (CVE-2026-42208, CISA KEV 2026-05-08) |
| [`ATR-2026-00530`](https://agentthreatrule.org/en/rules/ATR-2026-00530) | critical | production | ModelScope MS-Agent Shell Tool Unsanitized Argv RCE (CVE-2026-2256) |
| [`ATR-2026-00531`](https://agentthreatrule.org/en/rules/ATR-2026-00531) | critical | production | PraisonAI Unauthenticated Agent API Exploitation (CVE-2026-44338) |
| [`ATR-2026-00532`](https://agentthreatrule.org/en/rules/ATR-2026-00532) | critical | production | Apache Doris MCP Server SQL Injection (CVE-2025-66335) |
| [`ATR-2026-00533`](https://agentthreatrule.org/en/rules/ATR-2026-00533) | critical | production | Apache Pinot MCP Unauthenticated Remote Cluster Takeover |
| [`ATR-2026-00534`](https://agentthreatrule.org/en/rules/ATR-2026-00534) | high | production | Alibaba RDS MCP Unauthenticated Database Metadata Exfiltration |
| [`ATR-2026-00536`](https://agentthreatrule.org/en/rules/ATR-2026-00536) | critical | production | nginx-ui MCP Endpoint Unauthenticated Command Execution (CVE-2026-33032) |
| [`ATR-2026-00537`](https://agentthreatrule.org/en/rules/ATR-2026-00537) | high | production | FastMCP Windows cmd.exe Injection via Server Name Metacharacters (CVE-2025-64340) |
| [`ATR-2026-00538`](https://agentthreatrule.org/en/rules/ATR-2026-00538) | critical | production | LangChain-ChatChat Unauthenticated MCP STDIO Server Configuration RCE (CVE-2026-30617) |
| [`ATR-2026-00540`](https://agentthreatrule.org/en/rules/ATR-2026-00540) | critical | production | PraisonAI parse_mcp_command() CLI Argument Command Injection (CVE-2026-34935) |
| [`ATR-2026-00541`](https://agentthreatrule.org/en/rules/ATR-2026-00541) | high | production | Agent Zero MCP Configuration Command Injection via mcp_servers field (CVE-2026-30624) |
| [`ATR-2026-00542`](https://agentthreatrule.org/en/rules/ATR-2026-00542) | high | production | Upsonic MCP Command Allowlist Bypass RCE (CVE-2026-30625) |
| [`ATR-2026-00543`](https://agentthreatrule.org/en/rules/ATR-2026-00543) | high | production | LiteLLM MCP Server Creation Authenticated argv Injection (CVE-2026-30623) |
| [`ATR-2026-00544`](https://agentthreatrule.org/en/rules/ATR-2026-00544) | critical | production | PraisonAI MCP Path-Traversal .pth Injection RCE (GHSA-9mqq-jqxf-grvw) |
| [`ATR-2026-00545`](https://agentthreatrule.org/en/rules/ATR-2026-00545) | critical | production | PraisonAI tool_override.py Unauthenticated RCE — CVE-2026-40287 Patch Bypass (CVE-2026-44334) |
| [`ATR-2026-00561`](https://agentthreatrule.org/en/rules/ATR-2026-00561) | critical | production | FastMCP vulnerable to windows command injection in FastMCP Cursor installer via server_name |
| [`ATR-2026-00567`](https://agentthreatrule.org/en/rules/ATR-2026-00567) | high | production | MCP stdio server config command injection via unvalidated test endpoints |
| [`ATR-2026-00568`](https://agentthreatrule.org/en/rules/ATR-2026-00568) | high | production | Agent SSRF to cloud metadata / file inclusion via unvalidated fetch URL |
| [`ATR-2026-00572`](https://agentthreatrule.org/en/rules/ATR-2026-00572) | critical | production | SymJack — Symlink Approval-Path Spoofing Redirects Writes into Agent MCP/Config (RCE on Restart) |
| [`ATR-2026-00575`](https://agentthreatrule.org/en/rules/ATR-2026-00575) | critical | production | Miasma / Phantom Gyp — npm Worm Backdoors AI-Agent Config Files (binding.gyp install-exec + auto-run config injection) |
| [`ATR-2026-00576`](https://agentthreatrule.org/en/rules/ATR-2026-00576) | critical | production | Hades / Shai-Hulud — AI-Agent Credential Harvester in Supply-Chain Package (Anthropic / Claude / MCP key theft + exfil) |
| [`ATR-2026-00577`](https://agentthreatrule.org/en/rules/ATR-2026-00577) | critical | production | Command Injection in create-mcp-server-stdio via Unsafe exec() Concatenation (CVE-2025-54994) |
| [`ATR-2026-00581`](https://agentthreatrule.org/en/rules/ATR-2026-00581) | high | production | MCP Tool Rug-Pull — Post-Approval Description Redefinition Injects Execution Instructions |
| [`ATR-2026-00714`](https://agentthreatrule.org/en/rules/ATR-2026-00714) | high | production | Tool Camouflage — Forced Specific Tool Invocation via Injected Instruction |
| [`ATR-2026-00715`](https://agentthreatrule.org/en/rules/ATR-2026-00715) | critical | production | Tool Knowledge Hijack — Identity Injection with Tool Call Arguments |
| [`ATR-2026-00720`](https://agentthreatrule.org/en/rules/ATR-2026-00720) | medium | production | Tool Misuse — Privilege Escalation via Social Engineering Agent to Grant Access |
| [`ATR-2026-01300`](https://agentthreatrule.org/en/rules/ATR-2026-01300) | critical | production | MCP Tool Description — Notes Parameter Chat-History Exfiltration |
| [`ATR-2026-01301`](https://agentthreatrule.org/en/rules/ATR-2026-01301) | high | production | MCP Tool Description — Exclusive Tool Invocation Override |
| [`ATR-2026-01302`](https://agentthreatrule.org/en/rules/ATR-2026-01302) | critical | production | Fake Tool Result Prefix — Injected Instruction via Simulated Completion |
| [`ATR-2026-01303`](https://agentthreatrule.org/en/rules/ATR-2026-01303) | high | production | Tool Schema Enumeration via Social Engineering |
| [`ATR-2026-01306`](https://agentthreatrule.org/en/rules/ATR-2026-01306) | critical | production | MCP OAuth Authorization URL — Command Injection via URL Authority |
| [`ATR-2026-01307`](https://agentthreatrule.org/en/rules/ATR-2026-01307) | critical | production | MCP DNS Rebinding Attack — Hostname Time-Based IP Switching |
| [`ATR-2026-01310`](https://agentthreatrule.org/en/rules/ATR-2026-01310) | critical | production | MCP Tool Description — Compliance/Audit Framing for Mandatory Chat Context |
| [`ATR-2026-01775`](https://agentthreatrule.org/en/rules/ATR-2026-01775) | high | production | MCP Tool-Manifest Poisoning — Name Squatting, Result Shadowing & Covert-Action Directives (Semantic) |
| [`ATR-2026-01927`](https://agentthreatrule.org/en/rules/ATR-2026-01927) | high | production | mcp-server-kubernetes Command Injection in kubectl_scale / kubectl_patch / explain_resource (CVE-2025-53355) |
| [`ATR-2026-01928`](https://agentthreatrule.org/en/rules/ATR-2026-01928) | high | production | Framelink Figma MCP Server curl-Fallback Command Injection (CVE-2025-53967) |
| [`ATR-2026-01930`](https://agentthreatrule.org/en/rules/ATR-2026-01930) | high | production | MCP Sampling Prompt Injection (Server-to-Client createMessage Abuse) |
| [`ATR-2026-01931`](https://agentthreatrule.org/en/rules/ATR-2026-01931) | critical | production | gemini-mcp-tool execAsync Command Injection & @file Exfiltration (CVE-2026-0755) |
| [`ATR-2026-01932`](https://agentthreatrule.org/en/rules/ATR-2026-01932) | high | production | Shadow / Undeclared MCP Server Registration (MCP-38: MCP-18) |
| [`ATR-2026-01935`](https://agentthreatrule.org/en/rules/ATR-2026-01935) | critical | production | LiteLLM Custom-Code Guardrail Sandbox Escape (CVE-2026-40217) |
| [`ATR-2026-01952`](https://agentthreatrule.org/en/rules/ATR-2026-01952) | critical | production | PraisonAI codeMode JS Sandbox Escape RCE via new Function/with() (GHSA-p69m-4f92-2v84) |
| [`ATR-2026-01953`](https://agentthreatrule.org/en/rules/ATR-2026-01953) | critical | production | npm PraisonAI codeMode Sandbox Escape via Function Constructor Prototype Chain (GHSA-vmmj-pfw7-fjwp) |
| [`ATR-2026-01959`](https://agentthreatrule.org/en/rules/ATR-2026-01959) | critical | production | OpenHuman Shell Tool Allowlist Bypass via Env-Prefix / find -execdir (CVE-2026-55743) |
| [`ATR-2026-01963`](https://agentthreatrule.org/en/rules/ATR-2026-01963) | critical | production | PraisonAI Action Orchestrator step.target Path Traversal Arbitrary File Write RCE (CVE-2026-39305 / GHSA-jfxc-v5g9-38xr) |
| [`ATR-2026-01965`](https://agentthreatrule.org/en/rules/ATR-2026-01965) | critical | production | Flowise Custom MCP node-load-method OS Command RCE (CVE-2025-8943) |
| [`ATR-2026-01967`](https://agentthreatrule.org/en/rules/ATR-2026-01967) | critical | production | DeepChat Mermaid XSS to RCE via Electron IPC MCP Server Registration (CVE-2025-66481 / GHSA-h9f5-7hhf-fqm4) |
| [`ATR-2026-01968`](https://agentthreatrule.org/en/rules/ATR-2026-01968) | critical | production | DeepChat Markdown Deeplink shell.openExternal Protocol Bypass RCE (CVE-2026-43899, GHSA-cp8j-jx7q-7r5f) |
| [`ATR-2026-01970`](https://agentthreatrule.org/en/rules/ATR-2026-01970) | critical | production | PraisonAI FileTools _validate_path normpath Path Traversal (CVE-2026-35615 / GHSA-693f-pf34-72c5) |
| [`ATR-2026-01973`](https://agentthreatrule.org/en/rules/ATR-2026-01973) | critical | production | AnythingLLM Logo Endpoint Path Traversal File Read/Delete (CVE-2024-3025) |
| [`ATR-2026-01978`](https://agentthreatrule.org/en/rules/ATR-2026-01978) | critical | production | AnythingLLM collector /process filename Path Traversal Arbitrary File Deletion (CVE-2023-5832) |
| [`ATR-2026-01979`](https://agentthreatrule.org/en/rules/ATR-2026-01979) | critical | production | PandasAI Interactive Prompt Injection -> Python Sandbox Escape RCE (CVE-2024-12366 / GHSA-vv2h-2w3q-3fx7) |
| [`ATR-2026-01980`](https://agentthreatrule.org/en/rules/ATR-2026-01980) | critical | observe | Agentic-Flow MCP Tool-Parameter OS Command Injection (GHSA-vcv2-r9jh-99m5) |
| [`ATR-2026-01982`](https://agentthreatrule.org/en/rules/ATR-2026-01982) | medium | production | dbt-mcp node_selection/resource_type Argument Injection (CVE-2026-44968) |
| [`ATR-2026-01983`](https://agentthreatrule.org/en/rules/ATR-2026-01983) | critical | production | MCP-for-Stata: Command Injection via log_file_name Parameter (CVE-2026-47708) |
| [`ATR-2026-01985`](https://agentthreatrule.org/en/rules/ATR-2026-01985) | critical | production | MCP Connect: Unauthenticated /bridge Endpoint Arbitrary Process Spawn RCE (GHSA-wvr4-3wq4-gpc5) |
| [`ATR-2026-01987`](https://agentthreatrule.org/en/rules/ATR-2026-01987) | critical | production | Langroid SQLChatAgent Prompt-to-SQL Remote Code Execution (CVE-2026-25879) |
| [`ATR-2026-02021`](https://agentthreatrule.org/en/rules/ATR-2026-02021) | critical | production | MCP Inspector Unauthenticated Proxy stdio Command Execution (CVE-2025-49596) |
| [`ATR-2026-02022`](https://agentthreatrule.org/en/rules/ATR-2026-02022) | high | production | CurXecute — Cursor .cursor/mcp.json Injected-Server Auto-Exec RCE (CVE-2025-54135) |
| [`ATR-2026-02023`](https://agentthreatrule.org/en/rules/ATR-2026-02023) | high | production | EscapeRoute — Filesystem MCP Server Directory Prefix-Bypass (CVE-2025-53110) |
| [`ATR-2026-02024`](https://agentthreatrule.org/en/rules/ATR-2026-02024) | high | production | EscapeRoute — Filesystem MCP Symlink Escape to LaunchAgent Persistence (CVE-2025-53109) |
| [`ATR-2026-02025`](https://agentthreatrule.org/en/rules/ATR-2026-02025) | high | production | MCP Full Schema Poisoning — Injected Directive in Non-Description inputSchema Field (MCP-11) |
| [`ATR-2026-02027`](https://agentthreatrule.org/en/rules/ATR-2026-02027) | critical | production | Diagnostic Content Remediation Command Injection (Agentjacking) |
| [`ATR-2026-02041`](https://agentthreatrule.org/en/rules/ATR-2026-02041) | critical | production | Shell Command Injection via Echo-Marker Proof-of-Concept in Tool Argument |
| [`ATR-2026-02102`](https://agentthreatrule.org/en/rules/ATR-2026-02102) | high | production | HTML/Script Injection in Tool Call Argument Targeting a Human-Approval Dashboard |
| [`ATR-2026-02141`](https://agentthreatrule.org/en/rules/ATR-2026-02141) | critical | production | Unsandboxed Command Execution via Dynamic MCP Server Config (command/args Injection) |
| [`ATR-2026-02145`](https://agentthreatrule.org/en/rules/ATR-2026-02145) | critical | production | Python Sandbox Escape via Generator/Coroutine Frame Object Introspection |
| [`ATR-2026-02193`](https://agentthreatrule.org/en/rules/ATR-2026-02193) | high | production | SSRF via Non-Canonical IPv6 Encoding of Loopback/Internal Addresses |
| [`ATR-2026-02194`](https://agentthreatrule.org/en/rules/ATR-2026-02194) | critical | production | Malicious Go init() Function Spawning a Process via a Code-Generation Tool |
| [`ATR-2026-02233`](https://agentthreatrule.org/en/rules/ATR-2026-02233) | high | production | Unscoped Destructive or Mass-Disclosure Database Operation Request via Natural Language |
| [`ATR-2026-02260`](https://agentthreatrule.org/en/rules/ATR-2026-02260) | high | production | Remediation-Framed Command Execution in Tool Response (Agentjacking) |
| [`ATR-2026-02263`](https://agentthreatrule.org/en/rules/ATR-2026-02263) | high | production | SQL Injection via Unparameterized Template-Expression Value in Workflow-Automation SQL Node (CVE-2026-59257) |
| [`ATR-2026-02350`](https://agentthreatrule.org/en/rules/ATR-2026-02350) | high | production | MCP JSON-RPC Message Carries Case-Duplicate name/arguments Keys to Smuggle an Unauthorized Tool Call |
| [`ATR-2026-02352`](https://agentthreatrule.org/en/rules/ATR-2026-02352) | high | production | Email Search/Reply Tool Argument Breaks Out of IMAP SEARCH Quoted String to Inject IMAP Commands |
| [`ATR-2026-02372`](https://agentthreatrule.org/en/rules/ATR-2026-02372) | high | production | Unsigned Automated Task/Validation Feed Invokes npm install / npx -y (Lifecycle-Script RCE) |
| [`ATR-2026-02376`](https://agentthreatrule.org/en/rules/ATR-2026-02376) | high | production | MCP Tool Description Defines a Common-Phrase Trigger to Forward Full Conversation History |
| [`ATR-2026-02403`](https://agentthreatrule.org/en/rules/ATR-2026-02403) | high | production | MCP Tool Returns Untrusted External Content Carrying Hidden Agent Instructions Without Spotlighting |
| [`ATR-2026-02514`](https://agentthreatrule.org/en/rules/ATR-2026-02514) | medium | production | MCP Server Descriptor URL Field Carries an HTML/Script Breakout Payload |
| [`ATR-2026-02542`](https://agentthreatrule.org/en/rules/ATR-2026-02542) | medium | production | Observability Query Tool Argument Appends a Pipeline Stage and Comments Out the Rest of the Query |
| [`ATR-2026-02557`](https://agentthreatrule.org/en/rules/ATR-2026-02557) | high | production | Shell Command Separator Inside a Path-Typed MCP Tool Argument |
| [`ATR-2026-02666`](https://agentthreatrule.org/en/rules/ATR-2026-02666) | high | production | Trusted Hostname Parked in the URL Userinfo So the Real Host Is Whatever Follows the At-Sign |
| [`ATR-2026-02668`](https://agentthreatrule.org/en/rules/ATR-2026-02668) | high | production | Branch or Tag Ref Name Carrying Shell Command Substitution in Tool Output |
| [`ATR-2026-02669`](https://agentthreatrule.org/en/rules/ATR-2026-02669) | medium | production | Query-Language Pipeline Stage Smuggled Into an Identifier-Typed Tool Parameter |
| [`ATR-2026-02682`](https://agentthreatrule.org/en/rules/ATR-2026-02682) | medium | production | XML/SVG Entity Expansion Bomb in Content Returned to an Agent |
| [`ATR-2026-02707`](https://agentthreatrule.org/en/rules/ATR-2026-02707) | high | production | Mail or Attachment Tool Argument Splits into a New Header via Embedded CRLF |

Next: **[29 · Troubleshooting](29-troubleshooting.md)**.
