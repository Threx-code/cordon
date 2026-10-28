"""What code can do, as the capability detector names it: run a command, reach the network, read a
credential, write outside its own tree, hide itself, and the rest. A finding is a combination of
capabilities in one place, graded by where it sits and when it runs; each capability here says what
it covers and what it deliberately does not. Also how a rule's pattern is matched.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class MatchKind(enum.StrEnum):
    """How a rule decides whether it applies. Selects the matching strategy."""

    LITERAL = "literal"
    REGEX = "regex"
    ENTROPY = "entropy"
    STRUCTURAL = "structural"
    AST = "ast"
    GRAPH = "graph"
    COMPOSITE = "composite"


class Capability(enum.StrEnum):
    """Portable behavioural primitives.

    This enum is the mechanism that makes the detection engine language-agnostic,
    and it is the single most important abstraction in the system.

    Signature-based detection does not generalise. A rule written against a
    specific campaign's indicators stops working the moment the campaign changes
    a string, and it never worked for any other language in the first place.

    Capability-based detection does generalise, because the primitives are forced
    by the objective rather than chosen by the attacker. To exfiltrate data, code
    must read something sensitive and send it somewhere. To run a second stage,
    it must decode a payload and execute it. Those requirements hold in every
    language, and there are only a handful of them.

    So each language plugin supplies patterns for these names, and composite rules
    are written **once** against them. Adding a language means adding pattern data,
    not rewriting the rule set: a new ecosystem inherits every behavioural rule the
    moment its primitives are defined.

    The set grows when a primitive turns out to have been standing in for a different
    act, and five of the fifteen arrived that way -- `DECOMPRESS` out of `DECODE`,
    `DESERIALIZE` out of `EXECUTE`, `WALLET` out of `MINE`, `DELAY` out of
    `ANTI_ANALYSIS`, `RECONNAISSANCE` out of `CREDENTIAL`. Each was found by a composite whose own message claimed something
    its capabilities could not support, and splitting the primitive is what this model
    does instead of adding an exception to the rule that reads it.
    """

    DECODE = "decode"
    """Turns encoded data back into code or commands."""

    EXECUTE = "execute"
    """Evaluates code from a string: `eval`, `exec`, a script engine, `sh -c`."""

    DECOMPRESS = "decompress"
    """Expands a compressed stream: gzip, deflate, zlib, brotli, an archive.

    Separated from `DECODE` for the same reason `DESERIALIZE` is separated from
    `EXECUTE`: a composite was reading two different acts as one. Compression is not
    concealment. A gzip stream is how a release is shipped, not a way to hide code
    from review -- nobody chooses it to evade a scanner, because every scanner can
    read it and the ratio gives it away. What hides a payload is base64, hex or
    exclusive-or in a source literal.

    Measured: `SUSPECT.DECODE_EXEC.001` produced 184 findings across 38 repositories
    that carried three or fewer, and the shape in every language was a self-updater or
    a build tool -- unpack a release archive, run a binary. `lapce`, `schollz/croc`,
    `DioxusLabs/dioxus` and `dotnet/maui` are all exactly that, and each was reported
    as a second-stage loader.

    It remains a layer where a layer is the claim: `SUSPECT.DECODE_CHAIN.001` is about
    stacking encodings to defeat inspection, and base64 around a gzip blob is the
    commonest stack there is.
    """

    DESERIALIZE = "deserialize"
    """Turns a serialised byte stream back into live objects.

    `pickle.loads`, `Marshal.load`, `unserialize`, `readObject`. Every one of these
    is code execution by design -- the format names classes and calls their
    constructors -- and for years this enum said so by listing them under `EXECUTE`.

    They are separated because one composite could not survive the conflation.
    `SUSPECT.DECODE_EXEC.001` asks for a decode and an execution in the same file and
    says, in its own message, that the payload "is not present as code until runtime".
    A deserializer paired with a decode is not two acts: base64 around a pickle is how
    you keep a pickle in a text column, and it is the only way to do it. Django's
    database cache backend, Celery's serialization helpers and scikit-learn's dataset
    loader are all spelled exactly that way, and all three were reported at HIGH --
    three of the most-installed Python packages there are.

    What makes deserialization dangerous is the SOURCE of the bytes, which is why this
    primitive still counts towards every composite where another capability supplies an
    untrusted one. A pickle load applied to the body of an HTTP response is a dropper;
    the same call applied to a row the application itself wrote is a cache.
    """

    SPAWN = "spawn"
    """Starts a process or invokes a shell."""

    CREDENTIAL = "credential"
    """Reads environment variables, key material, or cloud and registry tokens."""

    RECONNAISSANCE = "reconnaissance"
    """Identifies the machine it is running on: hostname, user, working directory.

    The fifth primitive to arrive by splitting one that stood in for a different
    act, and the clearest case of the five. `socket.gethostname()`,
    `getpass.getuser()`, `os.getcwd()` and `os.environ["COMPUTERNAME"]` are not
    credentials -- nothing authenticates with a hostname -- so `CREDENTIAL` could
    not be widened to hold them without diluting every composite that reads it.
    Nor are they egress, or execution. They were simply unlabelled.

    Measured against the ASE 2023 dataset of real malicious PyPI packages, this is
    the shape of the install-time beacon, and it is written the same way every
    time: `fuzywuzy` and `requesgs` read `os.environ['COMPUTERNAME']` and
    concatenate it into a GET; `antchain-sdk-pcc` reads `socket.gethostname()`,
    `os.getcwd()` and `getpass.getuser()` and passes them as `params`;
    `bytedbackground` sends `socket.gethostname()`. Eleven of the forty-one
    packages still missed after the encoded-command and decryption work were this,
    and none of them produced a single finding, because reading the hostname was
    not an act the model had a name for.

    On its own it is close to meaningless -- half the diagnostics code ever written
    reports a hostname -- which is why the composite that reads it requires an
    install hook and egress as well. A build script has no reason to tell anybody
    which machine it is building on."""

    EGRESS = "egress"
    """Opens an outbound network connection."""

    PERSIST = "persist"
    """Installs itself somewhere that survives a reboot or a new shell."""

    DYNAMIC_DISPATCH = "dynamic_dispatch"
    """Reaches a function by a name computed at runtime.

    Emitted when reflective access -- `getattr`, `globals()[...]`,
    `__import__` -- is used with an argument that could not be resolved
    statically, into a namespace where that has no ordinary purpose.

    It exists so that evading the name match costs something. An attacker who
    writes `getattr(os, decode(blob))()` defeats every pattern that looks for
    `os.system`, and the shape they are forced into is itself the evidence:
    reflective dispatch on a computed name into `os` or `subprocess` has almost
    no benign analogue, while `getattr(self, method_name)` on a plugin object
    has plenty -- which is why the namespace is part of the condition.
    """

    FETCH_EXEC = "fetch_exec"
    """Network output flows directly into an interpreter.

    Distinct from `egress` plus `spawn`, and that distinction is the point.
    Those two co-occurring describe an enormous amount of ordinary operations
    code -- a deploy script that pushes and posts to Slack, a health check that
    runs `systemctl` and pings a status page -- because nothing in the pair
    requires the thing executed to be the thing fetched.

    A pipe does require it. `curl ... | sh` is not two capabilities that happen
    to share a file; it is one construct whose output is the other's input, and
    that is the actual dropper shape rather than a proxy for it.
    """

    ANTI_ANALYSIS = "anti_analysis"
    """Checks whether it is being observed, and can act on the answer.

    Sandbox and virtual-machine probes, debugger checks, CI and hostname gating.
    Individually each has a benign use: software legitimately behaves differently
    in CI.

    What has no benign use is the combination with a payload. Code that asks
    "am I being watched?" and then decodes or reaches the network is describing
    its own evasion, and the check is the part that cannot be explained away --
    an ordinary program has no reason to care.
    """

    DELAY = "delay"
    """Waits a long time, or schedules work far ahead.

    Separated from `ANTI_ANALYSIS` for the fourth time the same mistake was found.
    `SUSPECT.ANTI_ANALYSIS.001` is titled "Behaviour gated on whether it is being
    observed", and a sleep gates nothing: it is not a check, and the answer to "am I
    being watched?" is what every other member of that family produces.

    Measured across two sampling passes, every delay-only finding was a wait:
    `unsloth` hangs a thread with `while True: time.sleep(3600)` to keep a partial
    download's handle open and prints a heartbeat with
    `for _ in range(10000): time.sleep(300)`; `mongodb` keeps a cross-compilation
    container alive with `while true; do sleep 3600; done`; `Azure/azure-cli` waits five
    minutes between checks of a package repository. Four for four, and none of the
    malicious corpus samples uses a sleep at all -- the one that gates on the analysis
    environment tests `os.environ["CI"]`, the hostname and `sys.gettrace`.

    So nothing consumes this yet, and `CAP.ANTI.DELAY.001` reports on its own at the
    INFO severity it has always declared. A delay beside a payload is still visible in
    the report; what it no longer does is make the payload a high-severity finding about
    evasion, which is a claim the delay cannot support.
    """

    WALLET = "wallet"
    """A cryptocurrency payout address.

    Separated from `MINE` for the third time the same mistake was found: a primitive
    was standing in for a different act. An address is a DESTINATION, not an activity.
    `SUSPECT.CRYPTOMINER.001` says, in its own message, that the file "references a
    mining pool protocol, a pool host or a miner binary" -- and a bare address is none
    of those, while satisfying the rule on its own at HIGH.

    What a bare address actually is: a donation button (`ScreenToGif`'s
    `DonateSettings.xaml`, SmartTube's `donations.xml`), a wallet or a node's own source
    (`bitcoin/bitcoin`, twice), or a base58-shaped run inside a large data file that
    means nothing at all. The rule already carried a path exclusion for `FUNDING.json`
    for exactly this reason, which was the shape of the problem showing through.

    Cryptojacking carries a pool. `CAP.MINE.PROTOCOL.001` is the decisive evidence and
    stratum exists for mining and nothing else; an address corroborates it and does not
    replace it.
    """

    TARGETING = "targeting"
    """Decides what to do from where the machine is: its timezone, locale or country.

    Protestware and state-targeted payloads share one shape: a check of the region, then an
    act reserved for machines that pass it. node-ipc asked a geolocation service for the
    country and overwrote files for two of them; es5-ext and its successors read the
    timezone. The check alone is ordinary in software that localises, which is why it is a
    primitive and not a finding: it matters beside a destructive or executing act.
    """

    DESTROY = "destroy"
    """Deletes or wipes data wholesale: a recursive delete, a disk overwritten, a filesystem made.

    A cleanup script deletes recursively too, so this is a primitive: what makes it a finding is
    what it is aimed at, or what decided to run it.
    """

    AGENT = "agent"
    """Starts the machine's AI coding agent with its permission checks switched off.

    `claude --dangerously-skip-permissions`, `q --trust-all-tools`, `gemini --yolo`: the agent then
    reads, runs and deletes whatever its prompt says, with nobody asked. Two incidents made this a
    primitive. The Nx "s1ngularity" release (August 2025) ran every agent it found that way to
    inventory secrets and wallets; the compromised Amazon Q extension 1.84.0 (July 2025) ran `q`
    that way with a prompt to wipe the home directory and the AWS account. Neither needs code of
    its own to do harm: the agent is the payload, and the prompt is the program.

    An orchestrator that drives agents on purpose does the same thing, which is why this is a
    primitive: what makes it a finding is the instruction it carries, or what decided to run it.
    """

    FLOW = "flow"
    """A value followed from where it is read to where it leaves (`detect/js_flow.py`).

    Not a primitive of its own but evidence of how two primitives connect, kept apart for the same
    reason as the splits above: tagged `egress`, a followed flow also satisfied every composite
    that asks only for a network call somewhere in the file, and turned bundled editor extensions
    into install-time spelled-code findings (review 98, about twenty Open VSX agents). Only the
    composites written for flows read it.
    """

    MINE = "mine"
    """Consumes compute for a cryptocurrency.

    Unlike the other primitives this is closer to a signature than a
    capability -- mining is identifiable by its pools, protocols and wallet
    formats rather than by a language operation. It is modelled as a capability
    anyway so that it composes with the rest: mining inside an install hook is
    a different finding from mining in an application, and the existing context
    machinery already knows how to say that.
    """


__all__ = ["Capability", "MatchKind"]
