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
_INVISIBLE: Final = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿︀-️\U000e0000-\U000e007f]")

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
    r"\|\s*(?:curl|wget|nc|ncat|netcat|socat)\b|\b(?:curl|wget)\b[^\n|]{0,80}(?:-d\s*@|--data(?:-binary)?\s*@|-T\s|--upload-file)",
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
        if (
            _SEND.search(normal)
            and _URL.search(normal)
            and (_COVERT.search(normal) or _USER_INPUT.search(normal))
        ):
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
    def find(text: str) -> list[Intent]:
        found: list[Intent] = []
        for start, sentence in InstructionIntent.sentences(text[:MAX_TEXT]):
            kind = InstructionIntent.classify(sentence)
            if kind is not None:
                found.append(Intent(kind, sentence.strip()[:240], start))
        return found

    @staticmethod
    def chained_paths(text: str) -> list[tuple[int, str]]:
        """`(offset, path)` for each "follow the instructions in <path>" the text contains."""
        return [
            (m.start(), m.group("path"))
            for m in _CHAIN.finditer(InstructionIntent.normalise(text[:MAX_TEXT]))
        ]


__all__ = ["InstructionIntent", "Intent"]
