"""Every static reversal the scanner knows, tried in turn (review 98, item 41)."""

from __future__ import annotations

from cordon_scanner.analysis.shared.decoded_view import DecodedView, ViewOverBudget
from cordon_scanner.analysis.shared.decoder_helpers import DecoderHelpers
from cordon_scanner.analysis.shared.deobfuscation import Layers, ObfuscatorIo, Recovery


class Deobfuscator:
    """Every reversal this module knows, tried in turn: the string array first, then the layers
    under it."""

    @staticmethod
    def recover(text: str, language: str | None) -> Recovery | None:
        """The text as written reversed; where that resolves nothing, its decoded view (note 18):
        `function \\u005f0x5e1f(){...}` is the obfuscator's array function to the language, and to
        the reversal now. A view past its budget leaves the raw result, and the obfuscation finding
        keeps its grade (the closed side: nothing is lifted to read lower)."""
        if language not in ("javascript", "typescript"):
            return None
        found = Deobfuscator._recover(text)
        if found is not None and found.resolved:
            return found
        try:
            readings = DecodedView.readings(text, language)
        except ViewOverBudget:
            return found
        for reading in readings[1:]:
            viewed = Deobfuscator._recover(reading)
            if viewed is not None and viewed.resolved:
                return viewed
        return found

    @staticmethod
    def _recover(text: str) -> Recovery | None:
        recovery = ObfuscatorIo.recover(text)
        base = recovery.text if recovery is not None else text
        helped = DecoderHelpers.recover(base)
        if helped is not None:
            recovery = Recovery(
                helped.text,
                helped.technique if recovery is None else recovery.technique,
                helped.resolved + (recovery.resolved if recovery is not None else 0),
                helped.remaining + (recovery.remaining if recovery is not None else 0),
            )
            base = recovery.text
        peeled, layers = Layers.peel(base)
        if recovery is None and not layers:
            return None
        if recovery is None:
            # Only what was decoded is new: the file itself is read as it is.
            return Recovery(peeled[len(base) :], "layers", layers, 0)
        return Recovery(peeled, recovery.technique, recovery.resolved + layers, recovery.remaining)
