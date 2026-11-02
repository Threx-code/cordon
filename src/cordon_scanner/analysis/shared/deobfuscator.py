"""Every static reversal the scanner knows, tried in turn (review 98, item 41)."""

from __future__ import annotations

from cordon_scanner.analysis.shared.decoder_helpers import DecoderHelpers
from cordon_scanner.analysis.shared.deobfuscation import Layers, ObfuscatorIo, Recovery


class Deobfuscator:
    """Every reversal this module knows, tried in turn: the string array first, then the layers
    under it."""

    @staticmethod
    def recover(text: str, language: str | None) -> Recovery | None:
        if language not in ("javascript", "typescript"):
            return None
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
