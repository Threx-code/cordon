"""A second stage hidden behind exclusive-or rather than base64.

No decoding library is imported, so nothing in the import list gives it away,
and the payload never appears as a literal for any pattern to match.
"""

BLOB = bytes([0x2B, 0x27, 0x26, 0x2A, 0x2D])
KEY = 0x42

plain = bytes(b ^ KEY for b in BLOB)
exec(plain.decode())
