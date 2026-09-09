"""A credential helper storing its own token.

Writes to the keychain rather than reading somebody else's, and nothing leaves
the machine. This is what the software that owns a store looks like.
"""

import keyring

SERVICE = "example-cli"


def save(username: str, token: str) -> None:
    keyring.set_password(SERVICE, username, token)


def clear(username: str) -> None:
    keyring.delete_password(SERVICE, username)
