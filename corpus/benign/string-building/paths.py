"""Ordinary code that builds strings out of pieces.

This is what concatenation is normally for, and it is far more common than the
malicious use. None of it reaches the entropy floor, and none of it carries a
credential prefix.
"""

PREFIX = "cordon" + "-" + "scanner"
CACHE_DIR = "/var/cache/" + PREFIX
MESSAGE = "could not read " + "the manifest, so its hooks were not identified"
SEPARATOR = "-" * 40
QUERY = "SELECT id, name" + " FROM packages" + " WHERE ecosystem = ?"
