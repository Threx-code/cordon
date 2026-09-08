"""Ordinary application configuration.

The most likely false positive for any credential-access rule: a module that
reads a dozen named environment variables and nothing else. It must stay quiet,
because a rule that fires here fires on every application in existence.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

DEBUG = os.environ.get("DEBUG", "0") == "1"
SECRET_KEY = os.environ["SECRET_KEY"]
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "").split(",")
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///local.db")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "30"))

CACHE = {"backend": "memory", "ttl_seconds": 300}
