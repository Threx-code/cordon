"""Ordinary configuration module: named env reads, no execution, no egress."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEBUG = os.environ.get("DEBUG", "0") == "1"
SECRET_KEY = os.environ["SECRET_KEY"]
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "").split(",")
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///db.sqlite3")

CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
