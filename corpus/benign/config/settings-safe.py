"""Configuration read from the environment, with placeholder defaults.

The placeholders exist to prove the secret detector distinguishes a real
credential from an example. Every value here is deliberately fake.
"""

import os

API_KEY = os.environ.get("API_KEY", "your-api-key-here")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "changeme")
EXAMPLE_TOKEN = "sk_test_EXAMPLE_NOT_A_REAL_KEY"

# A content hash, not a secret. Low entropy over a hex alphabet.
CONTENT_SHA = "d41d8cd98f00b204e9800998ecf8427e"
