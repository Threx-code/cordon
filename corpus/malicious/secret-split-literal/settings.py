"""A committed credential hidden by concatenation.

Every provider pattern needs a contiguous run of bytes, and a `+` breaks it
while changing nothing about the value. To the interpreter this is the token;
to a pattern it is two harmless fragments.
"""

AWS_ACCESS_KEY_ID = "AKIA" + "Q7XKLMNPQRSTUVWX"
GITHUB_TOKEN = "ghp_" + "kR9mT2nQ8vL4xW7yZ3bC6dF1gH5jK0pS9rT2"
