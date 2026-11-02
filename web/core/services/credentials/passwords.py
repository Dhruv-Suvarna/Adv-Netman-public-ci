"""Password generation constrained to characters accepted by the cEOS CLI."""
from __future__ import annotations

import secrets
import string


# No whitespace, quotes, backslash, backtick, dollar, or shell/CLI separators.
ALPHABET = string.ascii_letters + string.digits + "-_@%+="
DEFAULT_LENGTH = 32


def generate_password(length: int = DEFAULT_LENGTH) -> str:
    if not 24 <= length <= 64:
        raise ValueError("Device passwords must be between 24 and 64 characters.")
    # Force representation of the three broad classes while keeping every
    # selection cryptographically secure.  Shuffle with SystemRandom so the
    # class positions reveal nothing.
    chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("-_@%+="),
        *(secrets.choice(ALPHABET) for _ in range(length - 4)),
    ]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
