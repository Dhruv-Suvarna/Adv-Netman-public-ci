"""Sanitization of a captured running configuration BEFORE anything is persisted (one-time legacy bootstrap).

A legacy baseline stores what is actually running, and a running configuration can carry credential material (local-user password hashes,
enable secrets, SNMPv3 keys, TACACS / RADIUS / routing-protocol keys ...).  Nothing secret-bearing may reach the database, the manifest, a
Git artifact, a log, an audit event or an export.  This module is the ONE place that decides what "secret-bearing" means, and it does so by
REUSING the project's existing detector (``raw_configlets.static_gate.secret_patterns``, the same one the Phase-18 Raw Configlet gate and the
Phase-19 bundle integrity check use) instead of growing a second, slightly different rule set.

    line flagged by the detector  ->  the line is kept up to (not including) the first VALUE token that makes it secret-shaped; that token and
                                      the rest of the line become ``<REDACTED>``.   ``username admin ... secret sha512 $6$abc``
                                      becomes ``username admin ... secret <REDACTED>``: the structure and provenance ("a local user with a
                                      secret exists") are preserved, the secret is not.
    PEM / private-key blocks      ->  replaced by one ``<REDACTED-PEM-BLOCK>`` line.
    anything still not clean      ->  the whole line becomes ``<REDACTED-LINE>`` (fail closed).

Two facts are recorded, never hidden:

* the stored text is NOT byte-identical to the device configuration: it is a SANITIZED representation.  ``redacted_lines`` and the pattern
  NAMES (never the matched text) are returned so the artifact can say so;
* a change to ONLY a redacted value (for example rotating a password) is therefore not visible to a digest of the sanitized text.  The
  baseline represents managed configuration SEMANTICS, not literal secret bytes (documented limitation).

Determinism: the same raw input always gives the same sanitized text (no randomness, no time, no dict ordering).  Comment-only lines
(``!`` separators / ``! Command:`` headers) and blank lines are dropped, trailing whitespace is stripped and line endings are normalized,
so cosmetic noise never looks like drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..raw_configlets import static_gate

# A STORED BASELINE is stricter than the Raw Configlet gate, which deliberately exempts free text (``description`` ...) and does not know the bare
# ``key`` keyword (``tacacs-server key 7 ...``).  Over-redaction is safe (it only hides a name); a leaked credential is not.
EXTRA_SECRET_TOKENS = frozenset({"key", "psk", "passphrase", "shared-secret", "sharedsecret"})
REDACTED = "<REDACTED>"
REDACTED_LINE = "<REDACTED-LINE>"
REDACTED_PEM = "<REDACTED-PEM-BLOCK>"
MAX_SECTION_BYTES = 1024 * 1024      # one sanitized section (the live read is already bounded to 2 MB)
_PEM_BEGIN, _PEM_END = "-----BEGIN ", "-----END "


class SanitizeError(ValueError):
    """The text cannot be sanitized safely (for example it is too large); the capture must fail rather than store it."""


@dataclass
class SanitizedText:
    text: str
    raw_lines: int
    kept_lines: int
    redacted_lines: int
    patterns: list = field(default_factory=list)   # sorted, unique detector pattern NAMES (never matched text)


def detect(line: str) -> list[str]:
    """Names of every secret-shaped construct in one statement: the shared detector PLUS the stricter baseline rules (see EXTRA_SECRET_TOKENS;
    free-text commands are scanned too).  Pattern names only -- never the matched text."""
    names = set(static_gate.secret_patterns(line))
    tokens = line.split()
    if tokens:
        head = tokens[1].lower() if tokens[0].lower() == "no" and len(tokens) > 1 else tokens[0].lower()
        if head in static_gate.FREE_TEXT_COMMANDS:      # the shared gate skips these lines entirely; a stored baseline must not
            names |= set(static_gate.secret_patterns(" ".join(tokens[1:])))
        names |= {f"KEYWORD:{t.lower()}" for t in tokens[:-1] if t.lower() in EXTRA_SECRET_TOKENS}   # a keyword is secret-shaped only when a VALUE follows
    return sorted(names)


def is_clean(line: str) -> bool:
    """True when nothing secret-shaped remains once the redaction markers are removed.  (The detector only flags a keyword when a VALUE follows
    it, so ``secret <REDACTED>`` is clean while ``secret sha512 $6$abc`` is not.)"""
    return not detect(line.replace(REDACTED, ""))


def _redact_line(line: str) -> tuple[str, list[str]]:
    """-> (sanitized line, detector pattern names).  An unflagged line is returned unchanged."""
    names = detect(line)
    if not names:
        return line, []
    indent = line[: len(line) - len(line.lstrip())]
    tokens = line.split()
    for cut in range(len(tokens)):
        if detect(" ".join(tokens[: cut + 1])):   # the first value token that makes the statement secret-shaped
            candidate = indent + " ".join([*tokens[:cut], REDACTED])
            if is_clean(candidate):
                return candidate, names
            break
    return REDACTED_LINE, names          # fail closed: the structure could not be preserved safely


def sanitize_config(raw: str) -> SanitizedText:
    """Sanitize and normalize one captured configuration text.  Pure and deterministic."""
    if not isinstance(raw, str):
        raise SanitizeError("NOT_TEXT")
    lines_in = raw.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    kept, patterns, redacted, in_pem = [], set(), 0, False
    for original in lines_in:
        line = original.rstrip()
        if in_pem:
            if _PEM_END in line:
                in_pem = False
            continue
        if not line.strip() or line.lstrip().startswith("!"):
            continue            # blank lines and comment-only lines (section separators, ``! Command:`` headers) carry no configuration
        if _PEM_BEGIN in line:   # any PEM block (key OR certificate) is replaced whole: a private key must never be stored, and telling them apart is not worth a leak
            patterns.add("PEM_BLOCK")
            redacted += 1
            kept.append(REDACTED_PEM)
            in_pem = _PEM_END not in line
            continue
        sanitized, names = _redact_line(line)
        if names:
            patterns |= set(names)
            redacted += 1
        kept.append(sanitized)
    text = "\n".join(kept) + ("\n" if kept else "")
    if len(text.encode("utf-8")) > MAX_SECTION_BYTES:
        raise SanitizeError("SECTION_TOO_LARGE")
    return SanitizedText(text=text, raw_lines=len(lines_in), kept_lines=len(kept), redacted_lines=redacted, patterns=sorted(patterns))


def residual_secret_lines(text: str) -> list[dict]:
    """Integrity check over STORED text: lines that are still secret-shaped after the redaction markers are removed.  Line numbers and pattern
    names only -- never the matched text.  Bounded."""
    hits = []
    for number, line in enumerate(str(text).splitlines(), start=1):
        names = detect(line.replace(REDACTED, ""))
        if names:
            hits.append({"line": number, "patterns": names})
            if len(hits) >= 20:
                break
    return hits
