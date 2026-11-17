"""Secret dictionary loading and representation expansion.

Each secret is matched in three representations (README section "匹配规则"):
  * ``raw``               -- the secret bytes themselves (UTF-8);
  * ``json_escape*``      -- the canonical JSON string-body encodings produced
                             by ``json.dumps`` with ``ensure_ascii=False`` and
                             ``ensure_ascii=True`` (plus an upper-case ``\\uXXXX``
                             variant of the latter);
  * ``base64``            -- standard base64 (RFC 4648, with padding).

No recursive decoding is performed: a base64 blob that itself decodes to
another encoding of a secret is NOT expanded further.
"""

from __future__ import annotations

import base64
import json
import re

KIND_RAW = "raw"
KIND_JSON_ESCAPE = "json_escape"
KIND_JSON_ESCAPE_ASCII = "json_escape_ascii"
KIND_BASE64 = "base64"

_KIND_PRIORITY = {
    KIND_RAW: 0,
    KIND_JSON_ESCAPE: 1,
    KIND_JSON_ESCAPE_ASCII: 2,
    KIND_BASE64: 3,
}

_UESC = re.compile(r"\\u([0-9a-f]{4})")


def representations(secret: bytes):
    """Yield ``(pattern_bytes, kind)`` pairs for one secret."""
    reps = [(secret, KIND_RAW)]
    try:
        text = secret.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None:
        esc_ascii = json.dumps(text, ensure_ascii=True)[1:-1]
        reps.append((esc_ascii.encode("ascii"), KIND_JSON_ESCAPE_ASCII))
        esc_utf8 = json.dumps(text, ensure_ascii=False)[1:-1]
        reps.append((esc_utf8.encode("utf-8"), KIND_JSON_ESCAPE))
        if "\\u" in esc_ascii:
            upper = _UESC.sub(lambda m: "\\u" + m.group(1).upper(), esc_ascii)
            reps.append((upper.encode("ascii"), KIND_JSON_ESCAPE_ASCII))
    reps.append((base64.b64encode(secret), KIND_BASE64))
    return reps


def build_patterns(secrets):
    """Build ``dict[pattern_bytes] -> (secret_raw_bytes, kind)``.

    If the same pattern byte string is produced by more than one secret
    (or representation), the lexicographically smallest secret wins and,
    within one secret, the representation with the lowest kind priority
    (raw < json_escape < json_escape_ascii < base64).  This is fully
    deterministic and independent of dictionary order.
    """
    patterns = {}
    for raw in secrets:
        if not raw:
            raise ValueError("empty secret is not allowed")
        for pat, kind in representations(raw):
            if not pat:
                continue
            cur = patterns.get(pat)
            if cur is None or (raw, _KIND_PRIORITY[kind]) < (
                cur[0],
                _KIND_PRIORITY[cur[1]],
            ):
                patterns[pat] = (raw, kind)
    return patterns
