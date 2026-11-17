"""Salted HMAC replacement identifiers.

One salt per batch (one CLI run).  The same secret material maps to the
same identifier within a batch; different batches (different salts) map
to different identifiers.  Identifiers carry no secret material and the
factory never logs or persists plaintext secrets.
"""

from __future__ import annotations

import hashlib
import hmac


class IdFactory:
    def __init__(self, salt: bytes):
        if not salt:
            raise ValueError("salt must be non-empty")
        self._salt = salt
        self._cache = {}

    def ident(self, material: bytes) -> str:
        value = self._cache.get(material)
        if value is None:
            digest = hmac.new(self._salt, material, hashlib.sha256).hexdigest()
            value = "[REDACTED#" + digest[:16] + "]"
            self._cache[material] = value
        return value

    def for_secret(self, secret_raw: bytes) -> str:
        """Identifier for a dictionary secret (canonical raw bytes)."""
        return self.ident(b"dict\x00" + secret_raw)

    def for_path_value(self, canonical_value: bytes) -> str:
        """Identifier for a sensitive JSON-path value (canonical JSON bytes)."""
        return self.ident(b"path\x00" + canonical_value)
