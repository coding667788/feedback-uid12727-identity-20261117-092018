"""Byte-level streaming secret matcher.

Overlap resolution rule (documented in README.md):
  1. a longer match wins over a shorter one;
  2. equal length -> the lexicographically smaller matched byte string wins;
  3. same bytes at different positions -> the earlier position wins.
Selected matches never overlap and are emitted left to right.

Streaming contract: feeding the same byte stream in any chunking yields
exactly the same output and evidence as one-shot processing.  A match is
only committed once every match that could overlap it is known, which is
guaranteed by holding back ``max_pattern_len - 1`` unprocessed bytes.
"""

from __future__ import annotations


def resolve_matches(matches):
    """Select the winning non-overlapping matches.

    ``matches`` is an iterable of ``(start, end, pattern, key, kind)``.
    Returns the selected matches sorted by start position.
    """
    ordered = sorted(matches, key=lambda m: (-(m[1] - m[0]), m[2], m[0]))
    selected = []
    for m in ordered:
        s, e = m[0], m[1]
        if all(e <= t[0] or s >= t[1] for t in selected):
            selected.append(m)
    selected.sort(key=lambda m: m[0])
    return selected


class StreamRedactor:
    """Incremental byte redactor with deterministic overlap resolution.

    ``patterns``: dict mapping pattern bytes -> ``(key_bytes, kind)``.
    ``id_fn``: callable mapping key bytes -> replacement identifier str.
    """

    def __init__(self, patterns, id_fn):
        self._id_fn = id_fn
        self._by_first = {}
        max_len = 1
        for pat, (key, kind) in patterns.items():
            if not pat:
                continue
            self._by_first.setdefault(pat[0], []).append((pat, key, kind))
            if len(pat) > max_len:
                max_len = len(pat)
        for lst in self._by_first.values():
            lst.sort(key=lambda t: (-len(t[0]), t[0]))
        self._max_len = max_len
        self._buf = bytearray()
        self._base = 0          # absolute offset of self._buf[0]
        self._scanned = 0       # buf positions [0, _scanned) already scanned
        self._matches = []      # known matches, absolute coordinates
        self.out = bytearray()
        self.evidence = []      # (start, end, key, kind), absolute offsets
        self._finalized = False

    def _scan_at(self, pos):
        hit = self._by_first.get(self._buf[pos])
        if not hit:
            return
        n = len(self._buf)
        base = self._base
        for pat, key, kind in hit:
            end = pos + len(pat)
            if end <= n and self._buf[pos:end] == pat:
                self._matches.append((base + pos, base + end, pat, key, kind))

    def feed(self, chunk: bytes, final: bool = False):
        if self._finalized:
            raise RuntimeError("feed() after finalization")
        if chunk:
            self._buf += chunk
        n = len(self._buf)
        limit = n if final else max(0, n - (self._max_len - 1))
        while self._scanned < limit:
            self._scan_at(self._scanned)
            self._scanned += 1
        # A winner can be committed once no unknown (future) match could
        # overlap it.  Unknown matches start at >= base + limit, so any
        # winner ending at or before base + limit is final.
        winners = resolve_matches(self._matches)
        committed = [w for w in winners if final or w[1] <= self._base + limit]
        if committed:
            frontier = 0
            for start, end, _pat, key, kind in committed:
                s = start - self._base
                e = end - self._base
                self.out += self._buf[frontier:s]
                self.out += self._id_fn(key).encode("ascii")
                self.evidence.append((start, end, key, kind))
                frontier = e
            self._matches = [
                m for m in self._matches
                if all(m[1] <= c[0] or m[0] >= c[1] for c in committed)
            ]
            del self._buf[:frontier]
            self._base += frontier
            self._scanned -= frontier
        if final:
            self.out += self._buf
            self._buf = bytearray()
            self._matches = []
            self._finalized = True
