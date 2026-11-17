"""JSON Lines record validation, sensitive-path redaction, dict matching.

Every record is fully validated (UTF-8, JSON syntax, size limit) before
anything is published.  Invalid or oversized records are quarantined;
the quarantine entry stores only the SHA-256 of the original line and
the error position -- never record content.

Redaction operates on the raw line bytes: non-sensitive JSON values keep
their exact original bytes (and therefore their semantics), and evidence
byte ranges refer directly to the original input.
"""

from __future__ import annotations

import json

from .engine import StreamRedactor

MAX_LINE_BYTES = 1048576  # 1 MiB, measured on the line without trailing "\n"
SENSITIVE_KEYS = frozenset({"password", "token", "secret"})

E_LINE_TOO_LONG = "E_LINE_TOO_LONG"
E_UTF8_INVALID = "E_UTF8_INVALID"
E_JSON_SYNTAX = "E_JSON_SYNTAX"


class LineError(Exception):
    """Validation failure for a single record.  Carries no record content."""

    def __init__(self, code, position):
        super().__init__(code)
        self.code = code
        self.position = position


class _NonStandardConstant(Exception):
    def __init__(self, constant):
        super().__init__("non-standard JSON constant")
        self.constant = constant


def _reject_constant(constant):
    raise _NonStandardConstant(constant)


def validate_line(content: bytes) -> None:
    """Raise LineError unless ``content`` is valid UTF-8 and valid JSON."""
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LineError(E_UTF8_INVALID, exc.start) from None
    try:
        json.loads(text, parse_constant=_reject_constant)
    except _NonStandardConstant as exc:
        prefix = text[: text.find(exc.constant)].encode("utf-8", "replace")
        raise LineError(E_JSON_SYNTAX, len(prefix)) from None
    except json.JSONDecodeError as exc:
        prefix = text[: exc.pos].encode("utf-8", "replace")
        raise LineError(E_JSON_SYNTAX, len(prefix)) from None


_WS = b" \t\r\n"


class _Scanner:
    """Records the byte span of every JSON value in a validated line.

    The line is validated with ``json.loads`` first, so this scanner may
    assume well-formed input.  ``values`` collects tuples of
    ``(path, value_span, content_span_or_None, is_string)`` where path
    elements are member keys (str) or array indices (int).
    """

    def __init__(self, buf: bytes):
        self.b = buf
        self.n = len(buf)
        self.values = []

    def skip_ws(self, i):
        b, n = self.b, self.n
        while i < n and b[i] in _WS:
            i += 1
        return i

    def string_token(self, i):
        # self.b[i] == '"'; returns (end, content_start, content_end)
        b = self.b
        j = i + 1
        while True:
            c = b[j]
            if c == 0x22:  # '"'
                return j + 1, i + 1, j
            if c == 0x5C:  # '\\'
                j += 2
            else:
                j += 1

    def value(self, i, path):
        b = self.b
        i = self.skip_ws(i)
        c = b[i]
        if c == 0x7B:  # '{'
            start = i
            i = self.skip_ws(i + 1)
            if b[i] == 0x7D:  # '}'
                i += 1
            else:
                while True:
                    i = self.skip_ws(i)
                    kend, _, _ = self.string_token(i)
                    key = json.loads(b[i:kend].decode("utf-8"))
                    i = self.skip_ws(kend)  # at ':'
                    i = self.value(i + 1, path + (key,))
                    i = self.skip_ws(i)
                    if b[i] == 0x2C:  # ','
                        i = self.skip_ws(i + 1)
                        continue
                    i += 1  # '}'
                    break
            self.values.append((path, (start, i), None, False))
            return i
        if c == 0x5B:  # '['
            start = i
            i = self.skip_ws(i + 1)
            if b[i] == 0x5D:  # ']'
                i += 1
            else:
                idx = 0
                while True:
                    i = self.value(i, path + (idx,))
                    i = self.skip_ws(i)
                    if b[i] == 0x2C:  # ','
                        i = self.skip_ws(i + 1)
                        idx += 1
                        continue
                    i += 1  # ']'
                    break
            self.values.append((path, (start, i), None, False))
            return i
        if c == 0x22:  # '"'
            end, cs, ce = self.string_token(i)
            self.values.append((path, (i, end), (cs, ce), True))
            return end
        # literal: number / true / false / null
        j = i
        n = self.n
        while j < n and b[j] not in _WS and b[j] not in b",}]":
            j += 1
        self.values.append((path, (i, j), None, False))
        return j

    def scan(self):
        self.value(0, ())


def _canonical_value(content: bytes, start: int, end: int) -> bytes:
    value = json.loads(content[start:end].decode("utf-8"))
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def process_line(content: bytes, patterns, id_factory):
    """Redact one validated JSON line.  Returns ``(output_bytes, evidence)``.

    Raises LineError if the record fails validation.  Evidence entries use
    line-relative byte offsets; the caller adds the line's absolute offset.
    """
    validate_line(content)
    scanner = _Scanner(content)
    scanner.scan()

    # 1. Sensitive JSON paths: any value whose member key (case-insensitive)
    #    is password / token / secret.  The whole value span is replaced by a
    #    quoted identifier, whatever its JSON type.
    sensitive = []
    for path, vspan, _cspan, _is_str in scanner.values:
        if path and isinstance(path[-1], str) and path[-1].lower() in SENSITIVE_KEYS:
            sensitive.append((vspan[0], vspan[1], path[-1]))
    sensitive.sort()
    top = []
    for span in sensitive:
        if not any(p[0] <= span[0] and span[1] <= p[1] for p in top):
            top.append(span)
    sensitive = top

    replacements = []  # (start, end, replacement_bytes, evidence_dict)
    for start, end, key in sensitive:
        canon = _canonical_value(content, start, end)
        ident = id_factory.for_path_value(canon)
        replacements.append((
            start,
            end,
            b'"' + ident.encode("ascii") + b'"',
            {
                "record": None,
                "byte_start": start,
                "byte_end": end,
                "id": ident,
                "source": "json_path",
                "key": key,
            },
        ))

    # 2. Dictionary matching, restricted to the raw content spans of string
    #    values that are not already covered by a sensitive path.  Keys,
    #    numbers and structural bytes are never touched, so the redacted
    #    line stays valid JSON with identical non-sensitive semantics.
    if patterns:
        allowed = []
        for path, vspan, cspan, is_str in scanner.values:
            if not is_str:
                continue
            if any(s <= cspan[0] and cspan[1] <= e for s, e, _k in sensitive):
                continue
            allowed.append(cspan)
        red = StreamRedactor(patterns, id_factory.for_secret)
        red.feed(content, final=True)
        for start, end, key, kind in red.evidence:
            if any(cs <= start and end <= ce for cs, ce in allowed):
                ident = id_factory.for_secret(key)
                replacements.append((
                    start,
                    end,
                    ident.encode("ascii"),
                    {
                        "record": None,
                        "byte_start": start,
                        "byte_end": end,
                        "id": ident,
                        "source": "dictionary",
                        "representation": kind,
                    },
                ))

    replacements.sort(key=lambda r: r[0])
    out = bytearray()
    frontier = 0
    evidence = []
    for start, end, rep, ev in replacements:
        out += content[frontier:start]
        out += rep
        frontier = end
        evidence.append(ev)
    out += content[frontier:]
    return bytes(out), evidence
