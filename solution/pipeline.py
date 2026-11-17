"""Batch pipeline: case loading, streaming orchestration, result assembly."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
from pathlib import Path

from .engine import StreamRedactor
from .ids import IdFactory
from .jsonline import (
    E_LINE_TOO_LONG,
    E_UTF8_INVALID,
    MAX_LINE_BYTES,
    LineError,
    process_line,
)
from .secretspec import build_patterns

SCHEMA_CASES = "redactor-cases/1"
SCHEMA_RESULT = "redactor-result/1"

E_BAD_CONFIG = "E_BAD_CONFIG"
E_INPUT_NOT_FOUND = "E_INPUT_NOT_FOUND"
E_UNSUPPORTED_FORMAT = "E_UNSUPPORTED_FORMAT"

DEFAULT_CHUNK_SIZES = (65536,)


class ConfigError(Exception):
    """Fatal configuration problem; the CLI exits with code 2."""


def salt_from_seed(seed):
    """Deterministic per-batch salt.  ``None`` -> random (non-replayable)."""
    if seed is None:
        return os.urandom(16)
    return random.Random(seed).randbytes(16)


def iter_chunks(data: bytes, chunk_sizes=None):
    sizes = list(chunk_sizes) if chunk_sizes else list(DEFAULT_CHUNK_SIZES)
    for s in sizes:
        if not isinstance(s, int) or s <= 0:
            raise ConfigError("chunk_sizes must be positive integers")
    i = 0
    k = 0
    n = len(data)
    while i < n:
        s = sizes[k % len(sizes)]
        k += 1
        yield data[i : i + s]
        i += s


def iter_lines(chunks):
    """Yield ``(absolute_offset, line_content_without_LF)`` from byte chunks.

    Chunk boundaries may fall anywhere (mid UTF-8 sequence, mid escape,
    mid secret); lines are reassembled before per-record processing.
    A final line without a trailing newline is still yielded.
    """
    buf = bytearray()
    base = 0
    scan = 0
    for chunk in chunks:
        buf += chunk
        while True:
            i = buf.find(b"\n", scan)
            if i < 0:
                scan = len(buf)
                break
            yield base, bytes(buf[:i])
            del buf[: i + 1]
            base += i + 1
            scan = 0
    if buf:
        yield base, bytes(buf)


def _quarantine_record(lineno, code, position, content):
    # The quarantine stores only the hash of the original line and the
    # error position -- never any record content.
    return {
        "line": lineno,
        "status": "quarantined",
        "error_code": code,
        "error_position": position,
        "line_length": len(content),
        "line_sha256": hashlib.sha256(content).hexdigest(),
    }


class Redactor:
    """One batch: a fixed secret dictionary and a fixed salt."""

    def __init__(self, secrets, salt):
        self.patterns = build_patterns(secrets)
        self.ids = IdFactory(salt)

    # -- plain UTF-8 text ------------------------------------------------
    def redact_text(self, data: bytes, chunk_sizes=None):
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            return {
                "status": "quarantined",
                "error_code": E_UTF8_INVALID,
                "error_position": exc.start,
                "input_length": len(data),
                "input_sha256": hashlib.sha256(data).hexdigest(),
                "output": None,
                "evidence": [],
            }
        red = StreamRedactor(self.patterns, self.ids.for_secret)
        for chunk in iter_chunks(data, chunk_sizes):
            red.feed(chunk)
        red.feed(b"", final=True)
        evidence = [
            {
                "record": None,
                "byte_start": s,
                "byte_end": e,
                "id": self.ids.for_secret(k),
                "source": "dictionary",
                "representation": kind,
            }
            for (s, e, k, kind) in red.evidence
        ]
        return {"status": "ok", "output": bytes(red.out), "evidence": evidence}

    # -- JSON Lines -------------------------------------------------------
    def redact_jsonl(self, data: bytes, chunk_sizes=None):
        out = bytearray()
        records = []
        lines = iter_lines(iter_chunks(data, chunk_sizes))
        for lineno, (offset, content) in enumerate(lines, 1):
            if not content.strip(b" \t\r"):
                records.append({"line": lineno, "status": "blank"})
                continue
            if len(content) > MAX_LINE_BYTES:
                records.append(
                    _quarantine_record(lineno, E_LINE_TOO_LONG, MAX_LINE_BYTES, content)
                )
                continue
            try:
                new_line, evidence = process_line(content, self.patterns, self.ids)
            except LineError as le:
                records.append(_quarantine_record(lineno, le.code, le.position, content))
                continue
            out += new_line
            out += b"\n"
            for entry in evidence:
                entry["record"] = lineno
                entry["byte_start"] += offset
                entry["byte_end"] += offset
            records.append({"line": lineno, "status": "published", "evidence": evidence})
        return {"status": "ok", "output": bytes(out), "records": records}


# ---------------------------------------------------------------------------
# cases.json loading
# ---------------------------------------------------------------------------

def load_secrets(cfg, base_dir: Path):
    secrets = []
    for item in cfg.get("secrets", []):
        if not isinstance(item, str):
            raise ConfigError("'secrets' entries must be strings")
        secrets.append(item.encode("utf-8"))
    for item in cfg.get("secrets_base64", []):
        if not isinstance(item, str):
            raise ConfigError("'secrets_base64' entries must be strings")
        try:
            secrets.append(base64.b64decode(item, validate=True))
        except Exception:
            raise ConfigError("invalid base64 in 'secrets_base64'") from None
    if "secrets_file" in cfg:
        path = Path(cfg["secrets_file"])
        if not path.is_absolute():
            path = base_dir / path
        try:
            blob = path.read_bytes()
        except OSError:
            raise ConfigError("secrets_file not found") from None
        for line in blob.split(b"\n"):
            line = line.rstrip(b"\r")
            if line:
                secrets.append(line)
    seen = set()
    result = []
    for s in secrets:
        if not s:
            raise ConfigError("empty secret is not allowed")
        if s not in seen:
            seen.add(s)
            result.append(s)
    return result


def load_case_input(case, base_dir: Path):
    kinds = [k for k in ("input", "content", "content_base64") if k in case]
    if len(kinds) != 1:
        raise ConfigError(
            "each case needs exactly one of 'input', 'content', 'content_base64'"
        )
    if "input" in case:
        if not isinstance(case["input"], str):
            raise ConfigError("'input' must be a path string")
        path = Path(case["input"])
        if not path.is_absolute():
            path = base_dir / path
        try:
            return path.read_bytes(), case["input"]
        except OSError:
            raise FileNotFoundError(str(path))
    if "content" in case:
        if not isinstance(case["content"], str):
            raise ConfigError("'content' must be a string")
        return case["content"].encode("utf-8"), None
    blob = case["content_base64"]
    if not isinstance(blob, str):
        raise ConfigError("'content_base64' must be a string")
    try:
        return base64.b64decode(blob, validate=True), None
    except Exception:
        raise ConfigError("invalid base64 in 'content_base64'") from None


_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_name(name):
    return _SAFE_NAME.sub("_", name)


def run_case(case, index, base_dir, outdir, redactor, chunk_override=None):
    if not isinstance(case, dict):
        raise ConfigError(f"case #{index} must be an object")
    name = case.get("name")
    if not isinstance(name, str) or not name:
        raise ConfigError(f"case #{index} misses a non-empty 'name'")
    fmt = case.get("format")
    chunk_sizes = chunk_override or case.get("chunk_sizes") or DEFAULT_CHUNK_SIZES
    entry = {"name": name, "format": fmt, "input": case.get("input")}
    try:
        data, _src = load_case_input(case, base_dir)
    except FileNotFoundError:
        entry["status"] = "error"
        entry["error"] = {"code": E_INPUT_NOT_FOUND, "message": "input file not found"}
        return entry

    if fmt == "text":
        res = redactor.redact_text(data, chunk_sizes)
        if res["status"] == "quarantined":
            entry.update(
                status="quarantined",
                error_code=res["error_code"],
                error_position=res["error_position"],
                input_length=res["input_length"],
                input_sha256=res["input_sha256"],
            )
            return entry
        out_name = _safe_name(name) + ".redacted.txt"
        (outdir / out_name).write_bytes(res["output"])
        entry.update(
            status="ok",
            output_file=outdir.name + "/" + out_name,
            output_sha256=hashlib.sha256(res["output"]).hexdigest(),
            evidence=res["evidence"],
        )
        return entry

    if fmt == "jsonl":
        res = redactor.redact_jsonl(data, chunk_sizes)
        out_name = _safe_name(name) + ".redacted.jsonl"
        (outdir / out_name).write_bytes(res["output"])
        records = res["records"]
        counts = {"published": 0, "quarantined": 0, "blank": 0}
        for rec in records:
            counts[rec["status"]] += 1
        entry.update(
            status="ok",
            output_file=outdir.name + "/" + out_name,
            output_sha256=hashlib.sha256(res["output"]).hexdigest(),
            counts=counts,
            records=records,
        )
        return entry

    entry["status"] = "error"
    entry["error"] = {"code": E_UNSUPPORTED_FORMAT, "message": "format must be 'text' or 'jsonl'"}
    return entry


def run_batch(cases_path, output_path, chunk_override=None):
    """Run the whole batch.  Returns the process exit code (0 or 1)."""
    cases_path = Path(cases_path)
    try:
        cfg = json.loads(cases_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"cases file not found: {cases_path}") from None
    except json.JSONDecodeError as exc:
        raise ConfigError(f"cases file is not valid JSON (char {exc.pos})") from None
    if not isinstance(cfg, dict) or not isinstance(cfg.get("cases"), list):
        raise ConfigError("cases file must be an object with a 'cases' array")

    secrets = load_secrets(cfg, cases_path.parent)
    salt = salt_from_seed(cfg.get("seed"))
    redactor = Redactor(secrets, salt)

    output_path = Path(output_path)
    outdir = output_path.parent / (output_path.stem + "_outputs")
    outdir.mkdir(parents=True, exist_ok=True)

    cases_out = []
    any_error = False
    for index, case in enumerate(cfg["cases"]):
        entry = run_case(case, index, cases_path.parent, outdir, redactor, chunk_override)
        cases_out.append(entry)
        if entry["status"] == "error":
            any_error = True

    result = {
        "schema": SCHEMA_RESULT,
        "seed": cfg.get("seed"),
        "batch_salt_hex": salt.hex(),
        "cases": cases_out,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return 1 if any_error else 0
