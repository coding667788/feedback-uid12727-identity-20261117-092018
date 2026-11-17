"""Regenerate the non-trivial sample files deterministically.

Run from the repository root:  python tools/make_samples.py
Creates/updates:
  samples/b64.txt        -- text containing a base64-encoded secret
  samples/escaped.jsonl  -- JSON lines with JSON-escaped secrets
  samples/badutf8.jsonl  -- JSON lines with invalid UTF-8 bytes
  samples/oversize.jsonl -- a >1MiB line followed by a valid line
"""

import base64
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"

SECRET_TOKEN = b"sk-live-9f8e7d6c5b"
SECRET_TRICKY = 'pa"ss\nwörd'


def main():
    SAMPLES.mkdir(exist_ok=True)

    blob = base64.b64encode(SECRET_TOKEN).decode("ascii")
    (SAMPLES / "b64.txt").write_text(
        "2026-11-17T09:21:00Z auth blob=" + blob + " trailer\n"
        "second line without secrets\n",
        encoding="utf-8",
    )

    lines = [
        json.dumps({"msg": "leak " + SECRET_TRICKY + " end", "id": 7}, ensure_ascii=True),
        json.dumps({"msg": "leak " + SECRET_TRICKY + " end", "id": 8}, ensure_ascii=False),
        json.dumps({"plain": "nothing here"}, ensure_ascii=True),
    ]
    (SAMPLES / "escaped.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    (SAMPLES / "badutf8.jsonl").write_bytes(
        b'{"ok": 1}\n{"bad": "\xff\xfe"}\n{"ok": 2}'
    )

    big = b'{"data":"' + b"A" * 1048576 + b'"}'  # 1 MiB + 11 bytes -> quarantine
    good = b'{"token": "sk-live-9f8e7d6c5b", "ok": true}'
    (SAMPLES / "oversize.jsonl").write_bytes(big + b"\n" + good + b"\n")

    print("samples regenerated")


if __name__ == "__main__":
    main()
