import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from solution.jsonline import MAX_LINE_BYTES
from solution.pipeline import Redactor

SALT = bytes.fromhex("00112233445566778899aabbccddeeff")


def redactor(secrets=()):
    return Redactor(list(secrets), SALT)


def first_line(out_bytes):
    return out_bytes.split(b"\n")[0]


class SensitivePathTests(unittest.TestCase):
    def test_password_key_redacted(self):
        r = redactor()
        data = b'{"user":"u1","password":"pw-1","ok":true}\n'
        res = r.redact_jsonl(data)
        rec = res["records"][0]
        self.assertEqual(rec["status"], "published")
        obj = json.loads(first_line(res["output"]))
        self.assertEqual(obj["user"], "u1")
        self.assertEqual(obj["ok"], True)
        self.assertRegex(obj["password"], r"^\[REDACTED#[0-9a-f]{16}\]$")
        ev = rec["evidence"][0]
        self.assertEqual(ev["source"], "json_path")
        self.assertEqual(ev["key"], "password")
        # evidence range covers the original value span including quotes
        self.assertEqual(data[ev["byte_start"] : ev["byte_end"]], b'"pw-1"')

    def test_nested_case_insensitive_and_non_string(self):
        r = redactor()
        data = b'{"outer":{"Token":"t1"},"arr":[{"SECRET":1}],"password":42}\n'
        res = r.redact_jsonl(data)
        obj = json.loads(first_line(res["output"]))
        self.assertRegex(obj["outer"]["Token"], r"^\[REDACTED#")
        self.assertRegex(obj["arr"][0]["SECRET"], r"^\[REDACTED#")
        self.assertRegex(obj["password"], r"^\[REDACTED#")
        self.assertIsInstance(obj["password"], str)  # 42 -> string placeholder
        keys = [e["key"] for e in res["records"][0]["evidence"]]
        self.assertEqual(sorted(keys), ["SECRET", "Token", "password"])

    def test_container_value_redacted_as_whole(self):
        r = redactor()
        data = b'{"secret":{"inner":"x","n":[1,2]},"keep":"y"}\n'
        res = r.redact_jsonl(data)
        obj = json.loads(first_line(res["output"]))
        self.assertRegex(obj["secret"], r"^\[REDACTED#")
        self.assertEqual(obj["keep"], "y")
        # exactly one replacement: the whole container span
        self.assertEqual(len(res["records"][0]["evidence"]), 1)

    def test_same_value_same_id_within_batch(self):
        r = redactor()
        data = b'{"password":"same"}\n{"token":"same"}\n'
        res = r.redact_jsonl(data)
        lines = res["output"].split(b"\n")
        id1 = json.loads(lines[0])["password"]
        id2 = json.loads(lines[1])["token"]
        self.assertEqual(id1, id2)

    def test_key_itself_and_numbers_not_matched_by_dictionary(self):
        r = redactor([b"123", b"mode"])
        data = b'{"mode":"fast","a":123,"b":"x123y"}\n'
        res = r.redact_jsonl(data)
        line = first_line(res["output"])
        obj = json.loads(line)
        self.assertIn(b'"mode"', line)          # key untouched
        self.assertEqual(obj["a"], 123)          # number literal untouched
        self.assertRegex(obj["b"], r"^x\[REDACTED#[0-9a-f]{16}\]y$")
        self.assertEqual(obj["mode"], "fast")    # value without the secret untouched


class DictionaryInJsonTests(unittest.TestCase):
    def test_dict_secret_in_string_value(self):
        r = redactor([b"sk-live-9f8e7d6c5b"])
        data = b'{"msg":"token sk-live-9f8e7d6c5b leaked","n":1}\n'
        res = r.redact_jsonl(data)
        obj = json.loads(first_line(res["output"]))
        self.assertRegex(obj["msg"], r"^token \[REDACTED#[0-9a-f]{16}\] leaked$")
        self.assertEqual(obj["n"], 1)
        ev = res["records"][0]["evidence"][0]
        self.assertEqual(ev["source"], "dictionary")
        self.assertEqual(ev["representation"], "raw")
        self.assertEqual(data[ev["byte_start"] : ev["byte_end"]], b"sk-live-9f8e7d6c5b")

    def test_json_escaped_secret_in_string(self):
        secret = 'pa"ss\nwörd'.encode("utf-8")
        r = redactor([secret])
        line = json.dumps({"m": "leak pa\"ss\nwörd end"}, ensure_ascii=True).encode() + b"\n"
        res = r.redact_jsonl(line)
        obj = json.loads(first_line(res["output"]))
        self.assertRegex(obj["m"], r"^leak \[REDACTED#[0-9a-f]{16}\] end$")
        ev = res["records"][0]["evidence"][0]
        self.assertEqual(ev["representation"], "json_escape_ascii")
        self.assertEqual(
            line[ev["byte_start"] : ev["byte_end"]], b'pa\\"ss\\nw\\u00f6rd'
        )

    def test_base64_secret_in_string(self):
        secret = b"sk-live-9f8e7d6c5b"
        r = redactor([secret])
        blob = base64.b64encode(secret)
        data = b'{"blob":"' + blob + b'"}\n'
        res = r.redact_jsonl(data)
        obj = json.loads(first_line(res["output"]))
        self.assertRegex(obj["blob"], r"^\[REDACTED#[0-9a-f]{16}\]$")
        ev = res["records"][0]["evidence"][0]
        self.assertEqual(ev["representation"], "base64")

    def test_path_redaction_has_priority_over_dictionary(self):
        secret = b"sk-live-9f8e7d6c5b"
        r = redactor([secret])
        data = b'{"token":"sk-live-9f8e7d6c5b"}\n'
        res = r.redact_jsonl(data)
        ev = res["records"][0]["evidence"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["source"], "json_path")
        # the whole quoted value is the replaced span
        self.assertEqual(data[ev[0]["byte_start"] : ev[0]["byte_end"]], b'"sk-live-9f8e7d6c5b"')


class ValidationTests(unittest.TestCase):
    def test_truncated_line_quarantined(self):
        r = redactor()
        content = b'{"user": "alice", "token": "sk-'
        res = r.redact_jsonl(content)
        rec = res["records"][0]
        self.assertEqual(rec["status"], "quarantined")
        self.assertEqual(rec["error_code"], "E_JSON_SYNTAX")
        self.assertIsInstance(rec["error_position"], int)
        self.assertEqual(rec["line_sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(rec["line_length"], len(content))
        self.assertEqual(res["output"], b"")  # nothing published

    def test_invalid_utf8_quarantined(self):
        r = redactor()
        content = b'{"a":"\xff"}'
        res = r.redact_jsonl(content + b"\n")
        rec = res["records"][0]
        self.assertEqual(rec["status"], "quarantined")
        self.assertEqual(rec["error_code"], "E_UTF8_INVALID")
        self.assertEqual(rec["error_position"], 6)  # offset of the 0xff byte
        self.assertEqual(rec["line_sha256"], hashlib.sha256(content).hexdigest())

    def test_oversize_line_quarantined_exact_limit_published(self):
        r = redactor()
        # exactly 1 MiB -> valid, published
        exact = b'{"p":"' + b"A" * (MAX_LINE_BYTES - 8) + b'"}'
        self.assertEqual(len(exact), MAX_LINE_BYTES)
        res = r.redact_jsonl(exact + b"\n")
        self.assertEqual(res["records"][0]["status"], "published")
        self.assertEqual(first_line(res["output"]), exact)
        # 1 MiB + 1 -> quarantined
        over = exact + b"A"
        res2 = r.redact_jsonl(b'{"q":1}\n' + over + b"\n" + b'{"r":2}\n')
        recs = res2["records"]
        self.assertEqual(recs[0]["status"], "published")
        self.assertEqual(recs[1]["status"], "quarantined")
        self.assertEqual(recs[1]["error_code"], "E_LINE_TOO_LONG")
        self.assertEqual(recs[1]["error_position"], MAX_LINE_BYTES)
        self.assertEqual(recs[1]["line_sha256"], hashlib.sha256(over).hexdigest())
        self.assertEqual(recs[2]["status"], "published")
        # order preserved, quarantined line omitted from output
        self.assertEqual(res2["output"], b'{"q":1}\n{"r":2}\n')

    def test_nonstandard_constant_rejected(self):
        r = redactor()
        res = r.redact_jsonl(b'{"x": NaN}\n')
        self.assertEqual(res["records"][0]["status"], "quarantined")
        self.assertEqual(res["records"][0]["error_code"], "E_JSON_SYNTAX")

    def test_blank_lines_skipped_order_preserved(self):
        r = redactor()
        data = b'{"a":1}\n\n   \n{"b":2}\n'
        res = r.redact_jsonl(data)
        statuses = [rec["status"] for rec in res["records"]]
        self.assertEqual(statuses, ["published", "blank", "blank", "published"])
        self.assertEqual(res["output"], b'{"a":1}\n{"b":2}\n')

    def test_semantics_of_non_sensitive_values_preserved(self):
        r = redactor([b"sk-live-9f8e7d6c5b"])
        data = (
            b'{"num": 1.50e2, "s": "keep\\u00e4", "list": [1, 2.0, null],'
            b' "password": "x", "token2": "sk-live-9f8e7d6c5b"}\n'
        )
        res = r.redact_jsonl(data)
        line = first_line(res["output"])
        # non-sensitive bytes are preserved verbatim (no re-serialization)
        self.assertIn(b'"num": 1.50e2', line)
        self.assertIn(b'"s": "keep\\u00e4"', line)
        self.assertIn(b'"list": [1, 2.0, null]', line)
        obj = json.loads(line)
        self.assertEqual(obj["num"], 150.0)
        self.assertEqual(obj["s"], "keepä")
        self.assertEqual(obj["list"], [1, 2.0, None])
        self.assertRegex(obj["password"], r"^\[REDACTED#")
        self.assertRegex(obj["token2"], r"^\[REDACTED#")

    def test_chunked_line_reassembly(self):
        # chunk boundaries may split UTF-8 chars, escapes and secrets
        secret = "密钥".encode("utf-8")
        r = redactor([secret])
        data = json.dumps({"m": "值密钥值"}, ensure_ascii=False).encode("utf-8") + b"\n"
        ref = r.redact_jsonl(data, chunk_sizes=[len(data)])
        for k in range(len(data) + 1):
            sizes = [s for s in (k, len(data) - k) if s > 0] or [1]
            res = r.redact_jsonl(data, chunk_sizes=sizes)
            self.assertEqual(res["output"], ref["output"], f"split at {k}")
            self.assertEqual(res["records"], ref["records"], f"split at {k}")


if __name__ == "__main__":
    unittest.main()
