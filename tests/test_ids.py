import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from solution.ids import IdFactory
from solution.pipeline import Redactor, salt_from_seed

ID_RE = re.compile(r"^\[REDACTED#[0-9a-f]{16}\]$")


class IdTests(unittest.TestCase):
    def test_id_format(self):
        idf = IdFactory(b"\x01" * 16)
        self.assertRegex(idf.for_secret(b"s"), ID_RE)
        self.assertRegex(idf.for_path_value(b'"v"'), ID_RE)

    def test_same_secret_same_id_within_batch(self):
        r = Redactor([b"sk-live-9f8e7d6c5b"], b"\x02" * 16)
        res = r.redact_text(b"a sk-live-9f8e7d6c5b b sk-live-9f8e7d6c5b c")
        ev = res["evidence"]
        self.assertEqual(len(ev), 2)
        self.assertEqual(ev[0]["id"], ev[1]["id"])

    def test_same_secret_same_id_across_representations(self):
        import base64

        secret = b"sk-live-9f8e7d6c5b"
        r = Redactor([secret], b"\x03" * 16)
        data = secret + b" " + base64.b64encode(secret)
        res = r.redact_text(data)
        ev = res["evidence"]
        self.assertEqual(len(ev), 2)
        self.assertEqual(ev[0]["id"], ev[1]["id"])  # same secret -> same id
        self.assertEqual(
            {e["representation"] for e in ev}, {"raw", "base64"}
        )

    def test_different_batches_different_ids(self):
        secret = b"sk-live-9f8e7d6c5b"
        r1 = Redactor([secret], salt_from_seed(1))
        r2 = Redactor([secret], salt_from_seed(2))
        id1 = r1.redact_text(secret)["evidence"][0]["id"]
        id2 = r2.redact_text(secret)["evidence"][0]["id"]
        self.assertNotEqual(id1, id2)

    def test_same_seed_reproduces_salt_and_ids(self):
        self.assertEqual(salt_from_seed(20261117), salt_from_seed(20261117))
        secret = b"sk-live-9f8e7d6c5b"
        r1 = Redactor([secret], salt_from_seed(20261117))
        r2 = Redactor([secret], salt_from_seed(20261117))
        self.assertEqual(
            r1.redact_text(secret)["evidence"], r2.redact_text(secret)["evidence"]
        )

    def test_id_contains_no_secret_material(self):
        secret = b"sk-live-9f8e7d6c5b"
        r = Redactor([secret], b"\x04" * 16)
        ident = r.redact_text(secret)["evidence"][0]["id"]
        self.assertNotIn("sk-live", ident)
        self.assertNotIn(secret.decode(), ident)


if __name__ == "__main__":
    unittest.main()
