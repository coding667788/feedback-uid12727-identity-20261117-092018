import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from solution.ids import IdFactory
from solution.pipeline import salt_from_seed
from solution.secretspec import representations


def run_cli(output_path, cases=None, extra=()):
    cmd = [
        sys.executable,
        "-m",
        "solution",
        "--input",
        str(cases or (ROOT / "cases.json")),
        "--output",
        str(output_path),
        *extra,
    ]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)


def load_secrets():
    cfg = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))
    secrets = [s.encode("utf-8") for s in cfg.get("secrets", [])]
    secrets += [base64.b64decode(s) for s in cfg.get("secrets_base64", [])]
    return cfg, secrets


class CliEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.out_dir = Path(cls._tmp.name)
        cls.result_path = cls.out_dir / "result.json"
        proc = run_cli(cls.result_path)
        assert proc.returncode == 0, proc.stderr
        cls.proc = proc
        cls.result = json.loads(cls.result_path.read_text(encoding="utf-8"))
        cls.cases = {c["name"]: c for c in cls.result["cases"]}
        cls.outputs = cls.out_dir / "result_outputs"

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def case_output(self, name):
        return (self.out_dir / self.cases[name]["output_file"]).read_bytes()

    def test_exit_code_and_schema(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stderr)
        self.assertEqual(self.result["schema"], "redactor-result/1")
        self.assertEqual(self.result["seed"], 20261117)
        self.assertEqual(len(self.result["batch_salt_hex"]), 32)

    def test_overlap_case_longest_then_byte_order(self):
        # "alphaSECRET" and "SECRETomega" overlap with equal length 11;
        # b"SECRETomega" < b"alphaSECRET" so SECRETomega wins.
        case = self.cases["overlap"]
        self.assertEqual(case["status"], "ok")
        salt = salt_from_seed(20261117)
        ident = IdFactory(salt).for_secret(b"SECRETomega")
        out = self.case_output("overlap")
        src = (ROOT / "samples" / "overlap.txt").read_bytes()
        pos = src.index(b"SECRETomega")
        self.assertEqual(
            out,
            src[:pos] + ident.encode("ascii") + src[pos + len(b"SECRETomega"):],
        )
        ev = case["evidence"]
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["byte_start"], ev[0]["byte_end"]), (pos, pos + 11))
        self.assertEqual(ev[0]["representation"], "raw")

    def test_unicode_case_chunk_size_one(self):
        # chunk_sizes [1] splits every multi-byte UTF-8 sequence; the CJK
        # secret and the ASCII token must still be redacted.
        case = self.cases["unicode"]
        self.assertEqual(case["status"], "ok")
        out = self.case_output("unicode")
        self.assertNotIn("密钥".encode("utf-8"), out)
        self.assertNotIn(b"sk-live-9f8e7d6c5b", out)
        kinds = sorted(e["representation"] for e in case["evidence"])
        self.assertEqual(kinds, ["raw", "raw"])
        self.assertEqual(len(case["evidence"]), 2)

    def test_b64_case(self):
        case = self.cases["b64"]
        out = self.case_output("b64")
        blob = base64.b64encode(b"sk-live-9f8e7d6c5b")
        self.assertNotIn(blob, out)
        self.assertEqual(len(case["evidence"]), 1)
        self.assertEqual(case["evidence"][0]["representation"], "base64")

    def test_escaped_case(self):
        case = self.cases["escaped"]
        self.assertEqual(case["counts"], {"published": 3, "quarantined": 0, "blank": 0})
        lines = self.case_output("escaped").split(b"\n")
        objs = [json.loads(line) for line in lines if line]
        self.assertEqual(objs[0]["id"], 7)
        self.assertEqual(objs[1]["id"], 8)
        for obj in objs[:2]:
            self.assertRegex(obj["msg"], r"^leak \[REDACTED#[0-9a-f]{16}\] end$")
        self.assertEqual(objs[2], {"plain": "nothing here"})
        kinds = sorted(e["representation"] for rec in case["records"] for e in rec.get("evidence", []))
        self.assertEqual(kinds, ["json_escape", "json_escape_ascii"])

    def test_paths_case(self):
        case = self.cases["paths"]
        objs = [json.loads(line) for line in self.case_output("paths").split(b"\n") if line]
        self.assertRegex(objs[0]["password"], r"^\[REDACTED#")
        self.assertEqual(objs[0]["user"], "u1")
        self.assertRegex(objs[1]["outer"]["Token"], r"^\[REDACTED#")
        self.assertRegex(objs[2]["arr"][0]["secret"], r"^\[REDACTED#")
        self.assertRegex(objs[2]["arr"][1]["secret"], r"^\[REDACTED#")
        self.assertRegex(objs[2]["password"], r"^\[REDACTED#")
        self.assertEqual(objs[3], {"note": "nothing sensitive"})
        sources = {e["source"] for rec in case["records"] for e in rec.get("evidence", [])}
        self.assertEqual(sources, {"json_path"})

    def test_truncated_case(self):
        case = self.cases["truncated"]
        recs = case["records"]
        self.assertEqual([r["status"] for r in recs], ["published", "quarantined"])
        q = recs[1]
        self.assertEqual(q["error_code"], "E_JSON_SYNTAX")
        self.assertIsInstance(q["error_position"], int)
        import hashlib

        src = (ROOT / "samples" / "truncated.jsonl").read_bytes()
        line2 = src.split(b"\n")[1]
        self.assertEqual(q["line_sha256"], hashlib.sha256(line2).hexdigest())
        self.assertEqual(self.case_output("truncated"), b'{"ok": 1, "note": "plain log line"}\n')

    def test_badutf8_case(self):
        case = self.cases["badutf8"]
        recs = case["records"]
        self.assertEqual([r["status"] for r in recs], ["published", "quarantined", "published"])
        self.assertEqual(recs[1]["error_code"], "E_UTF8_INVALID")
        self.assertEqual(recs[1]["error_position"], 9)

    def test_oversize_case(self):
        case = self.cases["oversize"]
        recs = case["records"]
        self.assertEqual([r["status"] for r in recs], ["quarantined", "published"])
        self.assertEqual(recs[0]["error_code"], "E_LINE_TOO_LONG")
        self.assertEqual(recs[0]["error_position"], 1048576)
        # the valid second line is still published, with its token redacted
        obj = json.loads(self.case_output("oversize").split(b"\n")[0])
        self.assertRegex(obj["token"], r"^\[REDACTED#")
        self.assertEqual(obj["ok"], True)

    def test_inline_and_binary_cases(self):
        inline = self.cases["inline_text"]
        self.assertEqual(inline["status"], "ok")
        out = self.case_output("inline_text")
        self.assertNotIn("密钥".encode("utf-8"), out)
        self.assertNotIn(b"sk-live-9f8e7d6c5b", out)
        binary = self.cases["binary_secret"]
        out_b = self.case_output("binary_secret")
        self.assertNotIn(bytes(range(8)), out_b)
        self.assertTrue(out_b.startswith(b"bin:"))
        self.assertTrue(out_b.endswith(b":end"))

    def test_no_secret_in_any_output_file(self):
        _cfg, secrets = load_secrets()
        files = [self.result_path] + sorted(self.outputs.iterdir())
        self.assertGreater(len(files), 5)
        for f in files:
            blob = f.read_bytes()
            for secret in secrets:
                for pattern, kind in representations(secret):
                    self.assertNotIn(
                        pattern, blob, f"{kind} form of a secret leaked into {f.name}"
                    )

    def test_quarantine_contains_only_hash_and_position(self):
        _cfg, secrets = load_secrets()
        for case in self.result["cases"]:
            for rec in case.get("records", []):
                if rec["status"] != "quarantined":
                    continue
                self.assertEqual(
                    set(rec),
                    {"line", "status", "error_code", "error_position", "line_length", "line_sha256"},
                )
                blob = json.dumps(rec).encode("utf-8")
                for secret in secrets:
                    self.assertNotIn(secret, blob)


class CliReplayTests(unittest.TestCase):
    def test_fixed_seed_replay_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
            p1, p2 = Path(t1) / "result.json", Path(t2) / "result.json"
            self.assertEqual(run_cli(p1).returncode, 0)
            self.assertEqual(run_cli(p2).returncode, 0)
            self.assertEqual(p1.read_bytes(), p2.read_bytes())
            d1 = sorted((Path(t1) / "result_outputs").iterdir())
            d2 = sorted((Path(t2) / "result_outputs").iterdir())
            self.assertEqual([f.name for f in d1], [f.name for f in d2])
            for f1, f2 in zip(d1, d2):
                self.assertEqual(f1.read_bytes(), f2.read_bytes())

    def test_different_seed_changes_ids(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))
            cfg["seed"] = 777
            cases2 = tmp / "cases2.json"
            cases2.write_text(json.dumps(cfg), encoding="utf-8")
            # relative sample paths resolve against the cases file location,
            # so use an absolute input for a minimal case instead
            cfg2 = {
                "seed": 1,
                "secrets": ["sk-live-9f8e7d6c5b"],
                "cases": [{"name": "c", "format": "text", "content": "x sk-live-9f8e7d6c5b y"}],
            }
            cfg3 = dict(cfg2, seed=2)
            c1, c2 = tmp / "c1.json", tmp / "c2.json"
            c1.write_text(json.dumps(cfg2), encoding="utf-8")
            c2.write_text(json.dumps(cfg3), encoding="utf-8")
            r1, r2 = tmp / "r1.json", tmp / "r2.json"
            self.assertEqual(run_cli(r1, cases=c1).returncode, 0)
            self.assertEqual(run_cli(r2, cases=c2).returncode, 0)
            id1 = json.loads(r1.read_text())["cases"][0]["evidence"][0]["id"]
            id2 = json.loads(r2.read_text())["cases"][0]["evidence"][0]["id"]
            self.assertNotEqual(id1, id2)

    def test_missing_cases_file_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            proc = run_cli(Path(td) / "r.json", cases=Path(td) / "nope.json")
            self.assertEqual(proc.returncode, 2)
            self.assertIn("error", proc.stderr.lower())

    def test_missing_input_file_case_error(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = {
                "seed": 5,
                "secrets": ["abc"],
                "cases": [{"name": "gone", "format": "text", "input": "no/such/file.bin"}],
            }
            c = tmp / "cases.json"
            c.write_text(json.dumps(cfg), encoding="utf-8")
            r = tmp / "result.json"
            proc = run_cli(r, cases=c)
            self.assertEqual(proc.returncode, 1)
            result = json.loads(r.read_text())
            self.assertEqual(result["cases"][0]["status"], "error")
            self.assertEqual(result["cases"][0]["error"]["code"], "E_INPUT_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
