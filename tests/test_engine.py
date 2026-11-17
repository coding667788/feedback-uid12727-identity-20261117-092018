import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from solution.engine import StreamRedactor
from solution.ids import IdFactory
from solution.secretspec import build_patterns

SALT = bytes.fromhex("00112233445566778899aabbccddeeff")


def make(secrets):
    idf = IdFactory(SALT)
    return build_patterns(secrets), idf


def oneshot(data, patterns, idf):
    red = StreamRedactor(patterns, idf.for_secret)
    red.feed(data, final=True)
    return bytes(red.out), list(red.evidence)


def stream(data, patterns, idf, sizes):
    red = StreamRedactor(patterns, idf.for_secret)
    i = 0
    k = 0
    while i < len(data):
        s = sizes[k % len(sizes)]
        k += 1
        red.feed(data[i : i + s])
        i += s
    red.feed(b"", final=True)
    return bytes(red.out), list(red.evidence)


def compositions(n):
    """All chunkings of n bytes into positive-size pieces."""
    if n == 0:
        yield []
        return
    for mask in range(1 << (n - 1)):
        sizes = []
        cur = 1
        for i in range(n - 1):
            if mask & (1 << i):
                sizes.append(cur)
                cur = 1
            else:
                cur += 1
        sizes.append(cur)
        yield sizes


class ResolutionTests(unittest.TestCase):
    def test_longest_match_wins(self):
        patterns, idf = make([b"abcdef", b"cdef"])
        out, ev = oneshot(b"0abcdef1", patterns, idf)
        self.assertEqual(out, b"0" + idf.for_secret(b"abcdef").encode() + b"1")
        self.assertEqual([(e[0], e[1]) for e in ev], [(1, 7)])
        self.assertEqual(ev[0][3], "raw")

    def test_equal_length_byte_order(self):
        # "abc" and "bcd" overlap in "abcd"; both length 3; b"abc" < b"bcd".
        patterns, idf = make([b"bcd", b"abc"])
        out, ev = oneshot(b"abcd", patterns, idf)
        self.assertEqual(out, idf.for_secret(b"abc").encode() + b"d")
        self.assertEqual([(e[0], e[1]) for e in ev], [(0, 3)])

    def test_longer_beats_earlier_start(self):
        # "xab" starts earlier but "abcd" is longer -> "abcd" wins.
        patterns, idf = make([b"xab", b"abcd"])
        out, ev = oneshot(b"xabcd", patterns, idf)
        self.assertEqual(out, b"x" + idf.for_secret(b"abcd").encode())
        self.assertEqual([(e[0], e[1]) for e in ev], [(1, 5)])

    def test_non_overlapping_multiple(self):
        patterns, idf = make([b"ab", b"cd"])
        out, _ = oneshot(b"ab cd ab", patterns, idf)
        expected = (
            idf.for_secret(b"ab") + " " + idf.for_secret(b"cd") + " " + idf.for_secret(b"ab")
        )
        self.assertEqual(out.decode("ascii"), expected)

    def test_base64_representation(self):
        secret = b"sk-live-9f8e7d6c5b"
        patterns, idf = make([secret])
        blob = base64.b64encode(secret)
        out, ev = oneshot(b"auth=" + blob + b"!", patterns, idf)
        self.assertEqual(out, b"auth=" + idf.for_secret(secret).encode() + b"!")
        self.assertEqual(ev[0][3], "base64")
        self.assertEqual((ev[0][0], ev[0][1]), (5, 5 + len(blob)))

    def test_json_escape_representations(self):
        secret = 'pa"ss\nwörd'.encode("utf-8")
        patterns, idf = make([secret])
        ident = idf.for_secret(secret).encode()
        # ensure_ascii=False form (raw UTF-8 inside the JSON string)
        esc_utf8 = 'pa\\"ss\\nwörd'.encode("utf-8")
        out, ev = oneshot(b'{"m":"' + esc_utf8 + b'"}', patterns, idf)
        self.assertEqual(out, b'{"m":"' + ident + b'"}')
        self.assertEqual(ev[0][3], "json_escape")
        # ensure_ascii=True form (ASCII with ö)
        esc_ascii = b'pa\\"ss\\nw\\u00f6rd'
        out2, ev2 = oneshot(b'{"m":"' + esc_ascii + b'"}', patterns, idf)
        self.assertEqual(out2, b'{"m":"' + ident + b'"}')
        self.assertEqual(ev2[0][3], "json_escape_ascii")
        # upper-case \u hex variant
        esc_upper = b'pa\\"ss\\nw\\u00F6rd'
        out3, _ = oneshot(b'{"m":"' + esc_upper + b'"}', patterns, idf)
        self.assertEqual(out3, b'{"m":"' + ident + b'"}')

    def test_no_recursive_decoding(self):
        secret = b"hello-secret"
        patterns, idf = make([secret])
        once = base64.b64encode(secret)
        twice = base64.b64encode(once)
        out, ev = oneshot(twice, patterns, idf)
        self.assertEqual(out, twice)  # no recursive decode -> untouched
        self.assertEqual(ev, [])
        out2, ev2 = oneshot(once, patterns, idf)
        self.assertEqual(out2, idf.for_secret(secret).encode())
        self.assertEqual(len(ev2), 1)

    def test_empty_input(self):
        patterns, idf = make([b"x"])
        out, ev = oneshot(b"", patterns, idf)
        self.assertEqual(out, b"")
        self.assertEqual(ev, [])


class StreamingEqualityTests(unittest.TestCase):
    SECRETS = [
        b"aaa",
        "密钥".encode("utf-8"),
        'pa"ss\nwörd'.encode("utf-8"),
        b"sk-live-9f8e7d6c5b",
    ]
    VECTORS = [
        b"",
        b"a",
        b"aaabaaa",
        "前文密钥后文".encode("utf-8"),
        "🔥密钥🔥".encode("utf-8"),
        b'x{"m":"pa\\"ss\\nw\\u00f6rd"}y',
        b"blob=" + base64.b64encode(b"sk-live-9f8e7d6c5b") + b"!!",
        "前缀sk-live-9f8e7d6c5b后缀密钥".encode("utf-8"),
    ]

    def setUp(self):
        self.patterns, self.idf = make(self.SECRETS)

    def test_all_single_split_positions(self):
        # Exhaustive: every two-piece chunking of every vector.
        for vec in self.VECTORS:
            ref_out, ref_ev = oneshot(vec, self.patterns, self.idf)
            for k in range(len(vec) + 1):
                sizes = [s for s in (k, len(vec) - k) if s > 0] or [1]
                out, ev = stream(vec, self.patterns, self.idf, sizes)
                self.assertEqual(out, ref_out, f"split at {k} of {vec!r}")
                self.assertEqual(ev, ref_ev, f"evidence split at {k} of {vec!r}")

    def test_all_compositions_short_vectors(self):
        # Exhaustive: every possible chunking of short vectors.
        for vec in [b"a", b"aaabaaa", "密钥".encode("utf-8")]:
            ref_out, ref_ev = oneshot(vec, self.patterns, self.idf)
            for sizes in compositions(len(vec)):
                out, ev = stream(vec, self.patterns, self.idf, sizes)
                self.assertEqual(out, ref_out, f"chunking {sizes} of {vec!r}")
                self.assertEqual(ev, ref_ev, f"evidence chunking {sizes} of {vec!r}")

    def test_chunk_size_one(self):
        for vec in self.VECTORS:
            ref_out, ref_ev = oneshot(vec, self.patterns, self.idf)
            out, ev = stream(vec, self.patterns, self.idf, [1])
            self.assertEqual(out, ref_out)
            self.assertEqual(ev, ref_ev)

    def test_mixed_chunk_sizes(self):
        for vec in self.VECTORS:
            ref_out, ref_ev = oneshot(vec, self.patterns, self.idf)
            out, ev = stream(vec, self.patterns, self.idf, [3, 1, 4, 1, 5, 9, 2, 6])
            self.assertEqual(out, ref_out)
            self.assertEqual(ev, ref_ev)

    def test_output_contains_no_secret(self):
        for vec in self.VECTORS:
            out, _ = oneshot(vec, self.patterns, self.idf)
            for secret in self.SECRETS:
                self.assertNotIn(secret, out)
                self.assertNotIn(base64.b64encode(secret), out)


if __name__ == "__main__":
    unittest.main()
