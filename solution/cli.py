"""Command line interface: python -m solution --input cases.json --output result.json"""

from __future__ import annotations

import argparse
import sys

from .pipeline import ConfigError, run_batch


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="Streaming secret redactor for security-log egress "
        "(UTF-8 text and JSON Lines).",
    )
    parser.add_argument("--input", required=True, help="path to cases.json")
    parser.add_argument("--output", required=True, help="path to result.json")
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=None,
        help="override every case's chunking with a fixed chunk size (testing)",
    )
    args = parser.parse_args(argv)
    override = [args.chunk_size] if args.chunk_size else None
    try:
        return run_batch(args.input, args.output, chunk_override=override)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
