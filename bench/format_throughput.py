#!/usr/bin/env python3
"""Format throughput test JSON-lines results as a Markdown table.

Usage:
    python3 bench/format_throughput.py results.json [--output comment.md]

Each line of results.json must be a JSON object with:
    label         – human-readable test name
    upload_mbps   – upload throughput in Mbps
    download_mbps – download throughput in Mbps
    total_bytes   – payload size in bytes
"""

import argparse
import json
import sys


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", help="JSON-lines result file")
    parser.add_argument("--output", "-o", help="Write markdown to this file (default: stdout)")
    args = parser.parse_args()

    rows = []
    with open(args.results) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"Warning: skipping invalid JSON line: {e}", file=sys.stderr)

    if not rows:
        md = "## 📊 Proxy Throughput Results\n\n_No results recorded._\n"
    else:
        rows.sort(key=lambda r: r.get("label", ""))
        lines = [
            "## 📊 Proxy Throughput Results",
            "",
            "| Transport | Payload | Upload (Mbps) | Download (Mbps) |",
            "|-----------|---------|:-------------:|:---------------:|",
        ]
        for r in rows:
            label = r.get("label", "?")
            payload_mb = r.get("total_bytes", 0) // (1024 * 1024)
            upload = r.get("upload_mbps", 0.0)
            download = r.get("download_mbps", 0.0)
            lines.append(f"| `{label}` | {payload_mb} MB | {upload:.1f} | {download:.1f} |")

        lines += [
            "",
            f"_Tests ran {len(rows)} variant(s) in parallel; each direction transfers the full payload._",
            "",
        ]
        md = "\n".join(lines)

    if args.output:
        with open(args.output, "w") as f:
            f.write(md)
        print(f"Written to {args.output}")
    else:
        print(md)


if __name__ == "__main__":
    main()
