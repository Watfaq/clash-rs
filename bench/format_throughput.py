#!/usr/bin/env python3
"""Format throughput test JSON-lines results as grouped Markdown tables.

Usage:
    python3 bench/format_throughput.py results.json [--output comment.md]

Each line of results.json must be a JSON object with:
    label         – test name in "<protocol>-<transport>" format (e.g. "trojan-ws")
    upload_mbps   – upload throughput in Mbps
    download_mbps – download throughput in Mbps
    total_bytes   – payload size in bytes

Output groups rows by protocol, with one table per outbound type.
"""

import argparse
import json
import sys
from collections import defaultdict

# Display name and canonical sort order for each protocol prefix.
PROTOCOL_META = {
    "ss":          ("Shadowsocks", 0),
    "trojan":      ("Trojan",      1),
    "vmess":       ("VMess",       2),
    "vless":       ("VLESS",       3),
    "socks5":      ("SOCKS5",      4),
    "anytls":      ("AnyTLS",      5),
    "hysteria2":   ("Hysteria2",   6),
    "tuic":        ("TUIC",        7),
    "shadowquic":  ("ShadowQUIC",  8),
    "ssh":         ("SSH",         9),
}


def split_label(label: str) -> tuple[str, str]:
    """Split 'proto-transport' into (proto, transport). Unknown protos kept as-is."""
    parts = label.split("-", 1)
    proto = parts[0]
    transport = parts[1] if len(parts) > 1 else "plain"
    return proto, transport


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", help="JSON-lines result file")
    parser.add_argument("--output", "-o", help="Write markdown to this file (default: stdout)")
    parser.add_argument("--run-url", help="URL to the GitHub Actions workflow run")
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
        # Group by protocol
        groups: dict[str, list] = defaultdict(list)
        for r in rows:
            proto, _ = split_label(r.get("label", "?"))
            groups[proto].append(r)

        # Sort protocols by canonical order, unknowns at end alphabetically
        def proto_sort_key(p: str) -> tuple:
            meta = PROTOCOL_META.get(p)
            return (0, meta[1], p) if meta else (1, 999, p)

        lines = ["## 📊 Proxy Throughput Results", ""]

        total = 0
        for proto in sorted(groups, key=proto_sort_key):
            display_name, _ = PROTOCOL_META.get(proto, (proto.upper(), 99))
            proto_rows = sorted(groups[proto], key=lambda r: split_label(r.get("label", ""))[1])
            total += len(proto_rows)

            lines += [
                f"### {display_name}",
                "",
                "| Transport | Payload | Upload (Mbps) | Download (Mbps) |",
                "|-----------|---------|:-------------:|:---------------:|",
            ]
            for r in proto_rows:
                _, transport = split_label(r.get("label", "?"))
                payload_mb = r.get("total_bytes", 0) // (1024 * 1024)
                upload = r.get("upload_mbps", 0.0)
                download = r.get("download_mbps", 0.0)
                lines.append(f"| `{transport}` | {payload_mb} MB | {upload:.1f} | {download:.1f} |")
            lines.append("")

        lines.append(
            f"_Ran {total} variant(s) in parallel; each direction transfers the full payload._"
        )
        lines.append("")

        if args.run_url:
            lines.append(f"[📎 View full workflow run and download artifacts]({args.run_url})")
            lines.append("")

        md = "\n".join(lines)

    if args.output:
        with open(args.output, "w") as f:
            f.write(md)
        print(f"Written to {args.output}")
    else:
        print(md)


if __name__ == "__main__":
    main()
