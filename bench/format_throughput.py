#!/usr/bin/env python3
"""Format throughput test JSON-lines results as grouped Markdown tables.

Usage:
    python3 bench/format_throughput.py results.json [--output comment.md]

Each line of results.json must be a JSON object with:
    label               – test name in "<protocol>-<transport>" format (e.g. "trojan-ws")
    upload_mbps         – upload throughput in Mbps (median across runs)
    download_mbps       – download throughput in Mbps (median across runs)
    upload_stdev_mbps   – upload stdev in Mbps (optional, 0 if absent)
    download_stdev_mbps – download stdev in Mbps (optional, 0 if absent)
    runs                – number of iterations (optional)
    total_bytes         – payload size in bytes
    netem               – netem description string if applicable (optional)

Output groups rows by protocol, with one table per outbound type.
Netem results (labels containing "-netem") are shown in a separate section.
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

# Canonical sort order for transport variants within each protocol group.
# Transports not listed here sort last (key 99), then alphabetically.
TRANSPORT_ORDER = {
    "tcp":          0,
    "tcp-tls":      1,
    "ws":           2,
    "ws-tls":       3,
    "h2":           4,
    "h2-tls":       5,
    "grpc":         6,
    "grpc-tls":     7,
    "plain":        8,
    "obfs-http":    9,
    "obfs-tls":    10,
    "v2ray-ws":    11,
    "v2ray-tls":   12,
    "salamander":  13,
    "over-stream": 14,
    "bbr":         15,
    "cubic":       16,
    "new_reno":    17,
    "password":    18,
    "ed25519":     19,
}


def split_label(label: str) -> tuple[str, str]:
    """Split 'proto-transport' into (proto, transport). Unknown protos kept as-is."""
    parts = label.split("-", 1)
    proto = parts[0]
    transport = parts[1] if len(parts) > 1 else "plain"
    return proto, transport


def normalize_transport(transport: str) -> str:
    """Strip suffixes that should not affect sort order (e.g. '-netem').
    Also map aliased variant names to their canonical TRANSPORT_ORDER key."""
    # Strip trailing -netem suffix so netem rows sort alongside their base transport
    base = transport.removesuffix("-netem")
    # socks5-auth / socks5-noauth → socks5 (no distinct transport, auth is a config detail)
    if base in ("auth", "noauth"):
        base = "socks5"
    return base


def is_netem(label: str) -> bool:
    return label.endswith("-netem") or "-netem-" in label


def fmt_mbps(value: float, stdev: float) -> str:
    if stdev > 0:
        return f"{value:.1f} ±{stdev:.1f}"
    return f"{value:.1f}"


def render_table(rows: list, lines: list) -> None:
    lines += [
        "| Transport | Payload | Runs | Upload Mbps (±σ) | Download Mbps (±σ) |",
        "|-----------|---------|:----:|:----------------:|:------------------:|",
    ]
    for r in rows:
        _, transport = split_label(r.get("label", "?"))
        payload_mb = r.get("total_bytes", 0) // (1024 * 1024)
        runs = r.get("runs", 1)
        upload = fmt_mbps(r.get("upload_mbps", 0.0), r.get("upload_stdev_mbps", 0.0))
        download = fmt_mbps(r.get("download_mbps", 0.0), r.get("download_stdev_mbps", 0.0))
        lines.append(f"| `{transport}` | {payload_mb} MB | {runs} | {upload} | {download} |")
    lines.append("")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", help="JSON-lines result file")
    parser.add_argument("--output", "-o", help="Write markdown to this file (default: stdout)")
    parser.add_argument("--run-url", help="URL to the GitHub Actions workflow run")
    parser.add_argument("--env-json", help="JSON string with test environment info")
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
        normal_rows = [r for r in rows if not is_netem(r.get("label", ""))]
        netem_rows = [r for r in rows if is_netem(r.get("label", ""))]

        # Group by protocol
        def group_by_proto(row_list: list) -> dict[str, list]:
            groups: dict[str, list] = defaultdict(list)
            for r in row_list:
                proto, _ = split_label(r.get("label", "?"))
                groups[proto].append(r)
            return groups

        # Sort protocols by canonical order, unknowns at end alphabetically
        def proto_sort_key(p: str) -> tuple:
            meta = PROTOCOL_META.get(p)
            return (0, meta[1], p) if meta else (1, 999, p)

        lines = ["## 📊 Proxy Throughput Results", ""]

        # Normal results
        groups = group_by_proto(normal_rows)
        total = 0
        for proto in sorted(groups, key=proto_sort_key):
            display_name, _ = PROTOCOL_META.get(proto, (proto.upper(), 99))
            proto_rows = sorted(groups[proto], key=lambda r: (TRANSPORT_ORDER.get(normalize_transport(split_label(r.get("label", ""))[1]), 99), split_label(r.get("label", ""))[1]))
            total += len(proto_rows)

            lines += [f"### {display_name}", ""]
            render_table(proto_rows, lines)

        # Netem results in a separate section
        if netem_rows:
            lines += [
                "### Netem Tests (50 ms delay, 1% packet loss)",
                "",
            ]
            netem_groups = group_by_proto(netem_rows)
            for proto in sorted(netem_groups, key=proto_sort_key):
                display_name, _ = PROTOCOL_META.get(proto, (proto.upper(), 99))
                proto_rows = sorted(netem_groups[proto], key=lambda r: (TRANSPORT_ORDER.get(normalize_transport(split_label(r.get("label", ""))[1]), 99), split_label(r.get("label", ""))[1]))
                total += len(proto_rows)
                lines += [f"#### {display_name}", ""]
                render_table(proto_rows, lines)

        lines.append(
            f"_Ran {total} variant(s) in parallel; each direction transfers the full payload._"
        )
        lines.append("")

        md = "\n".join(lines)

    # Append environment info table if provided
    if args.env_json:
        try:
            env = json.loads(args.env_json)
            env_lines = ["", "### 🖥️ Test Environment", ""]
            env_lines += ["| | |", "|---|---|"]
            os_info = env.get("os", {})
            if os_info.get("system"):
                os_str = f"{os_info['system']} {os_info.get('release', '')}".strip()
                env_lines.append(f"| **OS** | {os_str} |")
                env_lines.append(f"| **Architecture** | {os_info.get('machine', 'unknown')} |")
            if env.get("kernel"):
                env_lines.append(f"| **Kernel** | {env['kernel']} |")
            if env.get("cpu"):
                env_lines.append(f"| **CPU** | {env['cpu']} |")
            if env.get("cpu_cores"):
                env_lines.append(f"| **CPU Cores** | {env['cpu_cores']} |")
            if env.get("memory_gb"):
                env_lines.append(f"| **Memory** | {env['memory_gb']} GB |")
            if env.get("docker"):
                env_lines.append(f"| **Docker** | {env['docker']} |")
            if env.get("rustc"):
                env_lines.append(f"| **Rust** | {env['rustc']} |")
            md = md.rstrip("\n") + "\n" + "\n".join(env_lines) + "\n"
        except (json.JSONDecodeError, KeyError):
            pass

    if args.run_url:
        md = md.rstrip("\n") + f"\n\n[📎 View full workflow run and download artifacts]({args.run_url})\n"

    if args.output:
        with open(args.output, "w") as f:
            f.write(md)
        print(f"Written to {args.output}")
    else:
        print(md)


if __name__ == "__main__":
    main()
