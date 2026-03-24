#!/usr/bin/env python3
"""
Compare TUN benchmark results and generate PR comment.
"""

import argparse
import json
import sys
from pathlib import Path


def format_throughput(bps):
    """Format throughput in human-readable form."""
    if bps >= 1e9:
        return f"{bps / 1e9:.2f} Gbps"
    elif bps >= 1e6:
        return f"{bps / 1e6:.2f} Mbps"
    elif bps >= 1e3:
        return f"{bps / 1e3:.2f} Kbps"
    else:
        return f"{bps:.0f} bps"


def format_bytes(bytes_val):
    """Format bytes in human-readable form."""
    if bytes_val >= 1e9:
        return f"{bytes_val / 1e9:.2f} GB"
    elif bytes_val >= 1e6:
        return f"{bytes_val / 1e6:.2f} MB"
    elif bytes_val >= 1e3:
        return f"{bytes_val / 1e3:.2f} KB"
    else:
        return f"{bytes_val:.0f} bytes"


def get_status_emoji(regression_pct, threshold=5.0):
    """Get emoji based on regression percentage."""
    if regression_pct is None:
        return "⚪"
    elif regression_pct > threshold:
        return "🔴"  # Significant regression
    elif regression_pct > 0:
        return "🟡"  # Minor regression
    else:
        return "🟢"  # Improvement


def generate_comment(current_results, baseline_results=None):
    """Generate markdown comment for PR."""
    lines = ["## 🚀 TUN Throughput Benchmark Results\n"]

    # Environment information
    if current_results.get("environment"):
        env = current_results["environment"]
        lines.append("<details>")
        lines.append("<summary>📊 Test Environment</summary>")
        lines.append("")
        lines.append("| Component | Details |")
        lines.append("|-----------|---------|")
        
        # OS info
        if env.get("os"):
            os_info = env["os"]
            os_str = f"{os_info.get('system', 'Unknown')} {os_info.get('release', '')}"
            lines.append(f"| **OS** | {os_str} |")
            lines.append(f"| **Architecture** | {os_info.get('machine', 'Unknown')} |")
        
        # CPU info
        if env.get("cpu"):
            lines.append(f"| **CPU** | {env['cpu']} |")
        if env.get("cpu_cores"):
            lines.append(f"| **CPU Cores** | {env['cpu_cores']} |")
        
        # Memory info
        if env.get("memory_gb"):
            lines.append(f"| **Memory** | {env['memory_gb']} GB |")
        
        # Kernel info
        if env.get("kernel"):
            lines.append(f"| **Kernel** | {env['kernel']} |")
        
        # Network interfaces
        if env.get("interfaces"):
            interfaces = env["interfaces"]
            iface_parts = []
            for iface in interfaces:
                if isinstance(iface, dict):
                    name = iface.get("name", "unknown")
                    speed = iface.get("speed_mbps", "unknown")
                    if speed != "unknown":
                        iface_parts.append(f"{name} ({speed} Mbps)")
                    else:
                        iface_parts.append(name)
                else:
                    iface_parts.append(str(iface))
            ifaces = ", ".join(iface_parts)
            lines.append(f"| **Network Interfaces** | {ifaces} |")
        
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Current PR results
    if current_results.get("tun"):
        tun = current_results["tun"]
        lines.append("### Current PR Performance")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| **Throughput** | {format_throughput(tun['throughput_bps'])} |")
        lines.append(
            f"| **Data Transferred** | {format_bytes(tun['bytes_transferred'])} |"
        )
        lines.append(f"| **Duration** | {tun['duration_seconds']:.2f}s |")
        lines.append(f"| **Retransmits** | {tun.get('retransmits', 0)} |")
        lines.append("")

    # Comparison with baseline
    if baseline_results and baseline_results.get("tun"):
        baseline_tun = baseline_results["tun"]
        current_tun = current_results.get("tun")

        if current_tun:
            current_gbps = current_tun["throughput_bps"] / 1e9
            baseline_gbps = baseline_tun["throughput_bps"] / 1e9
            diff_gbps = current_gbps - baseline_gbps
            diff_pct = (diff_gbps / baseline_gbps) * 100

            status = get_status_emoji(
                -diff_pct
            )  # Negative because we want positive diff to be good

            lines.append("### Comparison with Baseline (master)")
            lines.append("")
            lines.append("| Metric | Baseline | Current | Difference |")
            lines.append("|--------|----------|---------|------------|")
            lines.append(
                f"| **Throughput** | {baseline_gbps:.2f} Gbps | {current_gbps:.2f} Gbps | "
                f"{status} {diff_gbps:+.2f} Gbps ({diff_pct:+.1f}%) |"
            )
            lines.append("")

            if diff_pct < -5:
                lines.append(
                    "⚠️ **Warning**: Throughput has decreased by more than 5% compared to baseline."
                )
                lines.append("")
            elif diff_pct > 5:
                lines.append(
                    "🎉 **Great**: Throughput has improved by more than 5% compared to baseline!"
                )
                lines.append("")

    # Direct baseline comparison (if available in current run)
    if current_results.get("comparison"):
        comp = current_results["comparison"]
        lines.append("### Direct vs TUN Comparison (Local)")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| **Direct Connection** | {comp['baseline_gbps']:.2f} Gbps |")
        lines.append(f"| **Through TUN** | {comp['tun_gbps']:.2f} Gbps |")
        lines.append(f"| **Overhead** | {comp['overhead_percent']:.1f}% |")
        lines.append("")

    # Footer
    footer_parts = []
    footer_parts.append(f"Test duration: {current_results.get('duration', 10)}s")
    
    if current_results.get("environment"):
        env = current_results["environment"]
        if env.get("os", {}).get("system"):
            footer_parts.append(f"{env['os']['system']} {env['os'].get('machine', '')}")
        if env.get("cpu_cores"):
            footer_parts.append(f"{env['cpu_cores']} cores")
    
    lines.append("<sub>🤖 Benchmark run on GitHub Actions CI • ")
    lines.append(" • ".join(footer_parts))
    lines.append("</sub>")

    return "\n".join(lines)


def load_results(filepath):
    """Load benchmark results from JSON file."""
    try:
        with open(filepath) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: Results file not found: {filepath}", file=sys.stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON from {filepath}: {e}", file=sys.stderr)
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Compare benchmark results and generate PR comment"
    )
    parser.add_argument(
        "--current", required=True, help="Path to current benchmark results JSON"
    )
    parser.add_argument(
        "--baseline",
        help="Path to baseline benchmark results JSON (from master/main branch)",
    )
    parser.add_argument(
        "--output",
        default="benchmark-comment.md",
        help="Output file for PR comment markdown",
    )
    parser.add_argument(
        "--fail-on-regression",
        type=float,
        help="Exit with error code if regression exceeds this percentage",
    )

    args = parser.parse_args()

    # Load results
    current = load_results(args.current)
    baseline = load_results(args.baseline) if args.baseline else None

    if not current:
        print("Error: Could not load current results", file=sys.stderr)
        return 1

    # Generate comment
    comment = generate_comment(current, baseline)

    # Write to file
    with open(args.output, "w") as f:
        f.write(comment)

    print(f"Comment written to {args.output}")
    print("\n--- Comment Preview ---")
    print(comment)
    print("--- End Preview ---\n")

    # Check for regression
    if args.fail_on_regression and baseline:
        baseline_tun = baseline.get("tun")
        current_tun = current.get("tun")

        if baseline_tun and current_tun:
            current_gbps = current_tun["throughput_bps"] / 1e9
            baseline_gbps = baseline_tun["throughput_bps"] / 1e9
            diff_pct = ((baseline_gbps - current_gbps) / baseline_gbps) * 100

            if diff_pct > args.fail_on_regression:
                print(
                    f"❌ REGRESSION DETECTED: {diff_pct:.1f}% decrease (threshold: {args.fail_on_regression}%)"
                )
                return 1
            else:
                print(
                    f"✅ Performance acceptable: {diff_pct:.1f}% change (threshold: {args.fail_on_regression}%)"
                )

    return 0


if __name__ == "__main__":
    sys.exit(main())
