#!/usr/bin/env python3
"""
TUN throughput benchmark script for ClashRS.
Measures network throughput through TUN device and outputs results in JSON format.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path


def check_requirements():
    """Check if required tools are available."""
    required = ["iperf3", "ip"]
    missing = []

    for tool in required:
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            missing.append(tool)

    if missing:
        print(f"Error: Missing required tools: {', '.join(missing)}", file=sys.stderr)
        print("Install with: sudo apt-get install iperf3 iproute2", file=sys.stderr)
        sys.exit(1)


def start_iperf_server():
    """Start iperf3 server in background."""
    print("Starting iperf3 server...")
    proc = subprocess.Popen(
        ["iperf3", "-s", "-D"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    time.sleep(2)  # Give server time to start
    return proc


def stop_iperf_server():
    """Stop iperf3 server."""
    print("Stopping iperf3 server...")
    subprocess.run(["pkill", "-9", "iperf3"], capture_output=True)
    time.sleep(1)


def run_clash_rs(config_path, log_file):
    """Start clash-rs with the given config."""
    clash_binary = os.environ.get("CLASH_BINARY", "./target/release/clash-rs")

    if not os.path.exists(clash_binary):
        print(f"Error: clash-rs binary not found at {clash_binary}", file=sys.stderr)
        sys.exit(1)

    print(f"Starting clash-rs with config: {config_path}")
    proc = subprocess.Popen(
        [clash_binary, "-c", config_path, "-l", log_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for clash-rs to initialize TUN device
    time.sleep(5)

    # Check if process is still running
    if proc.poll() is not None:
        stdout, stderr = proc.communicate()
        print(f"clash-rs failed to start:\n{stderr.decode()}", file=sys.stderr)
        sys.exit(1)

    return proc


def run_iperf_test(server_ip, duration=10, parallel=1):
    """Run iperf3 client test and parse results."""
    print(
        f"Running iperf3 test to {server_ip} for {duration}s with {parallel} streams..."
    )

    cmd = [
        "iperf3",
        "-c",
        server_ip,
        "-t",
        str(duration),
        "-P",
        str(parallel),
        "-J",  # JSON output
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"iperf3 test failed: {result.stderr}", file=sys.stderr)
        return None

    try:
        data = json.loads(result.stdout)
        return data
    except json.JSONDecodeError as e:
        print(f"Failed to parse iperf3 JSON output: {e}", file=sys.stderr)
        return None


def parse_iperf_results(data):
    """Extract key metrics from iperf3 JSON output."""
    if not data or "end" not in data:
        return None

    end = data["end"]

    return {
        "throughput_bps": end["sum_received"]["bits_per_second"],
        "throughput_gbps": end["sum_received"]["bits_per_second"] / 1e9,
        "bytes_transferred": end["sum_received"]["bytes"],
        "retransmits": end.get("sum_sent", {}).get("retransmits", 0),
        "duration_seconds": end["sum_received"]["seconds"],
    }


def run_direct_baseline(server_ip, duration):
    """Run baseline test without TUN (direct connection)."""
    print("\n=== Running baseline test (direct) ===")
    data = run_iperf_test(server_ip, duration)
    if data:
        return parse_iperf_results(data)
    return None


def run_tun_benchmark(config_path, server_ip, duration):
    """Run benchmark through TUN device."""
    print("\n=== Running TUN benchmark ===")

    log_file = "/tmp/clash-rs-bench.log"
    clash_proc = None

    try:
        clash_proc = run_clash_rs(config_path, log_file)
        data = run_iperf_test(server_ip, duration)

        if data:
            return parse_iperf_results(data)
        return None

    finally:
        if clash_proc:
            print("Stopping clash-rs...")
            clash_proc.terminate()
            try:
                clash_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                clash_proc.kill()


def calculate_regression(baseline, tun_result):
    """Calculate performance regression percentage."""
    if not baseline or not tun_result:
        return None

    baseline_gbps = baseline["throughput_gbps"]
    tun_gbps = tun_result["throughput_gbps"]

    regression_pct = ((baseline_gbps - tun_gbps) / baseline_gbps) * 100

    return {
        "baseline_gbps": baseline_gbps,
        "tun_gbps": tun_gbps,
        "regression_percent": regression_pct,
        "overhead_percent": 100 - (tun_gbps / baseline_gbps * 100),
    }


def main():
    parser = argparse.ArgumentParser(description="Run TUN throughput benchmark")
    parser.add_argument(
        "--config",
        default="clash-bin/tests/data/config/tun.yaml",
        help="Path to clash-rs config file with TUN enabled",
    )
    parser.add_argument(
        "--server", default="127.0.0.1", help="iperf3 server IP address"
    )
    parser.add_argument(
        "--duration", type=int, default=10, help="Test duration in seconds"
    )
    parser.add_argument(
        "--output",
        default="benchmark-results.json",
        help="Output JSON file for results",
    )
    parser.add_argument(
        "--skip-baseline",
        action="store_true",
        help="Skip baseline direct connection test",
    )

    args = parser.parse_args()

    check_requirements()

    # Start iperf3 server
    start_iperf_server()

    try:
        results = {
            "timestamp": time.time(),
            "config": args.config,
            "duration": args.duration,
        }

        # Run baseline if not skipped
        if not args.skip_baseline:
            baseline = run_direct_baseline(args.server, args.duration)
            results["baseline"] = baseline
        else:
            baseline = None

        # Run TUN benchmark
        tun_result = run_tun_benchmark(args.config, args.server, args.duration)
        results["tun"] = tun_result

        # Calculate regression
        if baseline and tun_result:
            results["comparison"] = calculate_regression(baseline, tun_result)

        # Write results
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)

        print(f"\n=== Results written to {args.output} ===")
        print(json.dumps(results, indent=2))

        # Return exit code based on results
        if tun_result:
            return 0
        else:
            return 1

    finally:
        stop_iperf_server()


if __name__ == "__main__":
    sys.exit(main())
