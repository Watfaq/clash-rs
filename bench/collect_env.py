#!/usr/bin/env python3
"""Collect test environment info and print it as a JSON object.

Used by the proxy-throughput workflow to embed environment details
in the PR comment alongside throughput results.
"""

import json
import os
import platform
import subprocess


def main() -> None:
    env: dict = {
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "cpu_cores": os.cpu_count(),
    }

    try:
        with open("/proc/cpuinfo") as f:
            cpuinfo = f.read()
        for line in cpuinfo.splitlines():
            if "model name" in line:
                env["cpu"] = line.split(":", 1)[1].strip()
                break
        env["cpu_cores"] = cpuinfo.count("processor\t:")
    except Exception:
        env["cpu"] = platform.processor()

    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    env["memory_gb"] = round(int(line.split()[1]) / 1024 / 1024, 2)
                    break
    except Exception:
        pass

    try:
        r = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=5)
        env["kernel"] = r.stdout.strip()
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        env["docker"] = r.stdout.strip()
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["rustc", "--version"], capture_output=True, text=True, timeout=5
        )
        env["rustc"] = r.stdout.strip()
    except Exception:
        pass

    print(json.dumps(env))


if __name__ == "__main__":
    main()
