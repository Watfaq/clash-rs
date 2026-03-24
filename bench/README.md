## To get a flamegraph

```
cargo flamegraph --root -- -d ./clash/tests/data/config/ -f rules.yaml
```

_adjust args on your own_


## An example

### Environment

* client - Debian 12.5 running inside Hyper-V on i9-9900KF and 64GB mem
* server - DS1821+
* connection - 10 Gig cabled 

### Direct connect

```
~ » iperf3 -c dsm                                                                                        
Connecting to host dsm, port 5201
[  5] local 10.0.0.14 port 40148 connected to 10.0.0.11 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  1.03 GBytes  8.87 Gbits/sec    0   3.09 MBytes
[  5]   1.00-2.00   sec  1.05 GBytes  9.06 Gbits/sec    0   3.09 MBytes
[  5]   2.00-3.00   sec  1.09 GBytes  9.37 Gbits/sec    0   3.09 MBytes
[  5]   3.00-4.00   sec  1.04 GBytes  8.90 Gbits/sec    0   3.09 MBytes
[  5]   4.00-5.00   sec  1.06 GBytes  9.07 Gbits/sec    0   3.09 MBytes
[  5]   5.00-6.00   sec  1.04 GBytes  8.93 Gbits/sec    0   3.09 MBytes
[  5]   6.00-7.00   sec  1.05 GBytes  9.00 Gbits/sec    0   3.09 MBytes
[  5]   7.00-8.00   sec  1.08 GBytes  9.24 Gbits/sec    0   3.09 MBytes
[  5]   8.00-9.00   sec  1.07 GBytes  9.15 Gbits/sec    0   3.09 MBytes
[  5]   9.00-10.00  sec  1.05 GBytes  9.02 Gbits/sec    0   3.09 MBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  10.5 GBytes  9.06 Gbits/sec    0             sender
[  5]   0.00-10.00  sec  10.5 GBytes  9.05 Gbits/sec                  receiver

iperf Done.
--------------
```

### Connect via tun


```
~ » iperf3 -c dsm                                                                                        
Connecting to host dsm, port 5201
[  5] local 10.0.0.14 port 41436 connected to 10.0.0.11 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   234 MBytes  1.96 Gbits/sec    1   47.1 KBytes
[  5]   1.00-2.00   sec   235 MBytes  1.97 Gbits/sec    0   47.1 KBytes
[  5]   2.00-3.00   sec   243 MBytes  2.04 Gbits/sec    0   47.1 KBytes
[  5]   3.00-4.00   sec   239 MBytes  2.00 Gbits/sec    0   47.1 KBytes
[  5]   4.00-5.00   sec   240 MBytes  2.02 Gbits/sec    0   47.1 KBytes
[  5]   5.00-6.00   sec   238 MBytes  1.99 Gbits/sec    0   47.1 KBytes
[  5]   6.00-7.00   sec   235 MBytes  1.97 Gbits/sec    0   47.1 KBytes
[  5]   7.00-8.00   sec   233 MBytes  1.95 Gbits/sec    0   47.1 KBytes
[  5]   8.00-9.00   sec   236 MBytes  1.98 Gbits/sec    0   47.1 KBytes
[  5]   9.00-10.00  sec   241 MBytes  2.03 Gbits/sec    0   47.1 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  2.32 GBytes  1.99 Gbits/sec    1             sender
[  5]   0.00-10.00  sec  2.32 GBytes  1.99 Gbits/sec                  receiver

iperf Done.
```

There should be room for the performance improve.

---

## Automated CI Benchmarking

### Overview

The project includes automated TUN throughput benchmarking that runs on every PR affecting TUN-related code. The benchmark results are automatically posted as comments on the PR.

### How It Works

1. **Trigger**: The benchmark workflow runs when PRs modify:
   - `clash-lib/src/proxy/tun/**`
   - `clash-netstack/**`
   - `bench/**`
   - `.github/workflows/benchmark.yml`

2. **Baseline Comparison**:
   - The repo includes a committed baseline file (`bench/baseline-tun-benchmark.json`)
   - This baseline represents the performance of the latest master branch
   - PRs are compared against this baseline (no need to rebuild master every time)
   - When a PR with good performance is merged, update the baseline for future comparisons

3. **Execution**:
   - Creates a veth pair (veth0 <-> veth1 @ namespace) with TEST-NET-1 IPs
   - Builds the PR code in release mode
   - Runs TUN benchmark with traffic routing through TUN device
   - Compares with committed baseline file
   - Posts results as a PR comment

4. **Results**: The workflow posts a comment showing:
   - Current PR throughput performance
   - Comparison with baseline (master branch)
   - Performance difference percentage
   - Warning if regression exceeds 10%
   - Clash-rs logs available as downloadable artifact

### Test Methodology

The benchmark uses **veth pairs with network namespaces** to ensure traffic actually goes through the TUN device:

- **Setup**: Creates veth pair using TEST-NET-1 range (192.0.2.1 <-> 192.0.2.2@namespace)
  - Uses RFC 5737 reserved range to avoid conflicts with real networks
  - veth1 placed in separate network namespace to prevent kernel local routing
- **Baseline**: Direct connection to 192.0.2.2 via veth (no TUN routing)
  - Expected: ~5-20 Gbps (virtual network interface speed)
- **TUN Test**: 
  - Removes direct route to 192.0.2.2
  - Configures TUN to route 192.0.2.0/24
  - Traffic to 192.0.2.2 **must** go through TUN
  - Expected: ~1-3 Gbps (TUN adds overhead)
- **Comparison**: Shows TUN overhead as percentage difference

### Running Benchmarks Locally

```bash
# Build clash-rs
cargo build --release --bin clash-rs --all-features

# Run the benchmark (includes baseline test)
python3 bench/run_tun_benchmark.py \
  --config bench/tun-benchmark.yaml \
  --duration 10 \
  --output results.json

# Run TUN-only benchmark (skip baseline, like CI)
python3 bench/run_tun_benchmark.py \
  --config bench/tun-benchmark.yaml \
  --duration 10 \
  --output results.json \
  --skip-baseline

# Compare with baseline
python3 bench/compare_results.py \
  --current results.json \
  --baseline bench/baseline-tun-benchmark.json \
  --output comment.md
```

### Updating the Baseline

When merging a PR that improves performance or after significant changes:

```bash
# Run benchmark to generate new baseline
python3 bench/run_tun_benchmark.py \
  --config bench/tun-benchmark.yaml \
  --duration 10 \
  --output bench/baseline-tun-benchmark.json \
  --skip-baseline

# Commit the updated baseline
git add bench/baseline-tun-benchmark.json
git commit -m "chore: update TUN benchmark baseline"
```

The committed baseline becomes the reference point for all future PRs.

### Configuration

- **Benchmark config**: `bench/tun-benchmark.yaml` - Minimal TUN config for CI
- **Test duration**: Default 10 seconds (configurable via `--duration`)
- **Regression threshold**: 10% decrease triggers a warning
- **Server**: Uses localhost iperf3 server

### Requirements

- iperf3 (`apt-get install iperf3`)
- iproute2 (`apt-get install iproute2`)
- Python 3.x
- sudo/root access (required for creating network interfaces and TUN device)

### Files

- `run_tun_benchmark.py` - Main benchmark script
- `compare_results.py` - Results comparison and comment generation
- `tun-benchmark.yaml` - CI benchmark configuration
