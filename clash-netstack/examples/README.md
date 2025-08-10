## Performace

Being the weaker implementation compared to netstack-lwip, there could be a few optimisation opportunities:

- [ ] Reduce memory allocations by reusing buffers in Device
- [ ] Batch packet processing to reduce overhead in Device
- [ ] What else?


### watfaq-netstack

```
cargo flamegraph -p watfaq-netstack --example with_tun_rs --root


➜  ~ iperf3 -c dsm -t 10
Connecting to host dsm, port 5201
[  5] local 198.19.0.1 port 44714 connected to 10.0.0.11 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   158 MBytes  1.32 Gbits/sec    0   1.23 MBytes
[  5]   1.00-2.00   sec   158 MBytes  1.32 Gbits/sec    0   1.23 MBytes
[  5]   2.00-3.00   sec   153 MBytes  1.28 Gbits/sec    0   1.23 MBytes
[  5]   3.00-4.00   sec   156 MBytes  1.31 Gbits/sec    0   1.23 MBytes
[  5]   4.00-5.00   sec   150 MBytes  1.26 Gbits/sec    0   1.23 MBytes
[  5]   5.00-6.00   sec   156 MBytes  1.31 Gbits/sec    0   1.23 MBytes
[  5]   6.00-7.00   sec   157 MBytes  1.32 Gbits/sec    0   1.23 MBytes
[  5]   7.00-8.00   sec   153 MBytes  1.28 Gbits/sec    0   1.23 MBytes
[  5]   8.00-9.00   sec   153 MBytes  1.28 Gbits/sec    0   1.23 MBytes
[  5]   9.00-10.00  sec   154 MBytes  1.29 Gbits/sec    0   1.23 MBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  1.51 GBytes  1.30 Gbits/sec    0            sender
[  5]   0.00-10.01  sec  1.51 GBytes  1.30 Gbits/sec                  receiver

iperf Done.
```

### netstack-lwip

```
cargo flamegraph -p watfaq-netstack --example netstack_lwip --root


➜  ~ iperf3 -c dsm -t 10
Connecting to host dsm, port 5201
[  5] local 198.19.0.1 port 53946 connected to 10.0.0.11 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   465 MBytes  3.90 Gbits/sec    1   49.9 KBytes
[  5]   1.00-2.00   sec   479 MBytes  4.02 Gbits/sec    0   49.9 KBytes
[  5]   2.00-3.00   sec   474 MBytes  3.98 Gbits/sec    0   49.9 KBytes
[  5]   3.00-4.00   sec   438 MBytes  3.67 Gbits/sec    0   49.9 KBytes
[  5]   4.00-5.00   sec   466 MBytes  3.91 Gbits/sec    0   49.9 KBytes
[  5]   5.00-6.00   sec   440 MBytes  3.69 Gbits/sec    0   49.9 KBytes
[  5]   6.00-7.00   sec   434 MBytes  3.64 Gbits/sec    0   49.9 KBytes
[  5]   7.00-8.00   sec   451 MBytes  3.79 Gbits/sec    0   49.9 KBytes
[  5]   8.00-9.00   sec   459 MBytes  3.85 Gbits/sec    0   49.9 KBytes
[  5]   9.00-10.00  sec   481 MBytes  4.03 Gbits/sec    0   49.9 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  4.48 GBytes  3.85 Gbits/sec    1            sender
[  5]   0.00-10.00  sec  4.48 GBytes  3.85 Gbits/sec                  receiver

iperf Done.
```

### Baseline

```
➜  ~ iperf3 -c dsm -t 10
Connecting to host dsm, port 5201
[  5] local 10.0.0.23 port 58860 connected to 10.0.0.11 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  1.08 GBytes  9.28 Gbits/sec    0   1.90 MBytes
[  5]   1.00-2.00   sec  1.09 GBytes  9.35 Gbits/sec    0   2.19 MBytes
[  5]   2.00-3.00   sec  1.09 GBytes  9.38 Gbits/sec    0   2.19 MBytes
[  5]   3.00-4.00   sec  1.09 GBytes  9.38 Gbits/sec    0   2.32 MBytes
[  5]   4.00-5.00   sec  1.09 GBytes  9.38 Gbits/sec    0   2.62 MBytes
[  5]   5.00-6.00   sec  1.06 GBytes  9.08 Gbits/sec    0   2.91 MBytes
[  5]   6.00-7.00   sec  1.09 GBytes  9.34 Gbits/sec    0   3.08 MBytes
[  5]   7.00-8.00   sec  1.09 GBytes  9.37 Gbits/sec    0   3.08 MBytes
[  5]   8.00-9.00   sec  1.09 GBytes  9.38 Gbits/sec    0   3.08 MBytes
[  5]   9.00-10.00  sec  1.09 GBytes  9.35 Gbits/sec  469   2.19 MBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  10.9 GBytes  9.33 Gbits/sec  469            sender
[  5]   0.00-10.00  sec  10.9 GBytes  9.32 Gbits/sec                  receiver

iperf Done.
```
