## Performance

Being the weaker implementation compared to netstack-lwip, there could be a few optimisation opportunities:

- [ ] Reduce memory allocations by reusing buffers in Device
- [ ] Batch packet processing to reduce overhead in Device
- [ ] What else?


### watfaq-netstack

```
cargo flamegraph -p watfaq-netstack --example with_tun_rs --root


➜  ~ iperf3 -c dsm -t 10
Connecting to host dsm, port 5201
[  5] local 198.19.0.1 port 44548 connected to 10.0.0.11 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   812 MBytes  6.80 Gbits/sec    0    560 KBytes
[  5]   1.00-2.00   sec   783 MBytes  6.57 Gbits/sec    0    560 KBytes
[  5]   2.00-3.00   sec   779 MBytes  6.54 Gbits/sec    0    560 KBytes
[  5]   3.00-4.00   sec   766 MBytes  6.42 Gbits/sec    0    560 KBytes
[  5]   4.00-5.00   sec   759 MBytes  6.37 Gbits/sec    0    560 KBytes
[  5]   5.00-6.00   sec   770 MBytes  6.46 Gbits/sec    0    560 KBytes
[  5]   6.00-7.00   sec   791 MBytes  6.64 Gbits/sec    0    560 KBytes
[  5]   7.00-8.00   sec   811 MBytes  6.80 Gbits/sec    0    560 KBytes
[  5]   8.00-9.00   sec   746 MBytes  6.26 Gbits/sec    0    560 KBytes
[  5]   9.00-10.00  sec   768 MBytes  6.44 Gbits/sec    0    560 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  7.60 GBytes  6.53 Gbits/sec    0            sender
[  5]   0.00-10.00  sec  7.60 GBytes  6.53 Gbits/sec                  receiver

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

### netstack-smoltcp

_Note that the socket buffer size matters in terms of max throughput._

```cargo flamegraph -p watfaq-netstack --example netstack_smoltcp --root

➜  ~ iperf3 -c dsm -t 10
Connecting to host dsm, port 5201
[  5] local 198.19.0.1 port 34250 connected to 10.0.0.11 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   668 MBytes  5.60 Gbits/sec    0    479 KBytes
[  5]   1.00-2.00   sec   691 MBytes  5.80 Gbits/sec    0    479 KBytes
[  5]   2.00-3.00   sec   682 MBytes  5.73 Gbits/sec    0    479 KBytes
[  5]   3.00-4.00   sec   670 MBytes  5.62 Gbits/sec    0    479 KBytes
[  5]   4.00-5.00   sec   671 MBytes  5.63 Gbits/sec    0    479 KBytes
[  5]   5.00-6.00   sec   688 MBytes  5.77 Gbits/sec    0    479 KBytes
[  5]   6.00-7.00   sec   672 MBytes  5.64 Gbits/sec    0    479 KBytes
[  5]   7.00-8.00   sec   690 MBytes  5.78 Gbits/sec    0    479 KBytes
[  5]   8.00-9.00   sec   684 MBytes  5.74 Gbits/sec    0    479 KBytes
[  5]   9.00-10.00  sec   664 MBytes  5.56 Gbits/sec    0    479 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  6.62 GBytes  5.69 Gbits/sec    0            sender
[  5]   0.00-10.00  sec  6.62 GBytes  5.68 Gbits/sec                  receiver

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
