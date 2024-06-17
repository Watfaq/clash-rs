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
