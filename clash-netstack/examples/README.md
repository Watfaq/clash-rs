```
wtf@devbox-hypv:~/projects/clash-rs$ iperf3 -c dsm
Connecting to host dsm, port 5201
[  5] local 198.19.0.1 port 48868 connected to 10.0.0.11 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  66.5 MBytes   558 Mbits/sec    0    754 KBytes
[  5]   1.00-2.00   sec  66.2 MBytes   556 Mbits/sec    0    754 KBytes
[  5]   2.00-3.00   sec  63.8 MBytes   535 Mbits/sec    0    754 KBytes
[  5]   3.00-4.00   sec  60.0 MBytes   503 Mbits/sec    0    754 KBytes
[  5]   4.00-5.00   sec  63.8 MBytes   535 Mbits/sec    0    754 KBytes
[  5]   5.00-6.00   sec  62.5 MBytes   524 Mbits/sec    0    754 KBytes
[  5]   6.00-7.00   sec  63.8 MBytes   535 Mbits/sec    0    754 KBytes
[  5]   7.00-8.00   sec  65.0 MBytes   545 Mbits/sec    0    754 KBytes
[  5]   8.00-9.00   sec  61.2 MBytes   514 Mbits/sec    0    754 KBytes
[  5]   9.00-10.00  sec  61.2 MBytes   514 Mbits/sec    0    754 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec   634 MBytes   532 Mbits/sec    0             sender
[  5]   0.00-10.01  sec   630 MBytes   528 Mbits/sec                  receiver

iperf Done.
```
