#!/bin/sh

# ip to bypass tproxy
readonly LOCAL_BY_PASS="\
127/8 \
10/8 \
"

# declare ip as local for tproxy
ip rule del fwmark 0x3333 lookup 3333
ip rule add fwmark 0x3333 lookup 3333
ip route del local 0.0.0.0/0 dev lo table 3333
ip route add local 0.0.0.0/0 dev lo table 3333

# where all traffic enter tproxy and get marked
iptables -t mangle -N CLASH-TPROXY-INPUT
# fill in the chain
for i in $LOCAL_BY_PASS; do
    iptables -t mangle -A CLASH-TPROXY-INPUT -d $i -j RETURN
done
iptables -t mangle -A CLASH-TPROXY-INPUT -p tcp -j TPROXY \
  --tproxy-mark 0x3333/0x3333 --on-port 8900 --on-ip 127.0.0.1
iptables -t mangle -A CLASH-TPROXY-INPUT -p udp -j TPROXY \
  --tproxy-mark 0x3333/0x3333 --on-port 8900 --on-ip 127.0.0.1

# for local traffic
iptables -t mangle -N CLASH-TPROXY-LOCAL
for i in $LOCAL_BY_PASS; do
    iptables -t mangle -A CLASH-TPROXY-LOCAL -d $i -j RETURN
done
iptables -t mangle -A CLASH-TPROXY-LOCAL -p tcp -m conntrack --ctdir REPLY -j RETURN
iptables -t mangle -A CLASH-TPROXY-LOCAL -p udp -m conntrack --ctdir REPLY -j RETURN

iptables -t mangle -A CLASH-TPROXY-LOCAL -m owner --uid-owner root -j RETURN
# https://github.com/shadowsocks/shadowsocks-rust/blob/6e6e6948d7fc426c99cc03ef91abae989b6482b4/configs/iptables_tproxy.sh#L187
iptables -t mangle -A CLASH-TPROXY-LOCAL -p tcp -j MARK --set-xmark 0x3333/0xffffffff # needs to match the ip rule fwmark
iptables -t mangle -A CLASH-TPROXY-LOCAL -p udp -j MARK --set-xmark 0x3333/0xffffffff

iptables -t mangle -A OUTPUT -p tcp -d 104.21.58.154 -j CLASH-TPROXY-LOCAL
iptables -t mangle -A OUTPUT -p tcp -d 172.67.161.121 -j CLASH-TPROXY-LOCAL
iptables -t mangle -A OUTPUT -p udp -d 1.1.1.1 -j CLASH-TPROXY-LOCAL
iptables -t mangle -A OUTPUT -p udp -d 8.8.8.8 -j CLASH-TPROXY-LOCAL

# for routed traffic
iptables -t mangle -A PREROUTING -p tcp -j CLASH-TPROXY-INPUT
iptables -t mangle -A PREROUTING -p udp -j CLASH-TPROXY-INPUT   



# ipv6
# TODO