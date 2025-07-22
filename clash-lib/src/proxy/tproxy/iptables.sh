#!/bin/bash

### IPv4 RULES

TPROXY_IP=127.0.0.1
TPROXY_PORT=8900

readonly IPV4_RESERVED_IPADDRS="\
0/8 \
10/8 \
100.64/10 \
127/8 \
169.254/16 \
172.16/12 \
192/24 \
192.0.2.0/24 \
192.88.99/24 \
192.168/16 \
198.18/15 \
198.51.100/24 \
203.0.113/24 \
224/4 \
240/4 \
255.255.255.255/32 \
"

## TCP+UDP
# Strategy Route
ip -4 rule del fwmark 0x1 table 803
ip -4 rule add fwmark 0x1 table 803
ip -4 route del local 0.0.0.0/0 dev lo table 803
ip -4 route add local 0.0.0.0/0 dev lo table 803

# TPROXY for LAN
iptables -t mangle -N clash-rs-tproxy
# Skip LoopBack, Reserved
for addr in ${IPV4_RESERVED_IPADDRS}; do
   iptables -t mangle -A clash-rs-tproxy -d "${addr}" -j RETURN
done

# Bypass LAN data
iptables -t mangle -A clash-rs-tproxy -m addrtype --dst-type LOCAL -j RETURN
# Bypass sslocal's outbound data
iptables -t mangle -A clash-rs-tproxy -m mark --mark 0xff/0xff -j RETURN
# UDP: TPROXY UDP to 60080
iptables -t mangle -A clash-rs-tproxy -p udp -j TPROXY --on-ip ${TPROXY_IP} --on-port ${TPROXY_PORT} --tproxy-mark 0x01/0x01
# TCP: TPROXY TCP to 60080
iptables -t mangle -A clash-rs-tproxy -p tcp -j TPROXY --on-ip ${TPROXY_IP} --on-port ${TPROXY_PORT} --tproxy-mark 0x01/0x01


# TPROXY for Local
iptables -t mangle -N clash-rs-tproxy-mark
# Skip LoopBack, Reserved
for addr in ${IPV4_RESERVED_IPADDRS}; do
   iptables -t mangle -A clash-rs-tproxy-mark -d "${addr}" -j RETURN
done

# TCP: conntrack
iptables -t mangle -A clash-rs-tproxy-mark -p tcp -m conntrack --ctdir REPLY -j RETURN
# Bypass calsh local's outbound data
iptables -t mangle -A clash-rs-tproxy-mark -m mark --mark 0xff/0xff -j RETURN
iptables -t mangle -A clash-rs-tproxy-mark -m owner --uid-owner root -j RETURN
# UDP: Set MARK and reroute
iptables -t mangle -A clash-rs-tproxy-mark -p udp -j MARK --set-xmark 0x01/0xffffffff
# TCP: Set MARK and reroute
iptables -t mangle -A clash-rs-tproxy-mark -p tcp -j MARK --set-xmark 0x01/0xffffffff

# Apply TPROXY to LAN
iptables -t mangle -A PREROUTING -p udp -j clash-rs-tproxy
iptables -t mangle -A PREROUTING -p tcp -j clash-rs-tproxy
#iptables -t mangle -A PREROUTING -p udp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j clash-rs-tproxy
# Apply TPROXY for Local
iptables -t mangle -A OUTPUT -p udp -j clash-rs-tproxy-mark
iptables -t mangle -A OUTPUT -p tcp -j clash-rs-tproxy-mark