### IPv6 RULES


TPROXY_IP=::
TPROXY_PORT=8900

readonly IPV6_RESERVED_IPADDRS="\
::/128 \
::1/128 \
::ffff:0:0/96 \
::ffff:0:0:0/96 \
64:ff9b::/96 \
100::/64 \
2001::/32 \
2001:20::/28 \
2001:db8::/32 \
2002::/16 \
fc00::/7 \
fe80::/10 \
ff00::/8 \
"

## TCP+UDP
# Strategy Route
ip -6 rule del fwmark 0x1 table 803
ip -6 rule add fwmark 0x1 table 803
ip -6 route del local ::/0 dev lo table 803
ip -6 route add local ::/0 dev lo table 803

# TPROXY for LAN
ip6tables -t mangle -N CLASH-TRPOXY
# Skip LoopBack, Reserved
for addr in ${IPV6_RESERVED_IPADDRS}; do
   ip6tables -t mangle -A CLASH-TRPOXY -d "${addr}" -j RETURN
done

# Bypass LAN data
ip6tables -t mangle -A CLASH-TRPOXY -m addrtype --dst-type LOCAL -j RETURN
# Bypass sslocal's outbound data
ip6tables -t mangle -A CLASH-TRPOXY -m mark --mark 0xff/0xff -j RETURN
# UDP: TPROXY UDP
ip6tables -t mangle -A CLASH-TRPOXY -p udp -j TPROXY --on-ip ${TPROXY_IP} --on-port ${TPROXY_PORT} --tproxy-mark 0x01/0x01

# TCP: TPROXY UDP
ip6tables -t mangle -A CLASH-TRPOXY -p tcp -j TPROXY --on-ip ${TPROXY_IP} --on-port ${TPROXY_PORT} --tproxy-mark 0x01/0x01

# TPROXY for Local
ip6tables -t mangle -N CLASH-TRPOXY-mark
# Skip LoopBack, Reserved
for addr in ${IPV6_RESERVED_IPADDRS}; do
   ip6tables -t mangle -A CLASH-TRPOXY-mark -d "${addr}" -j RETURN
done

# TCP: conntrack
ip6tables -t mangle -A CLASH-TRPOXY-mark -p tcp -m conntrack --ctdir REPLY -j RETURN
# Bypass sslocal's outbound data
ip6tables -t mangle -A CLASH-TRPOXY-mark -m mark --mark 0xff/0xff -j RETURN
ip6tables -t mangle -A CLASH-TRPOXY-mark -m owner --uid-owner root -j RETURN
# Set MARK and reroute
ip6tables -t mangle -A CLASH-TRPOXY-mark -p udp -j MARK --set-xmark 0x01/0xffffffff
ip6tables -t mangle -A CLASH-TRPOXY-mark -p tcp -j MARK --set-xmark 0x01/0xffffffff

# Apply TPROXY to LAN
ip6tables -t mangle -A PREROUTING -p udp -j CLASH-TRPOXY
ip6tables -t mangle -A PREROUTING -p tcp -j CLASH-TRPOXY
#ip6tables -t mangle -A PREROUTING -p udp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j CLASH-TRPOXY
# Apply TPROXY for Local
ip6tables -t mangle -A OUTPUT -p udp -j CLASH-TRPOXY-mark
ip6tables -t mangle -A OUTPUT -p tcp -j CLASH-TRPOXY-mark
#ip6tables -t mangle -A OUTPUT -p udp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j CLASH-TRPOXY-mark
