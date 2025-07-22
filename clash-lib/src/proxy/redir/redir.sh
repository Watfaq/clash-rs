iptables -t nat -N CLASH # Create a new chain named CLASH
iptables -t nat -A CLASH -d 192.168.0.0/16 -j RETURN # Directly connect 192.168.0.0/16
iptables -t nat -A CLASH -p tcp -j RETURN -m mark --mark 0xff # Directly connect traffic with SO_MARK 0xff (0xff is hexadecimal, equivalent to 255 above); this rule is to avoid proxying local (gateway) traffic and causing loopback issues
iptables -t nat -A CLASH -p tcp -j REDIRECT --to-ports 8901 # Redirect all other traffic to port 8901 (i.e., CLASH)
iptables -t nat -A PREROUTING -p tcp -j CLASH # Transparent proxy for other LAN devices
iptables -t nat -A OUTPUT -p tcp -j CLASH # Transparent proxy for local machine