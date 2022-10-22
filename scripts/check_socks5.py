import socks
import socket
import time


def check_socks5_udp(ip, port, rdns):
    s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)

    s.set_proxy(socks.SOCKS5, ip, port, rdns=rdns)

    req = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x62\x61\x69\x64\x75\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"
    s.sendto(req, ("8.8.8.8", 53))

    (rsp, address) = s.recvfrom(4096)
    if rsp[0] == req[0] and rsp[1] == req[1]:
        print("got response from %s:%d for request to %s" % address, "8.8.8.8:53")
    else:
        print("got invalid response from %s:%d" % address)
        return False

    s.sendto(req, ("1.1.1.1", 53))
    (rsp, address) = s.recvfrom(4096)
    if rsp[0] == req[0] and rsp[1] == req[1]:
        print("got response from %s:%d for request to %s" % address, "1.1.1.1:53")
        return True
    else:
        print("got invalid response from %s:%d" % address)
        return False


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: %s <ip> <port> [rdns]" % sys.argv[0])
        sys.exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])
    rdns = False
    if len(sys.argv) >= 4:
        rdns = sys.argv[3] == "true"

    if check_socks5_udp(ip, port, rdns):
        sys.exit(0)
    else:
        sys.exit(1)
