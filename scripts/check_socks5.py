import socks
import socket


def check_socks5_tun():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    req = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x62\x61\x69\x64\x75\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"
    s.sendto(req, ("8.8.8.8", 53))

    print(s.getsockname())

    (res, address) = s.recvfrom(4096)
    if res[0] == req[0] and res[1] == req[1]:
        print(
            "got response %s from %s for request to %s" % (
                res, address, "8.8.8.8:53")
        )
    else:
        print("got invalid response %s from %s" % (res, address))
        return False

    s.sendto(req, ("1.1.1.1", 53))
    (res, address) = s.recvfrom(4096)
    if res[0] == req[0] and res[1] == req[1]:
        print(
            "got response %s from %s for request to %s" % (
                res, address, "1.1.1.1:53")
        )
        return True
    else:
        print("got invalid response %s from %s" % (res, address))
        return False


def check_socks5_udp(ip, port, rdns):
    s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)

    s.set_proxy(socks.SOCKS5, ip, port, rdns=rdns)

    req = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x62\x61\x69\x64\x75\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"
    s.sendto(req, ("8.8.8.8", 53))

    (res, address) = s.recvfrom(4096)
    if res[0] == req[0] and res[1] == req[1]:
        print(
            "got response %s from %s for request to %s" % (
                res, address, "1.1.1.1:53")
        )
    else:
        print("got invalid response %s from %s" % (res, address))
        return False

    s.sendto(req, ("1.1.1.1", 53))
    (res, address) = s.recvfrom(4096)
    if res[0] == req[0] and res[1] == req[1]:
        print(
            "got response %s from %s for request to %s" % (
                res, address, "1.1.1.1:53")
        )
        return True
    else:
        print("got invalid response %s from %s" % (res, address))
        return False


if __name__ == "__main__":
    import sys

    if sys.argv[1] == 'tun':
        check_socks5_tun()
        sys.exit(0)

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
