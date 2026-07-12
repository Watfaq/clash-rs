use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
};

use socket2::{Domain, Protocol, Socket, Type};

use crate::config::Interface;

#[async_trait::async_trait]
pub trait SocketFactory: Send + Sync {
    async fn create_socket(&self) -> std::io::Result<socket2::Socket>;
}
pub struct UdpSocketFactory {
    pub addr: String,
    pub interface: Option<Interface>,
    pub fw_mark: Option<u32>,
    pub protect_path: Option<PathBuf>,
    pub try_dual_stack: bool,
}
#[async_trait::async_trait]
impl SocketFactory for UdpSocketFactory {
    async fn create_socket(&self) -> std::io::Result<socket2::Socket> {
        let addr = self
            .addr
            .to_socket_addrs()
            .unwrap_or_else(|_| panic!("resolve quic addr faile: {}", self.addr))
            .next()
            .unwrap_or_else(|| panic!("resolve quic addr faile: {}", self.addr));
        let socket = if let Some(Interface::Address(ip)) = self.interface {
            let domain = if ip.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            let bind_addr = SocketAddr::new(ip, 0);
            socket.bind(&bind_addr.into())?;
            socket
        } else {
            let ipv6 = addr.is_ipv6();
            let try_create_dual_stack = || {
                let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
                socket.set_only_v6(false)?;
                let bind_addr: SocketAddr = "[::]:0".parse().unwrap();
                socket.bind(&bind_addr.into())?;
                Ok(socket) as Result<Socket, io::Error>
            };
            if self.try_dual_stack
                && let Ok(socket) = try_create_dual_stack()
            {
                tracing::trace!("dual stack udp socket created");
                socket
            } else if ipv6 {
                let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
                let bind_addr: SocketAddr = "[::]:0".parse().unwrap();
                socket.bind(&bind_addr.into())?;
                socket
            } else {
                let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
                let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
                socket.bind(&bind_addr.into())?;
                socket
            }
        };
        socket.set_nonblocking(true)?;
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        {
            if let Some(fw_mark) = self.fw_mark {
                socket.set_mark(fw_mark)?;
            }
        }

        if let Some(Interface::Device(ref device_name)) = self.interface {
            if addr.ip().is_loopback() {
                tracing::trace!(
                    "skipping bind_device for udp socket to loopback destination {}",
                    addr
                );
            } else {
                crate::utils::platform::bind_device(&socket, device_name)?;
                tracing::debug!("udp socket bound to device {}", device_name);
            }
        }

        #[cfg(target_os = "android")]
        if let Some(path) = &self.protect_path {
            use crate::utils::protect_socket::protect_socket_with_retry;
            use std::os::fd::AsRawFd;

            tracing::debug!("trying protect socket");
            tokio::time::timeout(
                tokio::time::Duration::from_secs(5),
                protect_socket_with_retry(path, socket.as_raw_fd()),
            )
            .await
            .map_err(|_| io::Error::other("protecting socket timeout"))
            .and_then(|x| x)
            .map_err(|e| {
                tracing::error!("error during protecing socket:{}", e);
                e
            })?;
        }

        Ok(socket)
    }
}

pub struct TcpSocketFactory {
    pub addr: String,
    pub interface: Option<Interface>,
    pub fw_mark: Option<u32>,
    pub protect_path: Option<PathBuf>,
}
#[async_trait::async_trait]
impl SocketFactory for TcpSocketFactory {
    async fn create_socket(&self) -> std::io::Result<socket2::Socket> {
        let addr = self
            .addr
            .to_socket_addrs()
            .unwrap_or_else(|_| panic!("resolve tcp addr faile: {}", self.addr))
            .next()
            .unwrap_or_else(|| panic!("resolve tcp addr faile: {}", self.addr));
        let socket = if let Some(Interface::Address(ip)) = self.interface {
            let domain = if ip.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
            let bind_addr = SocketAddr::new(ip, 0);
            socket.bind(&bind_addr.into())?;
            socket
        } else {
            let ipv6 = addr.is_ipv6();
            if ipv6 {
                let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
                let bind_addr: SocketAddr = "[::]:0".parse().unwrap();
                socket.bind(&bind_addr.into())?;
                socket
            } else {
                let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
                let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
                socket.bind(&bind_addr.into())?;
                socket
            }
        };
        socket.set_nonblocking(true)?;

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        {
            if let Some(fw_mark) = self.fw_mark {
                socket.set_mark(fw_mark)?;
            }
        }

        if let Some(Interface::Device(ref device_name)) = self.interface {
            if addr.ip().is_loopback() {
                tracing::trace!(
                    "skipping bind_device for tcp socket to loopback destination {}",
                    addr
                );
            } else {
                crate::utils::platform::bind_device(&socket, device_name)?;
                tracing::debug!("tcp socket bound to device {}", device_name);
            }
        }

        #[cfg(target_os = "android")]
        if let Some(path) = &self.protect_path {
            use crate::utils::protect_socket::protect_socket_with_retry;
            use std::os::fd::AsRawFd;

            tracing::debug!("trying protect socket");
            tokio::time::timeout(
                tokio::time::Duration::from_secs(5),
                protect_socket_with_retry(path, socket.as_raw_fd()),
            )
            .await
            .map_err(|_| io::Error::other("protecting socket timeout"))
            .and_then(|x| x)
            .map_err(|e| {
                tracing::error!("error during protecing socket:{}", e);
                e
            })?;
        }

        Ok(socket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    /// Returns the local IP address that would be used when connecting to 1.1.1.1,
    /// by using the OS routing table via a non-blocking UDP connect (no packets sent).
    fn get_local_ip() -> Option<IpAddr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("1.1.1.1:53").ok()?;
        socket.local_addr().ok().map(|a| a.ip())
    }

    /// Returns the default network interface name by reading the kernel routing table.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn get_default_interface_name() -> Option<String> {
        let content = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in content.lines().skip(1) {
            let mut parts = line.split_whitespace();
            let iface = parts.next()?;
            let dest = parts.next()?;
            // "00000000" is the default route (0.0.0.0)
            if dest == "00000000" {
                return Some(iface.to_string());
            }
        }
        None
    }

    /// Returns the name of the interface whose address matches the local routing IP.
    /// Uses `getifaddrs` to enumerate all interfaces on macOS.
    #[cfg(target_os = "macos")]
    fn get_default_interface_name() -> Option<String> {
        use std::ffi::CStr;
        let local_ip = get_local_ip()?;
        let local_ipv4 = match local_ip {
            std::net::IpAddr::V4(v4) => v4,
            _ => return None,
        };
        let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
            return None;
        }
        let mut result = None;
        let mut cur = addrs;
        while !cur.is_null() {
            let ifa = unsafe { &*cur };
            if !ifa.ifa_addr.is_null()
                && unsafe { (*ifa.ifa_addr).sa_family } as u32 == libc::AF_INET as u32
            {
                let sin = ifa.ifa_addr as *const libc::sockaddr_in;
                let s_addr = unsafe { (*sin).sin_addr.s_addr };
                let addr = std::net::Ipv4Addr::from(s_addr.to_ne_bytes());
                if addr == local_ipv4 {
                    result = unsafe { CStr::from_ptr(ifa.ifa_name) }
                        .to_str()
                        .ok()
                        .map(str::to_string);
                    break;
                }
            }
            cur = unsafe { (*cur).ifa_next };
        }
        unsafe { libc::freeifaddrs(addrs) };
        result
    }

    /// Returns the adapter GUID name of the interface whose IP matches the local
    /// routing IP.  Uses `GetAdaptersInfo` from the Windows IP-Helper API; the
    /// returned GUID string is accepted by `if_nametoindex` on Windows.
    #[cfg(target_os = "windows")]
    fn get_default_interface_name() -> Option<String> {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetAdaptersInfo, IP_ADAPTER_INFO, IP_ADDR_STRING,
        };
        let local_ip = get_local_ip()?;
        let local_ipv4_str = match local_ip {
            std::net::IpAddr::V4(v4) => v4.to_string(),
            _ => return None,
        };
        let mut size: u32 = 16384;
        let mut buf = vec![0u8; size as usize];
        // First attempt; if the buffer is too small the function updates `size`
        // and we retry once with the grown buffer.
        let rc =
            unsafe { GetAdaptersInfo(Some(buf.as_mut_ptr() as *mut IP_ADAPTER_INFO), &mut size) };
        if rc != 0 {
            buf.resize(size as usize, 0);
            let rc2 = unsafe {
                GetAdaptersInfo(Some(buf.as_mut_ptr() as *mut IP_ADAPTER_INFO), &mut size)
            };
            if rc2 != 0 {
                return None;
            }
        }
        let mut adapter = buf.as_ptr() as *const IP_ADAPTER_INFO;
        while !adapter.is_null() {
            let a = unsafe { &*adapter };
            // Walk the singly-linked IP-address list for this adapter.
            let mut ip_node: *const IP_ADDR_STRING = &a.IpAddressList as *const _;
            while !ip_node.is_null() {
                let node = unsafe { &*ip_node };
                let str_bytes = &node.IpAddress.String;
                let null_pos = str_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(str_bytes.len());
                let str_u8 = unsafe {
                    std::slice::from_raw_parts(str_bytes.as_ptr() as *const u8, null_pos)
                };
                let ip_str = std::str::from_utf8(str_u8).unwrap_or("");
                if ip_str == local_ipv4_str.as_str() {
                    let name_bytes = &a.AdapterName;
                    let null_pos = name_bytes
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(name_bytes.len());
                    let name_u8 = unsafe {
                        std::slice::from_raw_parts(name_bytes.as_ptr() as *const u8, null_pos)
                    };
                    return std::str::from_utf8(name_u8).ok().map(str::to_string);
                }
                ip_node = unsafe { (*ip_node).Next };
            }
            adapter = unsafe { (*adapter).Next };
        }
        None
    }

    #[tokio::test]
    async fn test_udp_socket_factory_creation() {
        // Create factory with no special options
        let factory = UdpSocketFactory {
            addr: "127.0.0.1:0".to_string(),
            interface: None,
            fw_mark: None,
            protect_path: None,
            try_dual_stack: true,
        };
        let socket = factory.create_socket().await.unwrap();
        assert!(socket.local_addr().is_ok());

        // Create factory with interface address
        let factory_ip = UdpSocketFactory {
            addr: "127.0.0.1:0".to_string(),
            interface: Some(Interface::Address("127.0.0.1".parse().unwrap())),
            fw_mark: None,
            protect_path: None,
            try_dual_stack: true,
        };
        let socket_ip = factory_ip.create_socket().await.unwrap();
        assert_eq!(
            socket_ip.local_addr().unwrap().as_socket().unwrap().ip(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );

        // Create factory with firewall mark (only on supported platforms)
        let factory_mark = UdpSocketFactory {
            addr: "127.0.0.1:0".to_string(),
            interface: None,
            fw_mark: Some(123),
            protect_path: None,
            try_dual_stack: true,
        };

        let res = factory_mark.create_socket().await;
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        {
            if let Err(e) = res {
                // Setting non-zero SO_MARK typically requires CAP_NET_ADMIN.
                // It should either succeed or fail with an OS-level error
                // (e.g. PermissionDenied/EPERM/EACCES, or ENOPROTOOPT in emulated
                // environments such as QEMU used by cross for armv7/aarch64).
                assert!(e.raw_os_error().is_some());
            }
        }
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        {
            // On unsupported platforms, the mark option is ignored, so it should succeed
            assert!(res.is_ok());
        }
    }

    #[tokio::test]
    async fn test_tcp_socket_factory_creation() {
        // Create factory with no special options
        let factory = TcpSocketFactory {
            addr: "127.0.0.1:0".to_string(),
            interface: None,
            fw_mark: None,
            protect_path: None,
        };
        let socket = factory.create_socket().await.unwrap();
        assert!(socket.local_addr().is_ok());

        // Create factory with interface address
        let factory_ip = TcpSocketFactory {
            addr: "127.0.0.1:0".to_string(),
            interface: Some(Interface::Address("127.0.0.1".parse().unwrap())),
            fw_mark: None,
            protect_path: None,
        };
        let socket_ip = factory_ip.create_socket().await.unwrap();
        assert_eq!(
            socket_ip.local_addr().unwrap().as_socket().unwrap().ip(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );

        // Create factory with firewall mark (only on supported platforms)
        let factory_mark = TcpSocketFactory {
            addr: "127.0.0.1:0".to_string(),
            interface: None,
            fw_mark: Some(123),
            protect_path: None,
        };

        let res = factory_mark.create_socket().await;
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        {
            if let Err(e) = res {
                assert!(e.raw_os_error().is_some());
            }
        }
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        {
            assert!(res.is_ok());
        }
    }

    // Pick a real, existing non-loopback network interface name on Linux by
    // reading /sys/class/net. Returns None if no such interface is available
    // (in which case the test is skipped).
    #[cfg(target_os = "linux")]
    fn first_non_loopback_interface() -> Option<String> {
        std::fs::read_dir("/sys/class/net")
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .find(|name| name != "lo")
    }

    // Verify that when an outbound interface (Interface::Device) is configured
    // with a *real* non-loopback interface, sockets targeting a loopback
    // address still work. Without the loopback skip in create_socket(), the
    // socket would be restricted to the named device by SO_BINDTODEVICE and
    // would not be able to reach 127.0.0.1, so the end-to-end send/recv below
    // would time out.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_udp_socket_factory_device_loopback() {
        let Some(iface) = first_non_loopback_interface() else {
            eprintln!("no non-loopback interface available; skipping");
            return;
        };

        // Bind a receiver on loopback.
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = receiver.local_addr().unwrap();

        let factory = UdpSocketFactory {
            addr: recv_addr.to_string(),
            interface: Some(Interface::Device(iface.clone())),
            fw_mark: None,
            protect_path: None,
            try_dual_stack: false,
        };
        let socket = factory
            .create_socket()
            .await
            .expect("create_socket must succeed for loopback destination");
        let std_socket: std::net::UdpSocket = socket.into();
        let sender = tokio::net::UdpSocket::from_std(std_socket).unwrap();

        // If bind_device had been applied for the non-loopback interface, this
        // send would fail (Network unreachable) because loopback traffic does
        // not flow through that device. The loopback skip in create_socket()
        // is what makes this work.
        sender
            .send_to(b"hello", recv_addr)
            .await
            .expect("send to loopback must succeed when bind_device is skipped");

        let mut buf = [0u8; 16];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("receive must not time out")
        .unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_tcp_socket_factory_device_loopback() {
        let Some(iface) = first_non_loopback_interface() else {
            eprintln!("no non-loopback interface available; skipping");
            return;
        };

        // Start a TCP listener on loopback.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let factory = TcpSocketFactory {
            addr: listen_addr.to_string(),
            interface: Some(Interface::Device(iface.clone())),
            fw_mark: None,
            protect_path: None,
        };
        let socket = factory
            .create_socket()
            .await
            .expect("create_socket must succeed for loopback destination");

        // Initiate a non-blocking connect on the socket2 Socket directly.
        // create_socket() already set it non-blocking, so the call typically
        // returns WouldBlock/InProgress and the connection completes
        // asynchronously. If bind_device had been applied to a non-loopback
        // interface, the connect would fail synchronously (ENETUNREACH) and no
        // SYN would reach the listener, so the accept below would time out.
        let _ = socket.connect(&listen_addr.into());

        let accept = tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
            .await
            .expect("accept must not time out (bind_device must be skipped for loopback)");
        assert!(accept.is_ok(), "loopback connect must succeed");
    }

    // On non-Linux platforms, retain a basic smoke test that exercises the
    // loopback-skip path with a nonexistent device name: create_socket must
    // still succeed because bind_device is skipped for loopback destinations.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_udp_socket_factory_device_loopback() {
        let factory = UdpSocketFactory {
            addr: "127.0.0.1:0".to_string(),
            interface: Some(Interface::Device("nonexistent_device_name_123".to_string())),
            fw_mark: None,
            protect_path: None,
            try_dual_stack: false,
        };
        let socket = factory.create_socket().await.unwrap();
        assert!(socket.local_addr().is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_tcp_socket_factory_device_loopback() {
        let factory = TcpSocketFactory {
            addr: "127.0.0.1:0".to_string(),
            interface: Some(Interface::Device("nonexistent_device_name_123".to_string())),
            fw_mark: None,
            protect_path: None,
        };
        let socket = factory.create_socket().await.unwrap();
        assert!(socket.local_addr().is_ok());
    }

    /// Test that UdpSocketFactory correctly binds to an existing network interface
    /// (via Interface::Address) and that the resulting socket can be used to send
    /// a DNS query to 1.1.1.1:53.
    #[tokio::test]
    async fn test_udp_socket_factory_bind_interface() {
        let local_ip = match get_local_ip() {
            Some(ip) => ip,
            None => return, // skip: cannot determine local interface address
        };

        let factory = UdpSocketFactory {
            addr: "1.1.1.1:53".to_string(),
            interface: Some(Interface::Address(local_ip)),
            fw_mark: None,
            protect_path: None,
            try_dual_stack: false,
        };

        let socket = factory
            .create_socket()
            .await
            .expect("socket creation with interface binding should succeed");

        // Verify the socket is bound to the specified interface IP
        let bound_ip = socket.local_addr().unwrap().as_socket().unwrap().ip();
        assert_eq!(
            bound_ip, local_ip,
            "UDP socket should be bound to the interface IP"
        );

        // Convert to a tokio UdpSocket and issue a query to 1.1.1.1:53 (DNS over UDP)
        let std_socket: std::net::UdpSocket = socket.into();
        let tokio_socket = tokio::net::UdpSocket::from_std(std_socket).unwrap();

        // Minimal DNS query: ID=0x0001, RD=1, QDCOUNT=1, question=one.one.one.one A IN
        let dns_query: &[u8] = &[
            0x00, 0x01, // ID
            0x01, 0x00, // flags: recursion desired
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ANCOUNT, NSCOUNT, ARCOUNT
            // QNAME: one.one.one.one
            0x03, b'o', b'n', b'e', 0x03, b'o', b'n', b'e', 0x03, b'o', b'n', b'e', 0x03, b'o',
            b'n', b'e', 0x00, // root label
            0x00, 0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
        ];

        // The send may fail if the environment blocks outbound UDP; both outcomes are
        // acceptable — what matters is that the socket was successfully bound.
        let _ = tokio_socket.send_to(dns_query, "1.1.1.1:53").await;
    }

    /// Test that TcpSocketFactory correctly binds to an existing network interface
    /// (via Interface::Address) and that the resulting socket can be used to attempt
    /// a TCP connection to 1.1.1.1:80.
    #[tokio::test]
    async fn test_tcp_socket_factory_bind_interface() {
        let local_ip = match get_local_ip() {
            Some(ip) => ip,
            None => return, // skip: cannot determine local interface address
        };

        let factory = TcpSocketFactory {
            addr: "1.1.1.1:80".to_string(),
            interface: Some(Interface::Address(local_ip)),
            fw_mark: None,
            protect_path: None,
        };

        let socket = factory
            .create_socket()
            .await
            .expect("socket creation with interface binding should succeed");

        // Verify the socket is bound to the specified interface IP
        let bound_ip = socket.local_addr().unwrap().as_socket().unwrap().ip();
        assert_eq!(
            bound_ip, local_ip,
            "TCP socket should be bound to the interface IP"
        );

        // Convert to a tokio TcpSocket and attempt a connection to 1.1.1.1:80.
        // A short timeout ensures the test does not hang in restricted environments.
        let std_stream: std::net::TcpStream = socket.into();
        let tokio_socket = tokio::net::TcpSocket::from_std_stream(std_stream);
        let target: std::net::SocketAddr = "1.1.1.1:80".parse().unwrap();
        let _ = tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            tokio_socket.connect(target),
        )
        .await;
        // The connection attempt may succeed or fail depending on network availability;
        // what matters is that the socket was successfully bound to the interface.
    }

    /// Test that UdpSocketFactory correctly binds to an existing network device
    /// (via Interface::Device) and that the resulting socket can be used to send
    /// a DNS query to 1.1.1.1:53.  Requires CAP_NET_RAW on Linux; if the capability
    /// is absent the test accepts the OS-level permission error and exits cleanly.
    #[tokio::test]
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    async fn test_udp_socket_factory_bind_device() {
        let iface = match get_default_interface_name() {
            Some(name) => name,
            None => return, // skip: no default interface found
        };

        let factory = UdpSocketFactory {
            addr: "1.1.1.1:53".to_string(),
            interface: Some(Interface::Device(iface.clone())),
            fw_mark: None,
            protect_path: None,
            try_dual_stack: false,
        };

        let socket = match factory.create_socket().await {
            Ok(s) => s,
            Err(e) => {
                // Acceptable when the process lacks the required capability
                assert!(
                    e.raw_os_error().is_some(),
                    "unexpected error binding to device {iface}: {e}"
                );
                return;
            }
        };

        let std_socket: std::net::UdpSocket = socket.into();
        let tokio_socket = tokio::net::UdpSocket::from_std(std_socket).unwrap();

        let dns_query: &[u8] = &[
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'o',
            b'n', b'e', 0x03, b'o', b'n', b'e', 0x03, b'o', b'n', b'e', 0x03, b'o', b'n', b'e',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let _ = tokio_socket.send_to(dns_query, "1.1.1.1:53").await;
    }

    /// Test that TcpSocketFactory correctly binds to an existing network device
    /// (via Interface::Device) and that the resulting socket can be used to attempt
    /// a TCP connection to 1.1.1.1:80.  Requires CAP_NET_RAW on Linux; if the
    /// capability is absent the test accepts the OS-level permission error.
    #[tokio::test]
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    async fn test_tcp_socket_factory_bind_device() {
        let iface = match get_default_interface_name() {
            Some(name) => name,
            None => return, // skip: no default interface found
        };

        let factory = TcpSocketFactory {
            addr: "1.1.1.1:80".to_string(),
            interface: Some(Interface::Device(iface.clone())),
            fw_mark: None,
            protect_path: None,
        };

        let socket = match factory.create_socket().await {
            Ok(s) => s,
            Err(e) => {
                assert!(
                    e.raw_os_error().is_some(),
                    "unexpected error binding to device {iface}: {e}"
                );
                return;
            }
        };

        let std_stream: std::net::TcpStream = socket.into();
        let tokio_socket = tokio::net::TcpSocket::from_std_stream(std_stream);
        let target: std::net::SocketAddr = "1.1.1.1:80".parse().unwrap();
        let _ = tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            tokio_socket.connect(target),
        )
        .await;
    }

    /// macOS: bind UDP socket to the default network device and send a DNS query
    /// to 1.1.1.1:53.  Uses `IP_BOUND_IF` / `IPV6_BOUND_IF` via `bind_device`.
    /// Accepts an OS-level error when the process lacks the required privilege.
    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn test_udp_socket_factory_bind_device() {
        let iface = match get_default_interface_name() {
            Some(name) => name,
            None => return, // skip: no default interface found
        };

        let factory = UdpSocketFactory {
            addr: "1.1.1.1:53".to_string(),
            interface: Some(Interface::Device(iface.clone())),
            fw_mark: None,
            protect_path: None,
            try_dual_stack: false,
        };

        let socket = match factory.create_socket().await {
            Ok(s) => s,
            Err(e) => {
                assert!(
                    e.raw_os_error().is_some(),
                    "unexpected error binding to device {iface}: {e}"
                );
                return;
            }
        };

        let std_socket: std::net::UdpSocket = socket.into();
        let tokio_socket = tokio::net::UdpSocket::from_std(std_socket).unwrap();

        let dns_query: &[u8] = &[
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'o',
            b'n', b'e', 0x03, b'o', b'n', b'e', 0x03, b'o', b'n', b'e', 0x03, b'o', b'n', b'e',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let _ = tokio_socket.send_to(dns_query, "1.1.1.1:53").await;
    }

    /// macOS: bind TCP socket to the default network device and attempt a
    /// connection to 1.1.1.1:80.  Accepts an OS-level error when the process
    /// lacks the required privilege.
    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn test_tcp_socket_factory_bind_device() {
        let iface = match get_default_interface_name() {
            Some(name) => name,
            None => return, // skip: no default interface found
        };

        let factory = TcpSocketFactory {
            addr: "1.1.1.1:80".to_string(),
            interface: Some(Interface::Device(iface.clone())),
            fw_mark: None,
            protect_path: None,
        };

        let socket = match factory.create_socket().await {
            Ok(s) => s,
            Err(e) => {
                assert!(
                    e.raw_os_error().is_some(),
                    "unexpected error binding to device {iface}: {e}"
                );
                return;
            }
        };

        let std_stream: std::net::TcpStream = socket.into();
        let tokio_socket = tokio::net::TcpSocket::from_std_stream(std_stream);
        let target: std::net::SocketAddr = "1.1.1.1:80".parse().unwrap();
        let _ = tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            tokio_socket.connect(target),
        )
        .await;
    }

    /// Windows: bind UDP socket to the default network device (adapter GUID) and
    /// send a DNS query to 1.1.1.1:53.  Uses `IP_UNICAST_IF` via `bind_device`.
    /// Accepts an OS-level error when the process lacks the required privilege.
    #[tokio::test]
    #[cfg(target_os = "windows")]
    async fn test_udp_socket_factory_bind_device() {
        let iface = match get_default_interface_name() {
            Some(name) => name,
            None => return, // skip: no default interface found
        };

        let factory = UdpSocketFactory {
            addr: "1.1.1.1:53".to_string(),
            interface: Some(Interface::Device(iface.clone())),
            fw_mark: None,
            protect_path: None,
            try_dual_stack: false,
        };

        let socket = match factory.create_socket().await {
            Ok(s) => s,
            Err(e) => {
                assert!(
                    e.raw_os_error().is_some(),
                    "unexpected error binding to device {iface}: {e}"
                );
                return;
            }
        };

        let std_socket: std::net::UdpSocket = socket.into();
        let tokio_socket = tokio::net::UdpSocket::from_std(std_socket).unwrap();

        let dns_query: &[u8] = &[
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'o',
            b'n', b'e', 0x03, b'o', b'n', b'e', 0x03, b'o', b'n', b'e', 0x03, b'o', b'n', b'e',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let _ = tokio_socket.send_to(dns_query, "1.1.1.1:53").await;
    }

    /// Windows: bind TCP socket to the default network device (adapter GUID) and
    /// attempt a connection to 1.1.1.1:80.  Accepts an OS-level error when the
    /// process lacks the required privilege.
    #[tokio::test]
    #[cfg(target_os = "windows")]
    async fn test_tcp_socket_factory_bind_device() {
        let iface = match get_default_interface_name() {
            Some(name) => name,
            None => return, // skip: no default interface found
        };

        let factory = TcpSocketFactory {
            addr: "1.1.1.1:80".to_string(),
            interface: Some(Interface::Device(iface.clone())),
            fw_mark: None,
            protect_path: None,
        };

        let socket = match factory.create_socket().await {
            Ok(s) => s,
            Err(e) => {
                assert!(
                    e.raw_os_error().is_some(),
                    "unexpected error binding to device {iface}: {e}"
                );
                return;
            }
        };

        let std_stream: std::net::TcpStream = socket.into();
        let tokio_socket = tokio::net::TcpSocket::from_std_stream(std_stream);
        let target: std::net::SocketAddr = "1.1.1.1:80".parse().unwrap();
        let _ = tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            tokio_socket.connect(target),
        )
        .await;
    }
}
