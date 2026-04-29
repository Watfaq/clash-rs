use futures::TryFutureExt;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use std::net::{Shutdown, TcpStream};

pub fn start_clash(options: clash_lib::Options) -> Result<(), clash_lib::Error> {
    clash_lib::start_scaffold(options)
}

pub fn wait_port_ready(port: u16) -> Result<(), clash_lib::Error> {
    let addr = format!("127.0.0.1:{}", port);
    let mut attempts = 0;
    while attempts < 30 {
        if let Ok(stream) = TcpStream::connect(&addr) {
            stream.shutdown(Shutdown::Both).ok();
            return Ok(());
        }
        attempts += 1;
        // it may take some time for downloading the mmdbs
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    Err(clash_lib::Error::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("Port {} is not ready after 30 attempts", port),
    )))
}

#[allow(dead_code)]
fn wait_port_closed(port: u16) -> Result<(), clash_lib::Error> {
    let addr = format!("127.0.0.1:{}", port);
    let mut attempts = 0;
    while attempts < 30 {
        if TcpStream::connect(&addr).is_err() {
            return Ok(());
        }
        attempts += 1;
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(clash_lib::Error::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("Port {} is still open after 15 seconds", port),
    )))
}

/// RAII guard for Clash instance that ensures proper cleanup
#[allow(dead_code)]
pub struct ClashInstance {
    ports: Vec<u16>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ClashInstance {
    #[allow(dead_code)]
    pub fn start(
        options: clash_lib::Options,
        ports: Vec<u16>,
    ) -> Result<Self, clash_lib::Error> {
        let handle = std::thread::spawn(move || {
            start_clash(options).expect("Failed to start clash");
        });

        // Wait for the main port (usually API port) to be ready
        if let Some(&main_port) = ports.first() {
            wait_port_ready(main_port)?;
        }

        Ok(Self {
            ports,
            handle: Some(handle),
        })
    }
}

impl Drop for ClashInstance {
    fn drop(&mut self) {
        // Trigger shutdown
        clash_lib::shutdown();

        // Wait for all ports to be released
        for &port in &self.ports {
            if let Err(e) = wait_port_closed(port) {
                eprintln!(
                    "Warning: Failed to wait for port {} to close: {}",
                    port, e
                );
            }
        }

        // Join the thread to ensure it has fully exited, preventing ports from
        // being held by the spawned runtime across test runs.
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Sends an HTTP request to the specified URL using a TCP connection.
/// Don't use any domain name in the URL, which will trigger DNS resolution.
/// And libnss_files will likely cause a coredump(in static crt build).
/// TODO: Use a DNS resolver to resolve the domain name in the URL.
#[allow(dead_code)]
pub async fn send_http_request<T>(
    url: hyper::Uri,
    req: hyper::Request<T>,
) -> std::io::Result<http::Response<Incoming>>
where
    T: hyper::body::Body + Send + 'static,
    <T as hyper::body::Body>::Data: Send,
    <T as hyper::body::Body>::Error: Sync + Send + std::error::Error,
{
    let host = url.host().expect("uri has no host");
    let port = url.port_u16().unwrap_or(80);
    let addr = format!("{}:{}", host, port);

    let stream = tokio::net::TcpStream::connect(addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .map_err(|e| {
            std::io::Error::other(format!("Failed to establish connection: {}", e))
        })
        .await?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let res = sender
        .send_request(req)
        .map_err(|e| std::io::Error::other(format!("Failed to send request: {}", e)))
        .await?;

    Ok(res)
}

// ── SOCKS5 UDP client ────────────────────────────────────────────────────────

/// A SOCKS5 UDP relay session.
///
/// Keeps the control TCP connection alive for the duration of the session.
/// Provides helpers for sending and receiving SOCKS5 UDP datagrams with both
/// IPv4 (ATYP 0x01) and domain-name (ATYP 0x03) addressing.
#[allow(dead_code)]
pub struct Socks5UdpSession {
    // The TCP control connection must stay open for the relay to remain alive.
    _tcp: tokio::net::TcpStream,
    pub socket: tokio::net::UdpSocket,
    pub relay_addr: std::net::SocketAddr,
}

#[allow(dead_code)]
impl Socks5UdpSession {
    /// Perform a SOCKS5 UDP ASSOCIATE handshake against `proxy_port` on
    /// 127.0.0.1 and return the ready session.
    pub async fn connect(proxy_port: u16) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
            .await
            .unwrap();

        // Auth: no-auth
        tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        tcp.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00], "SOCKS5 auth failed");

        // UDP ASSOCIATE with zeroed client address
        tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .await
            .unwrap();

        let mut hdr = [0u8; 4];
        tcp.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[1], 0x00, "SOCKS5 UDP ASSOCIATE rejected");

        let relay_addr: std::net::SocketAddr = match hdr[3] {
            0x01 => {
                let mut ip = [0u8; 4];
                let mut port = [0u8; 2];
                tcp.read_exact(&mut ip).await.unwrap();
                tcp.read_exact(&mut port).await.unwrap();
                (std::net::Ipv4Addr::from(ip), u16::from_be_bytes(port)).into()
            }
            atyp => panic!("unexpected ATYP {atyp} in UDP ASSOCIATE reply"),
        };

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        Self {
            _tcp: tcp,
            socket,
            relay_addr,
        }
    }

    /// Send `data` addressed to `dst_ip:dst_port` (ATYP=0x01, IPv4).
    pub async fn send_ipv4(&self, data: &[u8], dst_ip: [u8; 4], dst_port: u16) {
        let mut dgram = Vec::with_capacity(10 + data.len());
        dgram.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // RSV, FRAG, ATYP=IPv4
        dgram.extend_from_slice(&dst_ip);
        dgram.extend_from_slice(&dst_port.to_be_bytes());
        dgram.extend_from_slice(data);
        self.socket.send_to(&dgram, self.relay_addr).await.unwrap();
    }

    /// Send `data` addressed to `domain:port` (ATYP=0x03, domain name).
    pub async fn send_domain(&self, data: &[u8], domain: &str, port: u16) {
        let domain_bytes = domain.as_bytes();
        assert!(domain_bytes.len() <= 255, "domain too long");
        let mut dgram = Vec::with_capacity(5 + domain_bytes.len() + 2 + data.len());
        dgram.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]); // RSV, FRAG, ATYP=domain
        dgram.push(domain_bytes.len() as u8);
        dgram.extend_from_slice(domain_bytes);
        dgram.extend_from_slice(&port.to_be_bytes());
        dgram.extend_from_slice(data);
        self.socket.send_to(&dgram, self.relay_addr).await.unwrap();
    }

    /// Receive one SOCKS5 UDP datagram.  Returns `(payload, src_addr_str)`
    /// where `src_addr_str` is the SOCKS5-encoded source address as
    /// `"ip:port"` or `"domain:port"`.
    pub async fn recv(&self) -> (Vec<u8>, String) {
        let mut buf = vec![0u8; 65535];
        let (n, sender) = self.socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(
            sender, self.relay_addr,
            "UDP datagram came from unexpected sender: expected {}, got {}",
            self.relay_addr, sender
        );
        let pkt = &buf[..n];

        // Skip RSV(2) + FRAG(1)
        assert!(pkt.len() >= 4);
        let atyp = pkt[3];
        let mut pos = 4usize;

        let src = match atyp {
            0x01 => {
                // IPv4
                let ip = std::net::Ipv4Addr::from([
                    pkt[pos],
                    pkt[pos + 1],
                    pkt[pos + 2],
                    pkt[pos + 3],
                ]);
                pos += 4;
                let port = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
                pos += 2;
                format!("{ip}:{port}")
            }
            0x03 => {
                // Domain
                let len = pkt[pos] as usize;
                pos += 1;
                let domain = std::str::from_utf8(&pkt[pos..pos + len])
                    .unwrap()
                    .to_owned();
                pos += len;
                let port = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
                pos += 2;
                format!("{domain}:{port}")
            }
            0x04 => {
                // IPv6
                let mut ip6 = [0u8; 16];
                ip6.copy_from_slice(&pkt[pos..pos + 16]);
                let ip = std::net::Ipv6Addr::from(ip6);
                pos += 16;
                let port = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
                pos += 2;
                format!("[{ip}]:{port}")
            }
            atyp => panic!("unknown ATYP {atyp}"),
        };

        (pkt[pos..].to_vec(), src)
    }
}
