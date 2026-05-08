#![allow(unused_imports)]

use clash_lib::{Config, Options};
use common::{Socks5UdpSession, start_clash, wait_port_ready};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;

#[cfg(feature = "shadowsocks")]
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
/// Test Shadowsocks inbound and outbound functionality
async fn integration_test() {
    let wd_server =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/server");
    let wd_client =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let server_config = wd_server.join("server.yaml");
    let client_config = wd_client.join("rules.yaml");

    assert!(
        server_config.exists(),
        "Server config file does not exist at: {}",
        server_config.to_string_lossy()
    );
    assert!(
        client_config.exists(),
        "Client config file does not exist at: {}",
        client_config.to_string_lossy()
    );

    std::thread::spawn(move || {
        start_clash(Options {
            config: Config::File(server_config.to_string_lossy().to_string()),
            cwd: Some(wd_server.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        })
        .expect("Failed to start server");
    });

    std::thread::spawn(move || {
        start_clash(Options {
            config: Config::File(client_config.to_string_lossy().to_string()),
            cwd: Some(wd_client.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        })
        .expect("Failed to start client");
    });

    let mock_server = httpmock::MockServer::start();
    let mock = mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/");
        then.status(200).body("Mock response for testing");
    });

    // 使用 reqwest 客户端发送请求
    let client = reqwest::Client::new();

    let response = client
        .get(mock_server.url("/"))
        .send()
        .await
        .expect("Failed to execute HTTP request");

    assert!(
        response.status().is_success(),
        "HTTP request failed with status: {}",
        response.status()
    );

    let body_str = response.text().await.expect("Failed to read response body");

    assert_eq!(mock.calls(), 1, "Mock server was not hit exactly once");
    assert_eq!(
        body_str, "Mock response for testing",
        "Unexpected response from mock server"
    );

    wait_port_ready(8899).expect("Proxy port is not ready");

    // 使用 reqwest 通过 SOCKS5 代理发送请求
    let proxy = reqwest::Proxy::all("socks5://127.0.0.1:8899")
        .expect("Failed to create proxy");

    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("Failed to build client with proxy");

    let response = client
        .get(mock_server.url("/"))
        .send()
        .await
        .expect("Failed to send request through proxy");

    assert!(
        response.status().is_success(),
        "HTTP request through proxy failed with status: {}",
        response.status()
    );

    let body_str = response.text().await.expect("Failed to read response body");

    assert_eq!(mock.calls(), 2, "Mock server was not hit exactly twice");
    assert_eq!(
        body_str, "Mock response for testing",
        "Unexpected response from mock server"
    );
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
/// Test AnyTLS inbound and outbound functionality (ephemeral self-signed cert)
async fn integration_test_anytls() {
    let wd_server =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/server");
    let wd_client =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let server_config = wd_server.join("server_anytls.yaml");
    let client_config = wd_client.join("rules_anytls.yaml");

    assert!(
        server_config.exists(),
        "Server config file does not exist at: {}",
        server_config.to_string_lossy()
    );
    assert!(
        client_config.exists(),
        "Client config file does not exist at: {}",
        client_config.to_string_lossy()
    );

    std::thread::spawn(move || {
        start_clash(Options {
            config: Config::File(server_config.to_string_lossy().to_string()),
            cwd: Some(wd_server.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        })
        .expect("Failed to start AnyTLS server");
    });

    std::thread::spawn(move || {
        start_clash(Options {
            config: Config::File(client_config.to_string_lossy().to_string()),
            cwd: Some(wd_client.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        })
        .expect("Failed to start AnyTLS client");
    });

    let mock_server = httpmock::MockServer::start();
    let mock = mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/");
        then.status(200).body("Mock response for AnyTLS testing");
    });

    wait_port_ready(8998).expect("AnyTLS proxy port is not ready");

    let proxy = reqwest::Proxy::all("socks5://127.0.0.1:8998")
        .expect("Failed to create proxy");

    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("Failed to build client with proxy");

    let response = client
        .get(mock_server.url("/"))
        .send()
        .await
        .expect("Failed to send request through AnyTLS proxy");

    assert!(
        response.status().is_success(),
        "HTTP request through AnyTLS proxy failed with status: {}",
        response.status()
    );

    let body_str = response.text().await.expect("Failed to read response body");

    assert_eq!(mock.calls(), 1, "Mock server was not hit exactly once");
    assert_eq!(
        body_str, "Mock response for AnyTLS testing",
        "Unexpected response from AnyTLS proxy"
    );
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
/// Test AnyTLS UDP-over-TCP v2: send a UDP datagram through SOCKS5 UDP
/// ASSOCIATE → AnyTLS inbound → echo server, verify round-trip payload.
async fn integration_test_anytls_udp() {
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    let wd_server =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/server");
    let wd_client =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let server_config = wd_server.join("server_anytls.yaml");
    let client_config = wd_client.join("rules_anytls.yaml");

    // ── UDP echo server ───────────────────────────────────────────────────────
    let echo_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr: SocketAddr = echo_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        // echo one packet then exit
        let (n, peer) = echo_sock.recv_from(&mut buf).await.unwrap();
        echo_sock.send_to(&buf[..n], peer).await.unwrap();
    });

    // ── Start clash server and client ─────────────────────────────────────────
    std::thread::spawn(move || {
        start_clash(Options {
            config: Config::File(server_config.to_string_lossy().to_string()),
            cwd: Some(wd_server.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        })
        .expect("Failed to start AnyTLS server");
    });

    std::thread::spawn(move || {
        start_clash(Options {
            config: Config::File(client_config.to_string_lossy().to_string()),
            cwd: Some(wd_client.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        })
        .expect("Failed to start AnyTLS client");
    });

    wait_port_ready(8998).expect("AnyTLS proxy port is not ready");

    // ── SOCKS5 UDP ASSOCIATE handshake ────────────────────────────────────────
    let mut tcp = tokio::net::TcpStream::connect("127.0.0.1:8998")
        .await
        .unwrap();

    // Auth negotiation: VER=5, NMETHODS=1, METHOD=0 (no auth)
    tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    tcp.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00], "SOCKS5 auth failed");

    // UDP ASSOCIATE request: VER=5, CMD=3, RSV=0, ATYP=1, ADDR=0.0.0.0, PORT=0
    tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await
        .unwrap();

    // Server reply: VER=5, REP=0, RSV=0, then bound addr/port for relay
    let mut hdr = [0u8; 4];
    tcp.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[1], 0x00, "SOCKS5 UDP ASSOCIATE rejected");
    let atyp = hdr[3];

    let relay_addr: SocketAddr = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            let mut port = [0u8; 2];
            tcp.read_exact(&mut ip).await.unwrap();
            tcp.read_exact(&mut port).await.unwrap();
            (std::net::Ipv4Addr::from(ip), u16::from_be_bytes(port)).into()
        }
        _ => panic!("unexpected ATYP {atyp} in UDP ASSOCIATE reply"),
    };

    // ── Send a UDP datagram through the relay ─────────────────────────────────
    // SOCKS5 UDP header: RSV(2) | FRAG(1) | ATYP(1) | DST_ADDR | DST_PORT | DATA
    let payload = b"hello-udp-anytls";
    let echo_ip = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => panic!("expected IPv4 echo addr"),
    };
    let echo_port = echo_addr.port().to_be_bytes();

    let mut dgram = Vec::new();
    dgram.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // RSV, FRAG, ATYP=IPv4
    dgram.extend_from_slice(&echo_ip);
    dgram.extend_from_slice(&echo_port);
    dgram.extend_from_slice(payload);

    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_sock.send_to(&dgram, relay_addr).await.unwrap();

    // ── Receive the echoed datagram ───────────────────────────────────────────
    let mut recv_buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client_sock.recv_from(&mut recv_buf),
    )
    .await
    .expect("UDP echo timed out")
    .unwrap();

    // Strip 10-byte SOCKS5 UDP header (RSV+FRAG+ATYP+IPv4+PORT)
    let echoed = &recv_buf[10..n];
    assert_eq!(echoed, payload, "UDP payload mismatch through AnyTLS");
}

// ── Direct UDP tests
// ──────────────────────────────────────────────────────────

fn start_direct_udp_clash() {
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let config = wd.join("direct_udp.yaml");
    std::thread::spawn(move || {
        start_clash(Options {
            config: Config::File(config.to_string_lossy().to_string()),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        })
        .expect("Failed to start direct-UDP clash instance");
    });
    wait_port_ready(19901).expect("direct-UDP clash port 19901 not ready");
}

/// Spin up a loopback UDP echo server; returns its port.
async fn spawn_echo_server() -> u16 {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    port
}

/// One SOCKS5 UDP client, two echo servers (1→N multi-dest):
/// each response must carry the correct server as its SOCKS5 src address.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn integration_test_udp_multi_dest_1_to_n() {
    start_direct_udp_clash();

    let port_a = spawn_echo_server().await;
    let port_b = spawn_echo_server().await;
    let client = Socks5UdpSession::connect(19901).await;

    let ip = [127u8, 0, 0, 1];
    client.send_ipv4(b"to-a", ip, port_a).await;
    client.send_ipv4(b"to-b", ip, port_b).await;

    let timeout = std::time::Duration::from_secs(5);

    let (data1, src1) = tokio::time::timeout(timeout, client.recv())
        .await
        .expect("timed out waiting for first UDP response");
    let (data2, src2) = tokio::time::timeout(timeout, client.recv())
        .await
        .expect("timed out waiting for second UDP response");

    let expected_a = format!("127.0.0.1:{port_a}");
    let expected_b = format!("127.0.0.1:{port_b}");

    // Responses may arrive in any order; verify payload ↔ src_addr coherence.
    let mut pairs = [
        (data1.as_slice(), src1.as_str()),
        (data2.as_slice(), src2.as_str()),
    ];
    pairs.sort_by_key(|&(_, src)| src);

    let srcs: std::collections::HashSet<&str> =
        pairs.iter().map(|&(_, s)| s).collect();
    assert!(
        srcs.contains(expected_a.as_str()),
        "missing src_addr for echo server A"
    );
    assert!(
        srcs.contains(expected_b.as_str()),
        "missing src_addr for echo server B"
    );

    for (data, src) in &pairs {
        if *src == expected_a.as_str() {
            assert_eq!(*data, b"to-a", "payload mismatch for echo server A");
        } else {
            assert_eq!(*data, b"to-b", "payload mismatch for echo server B");
        }
    }
}

/// Two independent SOCKS5 UDP clients send to the same echo server.
/// Each client must receive only its own echo — sessions are keyed by
/// (outbound_name, client_src_addr) — this is the full-cone NAT isolation
/// property.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn integration_test_udp_session_isolation() {
    start_direct_udp_clash();

    let echo_port = spawn_echo_server().await;
    let client_a = Socks5UdpSession::connect(19901).await;
    let client_b = Socks5UdpSession::connect(19901).await;

    let ip = [127u8, 0, 0, 1];
    client_a.send_ipv4(b"from-A", ip, echo_port).await;
    client_b.send_ipv4(b"from-B", ip, echo_port).await;

    let timeout = std::time::Duration::from_secs(5);

    let (data_a, _) = tokio::time::timeout(timeout, client_a.recv())
        .await
        .expect("client A timed out");
    let (data_b, _) = tokio::time::timeout(timeout, client_b.recv())
        .await
        .expect("client B timed out");

    assert_eq!(data_a, b"from-A", "client A received wrong payload");
    assert_eq!(data_b, b"from-B", "client B received wrong payload");
}
