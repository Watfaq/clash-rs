#![allow(unused_imports)]

use clash_lib::{Config, Options};
use common::{start_clash, wait_port_ready};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;

#[cfg(feature = "shadowsocks")]
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
/// Test Shadowsocks inbound and outbound functionality
async fn smoke_test() {
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
async fn smoke_test_anytls() {
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
async fn smoke_test_anytls_udp() {
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
