#![allow(unused_imports)]

use clash_lib::{Config, Options};
use common::{start_clash, wait_port_ready};
use std::path::PathBuf;

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
