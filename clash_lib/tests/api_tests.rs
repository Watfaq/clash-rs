use crate::common::{start_clash, wait_port_ready};
use clash_lib::{Config, Options};
use std::{path::PathBuf, time::Duration};

mod common;

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_connections_returns_proxy_chain_names() {
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

    wait_port_ready(8899).expect("Proxy port is not ready");

    tokio::spawn(async {
        let curl_cmd = format!(
            "curl -s -x socks5h://127.0.0.1:8899 {}",
            "https://httpbin.yba.dev/drip?duration=100&delay=1&numbytes=1000"
        );

        let output = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(curl_cmd)
            .output()
            .await
            .expect("Failed to execute curl command");

        assert!(
            output.status.success(),
            "Curl command failed with output: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let connections_url = "http://localhost:9090/connections";
    let curl_cmd = format!(
        "curl -s -H 'Authorization: Bearer {}' {}",
        "clash-rs", connections_url
    );
    let output = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(curl_cmd)
        .output()
        .await
        .expect("Failed to execute curl command");

    assert!(
        output.status.success(),
        "Curl command failed with output: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let response = String::from_utf8_lossy(&output.stdout);

    let json = serde_json::from_str::<serde_json::Value>(&response)
        .expect("Failed to parse JSON response");
    let connections = json
        .get("connections")
        .expect("No 'connections' field in response");
    assert!(connections.is_array(), "Connections field is not an array");
    let first_connection = connections
        .get(0)
        .expect("No connections found in response");

    let chains = first_connection
        .get("chains")
        .expect("No 'chains' field in first connection");

    assert!(chains.is_array(), "First connection is not an array");

    assert_eq!(
        chains.as_array().unwrap(),
        &["DIRECT", "url-test", "test 🌏"],
        "Chains do not match expected values"
    );
}
