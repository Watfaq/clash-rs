use crate::common::{ClashInstance, send_http_request};
use bytes::{Buf, Bytes};
use clash_lib::{Config, Options};
use http_body_util::BodyExt;
use std::{path::PathBuf, time::Duration};

mod common;

#[cfg(feature = "shadowsocks")]
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_get_set_allow_lan() {
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let config_path = wd.join("rules.yaml");
    assert!(
        config_path.exists(),
        "Config file does not exist at: {}",
        config_path.to_string_lossy()
    );

    // Start Clash instance with RAII guard - will auto-cleanup on drop
    let _clash = ClashInstance::start(
        Options {
            config: Config::File(config_path.to_string_lossy().to_string()),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        },
        vec![9090, 8888, 8889, 8899, 53553, 53554, 53555],
    )
    .expect("Failed to start clash");

    async fn get_allow_lan() -> bool {
        let get_configs_url = "http://127.0.0.1:9090/configs";
        let req = hyper::Request::builder()
            .uri(get_configs_url)
            .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .method(http::method::Method::GET)
            .body(http_body_util::Empty::<Bytes>::new())
            .expect("Failed to build request");

        let response = send_http_request(get_configs_url.parse().unwrap(), req)
            .await
            .expect("Failed to send request");
        let json: serde_json::Value = serde_json::from_reader(
            response
                .collect()
                .await
                .expect("Failed to collect response body")
                .aggregate()
                .reader(),
        )
        .expect("Failed to parse JSON response");
        json.get("allow-lan")
            .expect("No 'allow-lan' field in response")
            .as_bool()
            .expect("'allow-lan' is not a boolean")
    }

    assert!(
        get_allow_lan().await,
        "'allow_lan' should be true by config"
    );

    let configs_url = "http://127.0.0.1:9090/configs";
    let req = hyper::Request::builder()
        .uri(configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PATCH)
        .body("{\"allow-lan\": false}".into())
        .expect("Failed to build request");

    let res = send_http_request::<String>(configs_url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), http::StatusCode::ACCEPTED);

    assert!(
        !get_allow_lan().await,
        "'allow_lan' should be false after update"
    );

    // _clash will be dropped here, automatically cleaning up
}

#[cfg(feature = "shadowsocks")]
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

    // Start server instance with RAII guard
    let _server = ClashInstance::start(
        Options {
            config: Config::File(server_config.to_string_lossy().to_string()),
            cwd: Some(wd_server.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        },
        vec![9091, 8901],
    )
    .expect("Failed to start server");

    // Start client instance with RAII guard
    let _client = ClashInstance::start(
        Options {
            config: Config::File(client_config.to_string_lossy().to_string()),
            cwd: Some(wd_client.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        },
        vec![9090, 8888, 8889, 8899, 53553, 53554, 53555],
    )
    .expect("Failed to start client");

    let request_handle = tokio::spawn(async {
        let proxy = reqwest::Proxy::all("socks5h://127.0.0.1:8899")
            .expect("Failed to create proxy");

        let client = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to build reqwest client");

        let response = client
            .get("https://httpbin.yba.dev/drip?duration=2&delay=1&numbytes=500")
            .send()
            .await
            .expect("Failed to send request through proxy");

        assert!(
            response.status().is_success(),
            "Request failed with status: {}",
            response.status()
        );
    });

    // Yield to allow the spawned task to start, then wait for connection to
    // establish
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let connections_url = "http://127.0.0.1:9090/connections";

    let req = hyper::Request::builder()
        .uri(connections_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");
    let response = send_http_request(connections_url.parse().unwrap(), req);
    let response = response
        .await
        .expect("Failed to send request")
        .collect()
        .await
        .expect("Failed to collect response body")
        .aggregate()
        .reader();

    let json: serde_json::Value =
        serde_json::from_reader(response).expect("Failed to parse JSON response");
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

    // Ensure the request task completed successfully
    request_handle
        .await
        .expect("Request task panicked or failed");

    // Both _server and _client will be dropped here, automatically cleaning up
}
