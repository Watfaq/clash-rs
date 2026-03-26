use crate::common::{ClashInstance, send_http_request, wait_port_ready};
use bytes::{Buf, Bytes};
use clash_lib::{Config, Options};
use http_body_util::BodyExt;
use std::{path::PathBuf, time::Duration};

mod common;

async fn get_allow_lan(port: u16) -> bool {
    let url = format!("http://127.0.0.1:{}/configs", port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
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
        .and_then(|v| v.as_bool())
        .expect("'allow-lan' not found or not a bool")
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_config_reload_via_payload() {
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

    // Initial config has allow-lan: true
    assert!(
        get_allow_lan(9090).await,
        "expected allow-lan=true before reload"
    );

    // Reload with a new payload that flips allow-lan to false
    let new_payload = r#"
socks-port: 7892
bind-address: 127.0.0.1
allow-lan: false
mode: direct
log-level: info
external-controller: :9091
secret: clash-rs
tun:
  enable: false
proxies:
  - {name: DIRECT_alias, type: direct}
  - {name: REJECT_alias, type: reject}
"#;
    let body = serde_json::json!({ "payload": new_payload }).to_string();

    let configs_url = "http://127.0.0.1:9090/configs";
    let req = hyper::Request::builder()
        .uri(configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body(body)
        .expect("Failed to build request");

    let res = send_http_request::<String>(configs_url.parse().unwrap(), req)
        .await
        .expect("Failed to send PUT /configs request");
    assert_eq!(
        res.status(),
        http::StatusCode::NO_CONTENT,
        "PUT /configs should return 204 No Content"
    );

    // Wait briefly for the reload to propagate
    tokio::time::sleep(Duration::from_millis(500)).await;

    // allow-lan should now be false
    assert!(
        !get_allow_lan(9091).await,
        "expected allow-lan=false after reload"
    );
}

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

    assert!(
        get_allow_lan(9090).await,
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
        !get_allow_lan(9090).await,
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

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_get_configs_listeners() {
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let config_path = wd.join("rules.yaml");

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

    let url = "http://127.0.0.1:9090/configs";
    let req = hyper::Request::builder()
        .uri(url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON");

    // listeners field should be present and non-empty
    let listeners = json
        .get("listeners")
        .expect("'listeners' field missing")
        .as_array()
        .expect("'listeners' should be an array");
    assert!(!listeners.is_empty(), "listeners should not be empty");

    // Each listener should have name, type, port, active fields
    for listener in listeners {
        assert!(
            listener.get("name").is_some(),
            "listener missing 'name': {listener}"
        );
        assert!(
            listener.get("type").is_some(),
            "listener missing 'type': {listener}"
        );
        let port = listener
            .get("port")
            .and_then(|p| p.as_u64())
            .expect("listener missing 'port' or not a number");
        assert!(port > 0, "listener port should be > 0");
        assert!(
            listener.get("active").is_some(),
            "listener missing 'active': {listener}"
        );
    }

    // Verify known ports are present (config has port:8888, socks:8889, mixed:8899)
    let ports: Vec<u64> = listeners
        .iter()
        .filter_map(|l| l.get("port").and_then(|p| p.as_u64()))
        .collect();
    assert!(ports.contains(&8888), "expected port 8888 in listeners");
    assert!(ports.contains(&8889), "expected port 8889 in listeners");
    assert!(ports.contains(&8899), "expected port 8899 in listeners");
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_get_configs_lan_ips_when_allow_lan() {
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let config_path = wd.join("rules.yaml");

    // rules.yaml has allow-lan: true
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

    let url = "http://127.0.0.1:9090/configs";
    let req = hyper::Request::builder()
        .uri(url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON");

    // allow-lan is true, so lan-ips should be present and contain only IPv4
    let lan_ips = json
        .get("lan-ips")
        .expect("'lan-ips' field missing when allow-lan is true")
        .as_array()
        .expect("'lan-ips' should be an array");

    for ip in lan_ips {
        let ip_str = ip.as_str().expect("lan-ips entry should be a string");
        // Only IPv4 should be returned
        assert!(
            ip_str.parse::<std::net::Ipv4Addr>().is_ok(),
            "expected only IPv4 addresses in lan-ips, got: {ip_str}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_get_configs_dns_listen_when_enabled() {
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let config_path = wd.join("rules.yaml");

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

    // Reload with dns.enable: true so dns-listen is populated
    let new_payload = r#"
mixed-port: 8899
allow-lan: true
mode: direct
log-level: info
external-controller: :9090
secret: clash-rs
dns:
  enable: true
  ipv6: false
  listen:
    udp: 127.0.0.1:53553
    tcp: 127.0.0.1:53553
  default-nameserver:
    - 8.8.8.8
  nameserver:
    - 8.8.8.8
tun:
  enable: false
proxies:
  - {name: DIRECT_alias, type: direct}
"#;
    let body = serde_json::json!({ "payload": new_payload }).to_string();
    let configs_url = "http://127.0.0.1:9090/configs";
    let req = hyper::Request::builder()
        .uri(configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body(body)
        .expect("Failed to build request");

    let res = send_http_request::<String>(configs_url.parse().unwrap(), req)
        .await
        .expect("Failed to send PUT /configs");
    assert_eq!(res.status(), http::StatusCode::NO_CONTENT);

    // Wait briefly for the reload to propagate
    tokio::time::sleep(Duration::from_millis(1000)).await;
    wait_port_ready(9090).expect("API port not ready after reload");
    let req = hyper::Request::builder()
        .uri(configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(configs_url.parse().unwrap(), req)
        .await
        .expect("Failed to send GET /configs");
    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON");

    let dns_listen = json
        .get("dns-listen")
        .expect("'dns-listen' field missing when dns.enable is true");

    let udp = dns_listen
        .get("udp")
        .and_then(|v| v.as_str())
        .expect("'dns-listen.udp' field missing");
    assert_eq!(udp, "127.0.0.1:53553");

    let tcp = dns_listen
        .get("tcp")
        .and_then(|v| v.as_str())
        .expect("'dns-listen.tcp' field missing");
    assert_eq!(tcp, "127.0.0.1:53553");
}

async fn get_proxy_info(api_port: u16, proxy_name: &str) -> serde_json::Value {
    let url = format!("http://127.0.0.1:{}/proxies/{}", api_port, proxy_name);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(response.status(), http::StatusCode::OK);
    serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON")
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_plain_proxy_api_response_direct_reject() {
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let _clash = ClashInstance::start(
        Options {
            config: Config::File(
                wd.join("rules.yaml").to_string_lossy().to_string(),
            ),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        },
        vec![9090, 8888, 8889, 8899, 53553, 53554, 53555],
    )
    .expect("Failed to start clash");

    let direct = get_proxy_info(9090, "DIRECT").await;
    assert_eq!(direct["name"], "DIRECT");
    assert_eq!(direct["type"], "Direct");

    let reject = get_proxy_info(9090, "REJECT").await;
    assert_eq!(reject["name"], "REJECT");
    assert_eq!(reject["type"], "Reject");
}

/// `/user-stats` should return an empty JSON object when the server has started
/// but no traffic has been routed yet.  This verifies the endpoint is
/// registered, authenticated correctly, and resets-on-read semantics work.
#[cfg(feature = "shadowsocks")]
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_user_stats_endpoint_empty_on_no_traffic() {
    let wd_server =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/server");
    let server_config = wd_server.join("server_multiuser.yaml");

    let _server = ClashInstance::start(
        Options {
            config: Config::File(server_config.to_string_lossy().to_string()),
            cwd: Some(wd_server.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        },
        vec![9092, 8902],
    )
    .expect("Failed to start multiuser server");

    let url = "http://127.0.0.1:9092/user-stats";
    let req = hyper::Request::builder()
        .uri(url)
        .header(hyper::header::AUTHORIZATION, "Bearer test-secret")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "/user-stats should return 200"
    );

    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON response");

    assert!(
        json.is_object(),
        "/user-stats response should be a JSON object"
    );
    assert!(
        json.as_object().unwrap().is_empty(),
        "/user-stats should be empty when no traffic has been routed"
    );
}

#[cfg(feature = "shadowsocks")]
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_plain_proxy_api_response_shadowsocks() {
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let _clash = ClashInstance::start(
        Options {
            config: Config::File(
                wd.join("rules.yaml").to_string_lossy().to_string(),
            ),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        },
        vec![9090, 8888, 8889, 8899, 53553, 53554, 53555],
    )
    .expect("Failed to start clash");

    let proxy = get_proxy_info(9090, "ss-simple").await;
    assert_eq!(proxy["name"], "ss-simple");
    assert_eq!(proxy["type"], "Shadowsocks");
    assert_eq!(proxy["server"], "127.0.0.1");
    assert_eq!(proxy["port"], 8901);
    assert_eq!(proxy["cipher"], "2022-blake3-aes-256-gcm");
    assert!(
        proxy.get("password").is_some(),
        "password should be present"
    );
    assert_eq!(proxy["udp"], true);
}
