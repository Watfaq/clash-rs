use clash_lib::{Config, Options};
use common::{start_clash, wait_port_ready};
use std::path::PathBuf;

mod common;

#[tokio::test(flavor = "current_thread")]
/// Test Shadowsocks inbound and outbound functionality
async fn smoke_test() {
    let wd = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config");
    let server_config = wd.join("server.yaml");
    let client_config = wd.join("rules.yaml");

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

    let wds = wd.clone();
    std::thread::spawn(move || {
        start_clash(Options {
            config: Config::File(server_config.to_string_lossy().to_string()),
            cwd: Some(wds.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        })
        .expect("Failed to start server");
    });

    std::thread::spawn(move || {
        start_clash(Options {
            config: Config::File(client_config.to_string_lossy().to_string()),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        })
        .expect("Failed to start client");
    });
    
    let curl_cmd = "curl -v google.com";
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
    
    wait_port_ready(8899).expect("Proxy port is not ready");

    let curl_cmd = "curl -v -x socks5h://127.0.0.1:8899 google.com";
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
}
