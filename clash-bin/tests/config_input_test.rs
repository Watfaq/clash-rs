use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
    sync::OnceLock,
};
use tempfile::tempdir;

const VALID_CONFIG: &str = r#"mixed-port: 8899
external-controller: 127.0.0.1:9090
mode: global
bind-address: "0.0.0.0"
"#;

/// Returns `true` when the `clash-rs` binary can actually be executed as a
/// subprocess in the current environment.
///
/// In cross-compilation test runs (e.g. `cross` + QEMU), the test binary
/// itself runs inside an emulator, but `execve` of a child binary for a
/// foreign architecture is not intercepted by the emulator.  glibc falls back
/// to running the binary through `/bin/sh`, which exits with code 127
/// ("cannot execute binary file").  Any test that spawns the binary must skip
/// itself in such environments.
fn binary_can_be_spawned() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        std::process::Command::new(env!("CARGO_BIN_EXE_clash-rs"))
            .arg("-v")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.code() != Some(127))
            .unwrap_or(false)
    })
}

/// Skip the calling test when running inside a cross-compilation environment
/// where the binary cannot be spawned as a subprocess.
macro_rules! skip_on_cross {
    () => {
        if !binary_can_be_spawned() {
            eprintln!(
                "SKIP: clash-rs binary cannot be executed as a subprocess \
                 (cross-compilation / QEMU environment)"
            );
            return;
        }
    };
}

fn clash_cmd() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_clash-rs"));
    command
        .env_remove("CLASH_CONFIG_FILE")
        .env_remove("CLASH_CONFIG_STRING")
        .env_remove("CLASH_HOME_DIR");
    command
}

fn run_with_stdin(mut command: Command, stdin: &str) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clash-rs");
    child
        .stdin
        .as_mut()
        .expect("open stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait for clash-rs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn path_display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn file_success_outputs_summary_on_stdout() {
    skip_on_cross!();
    let temp = tempdir().expect("create temp dir");
    let config = temp.path().join("ok.yaml");
    fs::write(&config, VALID_CONFIG).expect("write config");

    let output = clash_cmd()
        .args(["-t", "-f"])
        .arg(&config)
        .output()
        .expect("run clash-rs");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(stderr(&output), "");
    assert!(stdout(&output).ends_with(&format!(
        "configuration file {} test is successful\n",
        path_display(&config)
    )));
}

#[test]
fn file_success_accepts_go_style_equals_flag() {
    skip_on_cross!();
    let temp = tempdir().expect("create temp dir");
    let config = temp.path().join("ok.yaml");
    fs::write(&config, VALID_CONFIG).expect("write config");

    let output = clash_cmd()
        .arg("-t")
        .arg(format!("-f={}", path_display(&config)))
        .output()
        .expect("run clash-rs");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(stderr(&output), "");
    assert_eq!(
        stdout(&output),
        format!(
            "configuration file {} test is successful\n",
            path_display(&config)
        )
    );
}

#[test]
fn file_failure_logs_error_then_summary_on_stdout() {
    skip_on_cross!();
    let temp = tempdir().expect("create temp dir");
    let config = temp.path().join("invalid.yaml");
    fs::write(&config, "log-level: definitely-not-a-level\n").expect("write config");

    let output = clash_cmd()
        .args(["-t", "-f"])
        .arg(&config)
        .output()
        .expect("run clash-rs");

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stderr(&output), "");

    let stdout = stdout(&output);
    let lines = stdout.lines().collect::<Vec<_>>();
    assert!(
        lines.first().is_some_and(|line| line.starts_with("time=\"")
            && line.contains(" level=error msg=\"")),
        "stdout:\n{stdout}"
    );
    let summary =
        format!("configuration file {} test failed", path_display(&config));
    assert_eq!(lines.last().copied(), Some(summary.as_str()));
}

#[test]
fn proxy_provider_without_health_check_is_accepted() {
    skip_on_cross!();
    let temp = tempdir().expect("create temp dir");
    let config = temp.path().join("provider.yaml");
    fs::write(
        &config,
        r#"mixed-port: 8899
proxy-providers:
  0.LocalProxyNode:
    type: file
    path: ./providers.yaml
"#,
    )
    .expect("write config");

    let output = clash_cmd()
        .args(["-t", "-f"])
        .arg(&config)
        .output()
        .expect("run clash-rs");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(stderr(&output), "");
    assert_eq!(
        stdout(&output),
        format!(
            "configuration file {} test is successful\n",
            path_display(&config)
        )
    );
}

#[test]
fn stdin_success_uses_bytes_summary_and_does_not_create_default_config() {
    skip_on_cross!();
    let temp = tempdir().expect("create temp dir");
    let mut command = clash_cmd();
    command.current_dir(temp.path()).args(["-t", "-f", "-"]);

    let output = run_with_stdin(command, VALID_CONFIG);

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(stderr(&output), "");
    assert!(
        stdout(&output)
            .ends_with("configuration file config.yaml test is successful\n")
    );
    assert!(!temp.path().join("config.yaml").exists());
}

#[test]
fn base64_config_success_uses_bytes_summary() {
    skip_on_cross!();
    let temp = tempdir().expect("create temp dir");
    let encoded = STANDARD.encode(VALID_CONFIG);

    let output = clash_cmd()
        .current_dir(temp.path())
        .args(["-t", "-config", &encoded])
        .output()
        .expect("run clash-rs");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(stderr(&output), "");
    assert_eq!(
        stdout(&output),
        "configuration file config.yaml test is successful\n"
    );
    assert!(!temp.path().join("config.yaml").exists());
}

#[test]
fn base64_decode_failure_is_stdout_fatal() {
    skip_on_cross!();
    let output = clash_cmd()
        .args(["-t", "-config", "not@base64"])
        .output()
        .expect("run clash-rs");

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stderr(&output), "");
    let stdout = stdout(&output);
    assert!(stdout.starts_with("time=\""), "stdout:\n{stdout}");
    assert!(
        stdout.contains(" level=fatal msg=\"decode config:"),
        "stdout:\n{stdout}"
    );
}

#[test]
fn missing_file_mode_creates_default_config() {
    skip_on_cross!();
    let temp = tempdir().expect("create temp dir");
    let config = temp.path().join("home").join("config.yaml");

    let output = clash_cmd()
        .args(["-t", "-f"])
        .arg(&config)
        .output()
        .expect("run clash-rs");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(stderr(&output), "");
    assert_eq!(
        fs::read_to_string(&config).expect("read default config"),
        "mixed-port: 7890"
    );
    assert_eq!(
        stdout(&output),
        format!(
            "configuration file {} test is successful\n",
            path_display(&config)
        )
    );
}

#[test]
fn empty_file_reports_empty_file_error() {
    skip_on_cross!();
    let temp = tempdir().expect("create temp dir");
    let config = temp.path().join("empty.yaml");
    fs::write(&config, "").expect("write empty config");

    let output = clash_cmd()
        .args(["-t", "-f"])
        .arg(&config)
        .output()
        .expect("run clash-rs");

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stderr(&output), "");

    let stdout = stdout(&output);
    let lines = stdout.lines().collect::<Vec<_>>();
    // The first line is a log entry; `escape_logrus_text` escapes path
    // separators on Windows, so we only check for the "is empty" substring
    // rather than the full path to stay cross-platform.
    assert!(
        lines.first().is_some_and(
            |line| line.starts_with("time=\"") && line.contains("is empty")
        ),
        "stdout:\n{stdout}"
    );
    // The summary line is printed via `println!` without any escaping, so
    // comparing the full path here is safe on all platforms.
    let summary =
        format!("configuration file {} test failed", path_display(&config));
    assert_eq!(lines.last().copied(), Some(summary.as_str()));
}
