fn main() -> anyhow::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(docker_test)");
    println!("cargo:rerun-if-env-changed=CLASH_DOCKER_TEST");
    if let Some("1" | "true") = option_env!("CLASH_DOCKER_TEST") {
        println!("cargo::rustc-cfg=docker_test");
    }

    build_dashboard()?;

    println!("cargo:rerun-if-changed=src/common/geodata/geodata.proto");

    // Use protox (pure Rust) instead of system protobuf-compiler
    let file_descriptors = protox::compile(
        ["src/common/geodata/geodata.proto"],
        ["src/common/geodata"],
    )?;

    prost_build::compile_fds(file_descriptors)?;

    let vars = ["CLASH_GIT_REF", "CLASH_GIT_SHA", "GITHUB_REF", "GITHUB_SHA"];
    for var in vars {
        println!("cargo:rerun-if-env-changed={var}");
    }

    let git_ref = std::env::var_os("CLASH_GIT_REF")
        .or_else(|| std::env::var_os("GITHUB_REF"))
        .and_then(|v| v.into_string().ok());
    let git_sha = std::env::var_os("CLASH_GIT_SHA")
        .or_else(|| std::env::var_os("GITHUB_SHA"))
        .and_then(|v| v.into_string().ok());

    let version = if let Some(ref git_ref_val) = git_ref
        && git_ref_val == "refs/heads/master"
        && let Some(ref sha) = git_sha
    {
        let short_sha = &sha[..7.min(sha.len())];
        // Nightly release below
        format!("{}-alpha+sha.{short_sha}", env!("CARGO_PKG_VERSION"))
    } else {
        env!("CARGO_PKG_VERSION").into()
    };
    println!("cargo:rustc-env=CLASH_VERSION_OVERRIDE={version}");

    Ok(())
}

fn build_dashboard() -> anyhow::Result<()> {
    // Only run when the `dashboard` feature is enabled.
    if std::env::var("CARGO_FEATURE_DASHBOARD").is_err() {
        return Ok(());
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let dashboard_dir =
        std::path::PathBuf::from(&manifest_dir).join("../clash-dashboard");

    // Always ensure dist/ exists so rust-embed can compile even if the npm
    // build is skipped (it will embed an empty bundle).
    let dist_dir = dashboard_dir.join("dist");
    std::fs::create_dir_all(&dist_dir)?;

    let dashboard_dir = match dashboard_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            println!(
                "cargo:warning=clash-dashboard directory not found at {}; skipping \
                 frontend build (embedded UI will be empty)",
                dashboard_dir.display()
            );
            return Ok(());
        }
    };

    // Watch source files so cargo reruns this script on any frontend change.
    let src_dir = dashboard_dir.join("src");
    emit_rerun_if_changed(&src_dir);
    for file in [
        "index.html",
        "vite.config.ts",
        "package.json",
        "package-lock.json",
        "tsconfig.json",
        "tsconfig.app.json",
    ] {
        println!(
            "cargo:rerun-if-changed={}",
            dashboard_dir.join(file).display()
        );
    }

    // On Windows npm is a .cmd script, not a binary.
    let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };

    // Run `npm ci` to install dependencies (no-op if already up to date).
    let status = match std::process::Command::new(npm)
        .args(["ci", "--prefer-offline"])
        .current_dir(&dashboard_dir)
        .status()
    {
        Ok(s) => s,
        Err(_) => {
            println!(
                "cargo:warning=npm not found; skipping frontend build (embedded UI \
                 will be empty)"
            );
            return Ok(());
        }
    };

    if !status.success() {
        println!(
            "cargo:warning=`npm ci` failed with status {status}; skipping frontend \
             build"
        );
        return Ok(());
    }

    // Run `npm run build`.
    let status = std::process::Command::new(npm)
        .args(["run", "build"])
        .current_dir(&dashboard_dir)
        .status()
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to run `npm run build` (is Node.js/npm installed?): {e}"
            )
        })?;

    anyhow::ensure!(
        status.success(),
        "`npm run build` exited with status {status}"
    );

    Ok(())
}

/// Recursively emits `cargo:rerun-if-changed` for every file under `dir`.
fn emit_rerun_if_changed(dir: &std::path::Path) {
    if !dir.exists() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            emit_rerun_if_changed(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}
