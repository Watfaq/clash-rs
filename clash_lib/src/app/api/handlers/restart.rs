#[cfg(unix)]
use std::os::unix::process::CommandExt;

use axum::{response::IntoResponse, Json};
use serde_json::Map;

pub async fn handle() -> impl IntoResponse {
    match std::env::current_exe() {
        Ok(exec) => {
            let mut map = Map::new();
            map.insert("status".to_owned(), "ok".into());
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                #[cfg(unix)]
                {
                    use tracing::info;

                    let err = std::process::Command::new(exec)
                        .args(std::env::args().skip(1))
                        .envs(std::env::vars())
                        .exec();
                    info!("process restarted: {}", err);
                }
                #[cfg(windows)]
                {
                    use tracing::error;

                    match std::process::Command::new(exec)
                        .args(std::env::args().skip(1))
                        .envs(std::env::vars())
                        .stdin(std::process::Stdio::inherit())
                        .stdout(std::process::Stdio::inherit())
                        .stderr(std::process::Stdio::inherit())
                        .spawn()
                    {
                        Ok(_) => {
                            // exit the current process
                            std::process::exit(0);
                        }
                        Err(e) => {
                            error!("Failed to restart: {}", e);
                        }
                    }
                }
            });
            Json(map).into_response()
        }
        Err(e) => {
            (http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}
