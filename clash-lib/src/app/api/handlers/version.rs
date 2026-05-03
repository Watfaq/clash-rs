use axum::response::IntoResponse;
use serde_json::json;

const VERSION: &str = env!("CLASH_VERSION_OVERRIDE");

pub async fn handle() -> impl IntoResponse {
    let mut resp = json!({
        "version": VERSION,
        "meta": false
    });
    // Extract commit SHA from semver build metadata (e.g. "0.x.y-alpha+sha.abc1234")
    if let Some(sha) = VERSION.split("+sha.").nth(1) {
        resp["commit"] = json!(sha);
    }
    axum::Json(resp)
}
