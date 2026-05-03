use axum::response::IntoResponse;
use serde_json::json;

const VERSION: &str = env!("CLASH_VERSION_OVERRIDE");
const COMMIT: &str = env!("CLASH_GIT_SHA_SHORT");

pub async fn handle() -> impl IntoResponse {
    let mut resp = json!({
        "version": VERSION,
        "meta": false
    });
    if !COMMIT.is_empty() {
        resp["commit"] = json!(COMMIT);
    }
    axum::Json(resp)
}
