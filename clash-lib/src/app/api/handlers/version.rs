use axum::response::IntoResponse;
use serde_json::json;

const VERSION: &str = env!("CLASH_VERSION_OVERRIDE");

pub async fn handle() -> impl IntoResponse {
    json!({
        "version": VERSION,
        "meta": false
    })
    .to_string()
}
