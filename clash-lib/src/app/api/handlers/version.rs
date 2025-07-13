use std::collections::HashMap;

use axum::response::IntoResponse;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn handle() -> impl IntoResponse {
    let mut val = HashMap::new();
    val.insert("version".to_owned(), VERSION.to_owned());
    axum::response::Json(val)
}
