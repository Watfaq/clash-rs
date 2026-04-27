use axum::{
    body::Body,
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

/// Embedded build output from `clash-dashboard/dist/`.
/// The dist/ folder is produced by `npm run build` in build.rs when the
/// `dashboard` feature is enabled.
#[derive(RustEmbed)]
#[folder = "../clash-dashboard/dist/"]
struct Assets;

/// Serves the built-in dashboard at `/ui/` (index).
pub async fn serve_index() -> impl IntoResponse {
    serve_path("index.html")
}

/// Serves a dashboard asset at `/ui/{*path}`, falling back to `index.html`
/// for unknown paths so that React Router's client-side routing works.
pub async fn serve_asset(Path(path): Path<String>) -> impl IntoResponse {
    serve_path(path.trim_start_matches('/'))
}

fn serve_path(path: &str) -> Response {
    match Assets::get(path) {
        Some(asset) => {
            let mime = content_type(path);
            // Vite hashes asset filenames (e.g. main-Abc123.js), so they can
            // be cached indefinitely. index.html must not be cached so the
            // browser always gets the latest entry point.
            let cache = if path == "index.html" {
                "no-cache"
            } else {
                "public, max-age=31536000, immutable"
            };
            Response::builder()
                .header(header::CONTENT_TYPE, mime)
                .header(header::CACHE_CONTROL, cache)
                .body(Body::from(asset.data.into_owned()))
                .unwrap()
        }
        None => {
            // SPA fallback: any route the React Router doesn't match gets
            // index.html so the client can render the correct page.
            match Assets::get("index.html") {
                Some(asset) => Response::builder()
                    .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .header(header::CACHE_CONTROL, "no-cache")
                    .body(Body::from(asset.data.into_owned()))
                    .unwrap(),
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }
    }
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript",
        Some("css") => "text/css",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("ico") => "image/x-icon",
        Some("json") => "application/json",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("ttf") => "font/ttf",
        Some("txt") => "text/plain",
        _ => "application/octet-stream",
    }
}
