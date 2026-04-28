use axum::{Router, ServiceExt};
use tower::{Layer, util::MapRequestLayer};
use tracing::{error, info};

use super::middlewares::{
    auth::AuthMiddlewareLayer, websocket_uri_rewrite::rewrite_websocket_uri,
};

pub async fn serve_tcp(
    bind_addr: String,
    router: Router,
    auth_secret: String,
    cors_allow_origins: Option<Vec<String>>,
) -> Result<(), crate::Error> {
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!(
        "API server is listening on TCP address {}",
        listener.local_addr()?
    );
    // TCP related security checks
    if let Ok(addr) = listener.local_addr()
        && !addr.ip().is_loopback()
        && auth_secret.is_empty()
    {
        error!(
            "API server is listening on a non-loopback address without a secret. \
             This is insecure!"
        );
        error!("Please set a secret in the configuration to secure the API server.");
        return Err(crate::Error::Operation(
            "API server is listening on a non-loopback address without a secret. \
             This is insecure!"
                .to_string(),
        ));
    }
    if let Ok(addr) = listener.local_addr()
        && !addr.ip().is_loopback()
        && cors_allow_origins.is_none()
    {
        error!(
            "API server is listening on a non-loopback address without CORS \
             origins configured. This is insecure!"
        );
        error!(
            "Please set CORS origins in the configuration to secure the API server."
        );
        return Err(crate::Error::Operation(
            "API server is listening on a non-loopback address without CORS \
             origins configured. This is insecure!"
                .to_string(),
        ));
    }
    let app = router.route_layer(AuthMiddlewareLayer::new(auth_secret));
    let app = MapRequestLayer::new(rewrite_websocket_uri).layer(app);
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|x| {
            error!("TCP API server error: {}", x);
            crate::Error::Operation(format!("API server error: {x}"))
        })
}
