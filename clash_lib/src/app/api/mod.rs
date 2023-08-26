use std::{net::SocketAddr, sync::Arc};

use axum::{routing::get, Router};

use tokio::sync::{broadcast::Sender, Mutex};
use tracing::info;

use crate::{config::internal::config::Controller, GlobalState, Runner};

use super::{
    dispatcher, inbound::manager::ThreadSafeInboundManager,
    outbound::manager::ThreadSafeOutboundManager, router::ThreadSafeRouter, ThreadSafeDNSResolver,
};

mod handlers;
mod middlewares;

pub struct AppState {
    log_source_tx: Sender<String>,
}

pub fn get_api_runner(
    controller_cfg: Controller,
    log_source: Sender<String>,
    inbound_manager: ThreadSafeInboundManager,
    dispatcher: Arc<dispatcher::Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
    outbound_manager: ThreadSafeOutboundManager,
    router: ThreadSafeRouter,
) -> Option<Runner> {
    if let Some(bind_addr) = controller_cfg.external_controller {
        let app_state = Arc::new(AppState {
            log_source_tx: log_source,
        });
        let addr = bind_addr.parse().unwrap();

        let runner = async move {
            info!("Starting API server at {}", addr);
            let app = Router::new()
                .route("/", get(handlers::hello::handle))
                .route("/logs", get(handlers::log::handle))
                .route("/version", get(handlers::version::handle))
                .nest(
                    "/configs",
                    handlers::config::routes(
                        inbound_manager,
                        dispatcher,
                        global_state,
                        dns_resolver.clone(),
                    ),
                )
                .nest("/rules", handlers::rule::routes(router))
                .nest(
                    "/proxies",
                    handlers::proxy::routes(outbound_manager.clone()),
                )
                .nest("/connections", handlers::connection::routes())
                .nest(
                    "/providers/proxies",
                    handlers::provider::routes(outbound_manager),
                )
                .nest("/dns", handlers::dns::routes(dns_resolver))
                .layer(middlewares::auth::AuthMiddlewareLayer::new(
                    controller_cfg.secret.unwrap_or_default(),
                ))
                .with_state(app_state);
            axum::Server::bind(&addr)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .unwrap();
        };
        Some(Box::pin(runner))
    } else {
        None
    }
}
