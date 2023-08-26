use std::{collections::HashMap, sync::Arc};

use axum::{extract::State, response::IntoResponse, routing::get, Router};

use crate::app::{api::AppState, router::ThreadSafeRouter};

#[derive(Clone)]
struct RuleState {
    router: ThreadSafeRouter,
}

pub fn routes(router: ThreadSafeRouter) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(get_rules))
        .with_state(RuleState { router })
}

async fn get_rules(State(state): State<RuleState>) -> impl IntoResponse {
    let rules = state.router.get_all_rules();
    let mut r = HashMap::new();
    r.insert(
        "rules",
        rules.iter().map(|r| r.as_map()).collect::<Vec<_>>(),
    );
    axum::response::Json(r)
}
