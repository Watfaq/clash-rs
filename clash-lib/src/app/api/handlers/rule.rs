use std::{collections::HashMap, sync::Arc};

use axum::{Router, extract::State, response::IntoResponse, routing::get};

use crate::app::{api::AppState, router::ArcRouter};

#[derive(Clone)]
struct RuleState {
    router: ArcRouter,
}

pub fn routes(router: ArcRouter) -> Router<Arc<AppState>> {
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
