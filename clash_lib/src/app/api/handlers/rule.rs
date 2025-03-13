use std::{collections::HashMap, sync::Arc};

use axum::{
    Router as AxumRouter, extract::State, response::IntoResponse, routing::get,
};

use crate::app::{api::AppState, router::Router};

#[derive(Clone)]
struct RuleState {
    router: Arc<Router>,
}

pub fn routes(router: Arc<Router>) -> AxumRouter<Arc<AppState>> {
    AxumRouter::new()
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
