use std::{collections::HashMap, sync::Arc};

use axum::{Router, extract::State, response::IntoResponse, routing::get};

use crate::app::{
    api::{CtrlResult, CtrlState},
    router::ArcRouter,
};

pub fn routes(router: ArcRouter) -> Router<Arc<CtrlState>> {
    Router::new().route("/", get(get_rules)).with_state(router)
}

async fn get_rules(
    State(router): State<ArcRouter>,
) -> CtrlResult<impl IntoResponse> {
    let rules = router.get_all_rules();
    let mut r = HashMap::new();
    r.insert("rules", rules);
    Ok(serde_json::to_string(&r)?)
}
