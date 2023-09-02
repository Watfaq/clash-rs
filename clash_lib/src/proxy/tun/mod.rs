use std::sync::Arc;

use crate::{app::dispatcher::Dispatcher, config::internal::config::TunConfig, Runner};

pub fn get_runner(cfg: TunConfig, dispatcher: Arc<Dispatcher>) -> anyhow::Result<Runner> {
    todo!()
}
