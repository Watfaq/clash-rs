use std::sync::Arc;

pub mod api;
pub mod dispatcher;
pub mod dns;
pub mod inbound;
pub mod logging;
pub mod outbound;
pub mod profile;
pub mod proxy_manager;
pub mod router;

pub type ThreadSafeDNSResolver = Arc<dyn dns::ClashResolver>;
