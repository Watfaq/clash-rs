use std::sync::Arc;
use tokio::sync::RwLock;

pub mod dispatcher;
pub mod dns;
pub mod inbound;
pub mod logging;
pub mod nat_manager;
pub mod outbound;
pub mod profile;
pub mod router;

pub type ThreadSafeDNSResolver = Arc<RwLock<dyn dns::ClashResolver>>;
