use std::sync::{Arc, OnceLock};

use crate::app::{outbound::manager::ThreadSafeOutboundManager, router::ArcRouter};

/// Late-bound reference to `Router`. Populated by `lib.rs` after the router
/// is constructed; the DNS resolver itself is built earlier.
pub type PendingRouter = Arc<OnceLock<ArcRouter>>;

/// Late-bound reference to `OutboundManager`. Populated by `lib.rs` after the
/// outbound manager is constructed.
pub type PendingOutboundManager = Arc<OnceLock<ThreadSafeOutboundManager>>;

/// Bundle of late-bound handles consulted by `DnsRuntimeProvider` when
/// `dns.respect-rules` is enabled, allowing upstream DNS dials to be routed
/// through the rule engine.
///
/// Both `OnceLock`s start empty and are filled exactly once during startup.
/// Until both are set, callers fall back to the static `outbound` handler —
/// this keeps early DNS lookups (during startup before the rule engine
/// exists) working.
pub struct RuleDispatch {
    pub router: PendingRouter,
    pub outbound_manager: PendingOutboundManager,
}

impl RuleDispatch {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            router: Arc::new(OnceLock::new()),
            outbound_manager: Arc::new(OnceLock::new()),
        })
    }
}
