use std::sync::Arc;

use crate::proxy::AnyInboundHandler;

pub struct NetworkInboundListener {
    pub address: String,
    pub port: u16,
    pub hanlder: AnyInboundHandler,
    pub dispather: Arc<Dispather>,
    pub nat_manager: Arc<NatManager>,
}
