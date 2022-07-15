use std::collections::HashMap;

use crate::{
    app::dns,
    config::def::{Experimental, LogLevel, RunMode},
};
use crate::config::internal::rule::Rule;

use super::proxy::OutboundProtocol;

pub struct Config {
    general: General,
    dns: dns::Config,
    experimental: Experimental,
    profile: Profile,
    rules: Vec<Rule>,

    proxies: HashMap<String, OutboundProtocol>,
}

struct General {
    inbound: Inbound,
    controller: Controller,
    mode: RunMode,
    log_level: LogLevel,
    ipv6: bool,
    interface: String,
    routing_mask: i32,
}

struct Profile {
    store_selected: bool,
    store_fakeip: bool,
}

struct Inbound {
    port: i16,
    socks_port: i16,
    redir_port: i16,
    tproxy_port: i16,
    mixed_port: i16,
    authentication: Vec<String>,
    bind_address: String,
}

struct Controller {
    external_controller: String,
    external_ui: String,
    secret: String,
}
