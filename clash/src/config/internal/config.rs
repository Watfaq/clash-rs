use crate::{
    app::dns,
    config::def::{Experimental, LogLevel, RunMode},
};

pub struct Config {
    general: General,
    dns: dns::DNS,
    experimental: Experimental,
    profile: Profile,
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
