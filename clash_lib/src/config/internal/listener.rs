use educe::Educe;
use serde::{Deserialize, Serialize};

use super::config::BindAddress;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum InboundOpts {
    Http {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        inherited: bool, // TODO users
    },
    Socks {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        udp: bool,
        inherited: bool, // TODO users
    },
    Mixed {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        udp: bool, // TODO users
        inherited: bool,
    },
    TProxy {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        udp: bool,
        inherited: bool,
    },
    Redir {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        inherited: bool,
    },
    Tunnel {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        network: Vec<String>,
        target: String,
    },
}

impl InboundOpts {
    pub fn common_opts(&self) -> &CommonInboundOpts {
        match self {
            InboundOpts::Http { common_opts, .. } => common_opts,
            InboundOpts::Socks { common_opts, .. } => common_opts,
            InboundOpts::Mixed { common_opts, .. } => common_opts,
            InboundOpts::TProxy { common_opts, .. } => common_opts,
            InboundOpts::Tunnel { common_opts, .. } => common_opts,
            InboundOpts::Redir { common_opts, .. } => common_opts,
        }
    }

    pub fn common_opts_mut(&mut self) -> &mut CommonInboundOpts {
        match self {
            InboundOpts::Http { common_opts, .. } => common_opts,
            InboundOpts::Socks { common_opts, .. } => common_opts,
            InboundOpts::Mixed { common_opts, .. } => common_opts,
            InboundOpts::TProxy { common_opts, .. } => common_opts,
            InboundOpts::Tunnel { common_opts, .. } => common_opts,
            InboundOpts::Redir { common_opts, .. } => common_opts,
        }
    }

    pub fn inherited(&self) -> bool {
        match self {
            InboundOpts::Http { inherited, .. } => *inherited,
            InboundOpts::Socks { inherited, .. } => *inherited,
            InboundOpts::Mixed { inherited, .. } => *inherited,
            InboundOpts::TProxy { inherited, .. } => *inherited,
            InboundOpts::Tunnel { .. } => false,
            InboundOpts::Redir { inherited, .. } => *inherited,
        }
    }

    pub fn port(&self) -> u16 {
        self.common_opts().port
    }

    pub fn port_mut(&mut self) -> &mut u16 {
        &mut self.common_opts_mut().port
    }
}

#[derive(Serialize, Deserialize, Debug, Educe, Clone)]
#[educe(Default)]
#[serde(rename_all = "kebab-case")]
pub struct CommonInboundOpts {
    pub name: String,
    pub listen: BindAddress,
    #[educe(Default = 0)]
    pub port: u16,
    // TODO opts down below is unimplemented
    pub rule: Option<String>,
    pub proxy: Option<String>,
}
