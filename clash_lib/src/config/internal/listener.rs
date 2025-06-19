use crate::common::utils::default_bool_true;
use serde::{Deserialize, Serialize};

use super::config::BindAddress;

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum InboundOpts {
    #[serde(alias = "http")]
    Http {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
    },
    #[serde(alias = "socks")]
    Socks {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        udp: bool,
    },
    #[serde(alias = "mixed")]
    Mixed {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        udp: bool, // TODO users
    },
    #[serde(alias = "tproxy")]
    TProxy {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        udp: bool,
    },
    #[serde(alias = "redir")]
    Redir {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
    },
    #[serde(alias = "tunnel")]
    Tunnel {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        network: Vec<String>,
        target: String,
    },
    #[cfg(feature = "shadowsocks")]
    #[serde(alias = "shadowsocks")]
    Shadowsocks {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default = "default_bool_true")]
        udp: bool,
        cipher: String,
        password: String,
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
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks { common_opts, .. } => common_opts,
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
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks { common_opts, .. } => common_opts,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct CommonInboundOpts {
    pub name: String,
    pub listen: BindAddress,
    #[serde(default)]
    pub allow_lan: bool,
    pub port: u16,
    /// Linux routing mark
    pub fw_mark: Option<u32>,
}
