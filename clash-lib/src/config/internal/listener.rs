use crate::common::utils::default_bool_true;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::HashMap;

use super::config::BindAddress;

/// A single user entry for SS2022 multi-user inbound.
/// `name` is stored in session metadata as `inboundUser` for traffic attribution.
/// `password` is a base64-encoded 32-byte key (for 2022-blake3-aes-256-gcm).
#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
pub struct InboundUser {
    pub name: String,
    pub password: String,
}

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
        #[serde(default = "default_bool_true")]
        udp: bool,
    },
    #[serde(alias = "mixed")]
    Mixed {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default = "default_bool_true")]
        udp: bool, // TODO users
    },
    #[cfg(feature = "tproxy")]
    #[serde(alias = "tproxy")]
    TProxy {
        #[serde(flatten)]
        common_opts: CommonInboundOpts,
        #[serde(default = "default_bool_true")]
        udp: bool,
    },
    #[cfg(feature = "redir")]
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
        /// Multi-user list for SS2022 EIH. Each entry has a name (FAC user_id)
        /// and a base64-encoded 32-byte user key. When non-empty, EIH is used
        /// to identify which user owns each connection.
        #[serde(default)]
        users: Vec<InboundUser>,
    },
}

impl InboundOpts {
    pub fn common_opts(&self) -> &CommonInboundOpts {
        match self {
            InboundOpts::Http { common_opts, .. } => common_opts,
            InboundOpts::Socks { common_opts, .. } => common_opts,
            InboundOpts::Mixed { common_opts, .. } => common_opts,
            #[cfg(feature = "tproxy")]
            InboundOpts::TProxy { common_opts, .. } => common_opts,
            InboundOpts::Tunnel { common_opts, .. } => common_opts,
            #[cfg(feature = "redir")]
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
            #[cfg(feature = "tproxy")]
            InboundOpts::TProxy { common_opts, .. } => common_opts,
            InboundOpts::Tunnel { common_opts, .. } => common_opts,
            #[cfg(feature = "redir")]
            InboundOpts::Redir { common_opts, .. } => common_opts,
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks { common_opts, .. } => common_opts,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            InboundOpts::Http { .. } => "http",
            InboundOpts::Socks { .. } => "socks",
            InboundOpts::Mixed { .. } => "mixed",
            #[cfg(feature = "tproxy")]
            InboundOpts::TProxy { .. } => "tproxy",
            InboundOpts::Tunnel { .. } => "tunnel",
            #[cfg(feature = "redir")]
            InboundOpts::Redir { .. } => "redir",
            #[cfg(feature = "shadowsocks")]
            InboundOpts::Shadowsocks { .. } => "shadowsocks",
        }
    }
}

/// Mirrors `OutboundProxyProviderDef` but for inbound listeners.
/// The provider URL/file must return YAML with a top-level `listeners:` key
/// containing a list of `InboundOpts`-compatible objects.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum InboundProviderDef {
    Http(InboundHttpProvider),
    File(InboundFileProvider),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct InboundHttpProvider {
    #[serde(skip)]
    pub name: String,
    pub url: String,
    pub interval: u64,
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct InboundFileProvider {
    #[serde(skip)]
    pub name: String,
    pub path: String,
    pub interval: Option<u64>,
}

impl TryFrom<HashMap<String, Value>> for InboundProviderDef {
    type Error = crate::Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        use serde::de::value::MapDeserializer;
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or_else(|| {
                crate::Error::InvalidConfig(
                    "missing field `name` in inbound provider".into(),
                )
            })?
            .to_owned();
        InboundProviderDef::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(|e| {
                crate::Error::InvalidConfig(format!("inbound provider {name}: {e}"))
            })
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
