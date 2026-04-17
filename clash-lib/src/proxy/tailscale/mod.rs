use std::{collections::HashMap, fmt::Debug, io, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use tokio::sync::Mutex;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedStream,
            ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::map_io_error,
    session::Session,
};

use super::{
    ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
    PlainProxyAPIResponse,
};

const TAILSCALE_CLIENT_NAME: &str = "clash-rs";
const TAILSCALE_STATE_FILE_NAME: &str = "tailscale_state.json";
const TAILSCALE_RS_EXPERIMENT_ENV: &str = "TS_RS_EXPERIMENT";
const TAILSCALE_RS_EXPERIMENT_VALUE: &str = "this_is_unstable_software";

#[derive(Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub state_dir: Option<String>,
    pub auth_key: Option<String>,
    pub hostname: Option<String>,
    pub control_url: Option<String>,
    pub ephemeral: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    device: Mutex<Option<Arc<::tailscale::Device>>>,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tailscale")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            device: Mutex::new(None),
        }
    }

    async fn get_device(&self) -> io::Result<Arc<::tailscale::Device>> {
        if std::env::var(TAILSCALE_RS_EXPERIMENT_ENV).as_deref()
            != Ok(TAILSCALE_RS_EXPERIMENT_VALUE)
        {
            return Err(io::Error::other(format!(
                "{TAILSCALE_RS_EXPERIMENT_ENV}={TAILSCALE_RS_EXPERIMENT_VALUE} \
                     is required to enable tailscale-rs runtime"
            )));
        }

        let mut guard = self.device.lock().await;
        if let Some(device) = guard.as_ref() {
            return Ok(Arc::clone(device));
        }

        let key_state = if self.opts.ephemeral {
            Default::default()
        } else if let Some(state_dir) = self.opts.state_dir.as_ref() {
            let state_file =
                PathBuf::from(state_dir).join(TAILSCALE_STATE_FILE_NAME);
            ::tailscale::load_key_file(
                state_file,
                ::tailscale::BadFormatBehavior::Error,
            )
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "failed to initialize tailscale key state: {e}"
                ))
            })?
        } else {
            Default::default()
        };

        let mut config = ::tailscale::Config {
            key_state,
            ..Default::default()
        };
        config.client_name = Some(TAILSCALE_CLIENT_NAME.to_owned());
        config.requested_hostname = self.opts.hostname.clone();

        if let Some(control_url) = self.opts.control_url.as_ref() {
            config.control_server_url = control_url.parse().map_err(|e| {
                io::Error::other(format!("invalid tailscale control-url: {e}"))
            })?;
        }

        let device = Arc::new(
            ::tailscale::Device::new(&config, self.opts.auth_key.clone())
                .await
                .map_err(|e| {
                    io::Error::other(format!(
                        "failed to initialize tailscale-rs device: {e}"
                    ))
                })?,
        );
        *guard = Some(Arc::clone(&device));
        Ok(device)
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Tailscale
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        let remote_ip = resolver
            .resolve(sess.destination.host().as_str(), false)
            .await
            .map_err(map_io_error)?
            .ok_or_else(|| io::Error::other("no dns result"))?;
        let device = self.get_device().await?;
        let s = device
            .tcp_connect((remote_ip, sess.destination.port()).into())
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "failed to connect over tailscale-rs to {}:{}: {e}",
                    remote_ip,
                    sess.destination.port()
                ))
            })?;

        let s = ChainedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        Err(std::io::Error::other(
            "Tailscale outbound handler does not support UDP",
        ))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        m.insert("name".to_owned(), Box::new(self.opts.name.clone()) as _);
        m.insert("type".to_owned(), Box::new(self.proto().to_string()) as _);
        m.insert(
            "state-dir".to_owned(),
            Box::new(self.opts.state_dir.clone()) as _,
        );
        m.insert(
            "hostname".to_owned(),
            Box::new(self.opts.hostname.clone()) as _,
        );
        m.insert(
            "control-url".to_owned(),
            Box::new(self.opts.control_url.clone()) as _,
        );
        m.insert("ephemeral".to_owned(), Box::new(self.opts.ephemeral) as _);
        m.insert(
            "auth-key-set".to_owned(),
            Box::new(self.opts.auth_key.is_some()) as _,
        );
        m
    }
}

#[cfg(test)]
mod tests {
    use super::{Handler, HandlerOptions};
    use crate::proxy::{OutboundHandler, PlainProxyAPIResponse};

    #[tokio::test]
    async fn tailscale_support_udp_is_disabled() {
        let h = Handler::new(HandlerOptions {
            name: "ts".to_owned(),
            state_dir: None,
            auth_key: None,
            hostname: None,
            control_url: None,
            ephemeral: false,
        });
        assert!(!h.support_udp().await);
    }

    #[tokio::test]
    async fn tailscale_api_response_redacts_auth_key() {
        let h = Handler::new(HandlerOptions {
            name: "ts".to_owned(),
            state_dir: None,
            auth_key: Some("tskey-auth-xxxx".to_owned()),
            hostname: None,
            control_url: None,
            ephemeral: false,
        });
        let map = h.as_map().await;
        assert!(
            map.contains_key("auth-key-set"),
            "auth-key-set should be present"
        );
        assert!(
            !map.contains_key("auth-key"),
            "raw auth-key must not be present"
        );
    }
}
