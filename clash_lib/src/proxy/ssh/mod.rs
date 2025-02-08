use std::{borrow::Cow, io, pin::Pin, sync::Arc, time::Duration};

use async_trait::async_trait;

mod connector;
use connector::Client;
use russh::{
    client::{self, Handle, Msg},
    kex::*,
    keys::{load_secret_key, Algorithm, PrivateKey, PrivateKeyWithHashAlg},
    ChannelStream, Preferred,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedStream,
            ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    impl_default_connector,
    session::Session,
};

use super::{
    utils::RemoteConnector, ConnectorType, DialWithConnector, HandlerCommonOptions,
    OutboundHandler, OutboundType, ProxyStream,
};

struct ChannelStreamWrapper {
    inner: ChannelStream<Msg>,
}

impl std::fmt::Debug for ChannelStreamWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelStreamWrapper").finish()
    }
}

impl AsyncRead for ChannelStreamWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChannelStreamWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[derive(Debug)]
pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub username: String,
    /// try public key first, then password
    pub password: Option<String>,
    /// key content or path
    /// if contains "PRIVATE KEY", it's raw content, otherwise it's a file path
    /// if so, it can start with "~" to represent home directory,
    pub private_key: Option<String>,
    /// password to protect private key file when `private_key` is a file path
    pub private_key_passphrase: Option<String>,
    /// if empty, will not verify host key
    pub host_key: Option<Vec<String>>,
    /// supported host key algorithms:
    ///   * `ssh-ed25519`
    ///   * `rsa-sha2-256`
    ///   * `rsa-sha2-512`
    ///   * `ssh-rsa` ✨
    ///   * `ecdsa-sha2-nistp256` ✨
    ///   * `ecdsa-sha2-nistp384` ✨
    ///   * `ecdsa-sha2-nistp521` ✨
    pub host_key_algorithms: Option<Vec<Algorithm>>,
}

#[derive(Debug)]
pub struct Handler {
    opts: HandlerOptions,

    connector: tokio::sync::Mutex<Option<Arc<dyn RemoteConnector>>>,
}

impl_default_connector!(Handler);

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: tokio::sync::Mutex::new(None),
        }
    }
}

/// default values defined in golang's crypto/ssh (used by mihomo)
/// https://github.com/golang/crypto/blob/9290511cd23ab9813a307b7f2615325e3ca98902/ssh/common.go#L65
const KEX_ALGORITHMS: &[Name] = &[
    CURVE25519,
    CURVE25519_PRE_RFC_8731,
    DH_GEX_SHA1,
    DH_GEX_SHA256,
    DH_G14_SHA1,
    DH_G14_SHA256,
    ECDH_SHA2_NISTP256,
    ECDH_SHA2_NISTP384,
    ECDH_SHA2_NISTP521,
    NONE,
    EXTENSION_SUPPORT_AS_CLIENT,
];

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Ssh
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        // key exchange algorithms
        let kex = Cow::Borrowed(KEX_ALGORITHMS);
        // host key algorithms
        let key = match self.opts.host_key_algorithms.clone() {
            Some(host_key_algorithms) => Cow::Owned(host_key_algorithms),
            None => Default::default(),
        };
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            preferred: Preferred {
                kex,
                key,
                ..Default::default()
            },
            ..<_>::default()
        };

        let config = Arc::new(config);

        let server_public_key = self.opts.host_key.as_ref().map(|x| {
            x.iter()
                .filter_map(|x| {
                    russh::keys::ssh_key::PublicKey::from_openssh(x).ok()
                })
                .collect::<Vec<_>>()
        });
        let sh = connector::Client { server_public_key };

        let mut session =
            client::connect(config, (self.opts.server.as_str(), self.opts.port), sh)
                .await
                .map_err(|ssh_e| io::Error::new(io::ErrorKind::Other, ssh_e))?;

        auth(&mut session, &self.opts).await?;

        let dst = sess.destination.clone();
        let channel = session
            .channel_open_direct_tcpip(
                dst.host(),
                sess.destination.port() as _,
                "0.0.0.0",
                0,
            )
            .await
            .map_err(|ssh_e| io::Error::new(io::ErrorKind::Other, ssh_e))?;
        let s = Box::new(ChannelStreamWrapper {
            inner: channel.into_stream(),
        });
        let chained: ChainedStreamWrapper<Box<dyn ProxyStream>> =
            ChainedStreamWrapper::new(s);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        Err(new_io_error("ssh udp is not implemented yet"))
    }
}

fn load_private_key(opts: &HandlerOptions) -> io::Result<PrivateKey> {
    let key_path_or_content = match opts.private_key.clone() {
        Some(key_path) => key_path,
        None => return Err(new_io_error("private key not found")),
    };
    if key_path_or_content.contains("PRIVATE KEY") {
        // raw content
        PrivateKey::from_openssh(&key_path_or_content)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    } else {
        // file path
        let key_path = if key_path_or_content.starts_with("~") {
            let home = dirs::home_dir()
                .ok_or_else(|| new_io_error("home directory not found"))?;
            key_path_or_content.replacen(
                "~",
                home.to_str()
                    .ok_or_else(|| new_io_error("home directory not found"))?,
                1,
            )
        } else {
            key_path_or_content
        };
        load_secret_key(key_path, opts.private_key_passphrase.as_deref())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

async fn auth(client: &mut Handle<Client>, opts: &HandlerOptions) -> io::Result<()> {
    if let Ok(key_pair) = load_private_key(opts) {
        let auth_res = client
            .authenticate_publickey(
                &opts.username,
                PrivateKeyWithHashAlg::new(
                    Arc::new(key_pair),
                    client.best_supported_rsa_hash().await.unwrap().flatten(),
                ),
            )
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        if auth_res.success() {
            return Ok(());
        }
    };

    if let Some(password) = opts.password.as_ref() {
        let auth_res = client
            .authenticate_password(&opts.username, password)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        if auth_res.success() {
            return Ok(());
        }
    }

    Err(new_io_error("ssh auth failed"))
}
