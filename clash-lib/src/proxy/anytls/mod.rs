use erased_serde::Serialize as ErasedSerialize;
use std::{collections::HashMap, io, sync::Arc};

use async_trait::async_trait;
use bytes::BytesMut;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedStream,
            ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    impl_default_connector,
    proxy::transport::Transport,
    session::Session,
};

use super::{
    AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
    OutboundHandler, OutboundType, PlainProxyAPIResponse,
    utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
};

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub udp: bool,
    pub tls: Option<Box<dyn Transport>>,
    pub transport: Option<Box<dyn Transport>>,
}

pub struct Handler {
    opts: HandlerOptions,

    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl_default_connector!(Handler);

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTLS")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    const DUPLEX_BUFFER_SIZE: usize = 64 * 1024;
    const RELAY_BUFFER_SIZE: usize = 16 * 1024;

    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: Default::default(),
        }
    }

    async fn inner_proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
    ) -> io::Result<AnyStream> {
        let s = if let Some(tls_client) = self.opts.tls.as_ref() {
            tls_client.proxy_stream(s).await?
        } else {
            s
        };

        let s = if let Some(transport) = self.opts.transport.as_ref() {
            transport.proxy_stream(s).await?
        } else {
            s
        };

        self.open_anytls_stream(s, sess).await
    }

    async fn open_anytls_stream(
        &self,
        mut stream: AnyStream,
        sess: &Session,
    ) -> io::Result<AnyStream> {
        const CMD_WASTE: u8 = 0;
        const CMD_SYN: u8 = 1;
        const CMD_PSH: u8 = 2;
        const CMD_FIN: u8 = 3;
        const CMD_SETTINGS: u8 = 4;
        const CMD_ALERT: u8 = 5;
        const STREAM_ID: u32 = 1;

        let password = Sha256::digest(self.opts.password.as_bytes());
        stream.write_all(password.as_slice()).await?;
        stream.write_u16(0).await?;

        let settings = format!("v=1\nclient=clash-rs/{}", env!("CARGO_PKG_VERSION"));
        Self::write_frame(&mut stream, CMD_SETTINGS, 0, settings.as_bytes()).await?;
        Self::write_frame(&mut stream, CMD_SYN, STREAM_ID, &[]).await?;

        let mut addr_buf = BytesMut::new();
        sess.destination.write_buf(&mut addr_buf);
        Self::write_frame(&mut stream, CMD_PSH, STREAM_ID, &addr_buf).await?;
        stream.flush().await?;

        let (mut remote_read, mut remote_write) = tokio::io::split(stream);
        let (app_stream, relay_stream) = tokio::io::duplex(Self::DUPLEX_BUFFER_SIZE);
        let (mut relay_read, mut relay_write) = tokio::io::split(relay_stream);
        let name = self.opts.name.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; Self::RELAY_BUFFER_SIZE];
            loop {
                let n = match relay_read.read(&mut buf).await {
                    Ok(n) => n,
                    Err(err) => {
                        debug!("anytls {} relay read error: {}", name, err);
                        break;
                    }
                };

                if n == 0 {
                    if let Err(err) =
                        Self::write_frame(&mut remote_write, CMD_FIN, STREAM_ID, &[])
                            .await
                    {
                        debug!("anytls {} send FIN failed: {}", name, err);
                    }
                    if let Err(err) = remote_write.flush().await {
                        debug!("anytls {} flush FIN failed: {}", name, err);
                    }
                    break;
                }

                if let Err(err) = Self::write_frame(
                    &mut remote_write,
                    CMD_PSH,
                    STREAM_ID,
                    &buf[..n],
                )
                .await
                {
                    debug!("anytls {} send PSH failed: {}", name, err);
                    break;
                }
            }
        });

        let name = self.opts.name.clone();
        tokio::spawn(async move {
            loop {
                let (cmd, stream_id, data) =
                    match Self::read_frame(&mut remote_read).await {
                        Ok(frame) => frame,
                        Err(err) => {
                            debug!("anytls {} read frame failed: {}", name, err);
                            break;
                        }
                };

                if stream_id != STREAM_ID {
                    debug!(
                        "anytls {} ignores frame for unexpected stream id {}",
                        name, stream_id
                    );
                    continue;
                }

                match cmd {
                    CMD_PSH => {
                        if let Err(err) = relay_write.write_all(&data).await {
                            debug!("anytls {} relay write failed: {}", name, err);
                            break;
                        }
                    }
                    CMD_FIN => {
                        if let Err(err) = relay_write.shutdown().await {
                            debug!("anytls {} relay shutdown failed: {}", name, err);
                        }
                        break;
                    }
                    CMD_ALERT => {
                        let msg = String::from_utf8_lossy(&data);
                        warn!("anytls {} alert: {}", name, msg);
                        let _ = relay_write.shutdown().await;
                        break;
                    }
                    CMD_WASTE | CMD_SYN | CMD_SETTINGS => {}
                    _ => {}
                }
            }
        });

        Ok(Box::new(app_stream))
    }

    async fn write_frame(
        writer: &mut (impl AsyncWrite + Unpin),
        command: u8,
        stream_id: u32,
        data: &[u8],
    ) -> io::Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "anytls frame payload exceeds 65535 bytes",
            ));
        }

        writer.write_u8(command).await?;
        writer.write_u32(stream_id).await?;
        writer.write_u16(data.len() as u16).await?;
        if !data.is_empty() {
            writer.write_all(data).await?;
        }
        Ok(())
    }

    async fn read_frame(
        reader: &mut (impl AsyncRead + Unpin),
    ) -> io::Result<(u8, u32, Vec<u8>)> {
        let command = reader.read_u8().await?;
        let stream_id = reader.read_u32().await?;
        let data_len = reader.read_u16().await? as usize;
        let mut data = vec![0u8; data_len];
        if data_len > 0 {
            reader.read_exact(&mut data).await?;
        }
        Ok((command, stream_id, data))
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Anytls
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let dialer = self.connector.read().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_stream_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let dialer = self.connector.read().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_datagram_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let stream = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let s = self.inner_proxy_stream(stream, sess).await?;
        let chained = ChainedStreamWrapper::new(s);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        let _ = (sess, resolver, connector);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "anytls UDP outbound is not implemented",
        ))
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
        m.insert("server".to_owned(), Box::new(self.opts.server.clone()) as _);
        m.insert("port".to_owned(), Box::new(self.opts.port) as _);
        m.insert(
            "password".to_owned(),
            Box::new(self.opts.password.clone()) as _,
        );
        if self.opts.udp {
            m.insert("udp".to_owned(), Box::new(true) as _);
        }
        if self.opts.tls.is_some() {
            m.insert("tls".to_owned(), Box::new(true) as _);
        }
        m
    }
}
