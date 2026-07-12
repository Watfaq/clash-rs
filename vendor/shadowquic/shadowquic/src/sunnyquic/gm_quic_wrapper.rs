use std::future::poll_fn;
use std::net::SocketAddr;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use std::{fs, io, u8};

use async_trait::async_trait;
use bytes::Bytes;
use gm_quic::prelude::handy::{ToCertificate, client_parameters, server_parameters};

use gm_quic::prelude::StreamReader;
use gm_quic::prelude::StreamWriter;
use gm_quic::prelude::handy::ToPrivateKey;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, crypto};
use thiserror::Error;

// Add import for DefaultSeqLogger
//use qevent::telemetry::DefaultSeqLogger;

use crate::config::{SunnyQuicClientCfg, SunnyQuicServerCfg};
use crate::error::SError;
use crate::quic::{QuicClient, QuicServer};
use crate::quic::{QuicConnection, QuicErrorRepr};

pub use gm_quic::prelude::QuicClient as EndClient;
pub type EndServer = Arc<gm_quic::prelude::QuicListeners>;
/// 202601, gm-quic unreliable datagram is broken
/// BBR is still not supported

/// Right now(202506), gm-quic doesn't provide BBR support.
/// So we stopped here.
#[deprecated(note = "Use quinn instead")]
#[derive(Clone)]
pub struct Connection {
    inner: Arc<gm_quic::prelude::Connection>,
    datagram_reader: gm_quic::prelude::DatagramReader,
    datagram_writer: gm_quic::prelude::DatagramWriter,
}

#[async_trait]
impl QuicClient for gm_quic::prelude::QuicClient {
    type C = Connection;
    type SC = SunnyQuicClientCfg;

    async fn new(cfg: &SunnyQuicClientCfg) -> crate::error::SResult<Self> {
        let mut roots = RootCertStore::empty();
        //roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        if let Some(path) = &cfg.cert_path {
            roots.add_parsable_certificates(path.to_certificate());
        }

        let mut cli_para = client_parameters();
        cli_para
            .set(qbase::param::ParameterId::InitialMaxData, 32 * 1024 * 1024)
            .unwrap();
        cli_para
            .set(
                qbase::param::ParameterId::InitialMaxStreamDataBidiLocal,
                16 * 1024 * 1024,
            )
            .unwrap();
        cli_para
            .set(
                qbase::param::ParameterId::InitialMaxStreamDataBidiRemote,
                16 * 1024 * 1024,
            )
            .unwrap();

        cli_para
            .set(gm_quic::prelude::ParameterId::MaxDatagramFrameSize, 2000)
            .unwrap();

        let mut client = gm_quic::prelude::QuicClient::builder()
            .with_root_certificates(roots)
            //.without_verifier()
            .without_cert()
            .with_parameters(cli_para)
            .with_alpns(cfg.alpn.iter().map(|alpn| alpn.clone().into_bytes()));

        if cfg.zero_rtt {
            client = client.enable_0rtt();
        }
        Ok(client.build())
    }

    async fn new_with_socket_factory(
        cfg: &Self::SC,
        _socket_factory: Arc<dyn crate::utils::socket_opt::SocketFactory>,
    ) -> crate::error::SResult<Self> {
        Self::new(cfg).await
    }

    async fn connect(
        &self,
        addr: std::net::SocketAddr,
        server_name: &str,
    ) -> Result<Self::C, QuicErrorRepr> {
        let conn = self.connected_to(server_name, [addr]).unwrap();
        Ok(Connection {
            datagram_reader: conn.unreliable_reader()??,
            datagram_writer: conn.unreliable_writer().await??,
            inner: conn.into(),
        })
    }
}

#[async_trait]
impl QuicConnection for Connection {
    type SendStream = StreamWriter;
    type RecvStream = StreamReader;
    async fn open_bi(&self) -> Result<(Self::SendStream, Self::RecvStream, u64), QuicErrorRepr> {
        let (id, (r, w)) = self.inner.open_bi_stream().await?.unwrap();
        Ok((w, r, id.id()))
    }
    async fn accept_bi(&self) -> Result<(Self::SendStream, Self::RecvStream, u64), QuicErrorRepr> {
        let (id, (r, w)) = self.inner.accept_bi_stream().await?;
        Ok((w, r, id.id()))
    }
    async fn open_uni(&self) -> Result<(Self::SendStream, u64), QuicErrorRepr> {
        let (id, w) = self.inner.open_uni_stream().await?.unwrap();
        Ok((w, id.id()))
    }
    async fn accept_uni(&self) -> Result<(Self::RecvStream, u64), QuicErrorRepr> {
        let (id, r) = self.inner.accept_uni_stream().await?;
        Ok((r, id.id()))
    }
    async fn read_datagram(&self) -> Result<Bytes, QuicErrorRepr> {
        let bytes = poll_fn(|cx| self.datagram_reader.poll_recv(cx)).await?;
        tracing::info!("Received datagram");
        Ok(bytes)
    }
    async fn send_datagram(&self, bytes: Bytes) -> Result<(), QuicErrorRepr> {
        self.datagram_writer.send_bytes(bytes)?;
        //tracing::info!("Sent datagram");
        Ok(())
    }
    fn close_reason(&self) -> Option<QuicErrorRepr> {
        // match self.deref().is_active() {
        //     true => None,
        //     false => Some(QuicErrorRepr::QuicError(qbase::error::Error::new(
        //         "Connection closed",
        //     ))),
        // }
        None
    }
    fn remote_address(&self) -> SocketAddr {
        "0.0.0.0:0".parse().unwrap()
    }
    fn peer_id(&self) -> u64 {
        let mut id: [u8; 8] = [0; 8];
        id.copy_from_slice(self.inner.origin_dcid().unwrap().as_ref());
        u64::from_be_bytes(id)
    }
    fn close(&self, error_code: u64, reason: &[u8]) {
        unimplemented!()
    }
}

#[async_trait]
impl QuicServer for EndServer {
    type C = Connection;
    type SC = SunnyQuicServerCfg;

    async fn new(cfg: &SunnyQuicServerCfg) -> crate::error::SResult<Self> {
        // let qlogger: Arc<dyn qevent::telemetry::Log + Send + Sync> =
        //     Arc::new(DefaultSeqLogger::new(PathBuf::from("./server.qlog")));

        // crypto.alpn_protocols = cfg
        //     .alpn
        //     .iter()
        //     .cloned()
        //     .map(|alpn| alpn.into_bytes())
        //     .collect();
        // crypto.max_early_data_size = if cfg.zero_rtt { u32::MAX } else { 0 };
        // crypto.send_half_rtt_data = cfg.zero_rtt;

        let mut server_para = server_parameters();
        server_para
            .set(qbase::param::ParameterId::InitialMaxData, 16 * 1024 * 1024)
            .unwrap();
        server_para
            .set(
                qbase::param::ParameterId::InitialMaxStreamDataBidiLocal,
                8 * 1024 * 1024,
            )
            .unwrap();
        server_para
            .set(
                qbase::param::ParameterId::InitialMaxStreamDataBidiRemote,
                8 * 1024 * 1024,
            )
            .unwrap();

        server_para
            .set(gm_quic::prelude::ParameterId::MaxDatagramFrameSize, 2000)
            .unwrap();

        let listeners = gm_quic::prelude::QuicListeners::builder()
            .map_err(|x| SError::QuicError(x.into()))?
            .with_parameters(server_para)
            .without_client_cert_verifier()
            .enable_0rtt()
            .with_alpns(cfg.alpn.iter().map(|alpn| alpn.clone().into_bytes()))
            .listen(128);
        listeners
            .add_server(
                cfg.server_name.as_str(),
                cfg.cert_path.as_path(),
                cfg.key_path.as_path(),
                [cfg.bind_addr],
                None,
            )
            .unwrap();
        Ok(listeners)
    }

    async fn accept(&self) -> Result<Self::C, QuicErrorRepr> {
        let (conn, sni, path, link) = self.deref().accept().await.unwrap();
        tracing::info!(
            "Accepted new connection from {}, sni: {:?}",
            link.src(),
            sni
        );
        Ok(Connection {
            datagram_reader: conn.unreliable_reader()??,
            datagram_writer: conn.unreliable_writer().await??,
            inner: conn.into(),
        })
    }

    async fn update_config(&self, _cfg: &Self::SC) -> crate::error::SResult<()> {
        tracing::warn!("sunnyquic gm-quic server does not support updating config");
        Ok(())
    }
}

impl From<std::io::Error> for QuicErrorRepr {
    fn from(err: std::io::Error) -> Self {
        QuicErrorRepr::QuicIoError(err.to_string())
    }
}
impl From<qbase::error::Error> for QuicErrorRepr {
    fn from(err: qbase::error::Error) -> Self {
        QuicErrorRepr::QuicBaseError(err.to_string())
    }
}
impl From<gm_quic::prelude::BuildListenersError> for QuicErrorRepr {
    fn from(err: gm_quic::prelude::BuildListenersError) -> Self {
        QuicErrorRepr::QuicListenerBuilderError(err.to_string())
    }
}

impl From<rustls::Error> for SError {
    fn from(err: rustls::Error) -> Self {
        SError::RustlsError(err.to_string())
    }
}
