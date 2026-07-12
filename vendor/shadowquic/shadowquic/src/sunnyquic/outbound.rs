use async_trait::async_trait;
use std::{net::ToSocketAddrs, sync::Arc};
use tokio::sync::{OnceCell, SetOnce};

use super::EndClient;
use tracing::{error, info};

use crate::{
    Outbound,
    config::{AuthUser, SunnyQuicClientCfg},
    error::SError,
    msgs::squic::{SQExtError, UserStats},
    quic::{QuicClient, QuicConnection},
    squic::{auth_sunny, inbound::UserManager, outbound},
    sunnyquic::gen_sunny_user_hash,
    utils::socket_opt::{SocketFactory, UdpSocketFactory},
};

use crate::squic::{IDStore, SQConn, handle_udp_packet_recv};

pub type SunnyQuicConn = SQConn<<EndClient as QuicClient>::C>;

pub struct SunnyQuicClient {
    pub quic_conn: Option<SunnyQuicConn>,
    pub config: SunnyQuicClientCfg,
    pub quic_end: OnceCell<EndClient>,
    pub socket_factory: Arc<dyn SocketFactory>,
}
impl SunnyQuicClient {
    pub fn new(cfg: SunnyQuicClientCfg) -> Self {
        Self {
            quic_conn: None,
            quic_end: OnceCell::new(),
            socket_factory: Arc::new(UdpSocketFactory {
                addr: cfg.addr.clone(),
                interface: cfg.socket_opt.bind_interface.clone(),
                fw_mark: cfg.socket_opt.fw_mark,
                protect_path: cfg.protect_path.clone(),
                try_dual_stack: true,
            }),
            config: cfg,
        }
    }
    pub async fn init_endpoint(&self) -> Result<EndClient, SError> {
        EndClient::new(&self.config).await
    }

    pub async fn get_conn(&self) -> Result<SunnyQuicConn, SError> {
        let addr = self
            .config
            .addr
            .to_socket_addrs()
            .unwrap_or_else(|_| panic!("resolve quic addr faile: {}", self.config.addr))
            .next()
            .unwrap_or_else(|| panic!("resolve quic addr faile: {}", self.config.addr));
        let end = self
            .quic_end
            .get_or_init(|| async {
                self.init_endpoint()
                    .await
                    .expect("error during initialize quic endpoint")
            })
            .await;
        let conn = QuicClient::connect(end, addr, &self.config.server_name).await?;

        let conn = SQConn {
            conn,
            authed: Arc::new(SetOnce::new()),
            send_id_store: Default::default(),
            recv_id_store: IDStore {
                id_counter: Default::default(),
                inner: Default::default(),
            },
        };

        let username = self.config.username.clone();
        let password = self.config.password.clone();
        let conn_clone = conn.clone();
        tokio::spawn(async move {
            let _ = auth_sunny(
                &conn_clone,
                &username,
                gen_sunny_user_hash(&username, &password),
            )
            .await
            .map_err(|x| error!("authentication failed: {}", x));
            let _ = handle_udp_packet_recv(conn_clone)
                .await
                .map_err(|x| error!("handle udp packet recv error: {}", x));
        });
        Ok(conn)
    }
    async fn prepare_conn(&mut self) -> Result<(), SError> {
        // delete connection if closed.
        self.quic_conn.take_if(|x| {
            QuicConnection::close_reason(&x.conn).is_some_and(|x| {
                info!("quic connection closed due to {}", x);
                true
            })
        });
        // Creating new connectin
        if self.quic_conn.is_none() {
            self.quic_conn = Some(self.get_conn().await?);
        }
        Ok(())
    }
}

#[async_trait]
impl UserManager for SunnyQuicClient {
    async fn add_user(&self, user: AuthUser) -> Result<(), SQExtError> {
        let conn = self
            .get_conn()
            .await
            .map_err(|error| SQExtError::Other(error.to_string()))?;
        outbound::add_user(&conn, &user.username, &user.password)
            .await
            .map_err(|error| SQExtError::Other(error.to_string()))?
    }

    async fn remove_user(&self, username: &str) -> Result<(), SQExtError> {
        let conn = self
            .get_conn()
            .await
            .map_err(|error| SQExtError::Other(error.to_string()))?;
        outbound::remove_user(&conn, username)
            .await
            .map_err(|error| SQExtError::Other(error.to_string()))?
    }

    async fn list_users(&self) -> Result<Vec<String>, SQExtError> {
        let conn = self
            .get_conn()
            .await
            .map_err(|error| SQExtError::Other(error.to_string()))?;
        outbound::list_users(&conn)
            .await
            .map_err(|error| SQExtError::Other(error.to_string()))?
    }

    async fn get_user_stats(&self, username: &str) -> Result<UserStats, SQExtError> {
        let conn = self
            .get_conn()
            .await
            .map_err(|error| SQExtError::Other(error.to_string()))?;
        outbound::get_user_stats(&conn, username)
            .await
            .map_err(|error| SQExtError::Other(error.to_string()))?
    }

    async fn get_all_stats(&self) -> Result<Vec<UserStats>, SQExtError> {
        let conn = self
            .get_conn()
            .await
            .map_err(|error| SQExtError::Other(error.to_string()))?;
        outbound::get_all_stats(&conn)
            .await
            .map_err(|error| SQExtError::Other(error.to_string()))?
    }

    async fn kill_user_conns(&self, username: &str) -> Result<(), SQExtError> {
        let conn = self
            .get_conn()
            .await
            .map_err(|error| SQExtError::Other(error.to_string()))?;
        outbound::kill_user_conns(&conn, username)
            .await
            .map_err(|error| SQExtError::Other(error.to_string()))?
    }
}

#[async_trait]
impl Outbound for SunnyQuicClient {
    async fn handle(&mut self, req: crate::ProxyRequest) -> Result<(), crate::error::SError> {
        self.prepare_conn().await?;

        let conn = self.quic_conn.as_mut().unwrap().clone();

        let over_stream = self.config.over_stream;
        outbound::handle_request(req, conn, over_stream).await?;
        Ok(())
    }
}
