use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use tokio::sync::{
    RwLock, SetOnce,
    mpsc::{Receiver, Sender, channel},
};
use tracing::{Instrument, error, info_span};

use crate::{
    Inbound, ProxyRequest,
    config::{AuthUser, SunnyQuicServerCfg},
    error::SError,
    msgs::squic::{SQExtError, SunnyCredential, UserStats},
    observe::Observer,
    quic::QuicConnection,
    squic::inbound::{SQServerConn, SunnyQuicUsers, UserManager},
    sunnyquic::EndServer,
};

use crate::squic::{IDStore, SQConn};

use crate::quic::QuicServer;
pub struct SunnyQuicServer {
    pub endpoint: EndServer,
    users: Arc<ArcSwap<HashMap<SunnyCredential, String>>>,
    user_manager: Option<Arc<SunnyQuicUserManager>>,
    request_sender: Sender<ProxyRequest>,
    request: Receiver<ProxyRequest>,
    observer: Arc<Observer>,
}

struct SunnyQuicUserManager {
    endpoint: EndServer,
    users: Arc<ArcSwap<HashMap<SunnyCredential, String>>>,
    config: RwLock<SunnyQuicServerCfg>,
    observer: Arc<Observer>,
}

#[async_trait]
impl UserManager for SunnyQuicUserManager {
    async fn add_user(&self, user: AuthUser) -> Result<(), SQExtError> {
        let mut config = self.config.write().await;
        let old_config = config.clone();
        if let Some(existing_user) = config
            .users
            .iter_mut()
            .find(|existing_user| existing_user.username == user.username)
        {
            existing_user.password = user.password;
        } else {
            config.users.push(user);
        }

        if let Err(error) = QuicServer::update_config(&self.endpoint, &config).await {
            *config = old_config;
            tracing::error!("failed to add sunnyquic user: {}", error);
            return Err(SQExtError::Other(error.to_string()));
        }
        self.users.store(SunnyQuicServer::gen_users_hash(&config));
        Ok(())
    }

    async fn remove_user(&self, username: &str) -> Result<(), SQExtError> {
        let mut config = self.config.write().await;
        let old_config = config.clone();
        let old_len = config.users.len();
        config.users.retain(|user| user.username != username);
        if config.users.len() == old_len {
            return Err(SQExtError::NotFound);
        }

        if let Err(error) = QuicServer::update_config(&self.endpoint, &config).await {
            *config = old_config;
            tracing::error!("failed to remove sunnyquic user: {}", error);
            return Err(SQExtError::Other(error.to_string()));
        }
        self.users.store(SunnyQuicServer::gen_users_hash(&config));
        self.observer.remove_user(username).await;
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<String>, SQExtError> {
        let config = self.config.read().await;
        Ok(config
            .users
            .iter()
            .map(|user| user.username.clone())
            .collect())
    }

    async fn get_user_stats(&self, username: &str) -> Result<UserStats, SQExtError> {
        let config = self.config.read().await;
        if !config.users.iter().any(|user| user.username == username) {
            return Err(SQExtError::NotFound);
        }
        drop(config);
        Ok(self.observer.get_user_stats(username).await)
    }

    async fn get_all_stats(&self) -> Result<Vec<UserStats>, SQExtError> {
        let config = self.config.read().await;
        let usernames = config
            .users
            .iter()
            .map(|user| user.username.clone())
            .collect::<Vec<_>>();
        drop(config);
        Ok(self.observer.get_all_stats(&usernames).await)
    }

    async fn kill_user_conns(&self, username: &str) -> Result<(), SQExtError> {
        let config = self.config.read().await;
        if !config.users.iter().any(|user| user.username == username) {
            return Err(SQExtError::NotFound);
        }
        drop(config);
        self.observer.close_conn(username).await;
        Ok(())
    }
}

impl SunnyQuicServer {
    pub async fn new(cfg: SunnyQuicServerCfg) -> Result<Self, SError> {
        Self::new_inner(cfg, true).await
    }

    pub async fn new_without_user_api(cfg: SunnyQuicServerCfg) -> Result<Self, SError> {
        Self::new_inner(cfg, false).await
    }

    async fn new_inner(
        cfg: SunnyQuicServerCfg,
        enable_user_api: bool,
    ) -> Result<Self, SError> {
        let (send, recv) = channel::<ProxyRequest>(10);
        let endpoint: EndServer = QuicServer::new(&cfg)
            .await
            .expect("Failed to listening on udp");
        let users = Arc::new(ArcSwap::new(Self::gen_users_hash(&cfg)));
        let observer = Arc::new(Observer::new());
        let user_manager = enable_user_api.then(|| {
            Arc::new(SunnyQuicUserManager {
                endpoint: endpoint.clone(),
                users: users.clone(),
                config: RwLock::new(cfg),
                observer: observer.clone(),
            })
        });

        Ok(Self {
            endpoint,
            users,
            user_manager,
            request_sender: send,
            request: recv,
            observer,
        })
    }

    pub async fn update_config(&self, cfg: &SunnyQuicServerCfg) -> Result<(), SError> {
        QuicServer::update_config(&self.endpoint, cfg).await?;
        self.users.store(Self::gen_users_hash(cfg));
        if let Some(user_manager) = &self.user_manager {
            *user_manager.config.write().await = cfg.clone();
        }
        Ok(())
    }

    async fn handle_incoming<C: QuicConnection>(
        incom: C,
        req_sender: Sender<ProxyRequest>,
        user_hash: SunnyQuicUsers,
        user_manager: Option<Arc<dyn UserManager>>,
    ) -> Result<(), SError> {
        let sq_conn = SQServerConn {
            inner: SQConn {
                conn: incom,
                authed: Arc::new(SetOnce::new()),
                send_id_store: Default::default(),
                recv_id_store: IDStore {
                    id_counter: Default::default(),
                    inner: Default::default(),
                },
            },
            users: user_hash,
            user_manager,
        };
        let span = info_span!("quic", id = sq_conn.inner.peer_id());
        let sq_conn = Arc::new(sq_conn);
        sq_conn
            .handle_connection(req_sender)
            .instrument(span)
            .await?;

        Ok(())
    }
    fn gen_users_hash(cfg: &SunnyQuicServerCfg) -> SunnyQuicUsers {
        let users = HashMap::from_iter(cfg.users.iter().map(|x| {
            let hash = crate::sunnyquic::gen_sunny_user_hash(&x.username, &x.password);
            (hash, x.username.clone())
        }));
        Arc::new(users)
    }
}

#[async_trait]
impl Inbound for SunnyQuicServer {
    async fn accept(&mut self) -> Result<crate::ProxyRequest, SError> {
        let req = self
            .request
            .recv()
            .await
            .ok_or(SError::InboundUnavailable)?;
        Ok(self.observer.wrap_request(req).await)
    }
    /// Init background job for accepting connection
    async fn init(&self) -> Result<(), SError> {
        let request_sender = self.request_sender.clone();
        let endpoint = self.endpoint.clone();
        let users = self.users.clone();
        let user_manager = self.user_manager.clone();
        let fut = async move {
            loop {
                match QuicServer::accept(&endpoint).await {
                    Ok(conn) => {
                        let request_sender = request_sender.clone();
                        let user_hash = users.load_full();
                        let user_manager = user_manager
                            .clone()
                            .map(|manager| manager as Arc<dyn UserManager>);
                        tokio::spawn(async move {
                            Self::handle_incoming(conn, request_sender, user_hash, user_manager)
                                .await
                                .map_err(|x| error!("{}", x))
                        });
                    }
                    Err(e) => {
                        error!("Error accepting quic connection: {}", e);
                    }
                }
            }
        };
        tokio::spawn(fut);
        Ok(())
    }
}
