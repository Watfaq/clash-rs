use crate::app::dispatcher::Dispatcher;
use crate::session::{DatagramSource, Network, Session, SocksAddr};
use futures::future::{abortable, BoxFuture};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::sync::{mpsc, oneshot, Mutex, MutexGuard};
use tokio::time::Instant;

pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocksAddr,
    pub dst_addr: SocksAddr,
}

impl UdpPacket {
    pub fn new(data: Vec<u8>, src_addr: SocksAddr, dst_addr: SocksAddr) -> Self {
        Self {
            data,
            src_addr,
            dst_addr,
        }
    }
}

type SessionMap = HashMap<DatagramSource, (Sender<UdpPacket>, oneshot::Sender<bool>, Instant)>;

pub struct NatManager {
    sessions: Arc<Mutex<SessionMap>>,
    dispatcher: Arc<Dispatcher>,
    timeout_check_task: Mutex<Option<BoxFuture<'static, ()>>>,
}

const UDP_SESSION_TIMEOUT: u64 = 30;
const UDP_SESSION_CHECK_INTERVAL: u64 = 10;

impl NatManager {
    pub fn new(dispatcher: Arc<Dispatcher>) -> Self {
        let sessions: Arc<Mutex<SessionMap>> = Arc::new(Mutex::new(HashMap::new()));

        let inner_session = sessions.clone();

        let timeout_check_task: BoxFuture<'static, ()> = Box::pin(async move {
            let mut sessions = inner_session.lock().await;
            let now = Instant::now();
            let mut to_remove = vec![];
            for (k, val) in sessions.iter() {
                if now.duration_since(val.2).as_secs() >= UDP_SESSION_TIMEOUT {
                    to_remove.push(k.to_owned());
                }
            }
            for k in to_remove.iter() {
                if let Some(sess) = sessions.remove(k) {
                    let _ = sess.1.send(true);
                }
            }
            tokio::time::sleep(Duration::from_secs(UDP_SESSION_CHECK_INTERVAL)).await;
        });

        NatManager {
            sessions,
            dispatcher,
            timeout_check_task: Mutex::new(Some(timeout_check_task)),
        }
    }

    pub async fn send<'a>(
        &self,
        sess: Option<&Session>,
        dgram_src: &DatagramSource,
        client_ch_tx: &Sender<UdpPacket>,
        packet: UdpPacket,
    ) {
        let mut guard = self.sessions.lock().await;
        if guard.contains_key(dgram_src) {
            self._send(dgram_src, packet).await;
            return;
        }

        let sess = sess.cloned().unwrap_or(Session {
            network: Network::UDP,
            source: dgram_src.address,
            destination: packet.dst_addr.clone(),
            ..Default::default()
        });

        self.add_session(sess, dgram_src.clone(), client_ch_tx.clone(), &mut guard)
            .await;

        self._send(dgram_src, packet).await;
    }

    pub async fn add_session<'a>(
        &self,
        sess: Session,
        raddr: DatagramSource,
        client_ch_tx: Sender<UdpPacket>,
        guard: &mut MutexGuard<'a, SessionMap>,
    ) {
        todo!()
    }
    async fn _send<'a>(&self, key: &DatagramSource, pkt: UdpPacket) {
        if let Some(sess) = self.sessions.lock().await.get_mut(key) {
            if let Err(_e) = sess.0.try_send(pkt) {}
            sess.2 = Instant::now();
        }
    }
}
