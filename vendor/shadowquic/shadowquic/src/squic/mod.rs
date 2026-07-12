//! This module is shared by sunnyquic and shadowquic
//! It handles the general tcp/udp proxying logic over quic connection
//! It contains an optional authentication feature for sunnyquic only

use std::{
    collections::{
        HashMap,
        hash_map::{self, Entry},
    },
    io::Cursor,
    mem::replace,
    ops::Deref,
    sync::{Arc, atomic::AtomicU16},
    time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{
        RwLock, SetOnce,
        watch::{Receiver, Sender, channel},
    },
};
use tracing::{Instrument, Level, debug, error, event, info, trace};

use crate::{
    AnyUdpRecv, AnyUdpSend, UdpSend,
    error::{SError, SResult},
    msgs::{
        SDecode, SEncode,
        socks5::SocksAddr,
        squic::{SQPacketDatagramHeader, SQReq, SQUdpControlHeader, SunnyCredential},
    },
    quic::QuicConnection,
};

pub mod inbound;
pub mod outbound;

/// SQuic connection, it is shared by shadowquic and sunnyquic and is a wrapper of quic connection.
/// It contains a connection object and two ID store for managing UDP sockets.
/// The IDStore stores the mapping between ids and the destionation addresses as well as associated sockets
#[derive(Clone)]
pub struct SQConn<T: QuicConnection> {
    pub(crate) conn: T,
    pub authed: Arc<SetOnce<SResult<String>>>,
    pub(crate) send_id_store: IDStore<()>,
    pub(crate) recv_id_store: IDStore<(AnyUdpSend, SocksAddr)>,
}

async fn wait_sunny_auth<T: QuicConnection>(conn: &SQConn<T>) -> SResult<String> {
    match tokio::time::timeout(Duration::from_millis(3200), conn.authed.wait()).await {
        Ok(Ok(name)) => Ok(name.clone()),
        Ok(Err(SError::SunnyAuthError(_))) => {
            Err(SError::SunnyAuthError("Wrong password/username".into()))
        }
        Err(_) => Err(SError::SunnyAuthError("timeout".into())),
        _ => unreachable!(),
    }
}

pub(crate) async fn auth_sunny<T: QuicConnection>(
    conn: &SQConn<T>,
    username: &str,
    user_hash: SunnyCredential,
) -> SResult<()> {
    if conn.authed.get().is_none() {
        let (mut send, _recv, _id) = conn.open_bi().await?;
        SQReq::SQAuthenticate(user_hash).encode(&mut send).await?;
        debug!("authentication request sent");
        conn.authed
            .set(Ok(username.to_string()))
            .expect("repeated authentication");
    }
    Ok(())
}

impl<T: QuicConnection> Deref for SQConn<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

pub(crate) struct NotifyBuffer {
    pub(crate) notify: Sender<()>,
    pub(crate) buffer: Vec<Bytes>,
}

// Use watch channel here. Notify is not suitable here
// see https://github.com/tokio-rs/tokio/issues/3757
type IDStoreVal<T> = Result<T, NotifyBuffer>;
/// IDStore is a thread-safe store for managing UDP sockets and their associated ids.
/// It uses a HashMap to store the mapping between ids and the destination addresses as well as associated sockets.
/// It also uses an atomic counter to generate unique ids for new sockets.
#[derive(Clone, Default)]
pub(crate) struct IDStore<T = (AnyUdpSend, SocksAddr)> {
    pub(crate) id_counter: Arc<AtomicU16>,
    pub(crate) inner: Arc<RwLock<HashMap<u16, IDStoreVal<T>>>>,
}

impl<T> IDStore<T>
where
    T: Clone,
{
    async fn get_socket_or_notify(&self, id: u16) -> Result<T, Receiver<()>> {
        if let Some(r) = self.inner.read().await.get(&id) {
            r.as_ref().map_err(|x| x.notify.subscribe()).cloned()
        } else {
            // Need to recheck
            // During change from read lock to write lock, hashmap may be modified
            match self.inner.write().await.entry(id) {
                Entry::Occupied(occupied_entry) => occupied_entry
                    .get()
                    .as_ref()
                    .map_err(|x| x.notify.subscribe())
                    .cloned(),
                Entry::Vacant(vacant_entry) => {
                    let (s, r) = channel(());
                    vacant_entry.insert(Err(NotifyBuffer {
                        notify: s,
                        buffer: Vec::new(),
                    }));
                    Err(r)
                }
            }
        }
    }
    async fn try_get_socket(&self, id: u16) -> Option<T> {
        if let Some(r) = self.inner.read().await.get(&id) {
            match r {
                Ok(s) => Some(s.clone()),
                Err(_) => None,
            }
        } else {
            None
        }
    }
    async fn get_socket_or_wait(&self, id: u16) -> Result<T, SError> {
        match self.get_socket_or_notify(id).await {
            Ok(r) => Ok(r),
            Err(mut n) => {
                // This may fail is UDP session is closed right at this moment.
                n.changed()
                    .await
                    .map_err(|_| SError::UDPSessionClosed("notify sender dropped".to_string()))?;
                //
                let ret = self
                    .try_get_socket(id)
                    .await
                    .ok_or(SError::UDPSessionClosed("UDP session closed".to_string()))?;
                Ok(ret)
            }
        }
    }
    #[allow(dead_code)]
    async fn store_socket(&self, id: u16, val: T) -> Option<Vec<Bytes>> {
        let mut h = self.inner.write().await;
        trace!("receiving side alive socket number: {}", h.len());
        let r = h.get_mut(&id);
        if let Some(s) = r {
            match s {
                Ok(_) => {
                    error!("id:{} already exists", id);
                }
                Err(_) => {
                    let notify = replace(s, Ok(val));
                    //let _ = notify.map_err(|x| x.notify_one());
                    match notify {
                        Ok(_) => {
                            panic!("should be notify"); // should never happen
                        }
                        Err(n) => {
                            n.notify.send(()).unwrap_or_else(|_| {
                                debug!("id:{} notifier without subscriber", id)
                            });
                            event!(Level::TRACE, "notify socket id:{}", id);
                            return Some(n.buffer);
                        }
                    }
                }
            }
        } else {
            h.insert(id, Ok(val));
        }
        None
    }
    async fn fetch_new_id(&self, val: T) -> u16 {
        let mut inner = self.inner.write().await;
        trace!("sending side socket number: {}", inner.len());
        let mut r;
        loop {
            r = self
                .id_counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst); // Wrapping occured if overflow
            if let Entry::Vacant(e) = inner.entry(r) {
                e.insert(Ok(val));
                break;
            }
        }
        r
    }
}

impl IDStore {
    async fn feed_datagram(&self, id: u16, packet: Bytes) -> SResult<()> {
        if let Some(Ok((socket, addr))) = self.inner.read().await.get(&id) {
            socket.send_to(packet, addr.clone()).await?;
            Ok(())
        } else {
            // Need to recheck
            // During change from read lock to write lock, hashmap may be modified
            match self.inner.write().await.entry(id) {
                Entry::Occupied(mut entry) => match entry.get_mut() {
                    Ok((socket, addr)) => {
                        socket.send_to(packet, addr.clone()).await?;
                        Ok(())
                    }
                    Err(notify) => {
                        notify.buffer.push(packet);
                        Ok(())
                    }
                },
                Entry::Vacant(vacant_entry) => {
                    let (s, _r) = channel(());
                    vacant_entry.insert(Err(NotifyBuffer {
                        notify: s,
                        buffer: vec![packet],
                    }));
                    Ok(())
                }
            }
        }
    }
    async fn store_socket_with_prelude(
        &self,
        id: u16,
        val: (Arc<dyn UdpSend>, SocksAddr),
    ) -> SResult<()> {
        let mut h = self.inner.write().await;
        trace!("receiving side alive socket number: {}", h.len());
        let r = h.get_mut(&id);
        if let Some(s) = r {
            match s {
                Ok(_) => {
                    error!("id:{} already exists", id);
                }
                Err(_) => {
                    let (socket, addr) = val.clone();
                    let notify = replace(s, Ok(val));
                    //let _ = notify.map_err(|x| x.notify_one());
                    match notify {
                        Ok(_) => {
                            panic!("should be notify"); // should never happen
                        }
                        Err(n) => {
                            for bytes in n.buffer {
                                socket.send_to(bytes, addr.clone()).await?;
                            }

                            n.notify.send(()).unwrap_or_else(|_| {
                                debug!("id:{} notifier without subscriber", id)
                            });
                            event!(Level::TRACE, "notify socket id:{}", id);
                        }
                    }
                }
            }
        } else {
            h.insert(id, Ok(val));
        }
        Ok(())
    }
}

/// AssociateSendSession is a session for sending UDP packets.
/// It is created for each association task
/// The local dst_map works as a inverse map from destination to id
/// When session ended, the ids created by this session will be removed from the IDStore.
struct AssociateSendSession<W: AsyncWrite> {
    id_store: IDStore<()>,
    dst_map: HashMap<SocksAddr, u16>,
    unistream_map: HashMap<SocksAddr, W>,
}
impl<W: AsyncWrite> AssociateSendSession<W> {
    pub async fn get_id_or_insert(&mut self, addr: &SocksAddr) -> (u16, bool) {
        if let Some(id) = self.dst_map.get(addr) {
            (*id, false)
        } else {
            let id = self.id_store.fetch_new_id(()).await;
            self.dst_map.insert(addr.clone(), id);
            debug!(context_id = id, dst = %addr, "send session insert");
            (id, true)
        }
    }
}

impl<W: AsyncWrite> Drop for AssociateSendSession<W> {
    fn drop(&mut self) {
        let id_store = self.id_store.inner.clone();
        let id_remove = self.dst_map.clone();
        tokio::spawn(
            async move {
                let mut id_store = id_store.write().await;
                let len = id_store.len();
                id_remove.values().for_each(|k| {
                    id_store.remove(k);
                });
                let decrease = len - id_store.len();
                event!(
                    Level::TRACE,
                    "AssociateSendSession dropped, session id size:{}, {} ids cleaned",
                    id_remove.len(),
                    decrease
                );
            }
            .in_current_span(),
        );
    }
}
/// AssociateRecvSession is a session for receiving UDP ctrl stream.
/// It is created for each association task
/// There are two usages for id_map
/// First, it works as local cache avoiding using global store repeatedly which is more expensive
/// Second. it records ids created by this session and clean those ids when session ended.
struct AssociateRecvSession {
    id_store: IDStore<(AnyUdpSend, SocksAddr)>,
    id_map: HashMap<u16, SocksAddr>,
}
impl AssociateRecvSession {
    pub async fn store_socket(
        &mut self,
        id: u16,
        dst: SocksAddr,
        socks: AnyUdpSend,
    ) -> SResult<()> {
        if let hash_map::Entry::Vacant(e) = self.id_map.entry(id) {
            self.id_store
                .store_socket_with_prelude(id, (socks, dst.clone()))
                .await?;
            debug!(context_id = id, dst = %dst, "recv session insert");
            e.insert(dst);
        }
        Ok(())
    }
}

impl Drop for AssociateRecvSession {
    fn drop(&mut self) {
        let id_store = self.id_store.inner.clone();
        let id_remove = self.id_map.clone();
        tokio::spawn(
            async move {
                let mut id_store = id_store.write().await;
                let len = id_store.len();

                id_remove.keys().for_each(|k| {
                    id_store.remove(k);
                });
                let decrease = len - id_store.len();
                event!(
                    Level::TRACE,
                    "AssociateRecvSession dropped, session id size:{}, {} ids cleaned",
                    id_remove.len(),
                    decrease
                );
            }
            .in_current_span(),
        );
    }
}

/// Handle udp packets send
/// It watches the udp socket and sends the packets to the quic connection.
/// This function is symetrical for both clients and servers.
pub async fn handle_udp_send<C: QuicConnection>(
    mut send: C::SendStream,
    udp_recv: AnyUdpRecv,
    conn: SQConn<C>,
    over_stream: bool,
) -> Result<(), SError> {
    let mut down_stream = udp_recv;
    let mut session = AssociateSendSession {
        id_store: conn.send_id_store.clone(),
        dst_map: Default::default(),
        unistream_map: Default::default(),
    };
    let quic_conn = conn.conn.clone();
    loop {
        let (bytes, dst) = down_stream.recv_from().await?;
        let (id, is_new) = session.get_id_or_insert(&dst).await;
        //let span = trace_span!("udp", id = id);
        let ctl_header = SQUdpControlHeader {
            dst: dst.clone(),
            id,
        };
        let dg_header = SQPacketDatagramHeader { id };
        if over_stream && !session.unistream_map.contains_key(&dst) {
            let (uni, _id) = conn.open_uni().await?;
            session.unistream_map.insert(dst.clone(), uni);
        }

        let fut1 = async {
            if is_new {
                ctl_header.encode(&mut send).await?;
            }
            //trace!("udp control header sent");
            Ok(()) as Result<(), SError>
        };
        let fut2 = async {
            let mut content = BytesMut::with_capacity(2000);
            let mut head = Vec::<u8>::new();
            dg_header.clone().encode(&mut head).await?;

            if over_stream {
                // Must be opened and inserted.
                let conn = session.unistream_map.get_mut(&dst).unwrap();
                let mut head = Vec::<u8>::new();
                if is_new {
                    dg_header.encode(&mut head).await?
                }
                (bytes.len() as u16).encode(&mut head).await?;
                conn.write_all(&head).await?;
                conn.write_all(&bytes).await?;
            } else {
                content.put(Bytes::from(head));
                content.put(bytes);
                let content = content.freeze();
                quic_conn.send_datagram(content).await?;
            }
            Ok(())
        };
        tokio::try_join!(fut1, fut2)?;
    }
    #[allow(unreachable_code)]
    Ok(())
}

/// Handle udp ctrl stream receive task
/// it retrieves the dst id pair from the bistream and records related socket and address
/// This function is symetrical for both clients and servers.
pub async fn handle_udp_recv_ctrl<C: QuicConnection>(
    mut recv: C::RecvStream,
    udp_socket: AnyUdpSend,
    conn: SQConn<C>,
) -> Result<(), SError> {
    let mut session = AssociateRecvSession {
        id_store: conn.recv_id_store.clone(),
        id_map: Default::default(),
    };
    loop {
        let SQUdpControlHeader { id, dst } = SQUdpControlHeader::decode(&mut recv).await?;
        info!(context_id = id, dst = %dst, "udp control header received");
        let _ = session
            .store_socket(id, dst, udp_socket.clone())
            .await
            .map_err(|e| error!("failed to writing data to udp socket:{e}"));
    }
    #[allow(unreachable_code)]
    Ok(())
}

/// Handle udp packet receive task
/// It watches udp packets from quic connection and sends them to the udp socket.
/// The udp socket could be downstream(inbound) or upstream(outbound)
/// This function is symetrical for both clients and servers.
pub async fn handle_udp_packet_recv<C: QuicConnection>(conn: SQConn<C>) -> Result<(), SError> {
    let id_store = conn.recv_id_store.clone();
    wait_sunny_auth(&conn).await?;
    loop {
        tokio::select! {
            b = conn.read_datagram() => {
                let b = b?;
                let b = BytesMut::from(b);
                let mut cur = Cursor::new(b);
                let SQPacketDatagramHeader{id} = SQPacketDatagramHeader::decode(&mut cur).await?;
                let pos = cur.position() as usize;
                id_store.feed_datagram(id, cur.into_inner().split_off(pos).freeze()).await?;
            }

            r = async {
                let (mut uni_stream, _id) = conn.accept_uni().await?;
                trace!("unistream accepted");
                let SQPacketDatagramHeader{id} = SQPacketDatagramHeader::decode(&mut uni_stream).await?;
                trace!(context_id = id, "resolving datagram id");

                let (udp,addr) = id_store.get_socket_or_wait(id).await?;

                info!(context_id = id, peer_addr = %conn.remote_address(), dst = %addr, "udp over stream");
                Ok((uni_stream,udp.clone(),addr.clone())) as Result<(C::RecvStream,AnyUdpSend,SocksAddr),SError>
            } => {

                let  (mut uni_stream,udp,addr) = match r {
                    Ok(r) => r,
                    Err(SError::UDPSessionClosed(_)) => {
                        continue;
                    }
                    Err(e) => {
                        return Err(e);
                    }
                };

                tokio::spawn(async move {
                    loop {
                        let l: usize = u16::decode(&mut uni_stream).await? as usize;
                        let mut b = BytesMut::with_capacity(l);
                        b.resize(l,0);
                        uni_stream.read_exact(&mut b).await?;
                        udp.send_to(b.freeze(), addr.clone()).await?;
                    }
                    #[allow(unreachable_code)]
                    (Ok(()) as Result<(), SError>)
                }.in_current_span());
            }
        }
    }
    #[allow(unreachable_code)]
    Ok(())
}
