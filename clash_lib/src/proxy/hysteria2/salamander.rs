use std::{
    io::IoSliceMut,
    ops::DerefMut,
    sync::Arc,
    task::{Context, Poll},
};

use blake2::{Blake2b, Digest};
use bytes::{BufMut, Bytes, BytesMut};
use digest::consts::U32;
use futures::ready;
use quinn::{
    udp::{RecvMeta, Transmit},
    AsyncUdpSocket, TokioRuntime,
};
use rand::Rng;

type Blake2b256 = Blake2b<U32>;

struct SalamanderObfs {
    key: Vec<u8>,
}

impl SalamanderObfs {
    /// create a new obfs
    ///
    /// new() should init a blake2b256 hasher with key to reduce calculation,
    /// but rust-analyzer can't recognize its type
    #[allow(dead_code)]
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    pub fn obfs(&self, sale: &[u8], data: &mut [u8]) {
        let mut hasher = Blake2b256::new();
        hasher.update(&self.key);
        hasher.update(sale);
        let res: [u8; 32] = hasher.finalize().into();

        data.iter_mut().enumerate().for_each(|(i, v)| {
            *v ^= res[i % 32];
        });
    }

    fn encrpyt(&self, data: &mut [u8]) -> Bytes {
        let salt: [u8; 8] = rand::thread_rng().gen();

        let mut res = BytesMut::with_capacity(8 + data.len());
        res.put_slice(&salt);
        self.obfs(&salt, data);
        res.put_slice(data);

        res.freeze()
    }

    fn decrpyt(&self, data: &mut [u8]) {
        assert!(data.len() > 8, "data len must > 8");

        let (salt, data) = data.split_at_mut(8);
        self.obfs(salt, data);
        // data.advance(8); // sadlly IoSliceMut::advance is unstable
    }
}

pub struct Salamander {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: SalamanderObfs,
}

impl Salamander {
    #[allow(dead_code)]
    pub fn new(socket: std::net::UdpSocket, key: Vec<u8>) -> std::io::Result<Self> {
        use quinn::Runtime;
        let inner = TokioRuntime.wrap_udp_socket(socket)?;

        std::io::Result::Ok(Self {
            inner,
            obfs: SalamanderObfs::new(key),
        })
    }
}

impl std::fmt::Debug for Salamander {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl AsyncUdpSocket for Salamander {
    fn create_io_poller(
        self: std::sync::Arc<Self>,
    ) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        let mut v = transmit.to_owned();
        // TODO: encrypt in place
        let x = self.obfs.encrpyt(&mut v.contents.to_vec());
        v.contents = &x;
        self.inner.try_send(&v)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        // the number of udp packets received
        let packet_nums = ready!(self.inner.poll_recv(cx, bufs, meta))?;
        meta.iter().take(packet_nums).for_each(|v| {
            tracing::trace!("meta addr {:?}, dst_ip: {:?}", v.addr, v.dst_ip);
        });
        bufs.iter_mut()
            .zip(meta.iter_mut())
            // first step take and then filter
            .take(packet_nums)
            .filter(|(_, meta)| meta.len > 8)
            .for_each(|(v, meta)| {
                let x = &mut v.deref_mut()[..meta.len];
                // decrypt in place, and drop first 8 bytes
                self.obfs.decrpyt(x);
                let data = &mut x[8..];
                unsafe {
                    //  because IoSliceMut is transparent and .0 is also transparent, so it is a &[u8]
                    let b: IoSliceMut<'_> = std::mem::transmute(data);
                    *v = b;
                }
                // MUST update meta.len
                meta.len -= 8;
            });

        Poll::Ready(Ok(packet_nums))
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[test]
#[ignore = "crash on Windows"]
fn test_skip() {
    let mut data = b"12345678AA".to_vec();

    let obfs = SalamanderObfs::new(b"123456".to_vec());

    let bufs = &mut [IoSliceMut::new(&mut data)];
    bufs.iter_mut().filter(|x| x.len() > 8).for_each(|v| {
        obfs.decrpyt(v);
        let data: &mut [u8] = v.as_mut();
        let data = &mut data[8..];
        unsafe {
            let b: IoSliceMut<'_> = std::mem::transmute(data);
            *v = b;
        }
        println!("{:?}", v);
    });
}

#[test]
fn test_obfs() {
    let obfs = SalamanderObfs::new(b"obfs".to_vec());
    let mut data = b"hhh".to_vec();
    let x = obfs.encrpyt(&mut data);
    let mut x = x.to_vec();

    let res = &mut IoSliceMut::new(&mut x);
    obfs.decrpyt(res);

    assert!(std::str::from_utf8(res[8..].as_ref()).unwrap() == "hhh");
}
