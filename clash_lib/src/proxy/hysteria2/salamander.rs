use std::{
    io::IoSliceMut,
    ops::DerefMut,
    task::{Context, Poll},
};

use blake2::{Blake2b, Digest};
use bytes::{BufMut, Bytes, BytesMut};
use digest::consts::U32;
use futures::ready;
use quinn::{
    udp::{RecvMeta, Transmit, UdpState},
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
    /// new() should init a blake2b256 hasher with key to reduce calculation, but rust-analyzer can't recognize its type
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

        // tracing::info!("content {:?}", data);
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
        // data.advance(8);  // sadlly IoSliceMut::advance is unstable
    }
}

pub struct Salamander {
    inner: Box<dyn AsyncUdpSocket>,
    obfs: SalamanderObfs,
}

impl Salamander {
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
    fn poll_send(
        &self,
        state: &UdpState,
        cx: &mut Context,
        transmits: &[Transmit],
    ) -> Poll<std::io::Result<usize>> {
        let mut v = transmits.iter().cloned().collect::<Vec<_>>();

        v.iter_mut().for_each(|v| {
            v.contents = self.obfs.encrpyt(&mut v.contents.to_vec());
        });
        self.inner.poll_send(state, cx, &v)
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
                // first 8 bytes will be dropped?, i test it in test_skip, loop 1000000 times
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
fn test_skip() {
    for _ in 0..10 {
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

    println!("done");
    // std::thread::sleep(std::time::Duration::from_secs(100000));
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
