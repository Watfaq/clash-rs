use std::{
    io::IoSliceMut,
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

    fn encrpy(&self, data: &mut [u8]) -> Bytes {
        let salt: [u8; 8] = rand::thread_rng().gen();

        tracing::info!("content {:?}", data);
        let mut res = BytesMut::with_capacity(8 + data.len());
        res.put_slice(&salt);
        self.obfs(&salt, data);
        res.put_slice(data);

        res.freeze()
    }

    fn decrpy(&self, data: &mut IoSliceMut<'_>) {
        assert!(data.len() > 8, "data len must > 8");

        let (salt, data) = data.split_at_mut(8);
        self.obfs(salt, data);
        // data.advance(8);  // sadlly IoSliceMut::advance is unstable
    }
}

#[test]
fn test_v2_encryp() {
    let key = b"123456";
    let mut data = b"12345678AA".to_vec();

    let obfs = SalamanderObfs::new(key.to_vec());
    let mut data = IoSliceMut::new(&mut data);
    obfs.decrpy(&mut data);
    println!("{:?}", data);
}

pub struct Salamander {
    inner: Box<dyn AsyncUdpSocket>,
    obfs: SalamanderObfs,
}

impl Salamander {
    pub fn new(socket: std::net::UdpSocket, key: Vec<u8>) -> std::io::Result<Self> {
        use quinn::Runtime;
        let inner = TokioRuntime.wrap_udp_socket(socket)?;
        let obfs = SalamanderObfs::new(key);

        std::io::Result::Ok(Self { inner, obfs })
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
            v.contents = self.obfs.encrpy(&mut v.contents.to_vec());
        });

        self.inner.poll_send(state, cx, &v)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let r = ready!(self.inner.poll_recv(cx, bufs, meta))?;
        tracing::warn!("recv {} bytes", r);

        bufs.iter_mut()
            .filter(|x| x.len() > 8)
            .take(r)
            .for_each(|v| {
                let ori = v.to_vec();
                self.obfs.decrpy(v);
                let data: &mut [u8] = v.as_mut();
                let data = &mut data[8..];
                unsafe {
                    //  because IoSliceMut is transparent and .0 is also transparent, so it is a &[u8]
                    let b: IoSliceMut<'_> = std::mem::transmute(data);
                    *v = b;
                }
                // tracing::warn!("recv ori {:?} ->  {:?}", &ori[..20], &v[..20]);
            });

        Poll::Ready(Ok(r))
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
            obfs.decrpy(v);
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

    // println!("{:?}", bufs[0]);
    std::thread::sleep(std::time::Duration::from_secs(100000));
}

#[test]
fn test_obfs() {
    let obfs = SalamanderObfs::new(b"obfs".to_vec());
    let mut data = b"hhh".to_vec();
    let x = obfs.encrpy(&mut data);
    let mut x = x.to_vec();

    let res = &mut IoSliceMut::new(&mut x);
    obfs.decrpy(res);

    println!("{:?}", std::str::from_utf8(res[8..].as_ref()).unwrap());
}
