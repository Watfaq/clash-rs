use std::pin::Pin;

use aes_gcm::Aes128Gcm;
use bytes::{BufMut, Bytes, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use futures::{pin_mut, ready, Future};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use super::MAX_CHUNK_SIZE;

use crate::common::crypto::AeadCipherHelper;

use super::CHUNK_SIZE;

pub enum VmessSecurity {
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl VmessSecurity {
    #[inline(always)]
    pub fn overhead_len(&self) -> usize {
        16
    }
    #[inline(always)]
    pub fn nonce_len(&self) -> usize {
        12
    }
}

pub(crate) struct AeadReader {
    buf: BytesMut,
    pos: usize,
    security: VmessSecurity,
    nonce: [u8; 32],
    iv: Bytes,
    count: u16,
    size_holder: [u8; 2],
}

impl AeadReader {
    pub fn new(iv: &[u8], security: VmessSecurity) -> Self {
        Self {
            buf: BytesMut::new(),
            pos: 0,
            security,
            nonce: [0u8; 32],
            iv: Bytes::copy_from_slice(iv),
            count: 0,
            size_holder: [0; 2],
        }
    }

    pub fn poll_read<R>(
        self: std::pin::Pin<&mut Self>,
        inner: &mut R,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        let Self {
            buf: inner_buf,
            pos,
            size_holder,
            count,
            nonce,
            iv,
            security,
            ..
        } = self.get_mut();

        if !inner_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), inner_buf.len() - *pos);
            buf.put_slice(&inner_buf[*pos..*pos + n]);
            *pos += n;

            if *pos == inner_buf.len() {
                inner_buf.clear();
                *pos = 0;
            }

            return std::task::Poll::Ready(Ok(()));
        } else {
            assert!(*pos == 0, "chunk reader bad state");

            let fut = inner.read_exact(&mut size_holder[..]);
            pin_mut!(fut);
            ready!(fut.poll(cx))?;

            let size = u16::from_be_bytes(*size_holder) as usize;
            if size > MAX_CHUNK_SIZE {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "chunk size too large. max: {}, got: {}",
                        MAX_CHUNK_SIZE, size
                    ),
                )));
            }

            inner_buf.resize(size, 0);
            let fut = inner.read_exact(&mut inner_buf[..]);
            pin_mut!(fut);
            ready!(fut.poll(cx))?;

            nonce[..2].copy_from_slice(&count.to_be_bytes());
            nonce[2..12].copy_from_slice(&iv[2..12]);
            *count += 1;

            let nonce = &nonce[..security.nonce_len()];
            match security {
                VmessSecurity::Aes128Gcm(cipher) => {
                    let dec =
                        cipher.decrypt_in_place_with_slice(nonce.into(), &[], &mut inner_buf[..]);
                    if dec.is_err() {
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            dec.unwrap_err().to_string(),
                        )));
                    }
                }
                VmessSecurity::ChaCha20Poly1305(cipher) => {
                    let dec =
                        cipher.decrypt_in_place_with_slice(nonce.into(), &[], &mut inner_buf[..]);
                    if dec.is_err() {
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            dec.unwrap_err().to_string(),
                        )));
                    }
                }
            }

            let real_len = size - security.overhead_len();
            inner_buf.truncate(real_len);

            let n: usize = std::cmp::min(buf.remaining(), inner_buf.len());
            buf.put_slice(&inner_buf[..n]);
            *pos += n;

            if *pos == inner_buf.len() {
                inner_buf.clear();
                *pos = 0;
            }

            return std::task::Poll::Ready(Ok(()));
        }
    }
}

pub(crate) struct AeadWriter {
    buf: BytesMut,
    security: VmessSecurity,
    nonce: [u8; 32],
    iv: Bytes,
    count: u16,
}

impl AeadWriter {
    pub fn new(iv: &[u8], security: VmessSecurity) -> Self {
        Self {
            buf: BytesMut::new(),
            security,
            nonce: [0u8; 32],
            iv: Bytes::copy_from_slice(iv),
            count: 0,
        }
    }

    pub fn poll_write<W>(
        self: Pin<&mut Self>,
        inner: &mut W,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>>
    where
        W: AsyncWrite + Unpin,
    {
        let mut remaining = buf.len();
        let mut sent = 0;

        let Self {
            buf: inner_buf,
            security,
            nonce,
            count,
            iv,
            ..
        } = self.get_mut();

        let mut pin = Pin::new(inner);

        while remaining > 0 {
            let payload_size = std::cmp::min(remaining, CHUNK_SIZE - security.overhead_len());

            inner_buf.reserve(2 + payload_size + security.overhead_len());
            inner_buf.put_u16((payload_size + security.overhead_len()) as u16);
            inner_buf.put_slice(&buf[sent..sent + payload_size]);
            inner_buf.extend_from_slice(vec![0u8; security.overhead_len()].as_ref());

            nonce[..2].copy_from_slice(&count.to_be_bytes());
            nonce[2..12].copy_from_slice(&iv[2..12]);

            *count += 1;

            let nonce_len = security.nonce_len();
            match security {
                VmessSecurity::Aes128Gcm(cipher) => {
                    cipher.encrypt_in_place_with_slice(
                        nonce[..nonce_len].into(),
                        &[],
                        &mut inner_buf[2..],
                    );
                }
                VmessSecurity::ChaCha20Poly1305(cipher) => {
                    cipher.encrypt_in_place_with_slice(
                        nonce[..nonce_len].into(),
                        &[],
                        &mut inner_buf[2..],
                    );
                }
            }

            ready!(pin
                .as_mut()
                .poll_write(cx, &inner_buf[..2 + payload_size + security.overhead_len()]))?;
            inner_buf.clear();

            sent += payload_size;
            remaining -= payload_size;
        }

        std::task::Poll::Ready(Ok(buf.len()))
    }
}
