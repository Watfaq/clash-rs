use std::pin::Pin;

use aes_gcm::Aes128Gcm;
use bytes::{BufMut, Bytes, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{common::crypto::AeadCipherHelper, proxy::vmess::MAX_CHUNK_SIZE};

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
    #[inline(always)]
    pub fn tag_len(&self) -> usize {
        16
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

            let mut pin = Pin::new(inner);
            let mut size_buf = tokio::io::ReadBuf::new(size_holder);
            ready!(pin.as_mut().poll_read(cx, &mut size_buf))?;

            if size_buf.filled().len() != 2 {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                )));
            }

            let size = u16::from_be_bytes(size_buf.filled().try_into().unwrap()) as usize;
            if size > MAX_CHUNK_SIZE {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "chunk size too large",
                )));
            }

            inner_buf.reserve(size);

            let mut chunk_buf = tokio::io::ReadBuf::new(inner_buf);
            ready!(pin.as_mut().poll_read(cx, &mut chunk_buf))?;
            if chunk_buf.filled().len() != size {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                )));
            }

            nonce[..2].copy_from_slice(&count.to_be_bytes());
            nonce[2..12].copy_from_slice(&iv[2..12]);
            *count += 1;

            let nonce = &nonce[..security.nonce_len()];
            match security {
                VmessSecurity::Aes128Gcm(cipher) => {
                    let dec = cipher.decrypt_in_place_with_slice(
                        nonce.into(),
                        &[],
                        chunk_buf.filled_mut(),
                    );
                    if dec.is_err() {
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            dec.unwrap_err().to_string(),
                        )));
                    }
                }
                VmessSecurity::ChaCha20Poly1305(cipher) => {
                    let dec = cipher.decrypt_in_place_with_slice(
                        nonce.into(),
                        &[],
                        chunk_buf.filled_mut(),
                    );
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

            let n = buf.remaining();
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

            inner_buf.reserve(2 + payload_size + security.tag_len());
            inner_buf.put_u16((payload_size + security.tag_len()) as u16);
            inner_buf.put_slice(&buf[sent..sent + payload_size]);

            nonce[..2].copy_from_slice(&count.to_be_bytes());
            nonce[2..12].copy_from_slice(&iv[2..12]);

            *count += 1;

            let nonce_len = security.nonce_len();
            match security {
                VmessSecurity::Aes128Gcm(cipher) => {
                    cipher.encrypt_in_place_with_slice(
                        nonce[..nonce_len].into(),
                        &[],
                        inner_buf.as_mut(),
                    );
                }
                VmessSecurity::ChaCha20Poly1305(cipher) => {
                    cipher.encrypt_in_place_with_slice(
                        nonce[..nonce_len].into(),
                        &[],
                        inner_buf.as_mut(),
                    );
                }
            }

            ready!(pin
                .as_mut()
                .poll_write(cx, &inner_buf[..2 + payload_size + security.tag_len()]))?;
            inner_buf.clear();

            sent += payload_size;
            remaining -= payload_size;
        }

        std::task::Poll::Ready(Ok(buf.len()))
    }
}
