use std::{fmt::Debug, pin::Pin, task::Poll, time::SystemTime};

use aes_gcm::Aes128Gcm;
use bytes::{BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use futures::{pin_mut, ready, Future};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::{
    common::{
        crypto::{self, AeadCipherHelper},
        errors::map_io_error,
        utils,
    },
    session::SocksAddr,
};

use super::{
    aead::{AeadReader, AeadWriter, VmessSecurity},
    chunk::{ChunkReader, ChunkWriter},
    header,
    kdf::{
        self, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
        KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
    },
    user::{ID, ID_BYTES_LEN},
    Security, COMMAND_TCP, COMMAND_UDP, OPTION_CHUNK_STREAM, SECURITY_AES_128_GCM,
    SECURITY_CHACHA20_POLY1305, SECURITY_NONE, VERSION,
};

pub(crate) enum VmessReader {
    None(ChunkReader),
    Aes128Gcm(AeadReader),
    ChaCha20Poly1305(AeadReader),
}

pub(crate) enum VmessWriter {
    None(ChunkWriter),
    Aes128Gcm(AeadWriter),
    ChaCha20Poly1305(AeadWriter),
}

pub struct VmessStream<S> {
    stream: S,
    reader: VmessReader,
    writer: VmessWriter,
    dst: SocksAddr,
    id: ID,
    req_body_iv: Vec<u8>,
    req_body_key: Vec<u8>,
    resp_body_iv: Vec<u8>,
    resp_body_key: Vec<u8>,
    resp_v: u8,
    security: u8,
    is_aead: bool,
    is_udp: bool,
    handshake_done: bool,
}

impl<S> Debug for VmessStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessStream")
            .field("dst", &self.dst)
            .field("is_aead", &self.is_aead)
            .field("is_udp", &self.is_udp)
            .finish()
    }
}

impl<S> VmessStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) async fn new(
        stream: S,
        id: &ID,
        dst: &SocksAddr,
        security: &Security,
        is_aead: bool,
        is_udp: bool,
    ) -> std::io::Result<VmessStream<S>> {
        let mut rand_bytes = [0u8; 33];
        utils::rand_fill(&mut rand_bytes[..]);
        let req_body_iv = rand_bytes[0..16].to_vec();
        let req_body_key = rand_bytes[16..32].to_vec();
        let resp_v = rand_bytes[32];

        let (resp_body_key, resp_body_iv) = if is_aead {
            (
                utils::sha256(req_body_key.as_slice())[0..16].to_vec(),
                utils::sha256(req_body_iv.as_slice())[0..16].to_vec(),
            )
        } else {
            (
                utils::md5(req_body_key.as_slice()),
                utils::md5(req_body_iv.as_slice()),
            )
        };

        let (reader, writer) = match security {
            &SECURITY_NONE => (
                VmessReader::None(ChunkReader::new()),
                VmessWriter::None(ChunkWriter::new()),
            ),
            &SECURITY_AES_128_GCM => {
                let write_cipher =
                    VmessSecurity::Aes128Gcm(Aes128Gcm::new_with_slice(&req_body_key));
                let writer = AeadWriter::new(&req_body_iv, write_cipher);
                let reader_cipher =
                    VmessSecurity::Aes128Gcm(Aes128Gcm::new_with_slice(&resp_body_key));
                let reader = AeadReader::new(&resp_body_iv, reader_cipher);
                (
                    VmessReader::Aes128Gcm(reader),
                    VmessWriter::Aes128Gcm(writer),
                )
            }
            &SECURITY_CHACHA20_POLY1305 => {
                let mut key = [0u8; 32];
                let tmp = utils::md5(&req_body_key);
                key.copy_from_slice(&tmp);
                let tmp = utils::md5(&key[..16]);
                key[16..].copy_from_slice(&tmp);
                let write_cipher =
                    VmessSecurity::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(&key));
                let writer = AeadWriter::new(&req_body_iv, write_cipher);

                let tmp = utils::md5(&req_body_key);
                key.copy_from_slice(&tmp);
                let tmp = utils::md5(&key[..16]);
                key[16..].copy_from_slice(&tmp);
                let reader_cipher =
                    VmessSecurity::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(&key));
                let reader = AeadReader::new(&resp_body_iv, reader_cipher);

                (
                    VmessReader::ChaCha20Poly1305(reader),
                    VmessWriter::ChaCha20Poly1305(writer),
                )
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "unsupported security",
                ))
            }
        };

        let mut stream = Self {
            stream,
            reader,
            writer,
            dst: dst.to_owned(),
            id: id.to_owned(),
            req_body_iv,
            req_body_key,
            resp_body_iv,
            resp_body_key,
            resp_v,
            security: *security,
            is_aead,
            is_udp,
            handshake_done: false,
        };

        stream.send_handshake_request().await?;

        Ok(stream)
    }
}

impl<S> VmessStream<S>
where
    S: AsyncRead + Unpin,
{
    async fn recv_handshake_response(&mut self) -> std::io::Result<()> {
        let Self {
            ref mut stream,
            ref is_aead,
            ref resp_body_key,
            ref resp_body_iv,
            ref resp_v,
            ..
        } = self;

        debug!("recv handshake response");
        let mut buf = Vec::new();

        if !is_aead {
            buf.resize(4, 0);
            stream.read_exact(buf.as_mut()).await?;
            crypto::aes_cfb_decrypt(resp_body_key, resp_body_iv, &mut buf).map_err(map_io_error)?;
        } else {
            let aead_response_header_length_encryption_key =
                &kdf::vmess_kdf_1_one_shot(resp_body_key, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY)
                    [..16];
            let aead_response_header_length_encryption_iv =
                &kdf::vmess_kdf_1_one_shot(resp_body_iv, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV)
                    [..12];

            debug!("recv handshake response header length");
            let mut hdr_len_buf = [0u8; 18];
            stream.read_exact(&mut hdr_len_buf).await?;
            debug!(
                "recv handshake response header length: {:?}",
                hdr_len_buf.as_slice()
            );

            let decrypted_response_header_len = crypto::aes_gcm_open(
                aead_response_header_length_encryption_key,
                aead_response_header_length_encryption_iv,
                hdr_len_buf.as_slice(),
                None,
            )
            .map_err(map_io_error)?;

            if decrypted_response_header_len.len() < 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid response header length",
                ))
                .into();
            }

            debug!(
                "recv handshake response header length: {:?}",
                decrypted_response_header_len
            );

            let decrypted_header_len =
                u16::from_be_bytes(decrypted_response_header_len[..2].try_into().unwrap());
            let aead_response_header_payload_encryption_key = &kdf::vmess_kdf_1_one_shot(
                resp_body_key,
                KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
            )[..16];
            let aead_response_header_payload_encryption_iv = &kdf::vmess_kdf_1_one_shot(
                resp_body_iv,
                KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV,
            )[..12];

            debug!("recv handshake response header");
            let mut hdr_buff = vec![0; decrypted_header_len as usize + 16];
            stream.read_exact(&mut hdr_buff).await?;

            buf = crypto::aes_gcm_open(
                &aead_response_header_payload_encryption_key,
                &aead_response_header_payload_encryption_iv,
                hdr_buff.as_slice(),
                None,
            )
            .map_err(map_io_error)?;

            if buf.len() < 4 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid response",
                ));
            }
        }

        if buf[0] != *resp_v {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid response",
            ));
        }

        if buf[2] != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid response",
            ));
        }

        Ok(())
    }
}

impl<S> VmessStream<S>
where
    S: AsyncWrite + Unpin,
{
    async fn send_handshake_request(&mut self) -> std::io::Result<()> {
        let Self {
            ref mut stream,
            ref req_body_key,
            ref req_body_iv,
            ref resp_v,
            ref security,
            ref dst,
            ref is_aead,
            ref is_udp,
            ref id,
            ..
        } = self;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("check your system clock")
            .as_secs();

        let mut mbuf = BytesMut::new();

        if !is_aead {
            let mut hash = [0u8; boring_sys::EVP_MAX_MD_SIZE as usize];
            let out_len = 0;

            unsafe {
                boring_sys::HMAC(
                    boring_sys::EVP_md5(),
                    id.uuid.as_bytes().as_ptr() as _,
                    ID_BYTES_LEN,
                    now.to_be_bytes().as_mut_ptr() as _,
                    8,
                    &mut hash as _,
                    out_len as _,
                );
            }
            mbuf.put_slice(&hash[..out_len])
        }

        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_slice(req_body_iv);
        buf.put_slice(req_body_key);
        buf.put_u8(*resp_v);
        buf.put_u8(OPTION_CHUNK_STREAM);

        let p = utils::rand_range(0..16);
        buf.put_u8((p << 4) as u8 | security);

        buf.put_u8(0);

        if *is_udp {
            buf.put_u8(COMMAND_UDP);
        } else {
            buf.put_u8(COMMAND_TCP);
        }

        dst.write_to_buf_vmess(&mut buf);

        if p > 0 {
            let mut padding = vec![0u8; p as usize];
            utils::rand_fill(&mut padding[..]);
            buf.put_slice(&padding);
        }

        unsafe {
            let sum = boring_sys::OPENSSL_hash32(buf.as_mut_ptr() as _, buf.len());
            buf.put_slice(sum.to_be_bytes().as_ref());
        }

        if !is_aead {
            let mut data = buf.to_vec();
            crypto::aes_cfb_encrypt(&id.cmd_key[..], &hash_timestamp(now)[..], &mut data)
                .map_err(map_io_error)?;

            mbuf.put_slice(data.as_slice());
            let out = mbuf.freeze();
            debug!("send non aead handshake request for user{}", id.uuid);
            stream.write_all(&out).await?;
        } else {
            let out = header::seal_vmess_aead_header(id.cmd_key, buf.freeze().to_vec(), now)
                .map_err(map_io_error)?;
            debug!("send aead handshake request for user {}", id.uuid);

            stream.write_all(&out).await?;
        }

        stream.flush().await?;

        Ok(())
    }
}

impl<S> AsyncRead for VmessStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        debug!("poll read with aead");

        let this = self.get_mut();

        if !this.handshake_done {
            debug!("doing handshake");
            let fut = this.recv_handshake_response();
            pin_mut!(fut);
            ready!(fut.poll(cx))?;
        }

        this.handshake_done = true;
        debug!("handshake done");

        let stream = &mut this.stream;
        let reader = &mut this.reader;

        return match reader {
            VmessReader::None(r) => Pin::new(r).poll_read(stream, cx, buf),
            VmessReader::Aes128Gcm(r) => Pin::new(r).poll_read(stream, cx, buf),
            VmessReader::ChaCha20Poly1305(r) => Pin::new(r).poll_read(stream, cx, buf),
        };
    }
}

impl<S> AsyncWrite for VmessStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let Self {
            ref mut stream,
            ref mut writer,
            ..
        } = self.get_mut();

        debug!("poll write with aead");

        return match writer {
            VmessWriter::None(w) => Pin::new(w).poll_write(stream, cx, buf),
            VmessWriter::Aes128Gcm(w) => Pin::new(w).poll_write(stream, cx, buf),
            VmessWriter::ChaCha20Poly1305(w) => Pin::new(w).poll_write(stream, cx, buf),
        };
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let Self { ref mut stream, .. } = self.get_mut();
        Pin::new(stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let Self { ref mut stream, .. } = self.get_mut();
        Pin::new(stream).poll_shutdown(cx)
    }
}

fn hash_timestamp(timestamp: u64) -> [u8; 16] {
    unsafe {
        let mut ctx = boring_sys::MD5_CTX::default();
        boring_sys::MD5_Init(&mut ctx);

        boring_sys::MD5_Update(&mut ctx, timestamp.to_be_bytes().as_ptr() as _, 8);
        boring_sys::MD5_Update(&mut ctx, timestamp.to_be_bytes().as_ptr() as _, 8);
        boring_sys::MD5_Update(&mut ctx, timestamp.to_be_bytes().as_ptr() as _, 8);
        boring_sys::MD5_Update(&mut ctx, timestamp.to_be_bytes().as_ptr() as _, 8);

        let mut hash = [0u8; 16];
        boring_sys::MD5_Final(hash.as_mut_ptr() as _, &mut ctx);
        hash
    }
}
