use std::{fmt::Debug, net::SocketAddrV4, pin::Pin, task::Poll, time::SystemTime};

use aes_gcm::Aes128Gcm;
use bytes::{BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
        };

        stream.handshake().await?;

        Ok(stream)
    }

    async fn handshake(&mut self) -> std::io::Result<()> {
        futures::future::poll_fn(|cx| {
            VmessStream::poll_send_request(
                cx,
                &mut self.stream,
                &self.req_body_key,
                &self.req_body_iv,
                self.resp_v,
                self.security,
                &self.dst,
                self.is_aead,
                self.is_udp,
                &self.id,
            )
        })
        .await?;

        futures::future::poll_fn(|cx| {
            VmessStream::poll_recv_response(
                cx,
                &mut self.stream,
                self.is_aead,
                &self.resp_body_key,
                &self.resp_body_iv,
                self.resp_v,
            )
        })
        .await
    }

    fn poll_send_request(
        cx: &mut std::task::Context<'_>,
        writer: &mut S,
        req_body_key: &[u8],
        req_body_iv: &[u8],
        resp_v: u8,
        security: u8,
        dst: &SocksAddr,
        is_aead: bool,
        is_udp: bool,
        id: &ID,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut pin = Pin::new(writer);
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
        buf.put_u8(resp_v);
        buf.put_u8(OPTION_CHUNK_STREAM);

        let p = utils::rand_range(0..16);
        buf.put_u8(p << 4 | security);
        buf.put_u8(0);
        if is_udp {
            buf.put_u8(COMMAND_UDP);
        } else {
            buf.put_u8(COMMAND_TCP);
        }

        dst.write_to_buf_vmess(&mut buf);

        if p > 0 {
            let padding = vec![0u8; p as usize];
            utils::rand_fill(buf.as_mut());
            buf.put_slice(&padding);
        }

        unsafe {
            let sum = boring_sys::OPENSSL_hash32(buf.as_mut_ptr() as _, buf.len());
            buf.put_u32(sum);
        }

        if !is_aead {
            let mut data = buf.to_vec();
            crypto::aes_cfb_encrypt(&id.cmd_key[..], &hash_timestamp(now)[..], &mut data)
                .map_err(map_io_error)?;

            mbuf.put_slice(data.as_slice());
            pin.as_mut()
                .poll_write(cx, mbuf.freeze().as_ref())
                .map(|x| x.map(|_| ()))
        } else {
            // TODO: in place encryption
            let out = header::seal_vmess_aead_header(id.cmd_key, buf.freeze().to_vec(), now)
                .map_err(map_io_error)?;
            pin.as_mut()
                .poll_write(cx, out.as_ref())
                .map(|x| x.map(|_| ()))
        }
    }

    fn poll_recv_response(
        cx: &mut std::task::Context<'_>,
        reader: &mut S,
        is_aead: bool,
        resp_body_key: &[u8],
        resp_body_iv: &[u8],
        resp_v: u8,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut buf = Vec::new();

        let mut pin = Pin::new(reader);

        if !is_aead {
            buf.resize(4, 0);
            let mut read_buf = ReadBuf::new(buf.as_mut());
            ready!(pin
                .as_mut()
                .poll_read(cx, &mut read_buf)
                .map(|x| x.map(|_| ()))?);
            buf = read_buf.filled().into();
            crypto::aes_cfg_decrypt(resp_body_key, resp_body_iv, &mut buf).map_err(map_io_error)?;
        } else {
            let aead_response_header_length_encryption_key =
                &kdf::vmess_kdf_1_one_shot(resp_body_key, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY)
                    [..16];
            let aead_response_header_length_encryption_iv =
                &kdf::vmess_kdf_1_one_shot(resp_body_iv, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV)
                    [..12];

            buf.resize(18, 0);
            let mut read_buf = ReadBuf::new(buf.as_mut());
            ready!(pin
                .as_mut()
                .poll_read(cx, &mut read_buf)
                .map(|x| x.map(|_| ()))?);

            let decrypted_response_header_len = crypto::aes_gcm_open(
                aead_response_header_length_encryption_key,
                aead_response_header_length_encryption_iv,
                read_buf.filled(),
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

            buf.resize(decrypted_header_len as usize + 16, 0);
            read_buf = ReadBuf::new(buf.as_mut());
            ready!(pin
                .as_mut()
                .poll_read(cx, &mut read_buf)
                .map(|x| x.map(|_| ()))?);

            buf = crypto::aes_gcm_open(
                &aead_response_header_payload_encryption_key,
                &aead_response_header_payload_encryption_iv,
                read_buf.filled(),
                None,
            )
            .map_err(map_io_error)?;

            if buf.len() < 4 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid response",
                )));
            }
        }

        if buf[0] != resp_v {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid response",
            )));
        }

        if buf[2] != 0 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid response",
            )));
        }

        return Poll::Ready(Ok(()));
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
        let Self {
            ref mut stream,
            ref mut reader,
            ..
        } = self.get_mut();

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

        let mut hash = [0u8; 16];
        boring_sys::MD5_Final(hash.as_mut_ptr() as _, &mut ctx);
        hash
    }
}
