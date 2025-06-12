use shadowsocks::crypto::CipherKind;
use std::io;

pub mod inbound;
pub mod outbound;

pub(crate) fn map_cipher(cipher: &str) -> std::io::Result<CipherKind> {
    match cipher {
        "aes-128-gcm" => Ok(CipherKind::AES_128_GCM),
        "aes-256-gcm" => Ok(CipherKind::AES_256_GCM),
        "chacha20-ietf-poly1305" => Ok(CipherKind::CHACHA20_POLY1305),

        "2022-blake3-aes-128-gcm" => Ok(CipherKind::AEAD2022_BLAKE3_AES_128_GCM),
        "2022-blake3-aes-256-gcm" => Ok(CipherKind::AEAD2022_BLAKE3_AES_256_GCM),
        "2022-blake3-chacha20-ietf-poly1305" => {
            Ok(CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305)
        }

        "rc4-md5" => Ok(CipherKind::SS_RC4_MD5),
        _ => Err(io::Error::new(io::ErrorKind::Other, "unsupported cipher")),
    }
}
