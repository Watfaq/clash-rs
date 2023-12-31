use std::ffi::CStr;

use crate::Error;

use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use aes_gcm::aes::cipher::Unsigned;
use aes_gcm::{AeadInPlace, KeyInit};

pub fn aes_cfb_encrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> anyhow::Result<()> {
    match key.len() {
        16 => {
            cfb_mode::Encryptor::<aes::Aes128>::new(key.into(), iv.into()).encrypt(data);
            Ok(())
        }
        24 => {
            cfb_mode::Encryptor::<aes::Aes192>::new(key.into(), iv.into()).encrypt(data);
            Ok(())
        }
        32 => {
            cfb_mode::Encryptor::<aes::Aes256>::new(key.into(), iv.into()).encrypt(data);
            Ok(())
        }
        _ => anyhow::bail!("invalid key length"),
    }
}

pub fn aes_cfb_decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> anyhow::Result<()> {
    match key.len() {
        16 => {
            cfb_mode::Decryptor::<aes::Aes128>::new(key.into(), iv.into()).decrypt(data);
            Ok(())
        }
        24 => {
            cfb_mode::Decryptor::<aes::Aes192>::new(key.into(), iv.into()).decrypt(data);
            Ok(())
        }
        32 => {
            cfb_mode::Decryptor::<aes::Aes256>::new(key.into(), iv.into()).decrypt(data);
            Ok(())
        }
        _ => anyhow::bail!("invalid key length"),
    }
}

pub fn aes_gcm_seal(
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    ad: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    unsafe {
        let ctx = boring_sys::EVP_AEAD_CTX_new(
            match key.len() {
                16 => boring_sys::EVP_aead_aes_128_gcm(),
                24 => boring_sys::EVP_aead_aes_192_gcm(),
                32 => boring_sys::EVP_aead_aes_256_gcm(),
                _ => anyhow::bail!("invalid key length"),
            },
            key.as_ptr(),
            key.len(),
            boring_sys::EVP_AEAD_DEFAULT_TAG_LENGTH as _,
        );

        let mut out = vec![0u8; data.len() + boring_sys::EVP_AEAD_MAX_OVERHEAD as usize];

        let mut out_len = 0;

        let rv = boring_sys::EVP_AEAD_CTX_seal(
            ctx,
            out.as_mut_ptr(),
            &mut out_len,
            out.len(),
            nonce.as_ptr(),
            nonce.len(),
            data.as_ptr(),
            data.len(),
            match ad {
                Some(ad) => ad.as_ptr(),
                None => std::ptr::null(),
            },
            match ad {
                Some(ad) => ad.len(),
                None => 0,
            },
        );

        boring_sys::EVP_AEAD_CTX_free(ctx);

        return if rv != 1 {
            Err(Error::Crypto(
                CStr::from_ptr(
                    boring_sys::ERR_reason_error_string(boring_sys::ERR_get_error()) as _,
                )
                .to_str()
                .expect("openssl error string is not utf8")
                .to_owned(),
            )
            .into())
        } else {
            out.truncate(out_len);
            Ok(out)
        };
    }
}

pub fn aes_gcm_open(
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    ad: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    unsafe {
        let ctx = boring_sys::EVP_AEAD_CTX_new(
            match key.len() {
                16 => boring_sys::EVP_aead_aes_128_gcm(),
                24 => boring_sys::EVP_aead_aes_192_gcm(),
                32 => boring_sys::EVP_aead_aes_256_gcm(),
                _ => anyhow::bail!("invalid key length"),
            },
            key.as_ptr(),
            key.len(),
            boring_sys::EVP_AEAD_DEFAULT_TAG_LENGTH as _,
        );

        let mut out = vec![0u8; data.len()];

        let mut out_len = 0;

        let rv = boring_sys::EVP_AEAD_CTX_open(
            ctx,
            out.as_mut_ptr(),
            &mut out_len,
            out.len(),
            nonce.as_ptr(),
            nonce.len(),
            data.as_ptr(),
            data.len(),
            match ad {
                Some(ad) => ad.as_ptr(),
                None => std::ptr::null(),
            },
            match ad {
                Some(ad) => ad.len(),
                None => 0,
            },
        );

        boring_sys::EVP_AEAD_CTX_free(ctx);

        return if rv != 1 {
            Err(Error::Crypto(
                CStr::from_ptr(
                    boring_sys::ERR_reason_error_string(boring_sys::ERR_get_error()) as _,
                )
                .to_str()
                .expect("openssl error string is not utf8")
                .to_owned(),
            )
            .into())
        } else {
            out.truncate(out_len);
            Ok(out)
        };
    }
}

pub trait AeadCipherHelper: AeadInPlace {
    fn new_with_slice(key: &[u8]) -> Self;
    /// it's up to the caller to ensure that the buffer is large enough
    /// i.e. buffer.len() >= plaintext.len() + Self::TagSize::to_usize()
    fn encrypt_in_place_with_slice(&self, nonce: &[u8], aad: &[u8], buffer: &mut [u8]) {
        let tag_pos = buffer.len() - Self::TagSize::to_usize();
        let (msg, tag) = buffer.split_at_mut(tag_pos);
        let x = self
            .encrypt_in_place_detached(nonce.into(), aad, msg)
            .expect("encryption failure!");
        tag.copy_from_slice(x.as_slice());
    }

    fn decrypt_in_place_with_slice(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), aes_gcm::Error> {
        let tag_pos = buffer.len() - Self::TagSize::to_usize();
        let (msg, tag) = buffer.split_at_mut(tag_pos);
        self.decrypt_in_place_detached(
            nonce.into(),
            aad,
            msg,
            aes_gcm::aead::Tag::<Self>::from_slice(tag),
        )
    }
}

impl AeadCipherHelper for aes_gcm::Aes128Gcm {
    fn new_with_slice(key: &[u8]) -> Self {
        aes_gcm::Aes128Gcm::new(key.into())
    }
}

impl AeadCipherHelper for aes_gcm::Aes256Gcm {
    fn new_with_slice(key: &[u8]) -> Self {
        aes_gcm::Aes256Gcm::new(key.into())
    }
}

impl AeadCipherHelper for chacha20poly1305::ChaCha20Poly1305 {
    fn new_with_slice(key: &[u8]) -> Self {
        chacha20poly1305::ChaCha20Poly1305::new(key.into())
    }
}
#[cfg(test)]
mod tests {

    use crate::common::{crypto::aes_gcm_open, utils};

    use super::{aes_cfb_encrypt, aes_gcm_seal};

    #[test]
    fn test_aes_cfb_256() {
        let key = "2b7e151628aed2a6abf7158809cf4f3c";
        let iv = "000102030405060708090a0b0c0d0e0f";

        let plain = "6bc1bee22e409f96e93d7e117393172a";
        let expect = "3b3fd92eb72dad20333449f8e83cfb4a";

        let mut binding = utils::decode_hex(plain).expect("plain");
        let data = binding.as_mut();

        aes_cfb_encrypt(
            utils::decode_hex(key).expect("key").as_slice(),
            utils::decode_hex(iv).expect("iv").as_slice(),
            data,
        )
        .expect("encryption");

        assert_eq!(data, &mut utils::decode_hex(expect).expect("ciphered"));
    }

    #[test]
    fn test_aes_gcm_seal_ok() {
        let key = "1234567890123456".as_bytes();
        let nonce = "456".as_bytes();
        let data = "789".as_bytes();
        let ad = "abc".as_bytes();
        let encrypted = aes_gcm_seal(key, nonce, data, Some(ad)).expect("sealed");

        let decrypted = aes_gcm_open(key, nonce, &encrypted, Some(ad)).expect("opened");
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_aes_gcm_seal_fail() {
        let key = "1234567890123456".as_bytes();
        let nonce = "456".as_bytes();
        let data = "789".as_bytes();
        let ad = "abc".as_bytes();
        let encrypted = aes_gcm_seal(key, nonce, data, Some(ad)).expect("sealed");

        let key2 = "1234567890123457".as_bytes();
        let decrypted = aes_gcm_open(key2, nonce, &encrypted, Some(ad));

        assert!(decrypted.is_err());
        assert_eq!(
            decrypted.unwrap_err().to_string(),
            "crypto error: BAD_DECRYPT"
        );
    }
}
