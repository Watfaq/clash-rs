use std::ffi::CString;

use crate::Error;

use aes_gcm::aes::cipher::Unsigned;
use aes_gcm::{AeadInPlace, KeyInit};

pub fn aes_cfb_encrypt(key: &[u8], iv: &[u8], data: &mut Vec<u8>) -> anyhow::Result<()> {
    unsafe {
        let ctx = boring_sys::EVP_CIPHER_CTX_new();
        let rv = boring_sys::EVP_EncryptInit_ex(
            ctx,
            match key.len() {
                16 => boring_sys::EVP_aes_128_cfb(),
                24 => boring_sys::EVP_aes_192_cfb(),
                32 => boring_sys::EVP_aes_256_cfb(),
                _ => anyhow::bail!("invalid key length"),
            },
            std::ptr::null_mut(),
            key.as_ptr(),
            iv.as_ptr(),
        );

        if rv != 1 {
            return Err(Error::Crypto(
                CString::from_raw(boring_sys::ERR_reason_error_string(rv as _) as _)
                    .to_str()
                    .expect("openssl error string is not utf8")
                    .to_owned(),
            )
            .into());
        }

        let mut out_len = 0;
        let rv = boring_sys::EVP_EncryptUpdate(
            ctx,
            data.as_mut_ptr(),
            &mut out_len,
            data.as_ptr(),
            data.len() as _,
        );

        if rv != 1 {
            return Err(Error::Crypto(
                CString::from_raw(boring_sys::ERR_reason_error_string(rv as _) as _)
                    .to_str()
                    .expect("openssl error string is not utf8")
                    .to_owned(),
            )
            .into());
        }

        let rv = boring_sys::EVP_EncryptFinal_ex(
            ctx,
            data.as_mut_ptr().offset(out_len as _),
            &mut out_len,
        );
        boring_sys::EVP_CIPHER_CTX_free(ctx);

        return if rv != 1 {
            Err(Error::Crypto(
                CString::from_raw(boring_sys::ERR_reason_error_string(rv as _) as _)
                    .to_str()
                    .expect("openssl error string is not utf8")
                    .to_owned(),
            )
            .into())
        } else {
            Ok(())
        };
    }
}

pub fn aes_cfg_decrypt(key: &[u8], iv: &[u8], data: &mut Vec<u8>) -> anyhow::Result<()> {
    unsafe {
        let ctx = boring_sys::EVP_CIPHER_CTX_new();
        let rv = boring_sys::EVP_DecryptInit_ex(
            ctx,
            match key.len() {
                16 => boring_sys::EVP_aes_128_cfb(),
                24 => boring_sys::EVP_aes_192_cfb(),
                32 => boring_sys::EVP_aes_256_cfb(),
                _ => anyhow::bail!("invalid key length"),
            },
            std::ptr::null_mut(),
            key.as_ptr(),
            iv.as_ptr(),
        );

        if rv != 1 {
            return Err(Error::Crypto(
                CString::from_raw(boring_sys::ERR_reason_error_string(rv as _) as _)
                    .to_str()
                    .expect("openssl error string is not utf8")
                    .to_owned(),
            )
            .into());
        }

        let mut out_len = 0;
        let rv = boring_sys::EVP_DecryptUpdate(
            ctx,
            data.as_mut_ptr(),
            &mut out_len,
            data.as_ptr(),
            data.len() as _,
        );

        if rv != 1 {
            return Err(Error::Crypto(
                CString::from_raw(boring_sys::ERR_reason_error_string(rv as _) as _)
                    .to_str()
                    .expect("openssl error string is not utf8")
                    .to_owned(),
            )
            .into());
        }

        let rv = boring_sys::EVP_DecryptFinal_ex(
            ctx,
            data.as_mut_ptr().offset(out_len as _),
            &mut out_len,
        );
        boring_sys::EVP_CIPHER_CTX_free(ctx);

        return if rv != 1 {
            Err(Error::Crypto(
                CString::from_raw(boring_sys::ERR_reason_error_string(rv as _) as _)
                    .to_str()
                    .expect("openssl error string is not utf8")
                    .to_owned(),
            )
            .into())
        } else {
            Ok(())
        };
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
                CString::from_raw(boring_sys::ERR_reason_error_string(rv as _) as _)
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
                CString::from_raw(boring_sys::ERR_reason_error_string(rv as _) as _)
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
    fn encrypt_in_place_with_slice(&self, nonce: &[u8], aad: &[u8], buffer: &mut [u8]) {
        let tag_pos = buffer.len() - Self::TagSize::to_usize();
        let (msg, tag) = buffer.split_at_mut(tag_pos);
        let x = self
            .encrypt_in_place_detached(nonce.into(), aad, msg)
            .expect("encryption failure!");
        tag.copy_from_slice(&x);
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

    use crate::common::utils;

    use super::aes_cfb_encrypt;

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
}
