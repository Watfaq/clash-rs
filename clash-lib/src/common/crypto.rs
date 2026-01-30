use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use aes_gcm::{AeadInPlace, KeyInit, aes::cipher::Unsigned};
use anyhow::{Ok, anyhow};

pub fn aes_cfb_encrypt(
    key: &[u8],
    iv: &[u8],
    data: &mut [u8],
) -> anyhow::Result<()> {
    match key.len() {
        16 => {
            cfb_mode::Encryptor::<aes::Aes128>::new(key.into(), iv.into())
                .encrypt(data);
            Ok(())
        }
        24 => {
            cfb_mode::Encryptor::<aes::Aes192>::new(key.into(), iv.into())
                .encrypt(data);
            Ok(())
        }
        32 => {
            cfb_mode::Encryptor::<aes::Aes256>::new(key.into(), iv.into())
                .encrypt(data);
            Ok(())
        }
        _ => anyhow::bail!("invalid key length"),
    }
}

pub fn aes_cfb_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &mut [u8],
) -> anyhow::Result<()> {
    match key.len() {
        16 => {
            cfb_mode::Decryptor::<aes::Aes128>::new(key.into(), iv.into())
                .decrypt(data);
            Ok(())
        }
        24 => {
            cfb_mode::Decryptor::<aes::Aes192>::new(key.into(), iv.into())
                .decrypt(data);
            Ok(())
        }
        32 => {
            cfb_mode::Decryptor::<aes::Aes256>::new(key.into(), iv.into())
                .decrypt(data);
            Ok(())
        }
        _ => anyhow::bail!("invalid key length"),
    }
}

pub fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(plaintext.len() + 16);
    buffer.append(&mut plaintext.to_vec());
    match key.len() {
        16 => {
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(key)?;
            cipher.encrypt_in_place(
                nonce.into(),
                associated_data.unwrap_or_default(),
                &mut buffer,
            )?;
        }
        32 => {
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)?;
            cipher.encrypt_in_place(
                nonce.into(),
                associated_data.unwrap_or_default(),
                &mut buffer,
            )?;
        }
        _ => return Err(anyhow!("Illegal key size {}", key.len())),
    }
    Ok(buffer)
}

/// TODO
pub fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let mut buffer = ciphertext.to_vec();
    match key.len() {
        16 => {
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(key)?;
            cipher.decrypt_in_place(
                nonce.into(),
                associated_data.unwrap_or_default(),
                &mut buffer,
            )?;
        }
        32 => {
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)?;
            cipher.decrypt_in_place(
                nonce.into(),
                associated_data.unwrap_or_default(),
                &mut buffer,
            )?;
        }
        _ => return Err(anyhow!("Illegal key size {}", key.len())),
    }
    buffer.shrink_to_fit();
    Ok(buffer)
}

pub trait AeadCipherHelper: AeadInPlace {
    fn new_with_slice(key: &[u8]) -> Self;
    /// it's up to the caller to ensure that the buffer is large enough
    /// i.e. buffer.len() >= plaintext.len() + Self::TagSize::to_usize()
    fn encrypt_in_place_with_slice(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
    ) {
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

    use crate::common::{crypto::aes_gcm_decrypt, utils};

    use super::{aes_cfb_encrypt, aes_gcm_encrypt};

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
        let nonce = "456456456456".as_bytes(); // it has to be 12 bytes
        let data = "789".as_bytes();
        let ad = "abc".as_bytes();
        let encrypted = aes_gcm_encrypt(key, nonce, data, Some(ad)).expect("sealed");

        let decrypted =
            aes_gcm_decrypt(key, nonce, &encrypted, Some(ad)).expect("opened");
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_aes_gcm_seal_fail() {
        let key = "1234567890123456".as_bytes();
        let nonce = "456456456456".as_bytes(); // it has to be 12 bytes
        let data = "789".as_bytes();
        let ad = "abc".as_bytes();
        let encrypted = aes_gcm_encrypt(key, nonce, data, Some(ad)).expect("sealed");

        let key2 = "1234567890123457".as_bytes();
        let decrypted = aes_gcm_decrypt(key2, nonce, &encrypted, Some(ad));

        assert!(decrypted.is_err());
    }
}
