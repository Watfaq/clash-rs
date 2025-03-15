use aead::KeyInit;
use aes_gcm::{AeadInPlace, aes::cipher::Unsigned};

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
