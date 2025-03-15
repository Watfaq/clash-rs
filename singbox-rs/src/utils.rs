use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use aes_gcm::{AeadInPlace, KeyInit};

use rand::{
    Fill, Rng,
    distr::uniform::{SampleRange, SampleUniform},
};
use sha2::Digest;

pub fn rand_range<T, R>(range: R) -> T
where
    T: SampleUniform,
    R: SampleRange<T>,
{
    let mut rng = rand::rng();
    rng.random_range(range)
}

pub fn rand_fill<T>(buf: &mut T)
where
    T: Fill + ?Sized,
{
    let mut rng = rand::rng();
    rng.fill(buf)
}

pub fn aes_cfb_encrypt(
    key: &[u8],
    iv: &[u8],
    data: &mut [u8],
) -> std::io::Result<()> {
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
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid key length",
        )),
    }
}

pub fn aes_cfb_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &mut [u8],
) -> std::io::Result<()> {
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
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid key length",
        )),
    }
}

pub fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(plaintext.len() + 16);
    buffer.append(&mut plaintext.to_vec());
    match key.len() {
        16 => {
            let cipher =
                ring_compat::aead::Aes128Gcm::new_from_slice(key).map_err(|x| {
                    std::io::Error::new(std::io::ErrorKind::Other, x.to_string())
                })?;
            cipher
                .encrypt_in_place(
                    nonce.into(),
                    associated_data.unwrap_or_default(),
                    &mut buffer,
                )
                .map_err(|x| {
                    std::io::Error::new(std::io::ErrorKind::Other, x.to_string())
                })?;
        }
        32 => {
            let cipher =
                ring_compat::aead::Aes256Gcm::new_from_slice(key).map_err(|x| {
                    std::io::Error::new(std::io::ErrorKind::Other, x.to_string())
                })?;
            cipher
                .encrypt_in_place(
                    nonce.into(),
                    associated_data.unwrap_or_default(),
                    &mut buffer,
                )
                .map_err(|x| {
                    std::io::Error::new(std::io::ErrorKind::Other, x.to_string())
                })?;
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Illegal key size {}", key.len()),
            ));
        }
    }
    Ok(buffer)
}

pub fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
) -> std::io::Result<Vec<u8>> {
    let mut buffer = ciphertext.to_vec();
    match key.len() {
        16 => {
            let cipher =
                ring_compat::aead::Aes128Gcm::new_from_slice(key).map_err(|x| {
                    std::io::Error::new(std::io::ErrorKind::Other, x.to_string())
                })?;
            cipher
                .decrypt_in_place(
                    nonce.into(),
                    associated_data.unwrap_or_default(),
                    &mut buffer,
                )
                .map_err(|x| {
                    std::io::Error::new(std::io::ErrorKind::Other, x.to_string())
                })?;
        }
        32 => {
            let cipher =
                ring_compat::aead::Aes256Gcm::new_from_slice(key).map_err(|x| {
                    std::io::Error::new(std::io::ErrorKind::Other, x.to_string())
                })?;
            cipher
                .decrypt_in_place(
                    nonce.into(),
                    associated_data.unwrap_or_default(),
                    &mut buffer,
                )
                .map_err(|x| {
                    std::io::Error::new(std::io::ErrorKind::Other, x.to_string())
                })?;
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Illegal key size {}", key.len()),
            ));
        }
    }
    buffer.shrink_to_fit();
    Ok(buffer)
}

pub fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

pub fn md5(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = md5::Md5::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}
