use bytes::{BufMut, BytesMut};

use crate::common::{crypto, errors::map_io_error, utils};

use super::kdf::{
    self, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY, KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
};

fn create_auth_id(cmd_key: [u8; 16], timestamp: u64) -> [u8; 16] {
    let mut buf = BytesMut::new();
    buf.put_slice(timestamp.to_be_bytes().as_ref());

    let mut random = [0u8; 4];
    utils::rand_fill(&mut random);
    buf.put_slice(&random);

    let zero = crc32fast::hash(buf.as_ref());
    buf.put_u32(zero);

    let mut aes_key = boring_sys::AES_KEY::default();
    let mut pk = kdf::vmess_kdf_1_one_shot(&cmd_key[..], KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY);
    unsafe {
        boring_sys::AES_set_encrypt_key(pk.as_ptr() as _, 128, &mut aes_key);
        boring_sys::AES_encrypt(buf.as_mut_ptr() as _, buf.as_mut_ptr() as _, &aes_key);
    }

    buf.freeze()[..16].try_into().unwrap()
}

pub(crate) fn seal_vmess_aead_header(
    key: [u8; 16],
    data: Vec<u8>,
    timestamp: u64,
) -> anyhow::Result<Vec<u8>> {
    let auth_id = create_auth_id(key, timestamp);
    let mut connection_nonce = [0u8; 8];
    utils::rand_fill(connection_nonce.as_mut());

    let payload_header_length_aead_key = &kdf::vmess_kdf_3_one_shot(
        &key[..],
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
        &auth_id[..],
        &connection_nonce[..],
    )[..16];
    let payload_header_length_aead_nonce = &kdf::vmess_kdf_3_one_shot(
        &key[..],
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
        &auth_id[..],
        &connection_nonce[..],
    )[..12];

    let heahder_encrypted = crypto::aes_gcm_seal(
        payload_header_length_aead_key,
        payload_header_length_aead_nonce,
        (data.len() as u16).to_be_bytes().as_ref(),
        Some(auth_id.as_ref()),
    )
    .map_err(map_io_error)?;

    let payload_header_aead_key = &kdf::vmess_kdf_3_one_shot(
        &key[..],
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
        &auth_id[..],
        &connection_nonce[..],
    )[..16];
    let payload_header_aead_nonce = &kdf::vmess_kdf_3_one_shot(
        &key[..],
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
        &auth_id[..],
        &connection_nonce[..],
    )[..12];

    let payload_encrypted = crypto::aes_gcm_seal(
        payload_header_aead_key,
        payload_header_aead_nonce,
        &data,
        Some(auth_id.as_ref()),
    )
    .map_err(map_io_error)?;

    let mut out = BytesMut::new();
    out.put_slice(&auth_id[..]);
    out.put_slice(&heahder_encrypted[..]);
    out.put_slice(connection_nonce.as_ref());
    out.put_slice(&payload_encrypted[..]);

    Ok(out.freeze().to_vec())
}
