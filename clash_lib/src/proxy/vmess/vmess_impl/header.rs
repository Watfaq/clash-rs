use aead::{generic_array::GenericArray, KeyInit};
use aes::cipher::BlockEncrypt;
use bytes::{Buf, BufMut, BytesMut};

use crate::common::{crypto, errors::map_io_error, utils};

use super::kdf::{
    self, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY, KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
};

fn create_auth_id(cmd_key: [u8; 16], timestamp: u64) -> [u8; 16] {
    let mut buf = BytesMut::new();
    buf.put_u64(timestamp);

    let mut random = [0u8; 4];
    utils::rand_fill(&mut random);
    buf.put_slice(&random);

    let zero = crc32fast::hash(buf.as_ref());
    buf.put_u32(zero);

    let pk = kdf::vmess_kdf_1_one_shot(&cmd_key[..], KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY);
    let pk: [u8; 16] = pk[..16].try_into().unwrap(); // That's wired
    let key = GenericArray::from(pk);
    let cipher = aes::Aes128::new(&key);
    let mut block = [0u8; 16];
    buf.copy_to_slice(&mut block);
    let mut block = GenericArray::from(block);
    cipher.encrypt_block(&mut block);
    block.as_slice()[..16].try_into().unwrap()
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

    let header_len_encrypted = crypto::aes_gcm_encrypt(
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

    let payload_encrypted = crypto::aes_gcm_encrypt(
        payload_header_aead_key,
        payload_header_aead_nonce,
        &data,
        Some(auth_id.as_ref()),
    )
    .map_err(map_io_error)?;

    let mut out = BytesMut::new();
    out.put_slice(&auth_id[..]);
    out.put_slice(&header_len_encrypted[..]);
    out.put_slice(connection_nonce.as_ref());
    out.put_slice(&payload_encrypted[..]);

    Ok(out.freeze().to_vec())
}

#[cfg(test)]
mod tests {
    use crate::{
        common::crypto,
        proxy::vmess::vmess_impl::kdf::{
            self, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
        },
    };
    use aead::{generic_array::GenericArray, KeyInit};
    use aes::cipher::BlockEncrypt;
    use bytes::{Buf, BufMut, BytesMut};

    #[test]
    fn test_create_auth_id() {
        let mut buf = BytesMut::new();
        buf.put_u64_ne(0);

        for _ in 0..4 {
            buf.put_u64_ne(0);
        }

        let zero = crc32fast::hash(buf.as_ref());
        assert_eq!(zero, 3924573617);
        buf.put_u32(zero);

        let cmd_key = "1234567890123456".as_bytes();

        let pk = kdf::vmess_kdf_1_one_shot(cmd_key, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY);
        let pk: [u8; 16] = pk[..16].try_into().unwrap(); // That's wired
        let key = GenericArray::from(pk);
        let cipher = aes::Aes128::new(&key);
        let mut block = [0u8; 16];
        buf.copy_to_slice(&mut block);
        let mut block = GenericArray::from(block);
        cipher.encrypt_block(&mut block);
        let block: [u8; 16] = block.as_slice()[..16].try_into().unwrap();
        assert_eq!(
            block.to_vec(),
            vec![55, 189, 144, 149, 192, 213, 241, 57, 37, 21, 179, 197, 135, 54, 86, 79]
        );
    }

    #[test]
    fn test_seal_vmess_header() {
        let key = "1234567890123456".as_bytes();
        let auth_id = [0u8; 16];
        let connection_nonce = [0u8; 8];
        let data = vec![0u8; 16];

        let payload_header_length_aead_key = &kdf::vmess_kdf_3_one_shot(
            key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
            &auth_id[..],
            &connection_nonce[..],
        )[..16];
        let payload_header_length_aead_nonce = &kdf::vmess_kdf_3_one_shot(
            key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
            &auth_id[..],
            &connection_nonce[..],
        )[..12];

        let header_len_encrypted = crypto::aes_gcm_encrypt(
            payload_header_length_aead_key,
            payload_header_length_aead_nonce,
            (data.len() as u16).to_be_bytes().as_ref(),
            Some(auth_id.as_ref()),
        )
        .unwrap();

        let payload_header_aead_key = &kdf::vmess_kdf_3_one_shot(
            key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
            &auth_id[..],
            &connection_nonce[..],
        )[..16];
        let payload_header_aead_nonce = &kdf::vmess_kdf_3_one_shot(
            key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
            &auth_id[..],
            &connection_nonce[..],
        )[..12];

        let payload_encrypted = crypto::aes_gcm_encrypt(
            payload_header_aead_key,
            payload_header_aead_nonce,
            &data,
            Some(auth_id.as_ref()),
        )
        .unwrap();

        let mut out = BytesMut::new();
        out.put_slice(&auth_id[..]);
        out.put_slice(&header_len_encrypted[..]);
        out.put_slice(connection_nonce.as_ref());
        out.put_slice(&payload_encrypted[..]);

        assert_eq!(
            out.freeze().to_vec(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 137, 101, 25, 33, 23, 247, 66, 8,
                94, 171, 181, 162, 176, 21, 19, 111, 34, 161, 0, 0, 0, 0, 0, 0, 0, 0, 199, 22, 13,
                123, 209, 206, 78, 166, 69, 198, 7, 29, 224, 54, 214, 146, 73, 34, 66, 61, 10, 203,
                144, 160, 81, 17, 17, 191, 39, 197, 163, 246
            ]
        );
    }
}
