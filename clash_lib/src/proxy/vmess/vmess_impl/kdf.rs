// https://github.com/Qv2ray/v2ray-rust/blob/1df95e479bd2844a484c663d7727fae82b3efabe/src/proxy/vmess/kdf.rs

use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

pub const KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY: &[u8; 22] =
    b"AES Auth ID Encryption";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY: &[u8; 24] =
    b"AEAD Resp Header Len Key";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV: &[u8; 23] =
    b"AEAD Resp Header Len IV";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8; 20] =
    b"AEAD Resp Header Key";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8; 19] =
    b"AEAD Resp Header IV";
pub const KDF_SALT_CONST_VMESS_AEAD_KDF: &[u8; 14] = b"VMess AEAD KDF";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY: &[u8; 21] =
    b"VMess Header AEAD Key";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV: &[u8; 23] =
    b"VMess Header AEAD Nonce";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &[u8; 28] =
    b"VMess Header AEAD Key_Length";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: &[u8; 30] =
    b"VMess Header AEAD Nonce_Length";

macro_rules! impl_hmac_with_hasher {
    ($name:tt, $hasher:tt) => {
        #[derive(Clone)]
        pub struct $name {
            okey: [u8; Self::BLOCK_LEN],
            hasher: $hasher,
            hasher_outer: $hasher,
        }

        impl $name {
            pub const BLOCK_LEN: usize = 64;
            pub const TAG_LEN: usize = 32;

            pub fn new(mut hasher: $hasher, key: &[u8]) -> Self {
                // H(K XOR opad, H(K XOR ipad, text))
                let mut ikey = [0u8; Self::BLOCK_LEN];
                let mut okey = [0u8; Self::BLOCK_LEN];
                let hasher_outer = hasher.clone();
                if key.len() > Self::BLOCK_LEN {
                    let mut hh = hasher.clone();
                    hh.update(key);
                    let hkey = hh.finalize();

                    ikey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
                    okey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
                } else {
                    ikey[..key.len()].copy_from_slice(&key);
                    okey[..key.len()].copy_from_slice(&key);
                }

                for idx in 0..Self::BLOCK_LEN {
                    ikey[idx] ^= IPAD;
                    okey[idx] ^= OPAD;
                }
                hasher.update(&ikey);
                Self {
                    okey,
                    hasher,
                    hasher_outer,
                }
            }

            pub fn update(&mut self, m: &[u8]) {
                self.hasher.update(m);
            }

            pub fn finalize(mut self) -> [u8; Self::TAG_LEN] {
                let h1 = self.hasher.finalize();

                self.hasher_outer.update(&self.okey);
                self.hasher_outer.update(&h1);

                let h2 = self.hasher_outer.finalize();

                return h2;
            }
        }
    };
}
#[derive(Clone)]
pub struct VmessKdf1 {
    okey: [u8; Self::BLOCK_LEN],
    hasher: HmacSha256,
    hasher_outer: HmacSha256,
}
impl VmessKdf1 {
    pub const BLOCK_LEN: usize = 64;
    pub const TAG_LEN: usize = 32;

    pub fn new(mut hasher: HmacSha256, key: &[u8]) -> Self {
        let mut ikey = [0u8; Self::BLOCK_LEN];
        let mut okey = [0u8; Self::BLOCK_LEN];
        let hasher_outer = hasher.clone();
        if key.len() > Self::BLOCK_LEN {
            let mut hh = hasher.clone();
            hh.update(key);
            let hkey = hh.finalize().into_bytes();

            ikey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
            okey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
        } else {
            ikey[..key.len()].copy_from_slice(key);
            okey[..key.len()].copy_from_slice(key);
        }

        for idx in 0..Self::BLOCK_LEN {
            ikey[idx] ^= IPAD;
            okey[idx] ^= OPAD;
        }
        hasher.update(&ikey);
        Self {
            okey,
            hasher,
            hasher_outer,
        }
    }

    pub fn update(&mut self, m: &[u8]) {
        self.hasher.update(m);
    }

    pub fn finalize(mut self) -> [u8; Self::TAG_LEN] {
        let h1 = self.hasher.finalize().into_bytes();

        self.hasher_outer.update(&self.okey);
        self.hasher_outer.update(&h1);

        self.hasher_outer.finalize().into_bytes().into()
    }
}

impl_hmac_with_hasher!(VmessKdf2, VmessKdf1);
impl_hmac_with_hasher!(VmessKdf3, VmessKdf2);

#[inline]
fn get_vmess_kdf_1(key1: &[u8]) -> VmessKdf1 {
    VmessKdf1::new(
        HmacSha256::new_from_slice(KDF_SALT_CONST_VMESS_AEAD_KDF).unwrap(),
        key1,
    )
}

pub fn vmess_kdf_1_one_shot(id: &[u8], key1: &[u8]) -> [u8; 32] {
    let mut h = get_vmess_kdf_1(key1);
    h.update(id);
    h.finalize()
}

#[inline]
fn get_vmess_kdf_2(key1: &[u8], key2: &[u8]) -> VmessKdf2 {
    VmessKdf2::new(get_vmess_kdf_1(key1), key2)
}

#[inline]
fn get_vmess_kdf_3(key1: &[u8], key2: &[u8], key3: &[u8]) -> VmessKdf3 {
    VmessKdf3::new(get_vmess_kdf_2(key1, key2), key3)
}

pub fn vmess_kdf_3_one_shot(
    id: &[u8],
    key1: &[u8],
    key2: &[u8],
    key3: &[u8],
) -> [u8; 32] {
    let mut h = get_vmess_kdf_3(key1, key2, key3);
    h.update(id);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use crate::proxy::vmess::vmess_impl::kdf::{
        vmess_kdf_1_one_shot, vmess_kdf_3_one_shot,
        KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
        KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
        KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
        KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY,
    };

    #[test]
    fn test_kdf_1_one_shot() {
        assert_eq!(
            vmess_kdf_1_one_shot(
                "test".as_bytes(),
                KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY
            ),
            vec![
                149, 109, 253, 20, 158, 39, 112, 199, 28, 74, 3, 106, 99, 8, 234,
                59, 64, 172, 126, 5, 155, 28, 59, 21, 220, 196, 241, 54, 138, 5, 71,
                107
            ]
            .as_slice()
        );
    }

    #[test]
    fn test_kdf_3_one_shot() {
        assert_eq!(
            vmess_kdf_3_one_shot(
                "test".as_bytes(),
                KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
                KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
                KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY
            ),
            vec![
                243, 80, 193, 249, 151, 10, 93, 168, 117, 239, 214, 89, 161, 130,
                122, 81, 238, 177, 51, 113, 21, 74, 73, 212, 199, 41, 75, 155, 49,
                55, 217, 226
            ]
            .as_slice()
        );
    }
}
