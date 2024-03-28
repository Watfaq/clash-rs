use std::{io::Read, ptr::copy_nonoverlapping};

use byteorder::{BigEndian, ReadBytesExt};
use hmac::Mac;

use prelude::*;
use sha2::{Digest, Sha256};

pub(crate) mod prelude {
    pub(crate) const TLS_MAJOR: u8 = 0x03;
    pub(crate) const TLS_MINOR: (u8, u8) = (0x03, 0x01);
    pub(crate) const SUPPORTED_VERSIONS_TYPE: u16 = 43;
    pub(crate) const TLS_RANDOM_SIZE: usize = 32;
    pub(crate) const TLS_HEADER_SIZE: usize = 5;
    pub(crate) const TLS_SESSION_ID_SIZE: usize = 32;
    pub(crate) const TLS_13: u16 = 0x0304;

    pub(crate) const SERVER_HELLO: u8 = 0x02;
    pub(crate) const HANDSHAKE: u8 = 0x16;
    pub(crate) const APPLICATION_DATA: u8 = 0x17;

    pub(crate) const SERVER_RANDOM_OFFSET: usize = 1 + 3 + 2;
    pub(crate) const SESSION_ID_LEN_IDX: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;
    pub(crate) const TLS_HMAC_HEADER_SIZE: usize = TLS_HEADER_SIZE + HMAC_SIZE;

    pub(crate) const COPY_BUF_SIZE: usize = 4096;
    pub(crate) const HMAC_SIZE: usize = 4;
}

#[derive(Clone)]
pub(crate) struct Hmac(hmac::Hmac<sha1::Sha1>);

impl std::fmt::Debug for Hmac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hmac").finish()
    }
}

impl Hmac {
    #[inline]
    pub(crate) fn new(password: &str, init_data: (&[u8], &[u8])) -> Self {
        // Note: infact new_from_slice never returns Err.
        let mut hmac: hmac::Hmac<sha1::Sha1> =
            hmac::Hmac::new_from_slice(password.as_bytes()).expect("unable to build hmac instance");
        hmac.update(init_data.0);
        hmac.update(init_data.1);
        Self(hmac)
    }

    #[inline]
    // #[tracing::instrument(skip(data), level = "debug")]
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    #[inline]
    pub(crate) fn finalize(&self) -> [u8; HMAC_SIZE] {
        let hmac = self.0.clone();
        let hash = hmac.finalize().into_bytes();
        let mut res = [0; HMAC_SIZE];
        unsafe { copy_nonoverlapping(hash.as_slice().as_ptr(), res.as_mut_ptr(), HMAC_SIZE) };
        res
    }

    #[inline]
    pub(crate) fn to_owned(&self) -> Self {
        Self(self.0.clone())
    }
}

#[inline]
pub(crate) fn kdf(password: &str, server_random: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(server_random);
    let hash = hasher.finalize();
    hash.to_vec()
}

#[inline]
pub(crate) fn xor_slice(data: &mut [u8], key: &[u8]) {
    data.iter_mut()
        .zip(key.iter().cycle())
        .for_each(|(d, k)| *d ^= k);
}

pub(crate) trait CursorExt {
    fn read_by_u16(&mut self) -> std::io::Result<Vec<u8>>;
    fn skip(&mut self, n: usize) -> std::io::Result<()>;
    fn skip_by_u8(&mut self) -> std::io::Result<u8>;
    fn skip_by_u16(&mut self) -> std::io::Result<u16>;
}

impl<T> CursorExt for std::io::Cursor<T>
where
    std::io::Cursor<T>: std::io::Read,
{
    #[inline]
    fn read_by_u16(&mut self) -> std::io::Result<Vec<u8>> {
        let len = self.read_u16::<BigEndian>()?;
        let mut buf = vec![0; len as usize];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }

    #[inline]
    fn skip(&mut self, n: usize) -> std::io::Result<()> {
        for _ in 0..n {
            self.read_u8()?;
        }
        Ok(())
    }

    #[inline]
    fn skip_by_u8(&mut self) -> std::io::Result<u8> {
        let len = self.read_u8()?;
        self.skip(len as usize)?;
        Ok(len)
    }

    #[inline]
    fn skip_by_u16(&mut self) -> std::io::Result<u16> {
        let len = self.read_u16::<BigEndian>()?;
        self.skip(len as usize)?;
        Ok(len)
    }
}

/// Parse ServerHello and return if tls1.3 is supported.
pub(crate) fn support_tls13(frame: &[u8]) -> bool {
    if frame.len() < SESSION_ID_LEN_IDX {
        return false;
    }
    let mut cursor = std::io::Cursor::new(&frame[SESSION_ID_LEN_IDX..]);
    macro_rules! read_ok {
        ($res: expr) => {
            match $res {
                Ok(r) => r,
                Err(_) => {
                    return false;
                }
            }
        };
    }

    // skip session id
    read_ok!(cursor.skip_by_u8());
    // skip cipher suites
    read_ok!(cursor.skip(3));
    // skip ext length
    let cnt = read_ok!(cursor.read_u16::<BigEndian>());

    for _ in 0..cnt {
        let ext_type = read_ok!(cursor.read_u16::<BigEndian>());
        if ext_type != SUPPORTED_VERSIONS_TYPE {
            read_ok!(cursor.skip_by_u16());
            continue;
        }
        let ext_len = read_ok!(cursor.read_u16::<BigEndian>());
        let ext_val = read_ok!(cursor.read_u16::<BigEndian>());
        let use_tls13 = ext_len == 2 && ext_val == TLS_13;
        tracing::debug!("found supported_versions extension, tls1.3: {use_tls13}");
        return use_tls13;
    }
    false
}
