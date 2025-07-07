pub(super) const TLS_MAJOR: u8 = 0x03;
pub(super) const TLS_MINOR: (u8, u8) = (0x03, 0x01);
pub(super) const SUPPORTED_VERSIONS_TYPE: u16 = 43;
pub(super) const TLS_RANDOM_SIZE: usize = 32;
pub(super) const TLS_HEADER_SIZE: usize = 5;
pub(super) const TLS_SESSION_ID_SIZE: usize = 32;
pub(super) const TLS_13: u16 = 0x0304;

pub(super) const SERVER_HELLO: u8 = 0x02;
pub(super) const HANDSHAKE: u8 = 0x16;
pub(super) const APPLICATION_DATA: u8 = 0x17;

pub(super) const SERVER_RANDOM_OFFSET: usize = 1 + 3 + 2;
pub(super) const SESSION_ID_LEN_IDX: usize =
    TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;
pub(super) const TLS_HMAC_HEADER_SIZE: usize = TLS_HEADER_SIZE + HMAC_SIZE;

pub(super) const COPY_BUF_SIZE: usize = 4096;
pub(super) const HMAC_SIZE: usize = 4;
