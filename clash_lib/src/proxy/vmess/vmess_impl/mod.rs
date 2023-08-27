mod cipher;
mod client;
mod header;
//pub mod http;
mod datagram;
mod kdf;
mod stream;
mod user;

pub(crate) const VERSION: u8 = 1;

pub(crate) const OPTION_CHUNK_STREAM: u8 = 1;
#[allow(unused)]
pub(crate) const OPTION_CHUNK_MASK: u8 = 2;

type Security = u8;

pub(crate) const SECURITY_AES_128_GCM: Security = 3;
pub(crate) const SECURITY_CHACHA20_POLY1305: Security = 4;
pub(crate) const SECURITY_NONE: Security = 5;

pub(crate) const COMMAND_TCP: u8 = 1;
pub(crate) const COMMAND_UDP: u8 = 2;

const CHUNK_SIZE: usize = 1 << 14;
const MAX_CHUNK_SIZE: usize = 17 * 1024;

pub use client::Builder;
pub use client::VmessOption;
pub use datagram::OutboundDatagramVmess;
pub use stream::VmessStream;
pub use user::new_alter_id_list;
pub use user::new_id;
