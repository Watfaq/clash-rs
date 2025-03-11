use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

use bytes::{Buf, BufMut};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt};

pub use watfaq_types::{Network, Session, SocksAddrType, TargetAddr, Type};
