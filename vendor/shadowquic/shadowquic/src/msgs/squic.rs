use std::sync::Arc;

use crate::UserName;
use crate::error::SError;

use super::socks5::SocksAddr;
use super::{SDecode, SEncode};
use crate::config::AuthUser;
use shadowquic_macros::{SDecode, SEncode};

pub static SUNNY_QUIC_AUTH_LEN: usize = 64;
pub(crate) type SunnyCredential = Arc<[u8; SUNNY_QUIC_AUTH_LEN]>;

#[derive(PartialEq)]
#[repr(u8)]
#[derive(SEncode, SDecode)]
pub enum SQReq {
    SQConnect(SocksAddr) = 0x1,
    SQBind(SocksAddr) = 0x2,
    SQAssociatOverDatagram(SocksAddr) = 0x3,
    SQAssociatOverStream(SocksAddr) = 0x4,
    SQAuthenticate(SunnyCredential) = 0x5,
    SQExtension(SQExtOpcode) = 0xFF,
}

#[derive(PartialEq)]
#[repr(u64)]
#[derive(SEncode, SDecode)]
/// SQ Extention Opcode
pub enum SQExtOpcode {
    /// Connection related opcode
    Conn(ExtOpcodeConn) = 0x1,
    /// User related opcode
    User(ExtOpcodeUser) = 0x2,
}
#[derive(PartialEq)]
#[repr(u8)]
#[derive(SEncode, SDecode)]
pub enum ExtOpcodeConn {
    /// Get connection stats
    GetConnStats = 0x0,
}
#[derive(PartialEq, SEncode, SDecode)]
#[size_tag] // size tag allow future compatibility by prefixing a size field before the content, so that decoder can skip unknown opcode content based on the size field.
pub struct ConnStats {
    pub lost_packets: u64,
    pub sent_packets: u64,
    /// In unit of milliseconds
    pub rtt: f64,
    pub current_mtu: u16,
}

#[derive(PartialEq)]
#[repr(u8)]
#[derive(SEncode, SDecode)]
pub enum ExtOpcodeUser {
    AddUser(AuthUser) = 0x0,
    RemoveUser(UserName) = 0x1,
    ListUsers = 0x2,
    GetUserStats(UserName) = 0x3,
    KillUserConn(UserName) = 0x4,
    GetAllStats = 0x5,
}
#[derive(PartialEq)]
#[repr(u8)]
#[derive(SEncode, SDecode, Debug)]
pub enum SQExtError {
    NotAvailable = 0x0,
    PermissionDenied = 0x1,
    NotFound = 0x2,
    Other(String) = 0xFF,
}

#[derive(PartialEq, SEncode, SDecode, Default)]
#[size_tag]
pub struct UserStats {
    pub tcp_sent: u64,
    pub tcp_recv: u64,
    pub udp_sent: u64,
    pub udp_recv: u64,
    pub tcp_conns: u64,
    pub udp_conns: u64,
    /// Number of online connections, equal to devices connected.
    pub conn_num: u32,
    /// User these stats belong to. Added in v0.3.11
    pub username: UserName,
}

#[derive(SEncode, SDecode)]
pub struct SQUdpControlHeader {
    pub dst: SocksAddr,
    pub id: u16, // id is one to one coresponance a udpsocket and proxy dst
}

#[derive(SEncode, SDecode)]
pub struct SQPacketStreamHeader {
    pub id: u16, // id is one to one coresponance a udpsocket and proxy dst
    pub len: u16,
}

#[derive(SEncode, SDecode, Clone)]
pub struct SQPacketDatagramHeader {
    pub id: u16, // id is one to one coresponance a udpsocket and proxy dst
}

#[tokio::test]
async fn test_encode_req() {
    let req = SQReq::SQAuthenticate(Arc::new([1u8; SUNNY_QUIC_AUTH_LEN]));
    let buf = vec![0u8; 1 + SUNNY_QUIC_AUTH_LEN];
    let mut cursor = std::io::Cursor::new(buf);
    req.encode(&mut cursor).await.unwrap();
    assert_eq!(cursor.into_inner()[0], 0x5);
}

#[tokio::test]
async fn test_macro_expand_req() {
    const TEST_CONST: u8 = 89;
    #[repr(u8)]
    #[derive(SDecode, SEncode, PartialEq)]
    #[allow(dead_code)]
    pub enum Cmd {
        Connect,
        Bind = 0x8,
        AssociatOverDatagram,
        AssociatOverStream = TEST_CONST,
        Authenticate,
    }
}
