use bytes::{BufMut, Bytes, BytesMut};

pub fn init() {
    let _ = env_logger::builder().is_test(false).try_init();
}

pub fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn tcp_udp_checksum(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    proto: u8,
    tcp_udp: &[u8],
) -> u16 {
    let mut sum = 0u32;
    // Pseudo-header
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += proto as u32;
    sum += (tcp_udp.len() as u32) & 0xFFFF;
    // TCP/UDP header and payload
    let mut i = 0;
    while i + 1 < tcp_udp.len() {
        sum += u16::from_be_bytes([tcp_udp[i], tcp_udp[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_udp.len() {
        sum += (tcp_udp[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn build_tcp_syn_packet() -> Bytes {
    let src_ip = [1, 1, 1, 1];
    let dst_ip = [2, 2, 2, 2];
    let mut buf = BytesMut::with_capacity(40);
    // IPv4 header (20 bytes)
    buf.put_slice(&[
        IPV4_VERSION_IHL, 0x00, 0x00, 40, // Version, IHL, Total Length
        0x00, 0x00, 0x40, 0x00, // ID, Flags/Frag
        IPV4_TTL, TCP_PROTOCOL, 0x00, 0x00, // TTL, Protocol (TCP), Checksum (to fill)
        src_ip[0], src_ip[1], src_ip[2], src_ip[3], dst_ip[0], dst_ip[1], dst_ip[2],
        dst_ip[3],
    ]);
    // TCP header (20 bytes)
    let mut tcp = [
        (TCP_SRC_PORT >> 8) as u8, (TCP_SRC_PORT & 0xFF) as u8, // Src port 1024
        (TCP_DST_PORT >> 8) as u8, (TCP_DST_PORT & 0xFF) as u8, // Dst port 80
        0x00, 0x00, 0x00, 0x00, // Seq
        0x00, 0x00, 0x00, 0x00, // Ack
        0x50, 0x02, 0x72, 0x10, // Data offset, SYN, window
        0x00, 0x00, // Checksum (to fill)
        0x00, 0x00, // Urgent
    ];
    // Compute TCP checksum
    let tcp_sum = tcp_udp_checksum(src_ip, dst_ip, 6, &tcp);
    tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());
    buf.put_slice(&tcp);
    // Compute IPv4 checksum
    let mut ip_hdr = buf[..20].to_vec();
    let ip_sum = ipv4_checksum(&ip_hdr);
    ip_hdr[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    buf[..20].copy_from_slice(&ip_hdr);
    buf.freeze()
}

pub fn build_udp_packet() -> Bytes {
    let src_ip = [1, 1, 1, 1];
    let dst_ip = [2, 2, 2, 2];
    let mut buf = BytesMut::with_capacity(28);
    // IPv4 header (20 bytes)
    buf.put_slice(&[
        0x45, 0x00, 0x00, 28, // Version, IHL, Total Length
        0x00, 0x00, 0x40, 0x00, // ID, Flags/Frag
        0x40, 0x11, 0x00, 0x00, // TTL, Protocol (UDP), Checksum (to fill)
        src_ip[0], src_ip[1], src_ip[2], src_ip[3], dst_ip[0], dst_ip[1], dst_ip[2],
        dst_ip[3],
    ]);
    // UDP header (8 bytes)
    let mut udp = [
        0x13, 0x88, // Src port 5000
        0x13, 0x89, // Dst port 5001
        0x00, 0x08, // Length
        0x00, 0x00, // Checksum (to fill)
    ];
    // Compute UDP checksum
    let udp_sum = tcp_udp_checksum(src_ip, dst_ip, 17, &udp);
    udp[6..8].copy_from_slice(&udp_sum.to_be_bytes());
    buf.put_slice(&udp);
    // Compute IPv4 checksum
    let mut ip_hdr = buf[..20].to_vec();
    let ip_sum = ipv4_checksum(&ip_hdr);
    ip_hdr[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    buf[..20].copy_from_slice(&ip_hdr);
    buf.freeze()
}

pub fn is_syn_ack(packet: &[u8]) -> bool {
    // IPv4 header: minimum 20 bytes
    if packet.len() < 20 {
        return false;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl + 14 {
        return false;
    } // TCP header at least 14 bytes after IP

    // Protocol field in IPv4 header (should be 6 for TCP)
    if packet[9] != 0x06 {
        return false;
    }

    // TCP header starts after IPv4 header
    let tcp_offset = ihl;
    // TCP flags are at offset 13 in TCP header (relative to TCP header start)
    let flags = packet[tcp_offset + 13];
    (flags & 0x12) == 0x12 // SYN and ACK bits set
}
