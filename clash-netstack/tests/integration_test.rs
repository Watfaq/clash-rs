use futures::{SinkExt, StreamExt};
use watfaq_netstack::{NetStack, Packet};

mod common;
mod mock_tun;

use common::{build_tcp_syn_packet, build_udp_packet, init, is_syn_ack};
use mock_tun::MockTun;

#[tokio::test]
async fn test_stack_with_mock_tun_real_tcp_udp() {
    init();

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, mut tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Forward packets from mock_tun to stack_sink (TUN -> NetStack)
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            let packet = Packet::new(pkt);
            stack_sink.send(packet).await.unwrap();
        }
    });

    // Send a TCP SYN packet
    let tcp_syn = build_tcp_syn_packet();
    tun_in.send(tcp_syn.clone()).unwrap();

    log::info!("Sent TCP SYN and UDP packets to mock TUN");

    let Some(Ok(reply)) = stack_stream.next().await else {
        panic!("No packets received from stack");
    };

    assert!(is_syn_ack(reply.data()));
    log::info!("Received TCP SYN-ACK packet from stack");

    let stream = tcp_listener.next().await.unwrap();
    log::info!("Accepted TCP stream: {:?}", stream);
    assert_eq!(stream.local_addr(), "1.1.1.1:1024".parse().unwrap());
    assert_eq!(stream.remote_addr(), "2.2.2.2:80".parse().unwrap());

    // Send a UDP packet
    let udp_pkt = build_udp_packet();
    tun_in.send(udp_pkt.clone()).unwrap();

    log::info!("Sent UDP packet to mock TUN");
    let (mut udp_read, _) = udp_socket.split();
    let Some(udp_packet) = udp_read.recv().await else {
        panic!("No UDP packet received");
    };
    assert_eq!(udp_packet.local_addr, "1.1.1.1:5000".parse().unwrap());
    assert_eq!(udp_packet.remote_addr, "2.2.2.2:5001".parse().unwrap());
}
