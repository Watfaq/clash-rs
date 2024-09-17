pub mod inbound;
pub use netstack_lwip as netstack;
mod datagram;
pub use inbound::get_runner as get_tun_runner;
mod routes;

#[cfg(test)]
mod tests {
    use std::thread;

    use crate::{shutdown, start, Config, Options};

    #[test]
    fn test_route_all() {
        let conf = r#"
        socks-port: 7891
        bind-address: 127.0.0.1
        mmdb: "tests/data/Country.mmdb"
        tun:
          enable: true
          device-id: "dev://utun1989"
          route-all: true
          gateway: "198.19.0.1/32"
          so-mark: 3389
        "#;

        let log_file = tempfile::tempdir()
            .unwrap()
            .into_path()
            .join("clash.log")
            .to_str()
            .unwrap()
            .to_string();

        let log_file_clone = log_file.clone();

        let handle = thread::spawn(|| {
            start(Options {
                config: Config::Str(conf.to_string()),
                cwd: None,
                rt: None,
                log_file: Some(log_file_clone),
            })
            .unwrap()
        });

        let echo_server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo_server.local_addr().unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 1024];
            loop {
                let (n, src) = echo_server.recv_from(&mut buf).unwrap();
                echo_server.send_to(&buf[..n], src).unwrap();
            }
        });

        let udp_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        udp_socket.send_to(b"hello", echo_addr).unwrap();
        let mut buf = [0u8; 1024];
        udp_socket.recv_from(&mut buf).unwrap();

        assert_eq!(b"hello", &buf[..5]);

        let logs = std::fs::read_to_string(&log_file).unwrap();

        assert!(logs.contains("route_all is enabled"));
        assert!(logs.contains("127.0.0.1"));

        assert!(shutdown());

        handle.join().unwrap();
    }
}
