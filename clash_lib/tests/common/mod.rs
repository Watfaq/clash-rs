use std::net::{Shutdown, TcpStream};

pub(crate) fn start_clash(
    options: clash_lib::Options,
) -> Result<(), clash_lib::Error> {
    clash_lib::start_scaffold(options)
}

pub(crate) fn wait_port_ready(port: u16) -> Result<(), clash_lib::Error> {
    let addr = format!("127.0.0.1:{}", port);
    let mut attempts = 0;
    while attempts < 10 {
        if let Ok(stream) = TcpStream::connect(&addr) {
            stream.shutdown(Shutdown::Both).ok();
            return Ok(());
        }
        attempts += 1;
        // it may take some time for downloading the mmdbs
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    Err(clash_lib::Error::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("Port {} is not ready after 10 attempts", port),
    )))
}
