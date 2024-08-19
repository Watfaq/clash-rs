use std::io;

pub fn new_io_error<T>(msg: T) -> io::Error
where
    T: Into<String>,
{
    io::Error::new(io::ErrorKind::Other, msg.into())
}

pub fn map_io_error<T>(err: T) -> io::Error
where
    T: Into<anyhow::Error> + Send,
{
    io::Error::new(io::ErrorKind::Other, format!("{:?}", anyhow::anyhow!(err)))
}
