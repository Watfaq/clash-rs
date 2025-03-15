use std::{mem::MaybeUninit, pin::Pin, task::Poll};

use bytes::BytesMut;
use futures::ready;
use tokio::io::{AsyncRead, ReadBuf};

pub trait ReadExactBase {
    /// inner stream to be polled
    type I: AsyncRead + Unpin;
    /// prepare the inner stream, read buffer and read position
    fn decompose(&mut self) -> (&mut Self::I, &mut BytesMut, &mut usize);
}

pub trait ReadExt: ReadExactBase {
    fn poll_read_exact(
        &mut self,
        cx: &mut std::task::Context,
        size: usize,
    ) -> Poll<std::io::Result<()>>;
}

impl<T: ReadExactBase> ReadExt for T {
    fn poll_read_exact(
        &mut self,
        cx: &mut std::task::Context,
        size: usize,
    ) -> Poll<std::io::Result<()>> {
        let (raw, read_buf, read_pos) = self.decompose();
        read_buf.reserve(size);
        // # safety: read_buf has reserved `size`
        unsafe { read_buf.set_len(size) }
        loop {
            if *read_pos < size {
                // # safety: read_pos<size==read_buf.len(), and
                // read_buf[0..read_pos] is initialized
                let dst = unsafe {
                    &mut *((&mut read_buf[*read_pos..size]) as *mut _
                        as *mut [MaybeUninit<u8>])
                };
                let mut buf = ReadBuf::uninit(dst);
                let ptr = buf.filled().as_ptr();
                ready!(Pin::new(&mut *raw).poll_read(cx, &mut buf))?;
                assert_eq!(ptr, buf.filled().as_ptr());
                if buf.filled().is_empty() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected eof",
                    )));
                }
                *read_pos += buf.filled().len();
            } else {
                assert!(*read_pos == size);
                *read_pos = 0;
                return Poll::Ready(Ok(()));
            }
        }
    }
}
