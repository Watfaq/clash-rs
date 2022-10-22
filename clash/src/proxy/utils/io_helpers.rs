use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, Future, Sink, Stream};

enum TransferState {
    Running(u64),
    ShuttingDown(u64),
    Done(u64),
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b: TransferState,
    b_to_a: TransferState,
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<u64>>
where
    A: Stream + Unpin,
    B: Sink<A::Item, Error = io::Error> + Unpin,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running(n_pkt) => {
                match r.as_mut().poll_next(cx) {
                    Poll::Ready(item) => match item {
                        Some(item) => {
                            ready!(w.as_mut().poll_ready(cx))?;
                            w.as_mut().start_send(item);
                            *state = TransferState::Running(*n_pkt + 1);
                        }
                        None => {
                            ready!(w.as_mut().poll_flush(cx))?;
                            *state = TransferState::ShuttingDown(*n_pkt);
                        }
                    },
                    Poll::Pending => *state = TransferState::Running(*n_pkt),
                };
            }
            TransferState::ShuttingDown(count) => {
                ready!(w.as_mut().poll_close(cx));

                *state = TransferState::Done(*count);
            }
            TransferState::Done(count) => return Poll::Ready(Ok(*count)),
        }
    }
}

impl<'a, A, B> Future for CopyBidirectional<'a, A, B>
where
    A: Stream + Sink<B::Item, Error = io::Error> + Unpin + Send,
    B: Stream + Sink<A::Item, Error = io::Error> + Unpin + Send,
{
    type Output = io::Result<(u64, u64)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Unpack self into mut refs to each field to avoid borrow check issues.
        let CopyBidirectional {
            a,
            b,
            a_to_b,
            b_to_a,
        } = &mut *self;

        let a_to_b = transfer_one_direction(cx, a_to_b, &mut *a, &mut *b)?;
        let b_to_a = transfer_one_direction(cx, b_to_a, &mut *b, &mut *a)?;

        // It is not a problem if ready! returns early because transfer_one_direction for the
        // other direction will keep returning TransferState::Done(count) in future calls to poll
        let a_to_b = ready!(a_to_b);
        let b_to_a = ready!(b_to_a);

        Poll::Ready(Ok((a_to_b, b_to_a)))
    }
}

/// Copies data in both directions between `a` and `b`.
///
/// This function returns a future that will read from both streams,
/// writing any data read to the opposing stream.
/// This happens in both directions concurrently.
///
/// If an EOF is observed on one stream, [`shutdown()`] will be invoked on
/// the other, and reading from that stream will stop. Copying of data in
/// the other direction will continue.
///
/// The future will complete successfully once both directions of communication has been shut down.
/// A direction is shut down when the reader reports EOF,
/// at which point [`shutdown()`] is called on the corresponding writer. When finished,
/// it will return a tuple of the number of bytes copied from a to b
/// and the number of bytes copied from b to a, in that order.
///
/// [`shutdown()`]: crate::io::AsyncWriteExt::shutdown
///
/// # Errors
///
/// The future will immediately return an error if any IO operation on `a`
/// or `b` returns an error. Some data read from either stream may be lost (not
/// written to the other stream) in this case.
///
/// # Return value
///
/// Returns a tuple of bytes copied `a` to `b` and bytes copied `b` to `a`.

pub async fn copy_bidirectional<A, B, Item>(
    a: &mut A,
    b: &mut B,
) -> Result<(u64, u64), std::io::Error>
where
    A: Stream<Item = Item> + Sink<Item, Error = io::Error> + Unpin + Send,
    B: Stream<Item = Item> + Sink<Item, Error = io::Error> + Unpin + Send,
{
    CopyBidirectional {
        a,
        b,
        a_to_b: TransferState::Running(0),
        b_to_a: TransferState::Running(0),
    }
    .await
}
