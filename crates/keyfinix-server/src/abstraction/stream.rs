use std::{
    pin::Pin,
    task::{Context, Poll},
};

use axum::body::Bytes;
use futures::{ready, Stream};
use tokio::io::{AsyncRead, ReadBuf};

#[ouroboros::self_referencing]
/// An adaptor to use [`tokio::io::AsyncRead`] with [`futures::TryStream`]
pub struct AsyncReadAdapter<R: AsyncRead + Unpin> {
    inner: R,
    slice: Box<[u8]>,
    #[borrows(mut slice)]
    #[covariant]
    buffer: ReadBuf<'this>,
}

impl<R: AsyncRead + Unpin> AsyncReadAdapter<R> {
    /// Build a new `AsyncReadAdapter`
    pub fn build(inner: R, buffer_size: usize) -> Self {
        AsyncReadAdapterBuilder {
            inner,
            slice: vec![0; buffer_size].into_boxed_slice(),
            buffer_builder: |slice| ReadBuf::new(&mut *slice),
        }
        .build()
    }
}

impl<R: AsyncRead + Unpin> Stream for AsyncReadAdapter<R> {
    type Item = Result<Bytes, tokio::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        #[allow(unsafe_code)]
        unsafe {
            let this = self.get_unchecked_mut();

            let start_len = this.with_buffer(|buffer| buffer.filled().len());
            let poll = this.with_mut(|fields| {
                let inner = Pin::new_unchecked(fields.inner);
                inner.poll_read(cx, fields.buffer)
            });

            if let Err(e) = ready!(poll) {
                return Poll::Ready(Some(Err(e)));
            }

            this.with_buffer_mut(|buffer| {
                if buffer.filled().len() == start_len {
                    return Poll::Ready(None);
                }
                let ret = Poll::Ready(Some(Ok(buffer.filled().to_vec().into())));
                buffer.clear();
                ret
            })
        }
    }
}
