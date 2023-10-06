use std::io::Error;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

#[pin_project]
pub struct XProto {
    #[pin]
    inner: TcpStream,
}

impl XProto {
    pub fn new(inner: TcpStream) -> Self {
        Self { inner }
    }
}

impl AsyncRead for XProto {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match ready!(self.project().inner.poll_read(cx, buf)) {
            Err(e) => Poll::Ready(Err(e)),
            Ok(()) => {
                buf.filled_mut()
                    .iter_mut()
                    .filter(|x| **x >= 88)
                    .for_each(|x| *x -= 88);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for XProto {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let new_buf = buf
            .iter()
            .map(|x| if *x <= 167 { *x + 88 } else { *x })
            .collect::<Vec<_>>();
        self.project().inner.poll_write(cx, &new_buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().inner.poll_shutdown(cx)
    }
}
