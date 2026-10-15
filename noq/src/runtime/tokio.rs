use std::{
    fmt::Debug,
    future::Future,
    io,
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Instant,
};

use tokio::{
    io::Interest,
    time::{Sleep, sleep_until},
};

use super::{AsyncTimer, AsyncUdpSocket, Runtime, UdpSenderHelper, UdpSenderHelperSocket};

/// A noq runtime for Tokio
#[derive(Debug)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn new_timer(&self, t: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(sleep_until(t.into()))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(&self, sock: std::net::UdpSocket) -> io::Result<Box<dyn AsyncUdpSocket>> {
        Ok(Box::new(UdpSocket {
            inner: Arc::new(udp::UdpSocketState::new((&sock).into())?),
            io: Arc::new(tokio::net::UdpSocket::from_std(sock)?),
        }))
    }

    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
}

impl AsyncTimer for Sleep {
    fn reset(self: Pin<&mut Self>, t: Instant) {
        Self::reset(self, t.into())
    }
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        Future::poll(self, cx)
    }
}

#[derive(Debug, Clone)]
struct UdpSocket {
    io: Arc<tokio::net::UdpSocket>,
    inner: Arc<udp::UdpSocketState>,
}

impl UdpSenderHelperSocket for UdpSocket {
    fn max_transmit_segments(&self) -> NonZeroUsize {
        self.inner.max_gso_segments()
    }

    fn try_send(&self, transmit: &udp::Transmit<'_>) -> io::Result<()> {
        // OpenBSD fails a non-blocking UDP send with EAGAIN while another thread holds
        // the socket's send buffer lock (`sosend` does not sleep for it under
        // MSG_DONTWAIT), never because that buffer is full: UDP does not queue there.
        // Clearing write readiness on such an error, as `try_io` does, waits for a
        // kqueue write event that a UDP socket never raises again, stalling every
        // sender on the socket for good. Retry instead, and drop the datagram if the
        // contention persists, as for other send errors.
        #[cfg(target_os = "openbsd")]
        {
            for _ in 0..OPENBSD_SEND_RETRIES {
                match self.inner.send((&self.io).into(), transmit) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
                    result => return result,
                }
            }
            Ok(())
        }
        #[cfg(not(target_os = "openbsd"))]
        self.io.try_io(Interest::WRITABLE, || {
            self.inner.send((&self.io).into(), transmit)
        })
    }
}

/// How often [`UdpSocket::try_send`] retries a send that lost the race for the
/// socket's send buffer lock on OpenBSD.
#[cfg(target_os = "openbsd")]
const OPENBSD_SEND_RETRIES: usize = 64;

impl AsyncUdpSocket for UdpSocket {
    fn create_sender(&self) -> Pin<Box<dyn super::UdpSender>> {
        Box::pin(UdpSenderHelper::new(self.clone(), |socket: &Self| {
            let socket = socket.clone();
            async move { socket.io.writable().await }
        }))
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(res) = self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        self.inner.gro_segments()
    }
}
