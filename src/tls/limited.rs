use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;

pub(super) struct LimitedTcp {
    stream: TcpStream,
    peer: IpAddr,
    _permit: OwnedSemaphorePermit,
}

impl LimitedTcp {
    pub(super) const fn new(stream: TcpStream, peer: IpAddr, permit: OwnedSemaphorePermit) -> Self {
        Self {
            stream,
            peer,
            _permit: permit,
        }
    }

    pub(super) const fn peer(&self) -> IpAddr {
        self.peer
    }
}

impl AsyncRead for LimitedTcp {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for LimitedTcp {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::LimitedTcp;
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Semaphore;

    #[tokio::test]
    #[allow(clippy::significant_drop_tightening)]
    async fn permit_is_held_for_connection_lifetime() -> Result<(), Box<dyn std::error::Error>> {
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let _client = client?;
        let (server, peer) = accepted?;
        let limited = LimitedTcp::new(server, peer.ip(), permit);

        assert!(semaphore.try_acquire().is_err());
        drop(limited);
        let _replacement = semaphore.try_acquire()?;
        Ok(())
    }
}
