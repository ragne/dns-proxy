use tokio_native_tls::{TlsConnector, TlsStream};

use native_tls::TlsConnector as NativeTlsConnector;
use tokio::net::{TcpSocket, TcpStream};
use anyhow::Context;
use std::net::SocketAddr;
use anyhow::Result;
use crate::TCP_TIMEOUT;


/// Configuration for dns resolver
#[derive(Debug)]
pub(crate) struct Resolver {
    dns_name: String,
    addr: SocketAddr,
}

impl Resolver {
    /// Constructs new resolver from TLS certificate name and address
    pub fn new(dns_name: String, addr: SocketAddr) -> Self {
        Self { dns_name, addr }
    }

    /// Constructs TLS connection to the resolver and returns the TLS stream to send/receive bytes
    pub async fn connect(&self) -> Result<TlsStream<TcpStream>> {
        let sock = TcpSocket::new_v4()?;

        let stream = tokio::time::timeout(TCP_TIMEOUT, sock.connect(self.addr))
            .await
            .with_context(|| format!("Failed to connect to {}", self.addr))??;

        let tls_conn = NativeTlsConnector::new()?;
        Ok(TlsConnector::from(tls_conn)
            .connect(&self.dns_name, stream)
            .await?)
    }

    /// Constructs TLS connection to the resolver and returns splitted pair or read and write handles
    pub async fn connect_and_split(
        &self,
    ) -> Result<(
        tokio::io::ReadHalf<tokio_native_tls::TlsStream<tokio::net::TcpStream>>,
        tokio::io::WriteHalf<tokio_native_tls::TlsStream<tokio::net::TcpStream>>,
    )> {
        let tls_stream = self.connect().await?;
        Ok(tokio::io::split(tls_stream))
    }
}