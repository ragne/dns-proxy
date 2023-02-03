pub mod cmdline;
mod resolver;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use cmdline::Options;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, UdpSocket},
};

use resolver::Resolver;
use tokio::net::TcpStream;

use trust_dns_proto::{
    op::{Message, OpCode, ResponseCode},
    serialize::binary::BinDecodable,
};

// TCP Timeout, hardcoded to 5 seconds for now
const TCP_TIMEOUT: Duration = Duration::from_secs(5);
// TCP packets prepend 2byte lenght field, see RFC https://tools.ietf.org/html/rfc1035#section-4.2.2
const TCP_DNS_LENGHT_OFFSET: usize = 2;

/// Tries to read original (request) DNS Message from buffer of bytes
/// and construct the ServFail response from original id
fn get_error_response(incoming: &[u8]) -> Result<Message> {
    let req_id = Message::from_bytes(incoming)?.id();
    tracing::trace!("Constructing ServFail message from original id {}", req_id);
    let mut m = Message::error_msg(req_id, OpCode::Query, ResponseCode::ServFail);
    m.set_id(req_id);
    m.set_response_code(ResponseCode::ServFail);
    Ok(m)
}

// set loglevel to info if there's no RUST_LOG env var present
// work around https://github.com/tokio-rs/tracing/issues/735
fn set_default_logging_level() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    set_default_logging_level();
    tracing_subscriber::fmt::init();
    let options = Options::parse();

    let udp_listener = UdpSocket::bind(options.udp).await?;

    let opts = options.clone();
    let mut fut_handles = Vec::with_capacity(2);

    let udp_server_fut_handle: tokio::task::JoinHandle<std::result::Result<(), anyhow::Error>> =
        tokio::spawn(async move {
            let mut buf = [0; 1024];
            loop {
                let (len, addr) = udp_listener.recv_from(&mut buf).await.unwrap();
                tracing::debug!("{:?} bytes received from {:?}", len, addr);

                match proxy_udp_request(&buf, len, &opts).await {
                    Ok(resp) => {
                        udp_listener.send_to(&resp, addr).await?;
                    }
                    Err(e) => {
                        tracing::error!("The request failed with {}.", e);
                        // the request might be maliciously crafted or just bogus, if we cannot parse it, just ignore
                        if let Ok(err_msg) = get_error_response(&buf) {
                            timeout(
                                Duration::from_millis(500),
                                udp_listener.send_to(&err_msg.to_vec().expect("infallible"), addr),
                            )
                            .await
                            .ok();
                        }
                    }
                };
            }
        });

    fut_handles.push(udp_server_fut_handle);

    tracing::info!("Listening on: {}", options.udp);
    tracing::info!(
        "Proxying to: {}(name: {})",
        options.server_addr,
        options.server_dns_name
    );

    if let Some(tcp_addr) = options.tcp {
        let listener = TcpListener::bind(tcp_addr).await?;
        tracing::info!("TCP server is listening on: {}", tcp_addr);

        tokio::spawn(async move {
            while let Ok((inbound, _)) = listener.accept().await {
                let peer_addr = inbound
                    .peer_addr()
                    .map_or("unknown".to_string(), |r| r.to_string());
                tracing::debug! {
                    peer_addr,
                    "accepted new connection from"
                };
                let proxied = proxy_tcp_request(
                    inbound,
                    options.server_dns_name.to_owned(),
                    options.server_addr.to_owned(),
                );
                tokio::spawn(proxied);
            }
            Ok::<(), anyhow::Error>(())
        });
    }

    // register signal handler and abort all pending tasks if signal is received
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            tracing::warn!("ctrl+c received, cancelling pending tasks..");
            for h in &fut_handles {
                h.abort();
            }
        }
        Err(err) => {
            eprintln!("Unable to listen for shutdown signal: {err}");
            std::process::exit(2);
        }
    }
    for h in fut_handles {
        match h.await {
            Ok(val) => {
                if val.is_err() {
                    // unwrapping option is safe here, we checked above
                    tracing::warn!("Got an error: {}", val.err().unwrap())
                }
            }
            Err(err) => {
                if !err.is_cancelled() {
                    tracing::error!("The proxy failed with {}.", err);
                } else {
                    eprintln!("Got error: {err}");
                }
            }
        }
    }

    Ok(())
}

/// Proxy incoming udp packets to the server specified in options
///
/// This function handles the prepending/removing TCP-specific lenght bytes automatically
/// returns correct response packet
async fn proxy_udp_request(incoming: &[u8], len: usize, options: &Options) -> Result<Vec<u8>> {
    let resolver = Resolver::new(options.server_dns_name.to_string(), options.server_addr);

    let mut tls_stream = resolver.connect().await?;
    // prepend the length
    let mut pkt = Vec::with_capacity(len + TCP_DNS_LENGHT_OFFSET);
    pkt.write_u16(len.try_into().unwrap_or(0)).await?;
    pkt.write_all(incoming).await?;

    tls_stream.write_all(&pkt).await?;
    tls_stream.flush().await?;
    let mut buf = Vec::with_capacity(1024);
    let read_len = tls_stream.read_buf(&mut buf).await?;

    if read_len == 0 {
        // server closed the connection. Either we constructed a bogus request or something went wrong
        // have nothing else to do than report a ServFail
        let r = get_error_response(incoming)?
            .to_vec()
            .expect("This shoudn't fail");
        return Ok(r);
    }

    buf.truncate(read_len);
    // skip prepended lenght in tcp packet
    Ok(buf.into_iter().skip(TCP_DNS_LENGHT_OFFSET).collect())
}

async fn process_packets(
    mut rh: impl AsyncRead + Unpin,
    mut wh: impl AsyncWrite + Unpin,
    offset: usize,
) -> Result<()> {
    // fixme: this is suspectible to DoS, good for PoC
    loop {
        let mut buf = vec![0; 1024];
        let read_len = rh.read(&mut buf).await?;
        tracing::debug!("read {} bytes into buffer", read_len);

        if read_len == 0 {
            break;
        }

        if let Ok(m) = Message::from_bytes(&buf[offset..]) {
            tracing::debug!("Decoded message: {:?}", m);
        } else {
            tracing::debug!("Cannot decode message, probably a partial read.");
        }

        tracing::trace!("about to write {} bytes to dst socket", read_len);
        let write_len = wh.write(&buf[..read_len]).await?;
        tracing::trace!("actually wrote {} bytes to dst socket", write_len);

        wh.flush().await?;
    }

    Ok(())
}

#[allow(clippy::unused_io_amount)]
// Proxying tcp request from inbound stream to the resolver
async fn proxy_tcp_request(
    mut inbound: TcpStream,
    dns_name: String,
    dns_addr: SocketAddr,
) -> Result<()> {
    let resolver = Resolver::new(dns_name, dns_addr);

    let local_addr = &inbound.local_addr()?;
    let peer_addr = &inbound.peer_addr()?;

    let (mut ri, mut wi) = inbound.split();
    match resolver.connect_and_split().await {
        Ok((mut ro, mut wo)) => {
            // we spawn two futures there, loosely based on this example from tokio: https://github.com/tokio-rs/tokio/blob/master/examples/proxy.rs
            let client_to_server = async {
                process_packets(&mut ri, &mut wo, TCP_DNS_LENGHT_OFFSET).await?;
                tracing::debug!("shutting down connection to {:?}", peer_addr);

                // one type annotation for two futures is enough, compiler is smart to interfere the return type of the next future in `try_join`
                Ok::<(), anyhow::Error>(wo.shutdown().await?)
            };

            let server_to_client = async {
                process_packets(&mut ro, &mut wi, TCP_DNS_LENGHT_OFFSET).await?;
                tracing::debug!("shutting down connection to {:?}", local_addr);

                Ok(wi.shutdown().await?)
            };

            tokio::try_join!(client_to_server, server_to_client)?;
        }
        Err(e) => {
            // send a servfail if connection failed
            tracing::error!("Couldn't connect to {}, error: {}", dns_addr, e);
            let mut buf = vec![0; 1024];
            // we're doing a partial read there, most DNS messages could fit into 1024byte buffer.
            // if message fails to parse, we'll just close connection
            ri.read(&mut buf).await?;
            if let Ok(err_msg) = get_error_response(&buf[TCP_DNS_LENGHT_OFFSET..])?.to_vec() {
                let mut msg = Vec::with_capacity(buf.len() + TCP_DNS_LENGHT_OFFSET);
                msg.write_u16(err_msg.len().try_into().unwrap_or(0)).await?;
                msg.extend(&err_msg);
                wi.write_all(&msg).await?;
            } else {
                tracing::warn!("Failed to parse a message, closing connection!");
            }
            wi.shutdown().await?;
            return Ok(());
        }
    }

    Ok(())
}
