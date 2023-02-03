use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser, Clone, Debug)]
pub struct Options {
    /// UDP address to listen on
    #[clap(long, short, default_value = "0.0.0.0:5053")]
    pub udp: SocketAddr,

    /// TCP address to listen on (optional)
    #[clap(long, short)]
    pub tcp: Option<SocketAddr>,

    /// Domain name of DNS-over-TLS server for certificate checking (can be IP address)
    #[clap(long, short = 'n', default_value = "8.8.8.8")]
    pub server_dns_name: String,

    /// Resolver IP address and port
    #[clap(long, short, default_value = "8.8.8.8:853")]
    pub server_addr: SocketAddr,
}
