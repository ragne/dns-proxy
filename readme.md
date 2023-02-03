# DNS-proxy

A tool to proxy DNS request to a TLS-enabled resolver (e.g. 1.1.1.1:853)

## Production ready? 
No way! Use off-the-shelf solutions for that. **This is a toy.**

## Usage 

```
Usage: dns-proxy [OPTIONS]

Options:
  -u, --udp <UDP>
          UDP address to listen on [default: 0.0.0.0:5053]
  -t, --tcp <TCP>
          TCP address to listen on (optional)
  -n, --server-dns-name <SERVER_DNS_NAME>
          Domain name of DNS-over-TLS server for certificate checking (can be IP address) [default: 1.1.1.1]
  -s, --server-addr <SERVER_ADDR>
          Resolver IP address and port [default: 1.1.1.1:853]
  -h, --help
          Print help
```

## Language choice

I've chosen to write the tool in rust, because I've always wanted to try writing network services with async rust and this looked like a perfect opportunity!

### Crates

* `anyhow` for easy idiomatic error handling
* `clap` for parsing cmdline arguments
* `tokio` for async executor
* `tokio-native-tls` for delegating to native OS TLS functionality (OpenSSL on linux, etc)
* `tracing` as glorified logging facility
* `trust-dns-proto` to parse and construct DNS packets

## How it works

By the rules of the challenge you don't actually need to parse all the packets, you can just send them back and forward. That's what basically the tool does.
The current version does actually parse (inspect) packets and prints them on debug level.

### The TCP DNS packet

The TCP DNS message has 2 more bytes at the start of a packet as specified in [RFC](https://tools.ietf.org/html/rfc1035#section-4.2.2), this is handled automatically for clients.

### Limitations and future improvements

The current code is in dire need of a connection pool, right now each request spawns a new TLS connection which is very latency and resource heavy.
In the next release there will be a proper connection pool which should make the program much faster to respond.

Response cache is also not present, but that's a product of the current "proxy" design, technically the program does not know about which packets it forwards back and forth, thus caching is impossible.

Possible improvement is to actually utilize parsed messages and employ LRU cache with configurable amount of entries.

Currently there's no blacklist for bad actors as well.

#### Testing

Currently there are no integration tests. Good integration testing suite requires investing even more time, which I'm currently lacking.


## Deployment

The repository contains a dockerfile from which image could be built.

To build:
```shell
docker build -t dns-proxy .
```

To launch (listening on both UDP and TCP):
```
docker run --rm --name dns-proxy -p 5053:5053 -p 5053:5053/udp dns-proxy -t 0.0.0.0:5053
```

for command-line options see [usage](#usage) section.

You could deploy the program into kubernetes as well, it's stateless, so you can just throw it into `Deployment` and put it behind a `Service` and it should work well.



### Security concerns
If you hypothetically deploy that into your infrastructure you have to take a look at the code given current [limitations](#limitations-and-future-improvements). 

The main concern should've come from using a `Vec` which grows and can lead to a possibility of a DoS attack.

The packet parsing library comes with its own test suite and was battle-tested, however the program currently does not block the bad-behaving clients, which is probably a requirements for deploying in any real-world scenario where you don't trust your clients.

You can also run a tool like [dnsblast](https://github.com/jedisct1/dnsblast) against the `dns-proxy` to test how it behaves. 


### Performance

Not very bad, but isn't decent. On my machine it takes around ~200ms to establish a TLS connection to a resolver, send a request and receive a response. You can test it with `dig` like that:

```shell
dig @127.0.0.1 -p 5053 google.com
```
for TCP proto add `+tcp` like that:

```shell
dig @127.0.0.1 -p 5053 google.com +tcp
```