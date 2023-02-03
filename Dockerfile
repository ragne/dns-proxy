ARG app_dir=/app/

FROM rust AS builder

# copy code files
COPY Cargo.toml Cargo.lock ${app_dir}
COPY /src/ ${app_dir}/src/

# build code
WORKDIR ${app_dir}
RUN --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,sharing=private,target=${app_dir}/target \
    cargo build --release

# runtime
FROM debian:11 AS runtime

# set default logging to info
ENV RUST_LOG=info

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder ${app_dir}/target/release/dns-proxy /usr/local/bin/dns-proxy

ENTRYPOINT ["/usr/local/bin/dns-proxy"]
