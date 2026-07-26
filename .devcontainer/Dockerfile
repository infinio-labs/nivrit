FROM mcr.microsoft.com/devcontainers/rust:1-bookworm

ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV PATH=$CARGO_HOME/bin:$PATH

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# WebAssembly target for nivrit-web-crypto
RUN rustup target add wasm32-unknown-unknown

# wasm-pack builds the crypto WASM used by the web frontend
RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# sqlx-cli runs migrations against the dev Postgres container.
# This compiles once during the image build; subsequent rebuilds are cached.
RUN cargo install sqlx-cli --version 0.9.0 --no-default-features --features native-tls,postgres

# Give the vscode user a local Cargo home for cached registries and artifacts
RUN mkdir -p /home/vscode/.cargo && chown -R vscode:vscode /home/vscode/.cargo

USER vscode
