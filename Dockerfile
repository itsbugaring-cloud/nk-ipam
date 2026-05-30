FROM rust:1.87-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.toml
COPY src src
COPY migrations migrations
COPY static static

RUN cargo build --release

FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssl sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/netking-ipam /usr/local/bin/netking-ipam
COPY --from=builder /app/static /app/static
COPY --from=builder /app/migrations /app/migrations

ENV APP_HOST=0.0.0.0
ENV APP_PORT=8080
ENV DATABASE_URL=sqlite://data/netking.db

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl --fail http://127.0.0.1:8080/api/health || exit 1

CMD ["netking-ipam"]
