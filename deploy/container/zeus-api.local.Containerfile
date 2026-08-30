FROM docker.io/library/rust:1.97.1-bookworm AS build
WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY vendor vendor
COPY crates/zeus-core crates/zeus-core
COPY apps/zeus-api apps/zeus-api
COPY db/migrations db/migrations
RUN cargo build --locked --offline --release -p zeus-api

FROM docker.io/library/debian:bookworm-slim AS runtime
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /workspace/target/release/zeus-api /usr/local/bin/zeus-api
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/zeus-api"]
CMD ["serve"]
