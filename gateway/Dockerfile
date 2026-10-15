# Gateway-Daemon (Go): wg0-Management + nft-Sets im Host-Netz-Namespace.
# Nur Standardbibliothek — keine Module-Downloads nötig.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -o /out/gateway ./cmd/gateway

# Runtime: Debian trixie statt Alpine — trixie liefert eine aktuelle
# nftables-Version; alpine:3.20 (nft 1.0.x) segfaultete auf Kernel 7.0
# bei 'nft -j list set'. Debian-Userland passt ausserdem zum Ubuntu-Host.
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends wireguard-tools nftables iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/gateway /usr/local/bin/gateway
ENTRYPOINT ["gateway"]
