# Gateway-Daemon (Go): wg0-Management + nft-Sets im Host-Netz-Namespace.
# Nur Standardbibliothek — keine Module-Downloads nötig.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -o /out/gateway ./cmd/gateway

# Runtime: wireguard-tools (wg, wg-quick), nftables, iproute2 (ip)
FROM alpine:3.20
RUN apk add --no-cache wireguard-tools nftables iproute2
COPY --from=build /out/gateway /usr/local/bin/gateway
ENTRYPOINT ["gateway"]
