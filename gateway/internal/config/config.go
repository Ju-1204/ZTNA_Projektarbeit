package config

import "os"

// Config fasst die Umgebungsvariablen des Gateway-Daemons zusammen
// (docker-compose.yml, Leitfaden 4.1).
type Config struct {
	ListenAddr string // interne API (default 127.0.0.1:9090 — im Deployment via nft geschützt)
	Iface      string // WireGuard-Interface
	Addr       string // Tunnel-Adresse des Gateways, z. B. 10.9.0.1/24
	ListenPort int    // UDP-Port (51820; bei Campus-UDP-Filter auf 443/53 umstellbar)
	NftFamily  string // nftables-Familie der Sets (inet)
	NftTable   string // nftables-Tabelle der Sets (waypoint)
	ConfPath   string // wg-quick-Konfiguration
	StatePath  string // Persistenz von Peers + Private Key über Container-Neustarts
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func FromEnv() Config {
	port := getenv("WG_LISTEN_PORT", "51820")
	return Config{
		ListenAddr: getenv("LISTEN_ADDR", "127.0.0.1:9090"),
		Iface:      getenv("WG_IFACE", "wg0"),
		Addr:       getenv("WG_ADDR", "10.9.0.1/24"),
		ListenPort: atoiDefault(port, 51820),
		NftFamily:  getenv("NFT_FAMILY", "inet"),
		NftTable:   getenv("NFT_TABLE", "waypoint"),
		ConfPath:   getenv("WG_CONF_PATH", "/etc/wireguard/wg0.conf"),
		StatePath:  getenv("STATE_PATH", "/etc/wireguard/gateway-state.json"),
	}
}

func atoiDefault(s string, def int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return def
	}
	return n
}
