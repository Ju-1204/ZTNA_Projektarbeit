// Gateway-Daemon: verwaltet wg0-Peers und nft-Sets des ZTNA-Waypoints.
package main

import (
	"log"
	"net/http"
	"time"

	"ztna-gateway/internal/api"
	"ztna-gateway/internal/config"
	"ztna-gateway/internal/nftsets"
	"ztna-gateway/internal/wireguard"
)

func main() {
	cfg := config.FromEnv()

	runner := wireguard.ExecRunner{}
	wg := wireguard.NewManager(runner, cfg.Iface, cfg.Addr, cfg.ListenPort, cfg.ConfPath, cfg.StatePath)
	if err := wg.Ensure(); err != nil {
		log.Fatalf("wg0-Initialisierung fehlgeschlagen: %v", err)
	}
	sets := nftsets.NewManager(runner, cfg.NftFamily, cfg.NftTable)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           api.New(wg, sets),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("gateway: lauscht auf %s (iface %s, UDP %d)", cfg.ListenAddr, cfg.Iface, cfg.ListenPort)
	log.Fatal(srv.ListenAndServe())
}
