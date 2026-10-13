// Package api ist die interne Gateway-API (Leitfaden 4.2): nur für die
// Control Plane; im Deployment durch die nft-Input-Kette geschützt.
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// PeerSyncer abstrahiert das WireGuard-Management (wireguard.Manager).
type PeerSyncer interface {
	PutPeer(id, pubkey, wgIP string) error
	DeletePeer(id string) error
	Pubkey() string
	Sync() error
}

// SetSyncer abstrahiert das nft-Set-Management (nftsets.Manager).
type SetSyncer interface {
	SyncSet(set string, clients []string) error
}

type Server struct {
	peers PeerSyncer
	sets  SetSyncer
}

func New(peers PeerSyncer, sets SetSyncer) http.Handler {
	s := &Server{peers: peers, sets: sets}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /pubkey", s.handlePubkey)
	mux.HandleFunc("PUT /peers/{id}", s.handlePutPeer)
	mux.HandleFunc("DELETE /peers/{id}", s.handleDeletePeer)
	mux.HandleFunc("PUT /service/{set}/clients", s.handlePutClients)
	mux.HandleFunc("POST /reload", s.handleReload)
	return s.logMiddleware(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handlePubkey(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"pubkey": s.peers.Pubkey()})
}

func (s *Server) handlePutPeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Pubkey string `json:"pubkey"`
		WgIP   string `json:"wg_ip"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := s.peers.PutPeer(id, body.Pubkey, body.WgIP); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "peer gesetzt"})
}

func (s *Server) handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	if err := s.peers.DeletePeer(r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "peer entfernt"})
}

func (s *Server) handlePutClients(w http.ResponseWriter, r *http.Request) {
	set := r.PathValue("set")
	var body struct {
		Clients []string `json:"clients"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := s.sets.SyncSet(set, body.Clients); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"status": http.StatusOK, "clients": len(body.Clients)})
}

func (s *Server) handleReload(w http.ResponseWriter, _ *http.Request) {
	if err := s.peers.Sync(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "synchronisiert"})
}

// ---------------------------------------------------------------- Helpers

// statusRecorder merkt sich den Statuscode für das Zugriffslogging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s -> %d", r.Method, r.URL.Path, rec.status)
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("Antwort-Encoding fehlgeschlagen: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func readJSON(w http.ResponseWriter, r *http.Request, body any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("ungültiger JSON-Body: %w", err))
		return false
	}
	return true
}
