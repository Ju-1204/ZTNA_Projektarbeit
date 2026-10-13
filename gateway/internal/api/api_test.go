package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakePeers struct {
	putCalls    map[string]string // device-ID -> "pubkey|wg_ip"
	deleteCalls []string
	syncCalls   int
	pubkey      string
	failPut     bool
}

func (f *fakePeers) PutPeer(id, pubkey, wgIP string) error {
	if f.failPut {
		return errors.New("put failed")
	}
	f.putCalls[id] = pubkey + "|" + wgIP
	return nil
}

func (f *fakePeers) DeletePeer(id string) error {
	f.deleteCalls = append(f.deleteCalls, id)
	return nil
}

func (f *fakePeers) Pubkey() string { return f.pubkey }

func (f *fakePeers) Sync() error {
	f.syncCalls++
	return nil
}

type fakeSets struct {
	calls map[string][]string // Set -> Clients
	fail  bool
}

func (f *fakeSets) SyncSet(set string, clients []string) error {
	if f.fail {
		return errors.New("set failed")
	}
	f.calls[set] = clients
	return nil
}

func newTestServer() (http.Handler, *fakePeers, *fakeSets) {
	peers := &fakePeers{putCalls: map[string]string{}, pubkey: "GATEWAYPUB"}
	sets := &fakeSets{calls: map[string][]string{}}
	return New(peers, sets), peers, sets
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealth(t *testing.T) {
	h, _, _ := newTestServer()
	rec := do(t, h, http.MethodGet, "/healthz", "")
	if rec.Code != http.StatusOK {
		t.Errorf("healthz = %d, will 200", rec.Code)
	}
}

func TestGetPubkey(t *testing.T) {
	h, _, _ := newTestServer()
	rec := do(t, h, http.MethodGet, "/pubkey", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("pubkey = %d, will 200", rec.Code)
	}
	var body struct {
		Pubkey string `json:"pubkey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("ungültiges JSON: %v", err)
	}
	if body.Pubkey != "GATEWAYPUB" {
		t.Errorf("pubkey = %q, will GATEWAYPUB", body.Pubkey)
	}
}

func TestPutAndDeletePeer(t *testing.T) {
	h, peers, _ := newTestServer()

	rec := do(t, h, http.MethodPut, "/peers/42", `{"pubkey":"PEERKEY1","wg_ip":"10.9.0.42"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT peer = %d: %s", rec.Code, rec.Body.String())
	}
	if got := peers.putCalls["42"]; got != "PEERKEY1|10.9.0.42" {
		t.Errorf("PutPeer(42) = %q", got)
	}

	rec = do(t, h, http.MethodDelete, "/peers/42", "")
	if rec.Code != http.StatusOK {
		t.Errorf("DELETE peer = %d", rec.Code)
	}
	if len(peers.deleteCalls) != 1 || peers.deleteCalls[0] != "42" {
		t.Errorf("DeletePeer = %v", peers.deleteCalls)
	}
}

func TestPutPeerRejectsBadBody(t *testing.T) {
	h, _, _ := newTestServer()
	// Ungültiger JSON-Body ist API-Verantwortung -> 400.
	// Die inhaltliche Validierung (wg_ip, pubkey) liegt im wireguard.Manager
	// und ist dort getestet (TestPutPeerValidatesInput).
	rec := do(t, h, http.MethodPut, "/peers/42", `kein json`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("ungültiger Body = %d, will 400", rec.Code)
	}
}

func TestPutPeerPropagatesError(t *testing.T) {
	h, peers, _ := newTestServer()
	peers.failPut = true

	rec := do(t, h, http.MethodPut, "/peers/42", `{"pubkey":"PEERKEY1","wg_ip":"10.9.0.42"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Fehler muss als 400 gemeldet werden, got %d", rec.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Error == "" {
		t.Error("Fehlermeldung darf nicht leer sein")
	}
}

func TestPutClients(t *testing.T) {
	h, _, sets := newTestServer()

	rec := do(t, h, http.MethodPut, "/service/svc_app_clients/clients", `{"clients":["10.9.0.10","10.9.0.11"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT clients = %d: %s", rec.Code, rec.Body.String())
	}
	got := sets.calls["svc_app_clients"]
	if len(got) != 2 || got[0] != "10.9.0.10" || got[1] != "10.9.0.11" {
		t.Errorf("SyncSet = %v", got)
	}
}

func TestPutClientsPropagatesError(t *testing.T) {
	h, _, sets := newTestServer()
	sets.fail = true

	rec := do(t, h, http.MethodPut, "/service/svc_app_clients/clients", `{"clients":["10.9.0.10"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Set-Fehler muss als 400 gemeldet werden, got %d", rec.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Error == "" {
		t.Error("Fehlermeldung darf nicht leer sein")
	}
}

func TestReload(t *testing.T) {
	h, peers, _ := newTestServer()
	rec := do(t, h, http.MethodPost, "/reload", "")
	if rec.Code != http.StatusOK || peers.syncCalls != 1 {
		t.Errorf("reload = %d (Sync-Aufrufe: %d), will 200/1", rec.Code, peers.syncCalls)
	}
}
