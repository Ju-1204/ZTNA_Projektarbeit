package wireguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner liefert für jeden Befehl eine canned Antwort oder einen Fehler.
type fakeRunner struct {
	calls   []string
	failOn  map[string]bool
	resps   map[string]string
	stdins  []string
}

func (f *fakeRunner) Run(stdin, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	f.stdins = append(f.stdins, stdin)
	if f.failOn[cmd] {
		return "", errFailed{}
	}
	return f.resps[cmd], nil
}

type errFailed struct{}

func (errFailed) Error() string { return "command failed" }

func newTestManager(t *testing.T) (*Manager, *fakeRunner, string, string) {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "wg0.conf")
	state := filepath.Join(dir, "state.json")
	r := &fakeRunner{
		resps: map[string]string{
			"wg genkey":           "TESTPRIVKEY\n",
			"wg pubkey":           "TESTPUBKEY\n",
			"ip link show wg0":    "",
			"wg-quick up wg0":     "",
			"wg syncconf wg0":     "", // wird mit tmp-Datei aufgerufen, s. calls-Prüfung unten
		},
	}
	m := NewManager(r, "wg0", "10.9.0.1/24", 51820, conf, state)
	return m, r, conf, state
}

func TestEnsureGeneratesKeysAndWritesConf(t *testing.T) {
	m, r, conf, state := newTestManager(t)

	if err := m.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	if got := m.Pubkey(); got != "TESTPUBKEY" {
		t.Errorf("Pubkey = %q, will TESTPUBKEY", got)
	}
	data, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("Konfigurationsdatei nicht geschrieben: %v", err)
	}
	want := []string{
		"[Interface]",
		"Address = 10.9.0.1/24",
		"ListenPort = 51820",
		"PrivateKey = TESTPRIVKEY",
	}
	for _, w := range want {
		if !strings.Contains(string(data), w) {
			t.Errorf("wg0.conf enthält nicht %q:\n%s", w, data)
		}
	}
	if _, err := os.Stat(state); err != nil {
		t.Errorf("State-Datei nicht geschrieben: %v", err)
	}
	// genkey (kein stdin) und pubkey (privater Key am stdin)
	if r.stdins[0] != "" || !strings.Contains(r.stdins[1], "TESTPRIVKEY") {
		t.Errorf("stdin-Erwartung verletzt: %q", r.stdins)
	}
}

func TestEnsureBringsInterfaceUp(t *testing.T) {
	m, r, _, _ := newTestManager(t)
	r.failOn = map[string]bool{"ip link show wg0": true} // Interface existiert noch nicht

	if err := m.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	found := false
	for _, c := range r.calls {
		if c == "wg-quick up wg0" {
			found = true
		}
	}
	if !found {
		t.Errorf("wg-quick up wurde nicht aufgerufen: %v", r.calls)
	}
}

func TestPutPeerRendersAndSyncsAtomically(t *testing.T) {
	m, _, conf, _ := newTestManager(t)
	if err := m.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	if err := m.PutPeer("42", "PEERKEY1", "10.9.0.42"); err != nil {
		t.Fatalf("PutPeer: %v", err)
	}
	data, _ := os.ReadFile(conf)
	if !strings.Contains(string(data), "PublicKey = PEERKEY1") ||
		!strings.Contains(string(data), "AllowedIPs = 10.9.0.42/32") {
		t.Errorf("Peer nicht in wg0.conf:\n%s", data)
	}

	// Rotation: gleiche ID, neuer Key -> 1:1 Ersatz, kein zweiter Peer-Block
	if err := m.PutPeer("42", "PEERKEY2", "10.9.0.42"); err != nil {
		t.Fatalf("PutPeer (Rotation): %v", err)
	}
	data, _ = os.ReadFile(conf)
	if strings.Count(string(data), "[Peer]") != 1 {
		t.Errorf("Nach Rotation muss genau 1 Peer-Block existieren:\n%s", data)
	}
	if strings.Contains(string(data), "PEERKEY1") {
		t.Errorf("Alter Key muss aus der Konfiguration verschwinden:\n%s", data)
	}

	// Löschen
	if err := m.DeletePeer("42"); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
	data, _ = os.ReadFile(conf)
	if strings.Contains(string(data), "PEERKEY2") {
		t.Errorf("Peer muss nach DeletePeer aus der Konfiguration verschwinden:\n%s", data)
	}
}

func TestDeletePeerIdempotent(t *testing.T) {
	m, _, _, _ := newTestManager(t)
	if err := m.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := m.DeletePeer("gibtsnicht"); err != nil {
		t.Errorf("DeletePeer für unbekannte ID muss idempotent sein, got %v", err)
	}
}

func TestPutPeerValidatesInput(t *testing.T) {
	m, _, _, _ := newTestManager(t)
	if err := m.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := m.PutPeer("1", "PEERKEY1", "keine-ip"); err == nil {
		t.Error("ungültige wg_ip muss abgelehnt werden")
	}
	if err := m.PutPeer("", "PEERKEY1", "10.9.0.42"); err == nil {
		t.Error("leere ID muss abgelehnt werden")
	}
}

func TestSyncconfStripsQuickDirectives(t *testing.T) {
	conf := "[Interface]\nAddress = 10.9.0.1/24\nListenPort = 51820\nPrivateKey = K\n# device 42\n\n[Peer]\nPublicKey = P\nAllowedIPs = 10.9.0.42/32\n"
	stripped := stripQuickDirectives(conf)
	if strings.Contains(stripped, "Address =") || strings.Contains(stripped, "# device") {
		t.Errorf("wg-quick-Direktiven/Kommentare müssen entfernt werden:\n%s", stripped)
	}
	if !strings.Contains(stripped, "PrivateKey = K") || !strings.Contains(stripped, "AllowedIPs = 10.9.0.42/32") {
		t.Errorf("wg-relevante Direktiven müssen bleiben:\n%s", stripped)
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	m, _, _, state := newTestManager(t)
	if err := m.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := m.PutPeer("7", "PEERKEY7", "10.9.0.7"); err != nil {
		t.Fatalf("PutPeer: %v", err)
	}

	// Neuer Manager, gleiche State-Datei: Peers müssen zurückkommen
	dir := filepath.Dir(state)
	r2 := &fakeRunner{resps: map[string]string{
		"wg pubkey":        "TESTPUBKEY\n",
		"ip link show wg0": "",
		"wg syncconf wg0":  "",
	}}
	m2 := NewManager(r2, "wg0", "10.9.0.1/24", 51820, filepath.Join(dir, "wg0.conf"), state)
	if err := m2.Ensure(); err != nil {
		t.Fatalf("Ensure (Neustart): %v", err)
	}
	if m2.Pubkey() != "TESTPUBKEY" {
		t.Errorf("Pubkey nach Neustart = %q", m2.Pubkey())
	}
	if err := m2.DeletePeer("7"); err != nil {
		t.Fatalf("Peer 7 muss nach Neustart bekannt sein: %v", err)
	}
}
