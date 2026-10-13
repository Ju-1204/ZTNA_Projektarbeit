// Package wireguard verwaltet wg0 und seine Peers.
//
// Hot-Reload ohne Sessionabriss (Leitfaden 4.2): Peer-Änderungen werden in die
// Konfigurationsdatei geschrieben und per 'wg syncconf' angewendet — laufende
// Verbindungen bleiben bestehen. Rotation ersetzt einen Peer atomar (R12).
package wireguard

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Runner abstrahiert Prozess-Aufrufe (für Tests ersetzbar).
type Runner interface {
	Run(stdin, name string, args ...string) (string, error)
}

// ExecRunner führt Befehle wirklich aus.
type ExecRunner struct{}

func (ExecRunner) Run(stdin, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...) //nolint:gosec // Argumente kommen aus validierter Config
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Peer ist ein WireGuard-Peer mit der Tunnel-IP des Geräts.
type Peer struct {
	Pubkey string `json:"pubkey"`
	WgIP   string `json:"wg_ip"`
}

type stateFile struct {
	PrivateKey string           `json:"private_key"`
	Peers      map[string]Peer  `json:"peers"`
}

// Manager hält den Peer-Stand und synchronisiert wg0.
type Manager struct {
	mu        sync.Mutex
	runner    Runner
	iface     string
	addr      string
	listen    int
	confPath  string
	statePath string

	privkey string
	pubkey  string
	peers   map[string]Peer // device-ID -> Peer
}

func NewManager(r Runner, iface, addr string, listenPort int, confPath, statePath string) *Manager {
	return &Manager{
		runner:    r,
		iface:     iface,
		addr:      addr,
		listen:    listenPort,
		confPath:  confPath,
		statePath: statePath,
		peers:     map[string]Peer{},
	}
}

// Ensure initialisiert den Manager: Zustand laden oder Schlüssel generieren,
// Interface hochfahren, Konfiguration anwenden.
func (m *Manager) Ensure() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.loadState(); err != nil {
		return err
	}
	if m.privkey == "" {
		key, err := m.runner.Run("", "wg", "genkey")
		if err != nil {
			return fmt.Errorf("wg genkey: %w", err)
		}
		m.privkey = strings.TrimSpace(key)
	}
	pub, err := m.runner.Run(m.privkey, "wg", "pubkey")
	if err != nil {
		return fmt.Errorf("wg pubkey: %w", err)
	}
	m.pubkey = strings.TrimSpace(pub)

	if err := m.writeConf(); err != nil {
		return err
	}
	if _, err := m.runner.Run("", "ip", "link", "show", m.iface); err != nil {
		if _, err := m.runner.Run("", "wg-quick", "up", m.iface); err != nil {
			return fmt.Errorf("wg-quick up %s: %w", m.iface, err)
		}
	}
	if err := m.saveState(); err != nil {
		return err
	}
	return m.syncconf()
}

// Pubkey liefert den öffentlichen Schlüssel von wg0 (für Client-Profile).
func (m *Manager) Pubkey() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pubkey
}

// PutPeer legt einen Peer an bzw. ersetzt ihn atomar (Rotation, R12).
func (m *Manager) PutPeer(id, pubkey, wgIP string) error {
	if id == "" || pubkey == "" || net.ParseIP(wgIP) == nil {
		return fmt.Errorf("ungültige Peer-Daten: id=%q wg_ip=%q", id, wgIP)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	old, existed := m.peers[id]
	m.peers[id] = Peer{Pubkey: pubkey, WgIP: wgIP}
	if err := m.saveState(); err != nil {
		if existed {
			m.peers[id] = old
		} else {
			delete(m.peers, id)
		}
		return err
	}
	if err := m.writeConf(); err != nil {
		return err
	}
	return m.syncconf() // Kernel-Update erst hier: atomarer Ersatz, kein Zeitfenster
}

// DeletePeer entfernt einen Peer (idempotent, falls er nicht existiert).
func (m *Manager) DeletePeer(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.peers[id]; !ok {
		return nil
	}
	delete(m.peers, id)
	if err := m.saveState(); err != nil {
		return err
	}
	if err := m.writeConf(); err != nil {
		return err
	}
	return m.syncconf()
}

// Sync wendet die Konfigurationsdatei erneut an (POST /reload).
func (m *Manager) Sync() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncconf()
}

// syncconf setzt den Peer-Stand im Kernel — entspricht
// 'wg syncconf wg0 <(wg-quick strip wg0)' ohne Sessionabriss.
func (m *Manager) syncconf() error {
	stripped := stripQuickDirectives(m.renderConf(false))
	tmp, err := os.CreateTemp("", "wg0-sync-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(stripped); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if _, err := m.runner.Run("", "wg", "syncconf", m.iface, tmp.Name()); err != nil {
		return fmt.Errorf("wg syncconf %s: %w", m.iface, err)
	}
	return nil
}

// renderConf erzeugt die wg-quick-Konfiguration; mit full=true inklusive
// Address (für die Datei), sonst nur wg-relevante Direktiven (für syncconf).
func (m *Manager) renderConf(full bool) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	if full {
		fmt.Fprintf(&b, "Address = %s\n", m.addr)
	}
	fmt.Fprintf(&b, "ListenPort = %d\n", m.listen)
	fmt.Fprintf(&b, "PrivateKey = %s\n", m.privkey)

	// Sortierung für deterministische Ausgaben (Tests, Diff-Freundlichkeit)
	ids := make([]string, 0, len(m.peers))
	for id := range m.peers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := m.peers[id]
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "# device %s\n", id)
		fmt.Fprintf(&b, "PublicKey = %s\n", p.Pubkey)
		fmt.Fprintf(&b, "AllowedIPs = %s/32\n", p.WgIP)
	}
	return b.String()
}

// stripQuickDirectives entfernt wg-quick-spezifische Schlüssel (wie 'wg-quick strip').
func stripQuickDirectives(conf string) string {
	skip := map[string]bool{"Address": true, "DNS": true, "MTU": true, "Table": true}
	var b strings.Builder
	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if key, _, ok := strings.Cut(trimmed, "="); ok {
			if skip[strings.TrimSpace(key)] {
				continue
			}
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func (m *Manager) writeConf() error {
	if err := os.MkdirAll(filepath.Dir(m.confPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(m.confPath, []byte(m.renderConf(true)), 0o600) // Private Key: 0600
}

func (m *Manager) saveState() error {
	if err := os.MkdirAll(filepath.Dir(m.statePath), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(stateFile{PrivateKey: m.privkey, Peers: m.peers}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.statePath, data, 0o600)
}

func (m *Manager) loadState() error {
	data, err := os.ReadFile(m.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Erststart: Schlüssel werden generiert
		}
		return err
	}
	var st stateFile
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("state-Datei %s unlesbar: %w", m.statePath, err)
	}
	m.privkey = st.PrivateKey
	m.peers = st.Peers
	if m.peers == nil {
		m.peers = map[string]Peer{}
	}
	return nil
}
