// Package nftsets pflegt die Per-Service-Client-Sets des Waypoint-Regelwerks
// (host/waypoint.nft). Der Daemon empfängt die vollständige Soll-Liste und
// gleicht atomar per 'nft add/delete element' ab — kein Regelwerks-Neuaufbau.
package nftsets

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// Runner führt Prozess-Aufrufe aus (gleiche Signatur wie wireguard.Runner).
type Runner interface {
	Run(stdin, name string, args ...string) (string, error)
}

// Manager verwaltet die Sets einer nftables-Tabelle.
type Manager struct {
	runner Runner
	family string
	table  string
}

func NewManager(r Runner, family, table string) *Manager {
	return &Manager{runner: r, family: family, table: table}
}

// setNameRe validiert Set-Namen, die aus der Control Plane kommen (Injektionsschutz).
var setNameRe = regexp.MustCompile(`^svc_[a-z][a-z0-9_]{0,60}_clients$`)

// SyncSet bringt das Set auf die Soll-Liste der Client-Tunnel-IPs.
func (m *Manager) SyncSet(set string, clients []string) error {
	if !setNameRe.MatchString(set) {
		return fmt.Errorf("ungültiger Set-Name: %q", set)
	}
	want := map[string]bool{}
	for _, ip := range clients {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("ungültige IP in Client-Liste: %q", ip)
		}
		want[ip] = true
	}

	have, err := m.current(set)
	if err != nil {
		return err
	}

	toAdd := make([]string, 0, len(want))
	for ip := range want {
		if !have[ip] {
			toAdd = append(toAdd, ip)
		}
	}
	toDel := make([]string, 0, len(have))
	for ip := range have {
		if !want[ip] {
			toDel = append(toDel, ip)
		}
	}
	sort.Strings(toAdd)
	sort.Strings(toDel)

	if len(toAdd) > 0 {
		if _, err := m.runner.Run("", "nft", "add", "element", m.family, m.table, set, elementArgs(toAdd)); err != nil {
			return fmt.Errorf("nft add element %s %s: %w", m.table, set, err)
		}
	}
	if len(toDel) > 0 {
		if _, err := m.runner.Run("", "nft", "delete", "element", m.family, m.table, set, elementArgs(toDel)); err != nil {
			return fmt.Errorf("nft delete element %s %s: %w", m.table, set, err)
		}
	}
	return nil
}

// current liest die Set-Elemente via 'nft -j list set' (JSON).
func (m *Manager) current(set string) (map[string]bool, error) {
	out, err := m.runner.Run("", "nft", "-j", "list", "set", m.family, m.table, set)
	if err != nil {
		return nil, fmt.Errorf("nft list set %s %s: %w (%s)", m.table, set, err, strings.TrimSpace(out))
	}
	return parseSetElements(out)
}

// elementArgs formatiert die Element-Notation für nft, z. B. "{ 10.9.0.10, 10.9.0.11 }".
func elementArgs(ips []string) string {
	return "{ " + strings.Join(ips, ", ") + " }"
}

type nftListOutput struct {
	Nftables []struct {
		Set struct {
			Name string            `json:"name"`
			Elem []json.RawMessage `json:"elem"`
		} `json:"set"`
	} `json:"nftables"`
}

// parseSetElements extrahiert die Elemente aus der nft-JSON-Ausgabe. Einfache
// Typen (ipv4_addr) erscheinen als String, zusammengesetzte als {"val": ...}.
func parseSetElements(out string) (map[string]bool, error) {
	var parsed nftListOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return nil, fmt.Errorf("nft-JSON unlesbar: %w", err)
	}
	elements := map[string]bool{}
	for _, item := range parsed.Nftables {
		if item.Set.Name == "" {
			continue
		}
		for _, raw := range item.Set.Elem {
			var s string
			if err := json.Unmarshal(raw, &s); err == nil {
				elements[s] = true
				continue
			}
			var obj struct {
				Val json.RawMessage `json:"val"`
			}
			if err := json.Unmarshal(raw, &obj); err == nil && len(obj.Val) > 0 {
				if err := json.Unmarshal(obj.Val, &s); err == nil {
					elements[s] = true
				}
			}
		}
	}
	return elements, nil
}
