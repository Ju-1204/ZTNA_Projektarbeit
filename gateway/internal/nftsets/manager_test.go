package nftsets

import (
	"strings"
	"testing"
)

type fakeRunner struct {
	calls []string
	// antwort für 'nft -j list set ...' — pro Set-Name
	listResp map[string]string
	listErr  map[string]bool
}

func (f *fakeRunner) Run(_ string, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	if name == "nft" && args[0] == "-j" {
		set := args[len(args)-1]
		if f.listErr[set] {
			return "Error: no such file or directory", errNF{}
		}
		return f.listResp[set], nil
	}
	return "", nil
}

type errNF struct{}

func (errNF) Error() string { return "no such set" }

const fixtureApp = `{"nftables":[
  {"set":{"family":"inet","name":"svc_app_clients","table":"waypoint",
    "type":["ipv4_addr"],"handle":42,"elem":["10.9.0.10","10.9.0.11"]}}
]}`

const fixtureComposite = `{"nftables":[
  {"set":{"family":"inet","name":"svc_db_clients","table":"waypoint",
    "type":["ipv4_addr"],"elem":[{"val":"10.9.0.13"},{"val":"10.9.0.99"}]}}
]}`

func newFake() *fakeRunner {
	return &fakeRunner{
		listResp: map[string]string{
			"svc_app_clients": fixtureApp,
			"svc_db_clients":  fixtureComposite,
		},
	}
}

func lastCallContaining(t *testing.T, calls []string, needle string) string {
	t.Helper()
	for i := len(calls) - 1; i >= 0; i-- {
		if strings.Contains(calls[i], needle) {
			return calls[i]
		}
	}
	t.Fatalf("kein Aufruf mit %q: %v", needle, calls)
	return ""
}

func TestSyncSetAddsAndDeletesDiff(t *testing.T) {
	f := newFake()
	m := NewManager(f, "inet", "waypoint")

	// App-Set: 10.9.0.10 bleibt, 10.9.0.11 fliegt, 10.9.0.12 kommt dazu
	if err := m.SyncSet("svc_app_clients", []string{"10.9.0.10", "10.9.0.12"}); err != nil {
		t.Fatalf("SyncSet: %v", err)
	}
	add := lastCallContaining(t, f.calls, "add element inet waypoint svc_app_clients")
	if !strings.Contains(add, "{ 10.9.0.12 }") {
		t.Errorf("add muss nur fehlende IP enthalten: %s", add)
	}
	del := lastCallContaining(t, f.calls, "delete element inet waypoint svc_app_clients")
	if !strings.Contains(del, "{ 10.9.0.11 }") {
		t.Errorf("delete muss nur überflüssige IP enthalten: %s", del)
	}
	if strings.Contains(add, "10.9.0.10") {
		t.Errorf("bereits vorhandene IP darf nicht erneut addiert werden: %s", add)
	}
}

func TestSyncSetCompositeElements(t *testing.T) {
	f := newFake()
	m := NewManager(f, "inet", "waypoint")

	if err := m.SyncSet("svc_db_clients", []string{"10.9.0.13"}); err != nil {
		t.Fatalf("SyncSet: %v", err)
	}
	// 10.9.0.13 war drin (komposites Format), 10.9.0.99 muss gelöscht werden
	del := lastCallContaining(t, f.calls, "delete element inet waypoint svc_db_clients")
	if !strings.Contains(del, "10.9.0.99") {
		t.Errorf("Komposit-Elemente müssen erkannt werden: %s", del)
	}
	if strings.Contains(del, "10.9.0.13") {
		t.Errorf("bestehendes Komposit-Element darf nicht gelöscht werden: %s", del)
	}
}

func TestSyncSetNoopOnIdenticalList(t *testing.T) {
	f := newFake()
	m := NewManager(f, "inet", "waypoint")

	before := len(f.calls)
	if err := m.SyncSet("svc_app_clients", []string{"10.9.0.10", "10.9.0.11"}); err != nil {
		t.Fatalf("SyncSet: %v", err)
	}
	if len(f.calls) != before+1 { // nur der list-Aufruf darf passieren
		t.Errorf("keine Änderung -> keine add/delete-Aufrufe, got %v", f.calls)
	}
}

func TestSyncSetRejectsInvalidInput(t *testing.T) {
	m := NewManager(newFake(), "inet", "waypoint")

	if err := m.SyncSet("boese_name", []string{"10.9.0.10"}); err == nil {
		t.Error("ungültiger Set-Name muss abgelehnt werden")
	}
	if err := m.SyncSet("svc_app_clients", []string{"10.9.0.10", "999.1.2.3"}); err == nil {
		t.Error("ungültige IP muss abgelehnt werden")
	}
}

func TestSyncSetPropagatesMissingSet(t *testing.T) {
	f := newFake()
	f.listErr = map[string]bool{"svc_app_clients": true}
	m := NewManager(f, "inet", "waypoint")

	if err := m.SyncSet("svc_app_clients", []string{"10.9.0.10"}); err == nil {
		t.Error("fehlendes Set (Regelwerk nicht geladen) muss als Fehler durchreichen")
	}
}
