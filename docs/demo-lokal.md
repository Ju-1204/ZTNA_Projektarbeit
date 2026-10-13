# ZTNA-Projekt — Was ist das und wie läuft es gerade?

*Stand: 13.10.2026, nach Meilenstein M1. Dieses Dokument erklärt den
aktuellen Stand in einfacher Sprache — für uns selbst und für die Doku.*

---

## 1. Worum geht es überhaupt?

Das Projekt ersetzt ein klassisches VPN für Studierendendienste durch eine
**ZTNA-Lösung** (Zero Trust Network Access). Die Grundidee von Zero Trust:
*Niemand kommt einfach rein, weil er "im richtigen Netz" ist — jeder muss
sich individuell ausweisen, und auch dann sieht er nur das, was ihm erlaubt wurde.*

Der Kern ist der **Waypoint**: ein alter Laptop mit zwei Netzwerk-Anschlüssen,
der als Türsteher zwischen dem Campus-Netz (Seite A) und dem Netz mit den
Studierendendiensten (Seite B) steht.

```
 Studierende/r                    Waypoint-Laptop                 Dienste
 (WLAN/Ethernet)   ──Tunnel──▶   ┌──────────────────┐   ──▶   App  192.168.30.10
                                │ prüft: darf dieses │         DB   192.168.30.11
                                │ Gerät zu diesem    │
                                │ Dienst? ja/nein    │
                                └──────────────────┘
```

## 2. Die drei Bausteine des Projekts

| Baustein | Wo im Repo | Aufgabe (einfach gesagt) |
|---|---|---|
| **Control Plane** | `control/` (Python) | Das Büro: verwaltet Personen, Dienste und Freigaben. Prüft Anmeldungen und stellt die WireGuard-Profile zum Herunterladen aus. |
| **Gateway** | `gateway/` (Go) | Der Türsteher: richtet die WireGuard-Verbindungen ein und pflegt die Freigabe-Listen (sogenannte nft-Sets) für jeden Dienst. |
| **Host** | `host/` | Die Grundausstattung des Waypoint-Laptops: Firewall-Regeln und Netzwerk-Einstellungen. |

Die Control Plane und der Gateway reden über eine kleine interne API miteinander:
Control Plane sagt "Gerät 42 darf Dienst App nutzen", der Gateway setzt das um.

## 3. Was läuft **gerade** auf dem Entwicklungs-Laptop?

Für die Entwicklung gibt es eine lokale Demo. Sie läuft **nur auf dem eigenen
Laptop** (Adresse `127.0.0.1` = "nur ich selbst") — niemand im WLAN kann darauf zugreifen.

| Was | Adresse | Echt oder simuliert? |
|---|---|---|
| Control Plane | http://127.0.0.1:8000 | **echt** (das echte Programm aus `control/`) |
| Datenbank | `control/data/dev.db` | echte SQLite-Datenbank |
| Gateway | http://127.0.0.1:9090 | **simuliert** (kleines Ersatzprogramm, `dev/stub_gateway.py`) |
| WireGuard-Tunnel, Firewall | — | existiert lokal noch nicht (erst auf dem Waypoint-Laptop) |

**Warum der Gateway simuliert wird:** Das echte Gateway-Programm (Go) richtet
echte WireGuard-Verbindungen und Firewall-Regeln ein — das geht nur auf dem
Waypoint-Laptop mit den nötigen Rechten. Der Stub tut nur so, zeichnet aber
jeden Aufruf im Log auf. Damit kann man den kompletten Ablauf üben und testen,
ohne dass etwas am echten Netz passiert.

Die Schlüsselerzeugung ist trotzdem echt: Es werden dieselben
kryptografischen Schlüssel (X25519) erzeugt, die auch WireGuard benutzt.

## 4. Demo starten (Schritt für Schritt)

Man braucht zwei offene Terminal-Fenster im Projektordner:

```bash
cd /home/ju/Uni/projektarbeit

# Einmalig nötig: Python-Umgebung einrichten
python3 -m venv .venv
.venv/bin/pip install -r control/requirements.txt cryptography
```

**Terminal 1** — der simulierte Gateway:

```bash
.venv/bin/python dev/stub_gateway.py
```

**Terminal 2** — die Control Plane:

```bash
.venv/bin/python dev/run_local_demo.py
```

Dann im Browser öffnen: **http://127.0.0.1:8000/docs**

Das ist eine automatisch generierte Klick-Oberfläche, auf der man alle
Funktionen direkt ausprobieren kann. Wichtig für geschützte Endpunkte:
im Feld für den Header `X-Admin-Token` den Wert **`devtoken`** eintragen.

## 5. Den Ablauf einmal durchspielen

Das ist die Geschichte aus dem Implementierungsleitfaden (Abschnitt 5.1),
Schritt für Schritt in `/docs`:

1. **Person anlegen** — `POST /users` → z. B. E-Mail `demo@hs.example`
2. **Dienst anlegen** — `POST /services` → z. B. App auf `192.168.30.10:443`
   (das Feld `nft_set` heißt dann `svc_app_clients` — die Firewall-Liste für diesen Dienst)
3. **Freigabe erteilen** — `PUT /policies` → "Person 1 darf Dienst 1 nutzen"
4. **Einladungs-Token erstellen** — `POST /tokens` → ergibt eine Art einmaligen Gutschein
5. **Gutschein einlösen** — `POST /enroll/{token}` mit `{"label": "Mein Laptop"}`

Bei Schritt 5 passiert das eigentliche ZTNA:
- Das System prüft: Ist die Person aktiv? Token noch gültig? Gerät-Limit nicht überschritten?
- Es erzeugt frisch ein Schlüsselpaar fürs Gerät.
- Es sagt dem Gateway Bescheid ("richte diesen Peer ein", "trage die Tunnel-IP in die App-Freigabeliste ein").
- Es liefert ein fertiges **WireGuard-Profil** zurück — mit dem privaten
  Schlüssel, der **genau einmal** angezeigt wird und danach nie wieder.

## 6. Was man ausprobieren sollte (Negativtests!)

Die Negativtests sind das eigentliche Beweisstück für Zero Trust:

- **Gutschein zweimal einlösen** → muss mit Fehler 403 abgelehnt werden.
- **Drittes Gerät** (Limit ist 2–3, konfigurierbar) → muss abgelehnt werden.
- **Nicht freigegebenen Dienst nutzen** → das erhaltene Profil darf nur die
  freigegebenen IPs enthalten (Feld `AllowedIPs`) — der DB-Dienst taucht dort nicht auf.
- **Gerät sperren** — `POST /devices/{id}/revoke` → im Terminal 1 sieht man,
  dass der Stub den Peer löscht und aus den Freigabelisten streicht.

Im Terminal 1 zeigt der Stub bei jedem Aufruf, was die Control Plane
gerade angefragt hat — dort sieht man die Zero-Trust-Logik bei der Arbeit.

## 7. Demo wieder stoppen

In beiden Terminals: `Strg + C` drücken.
(Oder von woanders: `pkill -f stub_gateway` und `pkill -f run_local_demo`.)

Die Demo-Daten liegen in `control/data/dev.db` — die Datei kann man löschen,
wenn man mit leerer Datenbank neu anfangen will.

## 8. Tests ausführen (ohne Demo-Server)

```bash
# Python-Tests (Control Plane)
cd control && ../.venv/bin/python -m unittest discover -s tests -t .

# Go-Tests (Gateway)
cd gateway && go test ./...
```

## 9. Was noch NICHT geht — und was als Nächstes kommt

| Es fehlt noch | Wann |
|---|---|
| Echter WireGuard-Tunnel + echte Firewall-Regeln | M2: Deployment auf den Waypoint-Laptop |
| `docker compose up` (Docker ist auf dem Dev-Laptop nicht installiert) | M2 auf dem Waypoint-Laptop |
| Schöne Web-UI (aktuell nur die technische Klick-Oberfläche) | optional, wenn Zeit bleibt |
| Key-Rotation/Widerruf gegen echte Verbindungen | M3 (Härtung) — die Logik ist da und getestet |

**Grober Fahrplan für M2:** Ubuntu Server auf dem Waypoint-Laptop installieren →
`host/install.sh` ausführen (Firewall + Netz) → Repo klonen → `docker compose up -d --build` →
mit einem echten Client die Schritte aus Abschnitt 5 durchspielen → jetzt kommt ein echter Tunnel raus.
