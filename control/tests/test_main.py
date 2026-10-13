"""End-to-End-Tests der Control-Plane-API mit gefaktem Gateway.

Der Fake-Gateway ersetzt den echten Go-Daemon (kein wg/nft nötig) und zeichnet
alle Aufrufe auf. Damit ist der komplette Lebenszyklus prüfbar:
Enrollment -> Profil -> Rotation -> Widerruf, inklusive Negativfällen
(Token-Wiederverwendung, Geräte-Limit, Gateway-Ausfall, Rollbacks).
"""

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="ztna-test-")
# Umgebungsvariablen VOR dem Import von app.main setzen (Modul liest sie beim Import)
os.environ["DB_PATH"] = os.path.join(_TMP, "test.db")
os.environ["ADMIN_TOKEN"] = "testtoken"
os.environ["ENDPOINT_HOST"] = "192.168.1.10"
os.environ["MAX_DEVICES_PER_USER"] = "2"
os.environ["WG_CLIENTS_FROM"] = "10.9.0.10"
os.environ["GATEWAY_URL"] = "http://fake:9090"

import unittest  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

import app.main as main  # noqa: E402
from app.wgrender import KeyPair  # noqa: E402


class FakeGateway:
    """Nimmt die Rolle des Go-Daemons ein und zeichnet alles auf."""

    def __init__(self):
        self.peers = {}      # device_id -> (pubkey, wg_ip)
        self.deleted = []
        self.sets = {}       # nft_set -> client-Liste
        self.fail = False

    def _check(self):
        if self.fail:
            raise main.GatewayError("gateway down")

    def get_pubkey(self):
        self._check()
        return "GATEWAYPUB"

    def put_peer(self, device_id, pubkey, wg_ip):
        self._check()
        self.peers[device_id] = (pubkey, wg_ip)

    def delete_peer(self, device_id):
        self._check()
        self.deleted.append(device_id)

    def put_service_clients(self, nft_set, clients):
        self._check()
        self.sets[nft_set] = list(clients)


class KeyGen:
    """Liefert deterministisch eindeutige Schlüssel (wg-Binary nicht nötig)."""

    def __init__(self):
        self.n = 0

    def __call__(self):
        self.n += 1
        return KeyPair(private=f"PRIVKEY{self.n:03d}", public=f"PUBKEY{self.n:03d}")


fake = FakeGateway()
main.gateway = fake
main.generate_keypair = KeyGen()

ADMIN = {"X-Admin-Token": "testtoken"}


def admin(client, method, path, **kwargs):
    return getattr(client, method)(path, headers=ADMIN, **kwargs)


class ApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        """Isolation: jede Testmethode startet mit leerer DB und geleertem Fake-Gateway."""
        main.Base.metadata.drop_all(main.engine)
        main.Base.metadata.create_all(main.engine)
        fake.__init__()


class HealthAndAuthTest(ApiTestCase):
    def test_healthz(self):
        resp = self.client.get("/healthz")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok"})

    def test_admin_endpoints_require_token(self):
        self.assertEqual(self.client.get("/users").status_code, 401)
        self.assertEqual(
            self.client.get("/users", headers={"X-Admin-Token": "falsch"}).status_code, 401
        )
        self.assertEqual(self.client.get("/users", headers=ADMIN).status_code, 200)

    def test_invalid_service_name_rejected(self):
        resp = admin(self.client, "post", "/services", json={
            "name": "BÖSER NAME", "ip": "192.168.30.10", "port": 443,
            "nft_set": "svc_app_clients",
        })
        self.assertEqual(resp.status_code, 422)  # Pydantic-Validierung


class LifecycleTest(ApiTestCase):
    """Der komplette Ablauf aus Leitfaden 5, als zusammenhängende Geschichte."""

    def test_full_lifecycle(self):
        c = self.client

        # 1) Nutzer + Dienste anlegen
        r = admin(c, "post", "/users", json={"email": "studix@hs.example"})
        self.assertEqual(r.status_code, 201, r.text)
        user_id = r.json()["id"]
        # doppelte E-Mail -> 409
        self.assertEqual(admin(c, "post", "/users", json={"email": "studix@hs.example"}).status_code, 409)

        r = admin(c, "post", "/services", json={
            "name": "app", "ip": "192.168.30.10", "port": 443, "nft_set": "svc_app_clients",
        })
        self.assertEqual(r.status_code, 201)
        app_svc = r.json()["id"]
        r = admin(c, "post", "/services", json={
            "name": "db", "ip": "192.168.30.11", "port": 5432, "nft_set": "svc_db_clients",
        })
        self.assertEqual(r.status_code, 201)

        # 2) Policy: nur "app" erlaubt, "db" nicht
        r = admin(c, "put", "/policies", json={
            "user_id": user_id, "service_id": app_svc, "allowed": True,
        })
        self.assertEqual(r.status_code, 200)

        # 3) Enrollment-Token erstellen und einlösen
        r = admin(c, "post", "/tokens", json={"user_id": user_id})
        self.assertEqual(r.status_code, 201)
        token = r.json()["token"]

        r = c.post(f"/enroll/{token}", json={"label": "Mein Laptop"})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["wg_ip"], "10.9.0.10")
        profile = body["profile"]

        # Profil-Inhalte: Gateway-Pubkey, Endpoint, Split-Tunnel nur auf "app"
        self.assertIn("PublicKey = GATEWAYPUB", profile)
        self.assertIn("Endpoint = 192.168.1.10:51820", profile)
        self.assertIn("AllowedIPs = 192.168.30.10/32", profile)
        self.assertNotIn("192.168.30.11", profile)  # db nicht autorisiert

        # Gateway-Zustand: Peer gesetzt, nur app-Set enthält die Tunnel-IP
        device_id = body["device_id"]
        self.assertEqual(fake.peers[device_id][1], "10.9.0.10")
        self.assertIn("10.9.0.10", fake.sets["svc_app_clients"])
        self.assertEqual(fake.sets["svc_db_clients"], [])

        # 4) Token ist verbraucht
        r = c.post(f"/enroll/{token}", json={"label": "Zweites Gerät"})
        self.assertEqual(r.status_code, 403)

        # 5) Zweites Gerät erlaubt (Limit 2), drittes verboten
        r = admin(c, "post", "/tokens", json={"user_id": user_id})
        token2 = r.json()["token"]
        r = c.post(f"/enroll/{token2}", json={"label": "Handy"})
        self.assertEqual(r.status_code, 200)

        r = admin(c, "post", "/tokens", json={"user_id": user_id})
        token3 = r.json()["token"]
        r = c.post(f"/enroll/{token3}", json={"label": "Tablet"})
        self.assertEqual(r.status_code, 403)
        self.assertIn("limit", r.json()["detail"])

        # 6) Rotation: neuer Key ersetzt den Peer atomar (gleiche ID, kein Duplikat)
        old_pub = fake.peers[device_id][0]
        r = admin(c, "post", f"/devices/{device_id}/rotate")
        self.assertEqual(r.status_code, 200, r.text)
        new_pub = fake.peers[device_id][0]
        self.assertNotEqual(old_pub, new_pub)
        # Peer-Anzahl unverändert -> atomarer Ersatz
        devices_list = admin(c, "get", "/devices").json()
        self.assertEqual(len([d for d in devices_list if d["id"] == device_id]), 1)

        # 7) Widerruf: Peer weg, Set-Eintrag weg
        r = admin(c, "post", f"/devices/{device_id}/revoke")
        self.assertEqual(r.status_code, 200)
        self.assertIn(device_id, fake.deleted)
        self.assertNotIn("10.9.0.10", fake.sets["svc_app_clients"])
        # Widerruf ist endgültig: erneuter Widerruf -> 409, Rotation -> 409
        self.assertEqual(admin(c, "post", f"/devices/{device_id}/revoke").status_code, 409)
        self.assertEqual(admin(c, "post", f"/devices/{device_id}/rotate").status_code, 409)

    def test_enrollment_with_expired_token_fails(self):
        c = self.client
        r = admin(c, "post", "/users", json={"email": "spaeter@hs.example"})
        user_id = r.json()["id"]
        r = admin(c, "post", "/tokens", json={"user_id": user_id, "ttl_hours": -1})
        expired = r.json()["token"]
        r = c.post(f"/enroll/{expired}", json={"label": "Zu spät"})
        self.assertEqual(r.status_code, 403)


class GatewayOutageTest(ApiTestCase):
    """Schlägt der Gateway fehl, muss die DB konsistent bleiben (Rollback)."""

    def test_enrollment_rolls_back_on_gateway_failure(self):
        c = self.client
        r = admin(c, "post", "/users", json={"email": "notfall@hs.example"})
        user_id = r.json()["id"]
        r = admin(c, "post", "/tokens", json={"user_id": user_id})
        token = r.json()["token"]

        fake.fail = True
        try:
            r = c.post(f"/enroll/{token}", json={"label": "Gerät"})
            self.assertEqual(r.status_code, 502, r.text)
        finally:
            fake.fail = False

        # Gerät wurde zurückgerollt, Token ist weiterhin nutzbar
        devices = [d for d in admin(c, "get", "/devices").json()
                   if d["user_id"] == user_id]
        self.assertEqual(devices, [])
        r = c.post(f"/enroll/{token}", json={"label": "Gerät"})
        self.assertEqual(r.status_code, 200, r.text)

    def test_revoke_rolls_back_status_on_gateway_failure(self):
        c = self.client
        r = admin(c, "post", "/users", json={"email": "widerruf@hs.example"})
        user_id = r.json()["id"]
        r = admin(c, "post", "/tokens", json={"user_id": user_id})
        r = c.post(f"/enroll/{r.json()['token']}", json={"label": "Gerät"})
        device_id = r.json()["device_id"]

        fake.fail = True
        try:
            r = admin(c, "post", f"/devices/{device_id}/revoke")
            self.assertEqual(r.status_code, 502, r.text)
        finally:
            fake.fail = False

        # Status zurück auf active — DB und Gateway konsistent
        device = [d for d in admin(c, "get", "/devices").json()
                  if d["id"] == device_id][0]
        self.assertEqual(device["status"], "active")

        # Jetzt ohne Störung: Widerruf klappt
        r = admin(c, "post", f"/devices/{device_id}/revoke")
        self.assertEqual(r.status_code, 200)


class ProfileFormatTest(ApiTestCase):
    def test_conf_and_qr_download(self):
        c = self.client
        r = admin(c, "post", "/users", json={"email": "formate@hs.example"})
        user_id = r.json()["id"]
        r = admin(c, "post", "/services", json={
            "name": "app2", "ip": "192.168.30.20", "port": 443, "nft_set": "svc_app2_clients",
        })
        admin(c, "put", "/policies", json={
            "user_id": user_id, "service_id": r.json()["id"], "allowed": True,
        })
        r = admin(c, "post", "/tokens", json={"user_id": user_id})
        token = r.json()["token"]

        r = c.post(f"/enroll/{token}?format=conf", json={"label": "Laptop"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("attachment", r.headers.get("content-disposition", ""))
        self.assertIn("[Interface]", r.text)

        # QR-Format: PNG-Magie-Bytes
        r = admin(c, "post", "/tokens", json={"user_id": user_id})
        r = c.post(f"/enroll/{r.json()['token']}?format=qr", json={"label": "Handy"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["content-type"], "image/png")
        self.assertTrue(r.content.startswith(b"\x89PNG"))


if __name__ == "__main__":
    unittest.main()
