#!/usr/bin/env python3
"""Startet die Control Plane lokal auf 127.0.0.1:8000 (nur für die lokale Demo).

Wichtig: Die Umgebungsvariablen (DB, Token, Gateway-Adresse ...) müssen VOR dem
Import von app.main gesetzt werden — deshalb stehen sie ganz oben.

Außerdem: Auf dem Entwicklungs-Laptop gibt es das Programm 'wg' nicht. Die
Schlüssel-Erzeugung wird deshalb durch eine X25519-Implementierung ersetzt
(erzeugt dieselbe Art von Schlüsseln wie 'wg'). Auf dem Waypoint-Laptop und im
Docker-Image ist wireguard-tools installiert — dort läuft das Original.
"""
import base64
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["DB_PATH"] = os.path.join(REPO, "control/data/dev.db")
os.environ["ADMIN_TOKEN"] = "devtoken"
os.environ["ENDPOINT_HOST"] = "192.168.1.10"          # Beispiel-IP des Waypoint
os.environ["GATEWAY_URL"] = "http://127.0.0.1:9090"   # der Stub aus dev/stub_gateway.py
os.environ["MAX_DEVICES_PER_USER"] = "3"
os.environ["WG_CLIENTS_FROM"] = "10.9.0.10"

os.chdir(os.path.join(REPO, "control"))
sys.path.insert(0, os.getcwd())

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app.wgrender import KeyPair


def generate_keypair():
    priv = X25519PrivateKey.generate()
    return KeyPair(
        private=base64.b64encode(priv.private_bytes_raw()).decode(),
        public=base64.b64encode(priv.public_key().public_bytes_raw()).decode(),
    )


import app.main as main  # noqa: E402

main.generate_keypair = generate_keypair

import uvicorn  # noqa: E402

print("[demo] Control Plane: http://127.0.0.1:8000/docs (Admin-Token: devtoken)", flush=True)
uvicorn.run(main.app, host="127.0.0.1", port=8000, log_level="info")
