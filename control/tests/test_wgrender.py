"""Tests für das Config-Rendering (wgrender.py) — ohne echte Schlüsselerzeugung."""

import base64
import os
import shutil
import subprocess
import unittest

from app import wgrender


class AllowedIPsTest(unittest.TestCase):
    def test_services_become_cidr32_list(self):
        result = wgrender.allowed_ips([("192.168.30.10", 443), ("192.168.30.11", 5432)])
        self.assertEqual(result, "192.168.30.10/32, 192.168.30.11/32")

    def test_empty_service_list(self):
        self.assertEqual(wgrender.allowed_ips([]), "")


class ClientProfileTest(unittest.TestCase):
    def test_profile_contains_all_elements(self):
        profile = wgrender.client_profile(
            private_key="PRIVKEY123",
            wg_ip="10.9.0.42",
            gateway_pubkey="GATEWAYPUB",
            endpoint_host="192.168.1.10",
            endpoint_port=51820,
            services=[("192.168.30.10", 443), ("192.168.30.11", 5432)],
        )
        for needle in [
            "[Interface]",
            "PrivateKey = PRIVKEY123",
            "Address = 10.9.0.42/32",
            "[Peer]",
            "PublicKey = GATEWAYPUB",
            "Endpoint = 192.168.1.10:51820",
            "AllowedIPs = 192.168.30.10/32, 192.168.30.11/32",  # Split-Tunnel
            "PersistentKeepalive = 25",
        ]:
            self.assertIn(needle, profile, needle)
        # DNS darf nicht auftauchen, wenn kein Resolver konfiguriert ist
        self.assertNotIn("DNS =", profile)

    def test_profile_with_dns(self):
        profile = wgrender.client_profile(
            private_key="PRIVKEY123",
            wg_ip="10.9.0.42",
            gateway_pubkey="GATEWAYPUB",
            endpoint_host="192.168.1.10",
            services=[("192.168.30.10", 443)],
            dns="192.168.30.1",
        )
        self.assertIn("DNS = 192.168.30.1", profile)


class KeypairTest(unittest.TestCase):
    def test_generate_keypair_matches_wg(self):
        """Nur ausführbar, wenn wireguard-tools installiert sind (Waypoint-Host/CI-Container)."""
        if shutil.which("wg") is None:
            self.skipTest("wg binary fehlt (lokale Dev-Maschine)")

        pair = wgrender.generate_keypair()
        # Base64-Check: WireGuard-Keys sind 32 Bytes, base64 = 44 Zeichen
        self.assertEqual(len(pair.private), 44)
        self.assertEqual(len(pair.public), 44)
        base64.b64decode(pair.private)
        base64.b64decode(pair.public)

        # Kreuz-Check: wg pubkey muss den gleichen Public Key liefern
        out = subprocess.run(
            ["wg", "pubkey"], input=pair.private + "\n",
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        self.assertEqual(out, pair.public)

    def test_missing_wg_binary_raises(self):
        if shutil.which("wg") is not None:
            self.skipTest("wg ist installiert — Fehlerpfad nicht testbar")
        old_path = os.environ["PATH"]
        os.environ["PATH"] = ""
        try:
            with self.assertRaises(RuntimeError):
                wgrender.generate_keypair()
        finally:
            os.environ["PATH"] = old_path


if __name__ == "__main__":
    unittest.main()
