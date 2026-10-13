"""Config-Rendering: Schlüsselgenerierung und WireGuard-Client-Profile.

Der private Schlüssel verlässt die Control Plane nur im einmaligen Download
(Leitfaden 5.1) — er wird nie persistiert.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

KEEPALIVE = 25  # NAT-Mapping am Leben halten (Leitfaden: Troubleshooting 3)


@dataclass(frozen=True)
class KeyPair:
    private: str
    public: str


def generate_keypair() -> KeyPair:
    """Schlüsselpaar via 'wg genkey'/'wg pubkey' erzeugen (benötigt wireguard-tools)."""
    try:
        private = subprocess.run(
            ["wg", "genkey"], capture_output=True, text=True, check=True
        ).stdout.strip()
        public = subprocess.run(
            ["wg", "pubkey"], input=private + "\n", capture_output=True, text=True, check=True
        ).stdout.strip()
    except FileNotFoundError as exc:
        raise RuntimeError("wireguard-tools fehlen: 'wg' nicht gefunden") from exc
    return KeyPair(private=private, public=public)


def allowed_ips(services: list[tuple[str, int]]) -> str:
    """Split-Tunnel: nur die freigegebenen Dienste, z. B. '192.168.30.10/32, 192.168.30.11/32'."""
    return ", ".join(f"{ip}/32" for ip, _port in services)


def client_profile(
    *,
    private_key: str,
    wg_ip: str,
    gateway_pubkey: str,
    endpoint_host: str,
    endpoint_port: int = 51820,
    services: list[tuple[str, int]],
    dns: str | None = None,
    keepalive: int = KEEPALIVE,
) -> str:
    """WireGuard-Client-Profil (Leitfaden 5.1).

    dns ist optional: im Projekt-Scope läuft KEIN DNS-Dienst auf dem Waypoint,
    daher wird die Zeile nur gerendert, wenn ein Resolver konfiguriert ist.
    """
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {wg_ip}/32",
    ]
    if dns:
        lines.append(f"DNS = {dns}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {gateway_pubkey}",
        f"Endpoint = {endpoint_host}:{endpoint_port}",
        f"AllowedIPs = {allowed_ips(services)}",
        f"PersistentKeepalive = {keepalive}",
    ]
    return "\n".join(lines) + "\n"


def qr_png(profile: str) -> bytes:
    """Profil als QR-Code-PNG (für den Download in der UI)."""
    try:
        import io

        import qrcode
    except ImportError as exc:
        raise RuntimeError("Paket 'qrcode' fehlt") from exc
    buf = io.BytesIO()
    qrcode.make(profile).save(buf, format="PNG")
    return buf.getvalue()
