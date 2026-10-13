"""HTTP-Client für die Gateway-API (Leitfaden 4.2, nur localhost/Control-Netz).

Die Gateway-API ist die einzige Stelle, an der die Control Plane den
Host-Zustand (wg0-Peers, nft-Sets) verändert.
"""

from __future__ import annotations

import httpx


class GatewayError(RuntimeError):
    pass


def _request(client_call, method: str, path: str, **kwargs):
    """Führt einen Gateway-Aufruf aus; HTTP- und Transportfehler
    (z. B. Gateway-Container down) werden einheitlich als GatewayError
    gemeldet, statt als unbehandelter 500er durchzuschlagen."""
    try:
        resp = client_call(path, **kwargs)
    except httpx.HTTPError as exc:
        raise GatewayError(f"{method} {path}: Verbindung fehlgeschlagen ({exc})") from exc
    if resp.status_code >= 400:
        raise GatewayError(f"{method} {path}: {resp.status_code} {resp.text}")
    return resp


class GatewayClient:
    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        self._client = httpx.Client(base_url=base_url, timeout=timeout)

    def get_pubkey(self) -> str:
        """Public Key von wg0 — wird für die Client-Profile benötigt."""
        return _request(self._client.get, "GET", "/pubkey").json()["pubkey"]

    def put_peer(self, device_id: int, pubkey: str, wg_ip: str) -> None:
        _request(
            self._client.put,
            "PUT",
            f"/peers/{device_id}",
            json={"pubkey": pubkey, "wg_ip": wg_ip},
        )

    def delete_peer(self, device_id: int) -> None:
        _request(self._client.delete, "DELETE", f"/peers/{device_id}")

    def put_service_clients(self, nft_set: str, clients: list[str]) -> None:
        """Vollständige Soll-Liste schicken — der Gateway diff't atomar (R11)."""
        _request(
            self._client.put,
            "PUT",
            f"/service/{nft_set}/clients",
            json={"clients": clients},
        )

    def reload(self) -> None:
        _request(self._client.post, "POST", "/reload")
