"""HTTP-Client für die Gateway-API (Leitfaden 4.2, nur localhost/Control-Netz).

Die Gateway-API ist die einzige Stelle, an der die Control Plane den
Host-Zustand (wg0-Peers, nft-Sets) verändert.
"""

from __future__ import annotations

import httpx


class GatewayError(RuntimeError):
    pass


class GatewayClient:
    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        self._client = httpx.Client(base_url=base_url, timeout=timeout)

    def get_pubkey(self) -> str:
        """Public Key von wg0 — wird für die Client-Profile benötigt."""
        resp = self._client.get("/pubkey")
        if resp.status_code >= 400:
            raise GatewayError(f"GET /pubkey: {resp.status_code} {resp.text}")
        return resp.json()["pubkey"]

    def put_peer(self, device_id: int, pubkey: str, wg_ip: str) -> None:
        resp = self._client.put(f"/peers/{device_id}", json={"pubkey": pubkey, "wg_ip": wg_ip})
        if resp.status_code >= 400:
            raise GatewayError(f"PUT /peers/{device_id}: {resp.status_code} {resp.text}")

    def delete_peer(self, device_id: int) -> None:
        resp = self._client.delete(f"/peers/{device_id}")
        if resp.status_code >= 400:
            raise GatewayError(f"DELETE /peers/{device_id}: {resp.status_code} {resp.text}")

    def put_service_clients(self, nft_set: str, clients: list[str]) -> None:
        """Vollständige Soll-Liste schicken — der Gateway diff't atomar (R11)."""
        resp = self._client.put(f"/service/{nft_set}/clients", json={"clients": clients})
        if resp.status_code >= 400:
            raise GatewayError(f"PUT /service/{nft_set}/clients: {resp.status_code} {resp.text}")

    def reload(self) -> None:
        resp = self._client.post("/reload")
        if resp.status_code >= 400:
            raise GatewayError(f"POST /reload: {resp.status_code} {resp.text}")
