"""Kriterienbasierte Autorisierung (Literatur: "criteria-based TA").

Bewusst binäre Prüfung, kein Score-Verfahren (dokumentierte Vereinfachung,
Score-basiertes Verfahren ist Ausblick). Alle Funktionen sind bewusst frei von
DB-Imports, damit die Logik isoliert getestet werden kann.
"""

from __future__ import annotations

from dataclasses import dataclass

STATUS_ACTIVE = "active"
STATUS_ROTATING = "rotating"
STATUS_REVOKED = "revoked"

# Zulässige Übergänge des Zustandsautomaten (Leitfaden 5.4):
# active -> rotating -> active  (Rotation ersetzt den Peer atomar)
# active/rotating -> revoked    (Widerruf: Peer löschen + Sets leeren)
_ALLOWED_TRANSITIONS = {
    (STATUS_ACTIVE, STATUS_ROTATING),
    (STATUS_ROTATING, STATUS_ACTIVE),
    (STATUS_ACTIVE, STATUS_REVOKED),
    (STATUS_ROTATING, STATUS_REVOKED),
}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def evaluate(
    *,
    user_active: bool,
    policy_allowed: bool,
    device_status: str,
    active_device_count: int,
    max_devices: int,
) -> Decision:
    """Freigabe nur wenn: user.active AND policy.allowed
    AND device.status == active AND devices_aktiv < LIMIT.
    """
    if not user_active:
        return Decision(False, "user inactive")
    if not policy_allowed:
        return Decision(False, "no policy allowing this service")
    if device_status != STATUS_ACTIVE:
        return Decision(False, f"device status is '{device_status}', not 'active'")
    if active_device_count >= max_devices:
        return Decision(False, f"device limit reached ({active_device_count}/{max_devices})")
    return Decision(True, "ok")


def can_transition(old_status: str, new_status: str) -> bool:
    return (old_status, new_status) in _ALLOWED_TRANSITIONS
