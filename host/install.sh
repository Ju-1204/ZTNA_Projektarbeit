#!/usr/bin/env bash
# Waypoint-Host: idempotentes Setup
# host/install.sh — NUR auf dem Waypoint-Laptop ausführen (Ubuntu Server 24.04).
# Achtung: 'netplan apply' und das nft-Regelwerk können die bestehende
# SSH-Session verändern — idealerweise an der Konsole oder mit out-of-band Zugriff.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "Bitte als root ausführen: sudo bash host/install.sh" >&2
    exit 1
fi

echo "==> Prüfe Ubuntu und WireGuard-Kernel (>= 5.6)"
kver="$(uname -r)"
echo "Kernel: ${kver}"

echo "==> sysctl-Drop-in installieren"
install -m 0644 "${REPO_DIR}/host/99-waypoint.sysctl" /etc/sysctl.d/99-waypoint.conf
sysctl --system >/dev/null
[[ "$(sysctl -n net.ipv4.ip_forward)" == "1" ]] || { echo "ip_forward != 1" >&2; exit 1; }

echo "==> nftables-Regelwerk installieren"
install -m 0644 "${REPO_DIR}/host/waypoint.nft" /etc/nftables.conf
nft -f /etc/nftables.conf
systemctl enable --now nftables

echo "==> netplan-Konfiguration installieren"
install -m 0600 "${REPO_DIR}/host/netplan/02-waypoint.yaml" /etc/netplan/02-waypoint.yaml
echo "    Achtung: 'netplan apply' kann die Netzwerkverbindung kurz stören."
netplan apply

echo "==> WLAN auf Seite A (optional, nur wenn Campus per WLAN)"
if [[ ! -f /etc/wpa_supplicant/wpa_supplicant-wlan0.conf && -f "${REPO_DIR}/host/wpa_supplicant-wlan0.conf" ]]; then
    echo "    wpa_supplicant-Konfiguration gefunden — Credentials prüfen, dann:"
    echo "    install -m 0600 ${REPO_DIR}/host/wpa_supplicant-wlan0.conf /etc/wpa_supplicant/wpa_supplicant-wlan0.conf"
    echo "    systemctl enable --now wpa_supplicant@wlan0"
fi

echo "==> Laptop-Betrieb: Akku-Ladelimit (60–80 % empfohlen, siehe PROJECT.md)"
for threshold in /sys/class/power_supply/BAT*/charge_control_end_threshold; do
    if [[ -f "${threshold}" ]]; then
        echo 80 > "${threshold}" 2>/dev/null || echo "    Ladelimit nicht setzbar: ${threshold}"
        echo "    Hinweis: Wert überlebt keinen Reboot — für Persistenz tlp oder ein systemd-onshot-Unit einrichten."
    fi
done

echo "==> Host-Setup abgeschlossen. Interface-Check:"
ip -brief address show
nft list table inet waypoint | head -5
