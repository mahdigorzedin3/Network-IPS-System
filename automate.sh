#!/bin/bash

# ✅ Hotspot configuration script for Raspberry Pi
# 🚨 Run with sudo or as root

set -e

echo "[+] Updating system..."
apt update

echo "[+] Installing required packages..."
apt install -y hostapd dnsmasq netfilter-persistent iptables-persistent

echo "[+] Stopping services for configuration..."
systemctl stop hostapd dnsmasq

echo "[+] Setting static IP for wlan0..."
if ! grep -q "interface wlan0" /etc/dhcpcd.conf; then
    cat >> /etc/dhcpcd.conf <<EOF

interface wlan0
    static ip_address=192.168.4.1/24
    nohook wpa_supplicant
EOF
fi

echo "[+] Restarting dhcpcd..."
systemctl restart dhcpcd

echo "[+] Configuring dnsmasq..."
mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig 2>/dev/null || true
cat > /etc/dnsmasq.conf <<EOF
interface=wlan0
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
EOF

echo "[+] Creating hostapd config..."
mkdir -p /etc/hostapd
cat > /etc/hostapd/hostapd.conf <<EOF
interface=wlan0
driver=nl80211
ssid=RPiHotspot
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=SecurePass123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

echo "[+] Pointing hostapd to config file..."
sed -i 's|^#*DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

echo "[+] Enabling IP forwarding..."
sed -i 's/^#*\s*net\.ipv4\.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p

echo "[+] Setting up NAT with iptables..."
iptables -t nat -F
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT

echo "[+] Saving iptables rules..."
netfilter-persistent save

echo "[+] Disabling conflicting services..."
systemctl disable --now wpa_supplicant 2>/dev/null || true
nmcli radio wifi off 2>/dev/null || true

echo "[+] Enabling services..."
systemctl unmask hostapd
systemctl enable --now hostapd dnsmasq

echo "[✔] Hotspot setup completed successfully!"
echo "📶 SSID: RPiHotspot"
echo "🔑 Password: SecurePass123"
echo "🌐 IP Range: 192.168.4.2-192.168.4.20"
