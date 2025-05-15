# 🔐 Network Intrusion Prevention System (NIPS) with Raspberry Pi

This project is a **real-time Network Intrusion Prevention System (NIPS)** developed in Python and deployed on a **Raspberry Pi 3**. It monitors local network traffic on `wlan0`, detects multiple types of attacks using packet analysis, and actively blocks malicious IPs using `iptables`.

---

## 🎯 Goal

To build a lightweight, low-cost network security solution that:

- Detects common network attacks in real time
    
- Logs all detected incidents
    
- Sends email alerts to the system administrator
    
- Blocks attackers automatically for a period of time
    

---

## 📡 How It Works

The Raspberry Pi is configured as a wireless access point. Devices connect to the internet **through the Pi**, allowing it to:

- **Sniff all traffic** on the wireless interface (`wlan0`)
    
- Analyze packets using [`scapy`](https://scapy.readthedocs.io/)
    
- Detect suspicious behavior patterns
    
- Log all incidents to a local file
    
- Send alerts via email
    
- Automatically block IPs using `iptables`
    
- Unblock IPs after a configurable cooldown period
    

---

## 🛡️ Detected Attacks

|Attack Type|Detection Logic|
|---|---|
|**DoS (SYN Flood)**|High rate of TCP SYN packets from a single IP|
|**Port Scanning**|Large number of unique destination ports from one IP|
|**ARP Spoofing**|One IP claimed by multiple MAC addresses|
|**SSH Brute-force**|Excessive TCP connections to port 22 (SSH) from the same IP|

---

## 🧠 Concepts Used

- Packet sniffing with `scapy`
    
- TCP/IP and ARP protocol analysis
    
- Stateful detection (track counts per IP per second)
    
- Intrusion prevention (blocking IPs)
    
- Email alerts using `smtplib`
    
- Logging with timestamp using `pytz`
    
- Automation of rule expiry and reactivation
    

---

## ⚙️ Technologies

- Python 3
    
- [Scapy](https://scapy.readthedocs.io/)
    
- iptables (Linux firewall)
    
- smtplib (Python email client)
    
- Raspberry Pi OS (Lite)
    

---

## 🚀 How to Use

1. **Connect Raspberry Pi to the internet via Ethernet**
    
2. **Enable AP mode on `wlan0` with running automate.sh** to act as a hotspot (e.g., using `hostapd` and `dnsmasq` . If you are stuck in this step, email us.)
    
3. Clone this repository:
    
    ```bash
    git clone https://github.com/yourusername/network-ips.git
    cd network-ips
    ```
    
4. **Configure email settings** in the script:
    
    ```python
    SENDER_EMAIL = "your_email@gmail.com"
    SENDER_PASSWORD = "your_password"
    RECIPIENT_EMAIL = "admin@example.com"
    ```
    
5. Run the detection script:
    
    ```bash
    sudo python3 Network-IPS.py
    ```
    

---

## 🧪 Simulating Attacks for Testing

You can test the system using standard tools:

| Attack Type     | Simulation Tool & Example                          |
| --------------- | -------------------------------------------------- |
| DoS             | `hping3 -S -p 80 --flood <raspberry_ip>`           |
| Port Scanning   | `nmap -p- <raspberry_ip>`                          |
| ARP Spoofing    | `arpspoof -i wlan0 -t <victim_ip> <gateway_ip>`    |
| SSH Brute-force | `hydra -l pi -P wordlist.txt ssh://<raspberry_ip>` |

---

## 📁 Log Output

Logs are saved to `log.txt` and include:

- Timestamp
    
- IP address
    
- Type of attack
    
- Details of the detection
    
- Action taken (e.g., "Blocked IP via iptables")
    

---

## 🔐 Security Notes

- The system is **active**: it not only detects but also **blocks** attackers.
    
- IPs are blocked via `iptables` and automatically unblocked after `BLOCK_DURATION` seconds.
    
The script is designed for **LAN or AP mode** networks where traffic can be monitored on `wlan0`. If you want to use it in other networks, you can change the desired interface.

---
Ahmad Hamidi wrote a complete report of this project for beginners in both English and the Persian language, that are in the Report folder. 
If you have any problems or questions, contact us :
mahdigorzdin@gmail.com
sajad.ssthm.k@gmail.com
ahmadsiarhamidi298@gmail.com
