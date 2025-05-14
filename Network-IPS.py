from scapy.all import sniff, TCP, IP, ARP
from collections import defaultdict
import time
from datetime import datetime
import pytz
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess
import smtplib
import subprocess

# Email sender config
SENDER_EMAIL = "senderemail@gmail.com"
SENDER_PASSWORD = "sender password"
RECIPIENT_EMAIL = "recipientemail@gmail.com"

DOS_THRESHOLD = 1000
SCAN_THRESHOLD = 70
SSH_THRESHOLD = 10
ARP_THRESHOLD = 2

REPORT_INTERVAL = 1      # Minimum time between reports (seconds)
RESET_INTERVAL = 1     # Time to reset counters after no activity (seconds)
COOLDOWN_PERIOD = 3     # Time after an attack before new alerts are generated (seconds)

BLOCKED_IPS = {} 
BLOCK_DURATION = 60

syn_counts = defaultdict(int)
port_scans = defaultdict(set)
ssh_attempts = defaultdict(int)
arp_spoof_tracker = defaultdict(set)
mac_to_ip = defaultdict(set)

last_packet_time = defaultdict(float)
last_reported = defaultdict(float)
last_alert_time = defaultdict(float)
attack_in_progress = defaultdict(dict)


# Email sending
def send_email(text):
    try:
        message = MIMEMultipart()
        message["From"] = SENDER_EMAIL
        message["To"] = RECIPIENT_EMAIL
        message["Subject"] = "Network security warning !!!"
        message.attach(MIMEText(text, "plain"))
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.ehlo() 
            server.starttls() 
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(message)
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")


# Save logs
def save_log(text):
    tehran_timezone = pytz.timezone('Asia/Tehran')
    tehran_time = datetime.now(tehran_timezone)
    time_stamp = tehran_time.strftime("%Y-%m-%d %H:%M:%S")
    text = text + f" ({time_stamp})"
    print(text)
    send_email(text)
    with open('log.txt', 'a') as file:
        file.write(text + '\n')


# Determine that this log Should report or not
def should_report(src, attack_type):
    current_time = time.time()

    if current_time - last_alert_time.get((src, attack_type), 0) < COOLDOWN_PERIOD:
        return False
    
    if current_time - last_reported[src] >= REPORT_INTERVAL:
        last_reported[src] = current_time
        last_alert_time[(src, attack_type)] = current_time
        return True
    
    return False


# Reset inative
def reset_inactive_counters():
    current_time = time.time()
    inactive_ips = [ip for ip, last_time in last_packet_time.items()
                    if current_time - last_time > RESET_INTERVAL]

    for ip in inactive_ips:
        if ip in syn_counts:
            del syn_counts[ip]
        if ip in port_scans:
            del port_scans[ip]
        if ip in ssh_attempts:
            del ssh_attempts[ip]
        if ip in arp_spoof_tracker:
            del arp_spoof_tracker[ip]
        if ip in last_packet_time:
            del last_packet_time[ip]
        if ip in last_reported:
            del last_reported[ip]

        # Remove any attack states for this IP
        for key in list(last_alert_time.keys()):
            if key[0] == ip:
                del last_alert_time[key]


# DoS Detection
def detect_dos(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].flags == 'S':
        src = pkt[IP].src
        last_packet_time[src] = time.time()
        syn_counts[src] += 1
        attack_state = attack_in_progress.get(src, {}).get('dos', False)
        if syn_counts[src] >= DOS_THRESHOLD:
            if not attack_state or should_report(src, 'dos'):
                attack_in_progress.setdefault(src, {})['dos'] = True
                save_log(f"[ALERT] DoS Attack Detected from {src} (SYN count: {syn_counts[src]})")
                block_ip(src)
        else:
            attack_in_progress.setdefault(src, {})['dos'] = False


# Port Scan Detection
def detect_port_scan(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        src = pkt[IP].src
        last_packet_time[src] = time.time()
        dport = pkt[TCP].dport
        port_scans[src].add(dport)
        attack_state = attack_in_progress.get(src, {}).get('scan', False)
        if len(port_scans[src]) >= SCAN_THRESHOLD:
            if not attack_state or should_report(src, 'scan'):
                attack_in_progress.setdefault(src, {})['scan'] = True
                save_log(
                    f"[ALERT] Port Scanning Detected from {src} (Unique ports: {len(port_scans[src])})")
                block_ip(src)
        else:
            attack_in_progress.setdefault(src, {})['scan'] = False


#arp_spoof detection
def detect_arp_spoof(pkt):
    if pkt.haslayer(ARP):
        claimed_ip = pkt[ARP].psrc
        claimed_mac = pkt[ARP].hwsrc
        mac_to_ip[claimed_mac].add(claimed_ip)
        arp_spoof_tracker[claimed_ip].add(claimed_mac)
        if len(arp_spoof_tracker[claimed_ip]) >= ARP_THRESHOLD:
            current_time = time.time()
            if current_time - last_reported[claimed_ip] >= REPORT_INTERVAL:
                last_reported[claimed_ip] = current_time
                possible_attackers = [mac for mac in arp_spoof_tracker[claimed_ip]]
                attacker_info = []
                for mac in possible_attackers:
                    ips = list(mac_to_ip[mac])
                    attacker_info.append(f"{mac} (claimed IPs: {ips})")
                save_log(
                    f"[ALERT] ARP Spoofing Detected! IP {claimed_ip} has multiple MACs: {attacker_info}")


# SSH Brute-force Detection
def detect_ssh_brute(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        if pkt[TCP].dport == 22:
            src = pkt[IP].src
            last_packet_time[src] = time.time()
            ssh_attempts[src] += 1
            attack_state = attack_in_progress.get(src, {}).get('ssh', False)
            if ssh_attempts[src] >= SSH_THRESHOLD:
                if not attack_state or should_report(src, 'ssh'):
                    attack_in_progress.setdefault(src, {})['ssh'] = True
                    save_log(
                        f"[ALERT] SSH Brute-force Detected from {src} (Attempts: {ssh_attempts[src]})")
                    block_ip(src)
            else:
                attack_in_progress.setdefault(src, {})['ssh'] = False


# Block ip
def block_ip(ip):
    if ip not in BLOCKED_IPS:
        try:
            subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            save_log(f"[ACTION] Blocked IP via iptables: {ip}")
            BLOCKED_IPS[ip] = time.time()
        except subprocess.CalledProcessError as e:
            save_log(f"[ERROR] Failed to block IP {ip}: {e}")


def release_expired_blocks():
    now = time.time()
    expired_ips = [ip for ip, t in BLOCKED_IPS.items() if now - t >= BLOCK_DURATION]

    for ip in expired_ips:
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            save_log(f"[ACTION] Unblocked IP (timeout): {ip}")
            del BLOCKED_IPS[ip]
        except subprocess.CalledProcessError as e:
            save_log(f"[ERROR] Failed to unblock IP {ip}: {e}")


def process_packet(pkt):
    try:
        release_expired_blocks()
        reset_inactive_counters()

        if pkt.haslayer(IP):
            detect_dos(pkt)
            detect_port_scan(pkt)
            detect_ssh_brute(pkt)
        if pkt.haslayer(ARP):
            detect_arp_spoof(pkt)
    except Exception as e:
        print(f"[ERROR] Processing packet: {e}")


print("[*] Sniffing started on wlan0 ... Press Ctrl+C to stop.")
sniff(iface="wlan0", prn=process_packet, store=0)
