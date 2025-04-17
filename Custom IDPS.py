from scapy.all import sniff, IP, ICMP, TCP, UDP, Raw, ARP, Ether
from collections import defaultdict
import time
import os
import logging

# Logging setup
logging.basicConfig(
    filename="idps_alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# Time window and thresholds
TIME_WINDOW = 5  # seconds
ICMP_THRESHOLD = 50
SYN_THRESHOLD = 100
UDP_THRESHOLD = 100
HTTP_THRESHOLD = 40
DNS_THRESHOLD = 60
POD_SIZE_THRESHOLD = 65535
SLOWLORIS_CONN_THRESHOLD = 40

# Packet counters
icmp_count = defaultdict(list)
syn_count = defaultdict(list)
udp_count = defaultdict(list)
http_count = defaultdict(list)
dns_count = defaultdict(list)
slowloris_conn = defaultdict(list)
blocked_ips = set()
arp_table = {}  # For ARP spoofing detection

def block_ip(ip):
    if ip not in blocked_ips:
        print(f"[BLOCKED] Blocking IP: {ip}")
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        blocked_ips.add(ip)

def detect_icmp_flood(packet):
    if IP in packet and ICMP in packet:
        src_ip = packet[IP].src
        now = time.time()
        icmp_count[src_ip].append(now)
        icmp_count[src_ip] = [t for t in icmp_count[src_ip] if now - t < TIME_WINDOW]
        if len(icmp_count[src_ip]) > ICMP_THRESHOLD:
            alert = f"[ALERT] ICMP Flood detected from {src_ip}"
            print(alert)
            logging.info(alert)
            block_ip(src_ip)

def detect_syn_flood(packet):
    if IP in packet and TCP in packet and packet[TCP].flags == 'S':
        src_ip = packet[IP].src
        now = time.time()
        syn_count[src_ip].append(now)
        syn_count[src_ip] = [t for t in syn_count[src_ip] if now - t < TIME_WINDOW]
        if len(syn_count[src_ip]) > SYN_THRESHOLD:
            alert = f"[ALERT] SYN Flood detected from {src_ip}"
            print(alert)
            logging.info(alert)
            block_ip(src_ip)

def detect_udp_flood(packet):
    if IP in packet and UDP in packet:
        src_ip = packet[IP].src
        now = time.time()
        udp_count[src_ip].append(now)
        udp_count[src_ip] = [t for t in udp_count[src_ip] if now - t < TIME_WINDOW]
        if len(udp_count[src_ip]) > UDP_THRESHOLD:
            alert = f"[ALERT] UDP Flood detected from {src_ip}"
            print(alert)
            logging.info(alert)
            block_ip(src_ip)

def detect_http_get_flood(packet):
    if IP in packet and TCP in packet and packet[TCP].dport in [80, 443] and Raw in packet:
        payload = packet[Raw].load
        if payload.startswith(b"GET"):
            src_ip = packet[IP].src
            now = time.time()
            http_count[src_ip].append(now)
            http_count[src_ip] = [t for t in http_count[src_ip] if now - t < TIME_WINDOW]
            if len(http_count[src_ip]) > HTTP_THRESHOLD:
                alert = f"[ALERT] HTTP GET Flood detected from {src_ip}"
                print(alert)
                logging.info(alert)
                block_ip(src_ip)

def detect_dns_flood(packet):
    if IP in packet and UDP in packet and packet[UDP].dport == 53:
        src_ip = packet[IP].src
        now = time.time()
        dns_count[src_ip].append(now)
        dns_count[src_ip] = [t for t in dns_count[src_ip] if now - t < TIME_WINDOW]
        if len(dns_count[src_ip]) > DNS_THRESHOLD:
            alert = f"[ALERT] DNS Flood detected from {src_ip}"
            print(alert)
            logging.info(alert)
            block_ip(src_ip)

def detect_ping_of_death(packet):
    if IP in packet and ICMP in packet:
        src_ip = packet[IP].src
        if len(packet) > POD_SIZE_THRESHOLD:
            alert = f"[ALERT] Ping of Death detected from {src_ip}"
            print(alert)
            logging.info(alert)
            block_ip(src_ip)

def detect_slowloris(packet):
    if IP in packet and TCP in packet and packet[TCP].dport == 80 and packet[TCP].flags == 'S':
        src_ip = packet[IP].src
        now = time.time()
        slowloris_conn[src_ip].append(now)
        slowloris_conn[src_ip] = [t for t in slowloris_conn[src_ip] if now - t < 60]
        if len(slowloris_conn[src_ip]) > SLOWLORIS_CONN_THRESHOLD:
            alert = f"[ALERT] Slowloris-style connection flood from {src_ip}"
            print(alert)
            logging.info(alert)
            block_ip(src_ip)

def detect_arp_spoof(packet):
    if ARP in packet and packet[ARP].op == 2:  
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        if src_ip in arp_table:
            if arp_table[src_ip] != src_mac:
                alert = f"[ALERT] Possible ARP Spoofing detected! {src_ip} changed MAC from {arp_table[src_ip]} to {src_mac}"
                print(alert)
                logging.info(alert)
                block_ip(src_ip)
        else:
            arp_table[src_ip] = src_mac

def handle_packet(packet):
    detect_icmp_flood(packet)
    detect_syn_flood(packet)
    detect_udp_flood(packet)
    detect_http_get_flood(packet)
    detect_dns_flood(packet)
    detect_ping_of_death(packet)
    detect_slowloris(packet)
    detect_arp_spoof(packet)

def start_idps():
    print("[*] IDPS is running. Monitoring all Attacks...")
    sniff(prn=handle_packet, store=0)

if __name__ == "__main__":
    start_idps()
