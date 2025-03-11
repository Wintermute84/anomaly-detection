from scapy.all import *
import time
import random

# Target (Localhost for Safety)
TARGET_IP = "127.0.0.1"

# Common Ports for Attacks & Normal Traffic
PORTS = {
    "HTTP": 80,
    "HTTPS": 443,
    "SSH": 22,
    "MYSQL": 3306,
    "DNS": 53,
    "RDP": 3389
}

# Limit packet rate to prevent system overload
RATE_LIMIT = 0.05  # Adjust as needed

# 🛑 Malicious Traffic Functions
def syn_flood():
    """Simulate a slow SYN flood attack"""
    print("[*] Launching SYN Flood")
    for _ in range(10):
        packet = IP(dst=TARGET_IP) / TCP(dport=random.choice(list(PORTS.values())), flags="S")
        send(packet, verbose=False)
        time.sleep(RATE_LIMIT)

def port_scan():
    """Simulate a basic port scan"""
    print("[*] Scanning Ports")
    for port in PORTS.values():
        packet = IP(dst=TARGET_IP) / TCP(dport=port, flags="S")
        send(packet, verbose=False)
        time.sleep(RATE_LIMIT)

def web_attack():
    """Simulate web attack (fake HTTP requests)"""
    print("[*] Sending Fake HTTP Requests")
    http_payload = b"GET /malicious HTTP/1.1\r\nHost: localhost\r\n\r\n"
    for _ in range(5):
        packet = IP(dst=TARGET_IP) / TCP(dport=PORTS["HTTP"], flags="PA") / Raw(load=http_payload)
        send(packet, verbose=False)
        time.sleep(RATE_LIMIT)

# ✅ Normal Traffic Functions
def normal_web_request():
    """Simulate a real web request"""
    print("[*] Simulating Normal Web Traffic")
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n"
    packet = IP(dst=TARGET_IP) / TCP(dport=PORTS["HTTP"], flags="PA") / Raw(load=http_payload)
    send(packet, verbose=False)
    time.sleep(RATE_LIMIT)

def normal_dns_request():
    """Simulate a normal DNS query"""
    print("[*] Sending Normal DNS Query")
    dns_query = IP(dst=TARGET_IP) / UDP(dport=PORTS["DNS"]) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    send(dns_query, verbose=False)
    time.sleep(RATE_LIMIT)

def normal_ssh_connection():
    """Simulate an SSH handshake"""
    print("[*] Simulating Normal SSH Connection")
    packet = IP(dst=TARGET_IP) / TCP(dport=PORTS["SSH"], flags="S")
    send(packet, verbose=False)
    time.sleep(RATE_LIMIT)

def normal_mysql_query():
    """Simulate a MySQL database query"""
    print("[*] Sending Normal MySQL Query")
    mysql_query = IP(dst=TARGET_IP) / TCP(dport=PORTS["MYSQL"], flags="PA") / Raw(load="SELECT * FROM users;")
    send(mysql_query, verbose=False)
    time.sleep(RATE_LIMIT)

# 🎛️ Function to Run Mixed Traffic
def run_mixed_traffic():
    """Randomly generate both normal and attack traffic"""
    while True:
        choice = random.choice(["SYN_FLOOD", "PORT_SCAN", "WEB_ATTACK", 
                                "NORMAL_WEB", "NORMAL_DNS", "NORMAL_SSH", "NORMAL_MYSQL"])
        
        if choice == "SYN_FLOOD":
            syn_flood()
        elif choice == "PORT_SCAN":
            port_scan()
        elif choice == "WEB_ATTACK":
            web_attack()
        elif choice == "NORMAL_WEB":
            normal_web_request()
        elif choice == "NORMAL_DNS":
            normal_dns_request()
        elif choice == "NORMAL_SSH":
            normal_ssh_connection()
        elif choice == "NORMAL_MYSQL":
            normal_mysql_query()
        
        # Run every few seconds to mimic real network behavior
        time.sleep(1)

# 🚀 Run the Script
if __name__ == "__main__":
    print("🚀 Safe Mixed Traffic Simulator")
    print("⚠️ Target:", TARGET_IP)
    print("📡 Open Wireshark and use 'ip.addr == 127.0.0.1' to monitor traffic")
    run_mixed_traffic()

