import random
import time
import threading
from config import Config
from detector.packet_capture import process_packet_data

# Common local IP pools
LAB_CLIENT_IPS = ['192.168.1.10', '192.168.1.15', '192.168.1.22', '10.0.0.45', '172.16.0.12']
LAB_SERVER_IPS = ['192.168.1.1', '192.168.1.100', '10.0.0.1']

COMMON_PORTS = [80, 443, 53, 22, 21, 3306, 8080, 8443]
PROTOCOLS = ['TCP', 'TCP', 'TCP', 'UDP', 'ICMP']

simulator_running = False

def generate_normal_packet():
    """Generates a realistic background network packet."""
    src_ip = random.choice(LAB_CLIENT_IPS)
    dst_ip = random.choice(LAB_SERVER_IPS)
    protocol = random.choice(PROTOCOLS)
    
    src_port = random.randint(49152, 65535)
    dst_port = random.choice(COMMON_PORTS) if protocol in ['TCP', 'UDP'] else None
    size = random.randint(64, 1460)
    
    payloads = [
        "GET /index.html HTTP/1.1\r\nHost: example.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        "POST /api/v1/telemetry HTTP/1.1\r\nHost: server.local\r\nContent-Type: application/json\r\n\r\n",
        "DNS Standard Query A google.com",
        "TCP SYN Connection Request",
        "ICMP Echo Request (Ping)"
    ]
    payload = random.choice(payloads)

    process_packet_data(src_ip, dst_ip, protocol, src_port, dst_port, size, payload)

def run_background_simulator():
    """Runs continuous background normal network traffic generator."""
    global simulator_running
    if simulator_running:
        return
    
    simulator_running = True

    def _loop():
        while True:
            try:
                generate_normal_packet()
                time.sleep(Config.SIMULATOR_INTERVAL)
            except Exception as e:
                time.sleep(2)

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()

# --- Attack Simulation Triggers ---

def trigger_port_scan(attacker_ip='192.168.1.50', victim_ip='192.168.1.100'):
    """Simulates Nmap multi-port scanning attack sequence."""
    def _run():
        scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
        for port in scan_ports:
            payload = f"Nmap Port Probe -> TCP SYN {port}"
            process_packet_data(attacker_ip, victim_ip, 'TCP', random.randint(50000, 60000), port, 64, payload)
            time.sleep(0.05)
    
    threading.Thread(target=_run, daemon=True).start()
    return f"Triggered Port Scan simulation from {attacker_ip}"

def trigger_excessive_connections(attacker_ip='192.168.1.75', victim_ip='192.168.1.100'):
    """Simulates DoS connection flood attack."""
    def _run():
        for _ in range(30):
            process_packet_data(attacker_ip, victim_ip, 'TCP', random.randint(40000, 65000), 80, 512, "SYN FLOOD PACKET")
            time.sleep(0.02)
    
    threading.Thread(target=_run, daemon=True).start()
    return f"Triggered Excessive Connection spike from {attacker_ip}"

def trigger_icmp_flood(attacker_ip='192.168.1.99', victim_ip='192.168.1.1'):
    """Simulates Ping Flood ICMP anomaly."""
    def _run():
        for _ in range(20):
            process_packet_data(attacker_ip, victim_ip, 'ICMP', None, None, 1024, "ECHO REQUEST FLOOD")
            time.sleep(0.03)

    threading.Thread(target=_run, daemon=True).start()
    return f"Triggered ICMP Flood simulation from {attacker_ip}"

def trigger_sqli_attack(attacker_ip='192.168.1.88', victim_ip='192.168.1.100'):
    """Simulates SQL Injection malicious web attack payload."""
    def _run():
        payload = "GET /login?user=admin' UNION SELECT 1,username,password FROM users-- HTTP/1.1"
        process_packet_data(attacker_ip, victim_ip, 'TCP', random.randint(50000, 60000), 80, 512, payload)

    threading.Thread(target=_run, daemon=True).start()
    return f"Triggered SQL Injection attack simulation from {attacker_ip}"

def trigger_xss_attack(attacker_ip='192.168.1.89', victim_ip='192.168.1.100'):
    """Simulates XSS payload attack."""
    def _run():
        payload = "POST /comment HTTP/1.1\r\n\r\ncomment=<script>alert('IDPS_XSS_TEST')</script>"
        process_packet_data(attacker_ip, victim_ip, 'TCP', random.randint(50000, 60000), 443, 720, payload)

    threading.Thread(target=_run, daemon=True).start()
    return f"Triggered XSS attack simulation from {attacker_ip}"
