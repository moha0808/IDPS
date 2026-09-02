import time
from collections import defaultdict
from config import Config

# Dynamic window memory for rate & anomaly tracking
port_scan_history = defaultdict(list)
connection_history = defaultdict(list)
icmp_history = defaultdict(list)

# Malicious Payload Signatures
MALICIOUS_SIGNATURES = [
    ('SQL Injection Attempt', ['UNION SELECT', "' OR '1'='1", "DROP TABLE", "--", "INFORMATION_SCHEMA"]),
    ('Cross-Site Scripting (XSS)', ['<script>', 'javascript:', 'onerror=', 'onload=']),
    ('Directory Traversal', ['../..', '/etc/passwd', 'c:\\windows\\system32']),
    ('Command Injection', ['; cat /etc', '| dir', '&& whoami', '`id`']),
    ('Nmap / Scanner User-Agent Probing', ['Nmap', 'Nikto', 'sqlmap', 'Gobuster', 'DirBuster'])
]

def check_port_scan(src_ip, dst_port):
    """Detects if source IP is probing multiple unique ports in a short window."""
    if dst_port is None:
        return None

    current_time = time.time()
    # Record current event
    port_scan_history[src_ip].append((current_time, dst_port))

    # Purge entries older than window
    port_scan_history[src_ip] = [
        (t, p) for t, p in port_scan_history[src_ip]
        if current_time - t <= Config.PORT_SCAN_WINDOW
    ]

    # Calculate unique ports targeted
    unique_ports = set(p for _, p in port_scan_history[src_ip])

    if len(unique_ports) >= Config.PORT_SCAN_THRESHOLD:
        return {
            'detected': True,
            'alert_type': 'Port Scanning Activity',
            'severity': 'HIGH',
            'confidence': 'HIGH',
            'details': f'Source IP {src_ip} targeted {len(unique_ports)} unique ports in under {Config.PORT_SCAN_WINDOW}s.'
        }
    return None

def check_excessive_connections(src_ip):
    """Detects if source IP sends connections faster than threshold."""
    current_time = time.time()
    connection_history[src_ip].append(current_time)

    # Purge old timestamps
    connection_history[src_ip] = [
        t for t in connection_history[src_ip]
        if current_time - t <= Config.EXCESSIVE_CONN_WINDOW
    ]

    count = len(connection_history[src_ip])
    if count >= Config.EXCESSIVE_CONN_THRESHOLD:
        return {
            'detected': True,
            'alert_type': 'Excessive Connection Spike',
            'severity': 'HIGH',
            'confidence': 'MEDIUM',
            'details': f'Source IP {src_ip} generated {count} connections in under {Config.EXCESSIVE_CONN_WINDOW}s (DoS indicator).'
        }
    return None

def check_icmp_flood(src_ip, protocol):
    """Detects unusually high ICMP volume."""
    if protocol != 'ICMP':
        return None

    current_time = time.time()
    icmp_history[src_ip].append(current_time)

    icmp_history[src_ip] = [
        t for t in icmp_history[src_ip]
        if current_time - t <= Config.ICMP_FLOOD_WINDOW
    ]

    count = len(icmp_history[src_ip])
    if count >= Config.ICMP_FLOOD_THRESHOLD:
        return {
            'detected': True,
            'alert_type': 'ICMP Flood Indicator',
            'severity': 'MEDIUM',
            'confidence': 'HIGH',
            'details': f'Source IP {src_ip} sent {count} ICMP echo requests in under {Config.ICMP_FLOOD_WINDOW}s.'
        }
    return None

def check_payload_signatures(payload):
    """Inspects packet payload string for known malicious signatures."""
    if not payload:
        return None

    payload_str = str(payload).upper()

    for attack_type, keywords in MALICIOUS_SIGNATURES:
        for kw in keywords:
            if kw.upper() in payload_str:
                return {
                    'detected': True,
                    'alert_type': f'Malicious Payload ({attack_type})',
                    'severity': 'CRITICAL',
                    'confidence': 'HIGH',
                    'details': f'Payload matched signature pattern: "{kw}"'
                }
    return None

def analyze_packet_rules(src_ip, dst_ip, protocol, src_port, dst_port, payload=""):
    """Runs all detection rules on an incoming packet and returns triggered alerts list."""
    alerts = []

    # 1. Signature Check
    sig_alert = check_payload_signatures(payload)
    if sig_alert:
        alerts.append(sig_alert)

    # 2. Port Scan Check
    ps_alert = check_port_scan(src_ip, dst_port)
    if ps_alert:
        alerts.append(ps_alert)

    # 3. Excessive Connection / DoS Check
    conn_alert = check_excessive_connections(src_ip)
    if conn_alert:
        alerts.append(conn_alert)

    # 4. ICMP Flood Check
    icmp_alert = check_icmp_flood(src_ip, protocol)
    if icmp_alert:
        alerts.append(icmp_alert)

    return alerts
