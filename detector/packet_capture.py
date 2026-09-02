import threading
import time

try:
    # pyrefly: ignore [missing-import]
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except Exception as e:
    SCAPY_AVAILABLE = False

from database.db_manager import insert_packet, insert_alert, is_ip_blocked
from detector.rules import analyze_packet_rules
from detector.risk_engine import evaluate_risk_and_policy

def process_packet_data(src_ip, dst_ip, protocol, src_port=None, dst_port=None, size=64, payload=""):
    """
    Central packet ingestion pipeline. Parses, logs packet, executes rules, and triggers risk engine.
    """
    # 1. Insert packet into DB
    insert_packet(src_ip, dst_ip, protocol, src_port, dst_port, size, payload)

    # 2. Check if source IP is blocked by firewall policy
    if is_ip_blocked(src_ip):
        # Packet dropped by simulated firewall policy
        return

    # 3. Analyze packet through rule engine
    triggered_alerts = analyze_packet_rules(src_ip, dst_ip, protocol, src_port, dst_port, payload)

    # 4. Process triggered alerts through risk engine & log
    for alert in triggered_alerts:
        evaluated_alert = evaluate_risk_and_policy(src_ip, alert)
        
        insert_alert(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            alert_type=evaluated_alert['alert_type'],
            severity=evaluated_alert['severity'],
            confidence=evaluated_alert['confidence'],
            risk_score=evaluated_alert['risk_score'],
            details=evaluated_alert['details'],
            payload_snippet=str(payload)[:150]
        )

def _scapy_packet_callback(packet):
    """Callback function for Scapy live packet sniffer."""
    try:
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            size = len(packet)
            protocol = 'IP'
            src_port = None
            dst_port = None
            payload = ""

            if packet.haslayer(TCP):
                protocol = 'TCP'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = 'UDP'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = 'ICMP'

            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                except Exception:
                    payload = str(packet[Raw].load)

            process_packet_data(src_ip, dst_ip, protocol, src_port, dst_port, size, payload)
    except Exception as e:
        pass

def start_live_sniffing():
    """Starts live network packet sniffing in a background daemon thread."""
    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not available. Live packet sniffing disabled.")
        return False

    def _sniff_thread():
        try:
            print("[+] Live Scapy Packet Sniffer starting on background thread...")
            sniff(prn=_scapy_packet_callback, store=False)
        except Exception as e:
            print(f"[!] Scapy Live Sniffer exception: {e}")

    thread = threading.Thread(target=_sniff_thread, daemon=True)
    thread.start()
    return True
