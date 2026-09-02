import os
import sys
import unittest

# Add root directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.db_manager import (
    init_db, insert_packet, get_recent_packets,
    insert_alert, get_recent_alerts, block_ip,
    unblock_ip, is_ip_blocked, get_dashboard_stats
)
from detector.rules import (
    check_payload_signatures, check_port_scan,
    check_excessive_connections, check_icmp_flood,
    analyze_packet_rules
)
from detector.risk_engine import calculate_risk_score, evaluate_risk_and_policy
from detector.packet_capture import process_packet_data

class TestIDPSCore(unittest.TestCase):

    def setUp(self):
        init_db()

    def test_database_operations(self):
        pkt_id = insert_packet("192.168.1.10", "192.168.1.1", "TCP", 12345, 80, 512, "Test Packet")
        self.assertIsNotNone(pkt_id)

        packets = get_recent_packets(limit=5)
        self.assertGreater(len(packets), 0)

        alert_id = insert_alert("192.168.1.50", "192.168.1.20", "TCP", "Port Scanning", "HIGH", "HIGH", 85, "Details")
        self.assertIsNotNone(alert_id)

        alerts = get_recent_alerts(limit=5)
        self.assertGreater(len(alerts), 0)

    def test_firewall_block_unblock(self):
        test_ip = "192.168.1.99"
        unblock_ip(test_ip)
        self.assertFalse(is_ip_blocked(test_ip))

        block_ip(test_ip, reason="Test Block", blocked_by="UnitTest")
        self.assertTrue(is_ip_blocked(test_ip))

        unblock_ip(test_ip)
        self.assertFalse(is_ip_blocked(test_ip))

    def test_signature_detection(self):
        sqli_payload = "GET /user?id=1' UNION SELECT 1,2,3-- HTTP/1.1"
        res = check_payload_signatures(sqli_payload)
        self.assertIsNotNone(res)
        self.assertEqual(res['severity'], 'CRITICAL')

    def test_risk_engine(self):
        score_critical = calculate_risk_score('CRITICAL', 'HIGH')
        self.assertGreaterEqual(score_critical, 90)

        score_low = calculate_risk_score('LOW', 'LOW')
        self.assertLessEqual(score_low, 30)

    def test_end_to_end_ingestion(self):
        process_packet_data("10.0.0.99", "10.0.0.1", "TCP", 54321, 80, 64, "GET /admin' UNION SELECT 1--")
        stats = get_dashboard_stats()
        self.assertGreater(stats['total_packets'], 0)
        self.assertGreater(stats['total_alerts'], 0)

if __name__ == '__main__':
    unittest.main()
