import sqlite3
import os
import datetime
from config import Config

def get_db_connection():
    db_path = Config.DATABASE_PATH
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Packets Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            size INTEGER,
            payload TEXT
        )
    ''')

    # Alerts Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            status TEXT DEFAULT 'Open',
            details TEXT,
            payload_snippet TEXT
        )
    ''')

    # Blocked IPs Table (Simulated Firewall)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            reason TEXT NOT NULL,
            blocked_by TEXT DEFAULT 'System'
        )
    ''')

    # Rules Config Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rules_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT UNIQUE NOT NULL,
            enabled INTEGER DEFAULT 1,
            threshold INTEGER NOT NULL,
            time_window INTEGER NOT NULL,
            severity TEXT NOT NULL
        )
    ''')

    # Insert default rules if not existing
    default_rules = [
        ('Port Scan Detection', 1, Config.PORT_SCAN_THRESHOLD, Config.PORT_SCAN_WINDOW, 'HIGH'),
        ('Excessive Connections', 1, Config.EXCESSIVE_CONN_THRESHOLD, Config.EXCESSIVE_CONN_WINDOW, 'HIGH'),
        ('ICMP Flood Indicator', 1, Config.ICMP_FLOOD_THRESHOLD, Config.ICMP_FLOOD_WINDOW, 'MEDIUM'),
        ('Malicious Signature Match', 1, 1, 0, 'CRITICAL')
    ]

    for rule in default_rules:
        cursor.execute('''
            INSERT OR IGNORE INTO rules_config (rule_name, enabled, threshold, time_window, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', rule)

    conn.commit()
    conn.close()

def insert_packet(src_ip, dst_ip, protocol, src_port, dst_port, size, payload=""):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO packets (src_ip, dst_ip, protocol, src_port, dst_port, size, payload)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (src_ip, dst_ip, protocol, src_port, dst_port, size, str(payload)))
    packet_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return packet_id

def get_recent_packets(limit=50):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, strftime('%H:%M:%S', timestamp) as time_str, src_ip, dst_ip, protocol, src_port, dst_port, size, payload
        FROM packets ORDER BY id DESC LIMIT ?
    ''', (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def insert_alert(src_ip, dst_ip, protocol, alert_type, severity, confidence, risk_score, details="", payload_snippet=""):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (src_ip, dst_ip, protocol, alert_type, severity, confidence, risk_score, details, payload_snippet)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (src_ip, dst_ip, protocol, alert_type, severity, confidence, risk_score, details, payload_snippet))
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return alert_id

def get_recent_alerts(limit=50, severity=None, status=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT id, strftime('%Y-%m-%d %H:%M:%S', timestamp) as time_str, src_ip, dst_ip, protocol, alert_type, severity, confidence, risk_score, status, details, payload_snippet FROM alerts WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if status:
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def update_alert_status(alert_id, status):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE alerts SET status = ? WHERE id = ?', (status, alert_id))
    conn.commit()
    conn.close()

def block_ip(ip, reason="Security Policy Violation", blocked_by="Admin"):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_by, timestamp)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ''', (ip, reason, blocked_by))
        conn.commit()
        success = True
    except Exception as e:
        success = False
    conn.close()
    return success

def unblock_ip(ip):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
    conn.commit()
    conn.close()

def get_blocked_ips():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, strftime('%Y-%m-%d %H:%M:%S', timestamp) as time_str, ip, reason, blocked_by
        FROM blocked_ips ORDER BY id DESC
    ''')
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def is_ip_blocked(ip):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM blocked_ips WHERE ip = ?', (ip,))
    blocked = cursor.fetchone() is not None
    conn.close()
    return blocked

def get_dashboard_stats():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM packets')
    total_packets = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(DISTINCT src_ip) FROM packets')
    unique_sources = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM alerts')
    total_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('HIGH', 'CRITICAL')")
    high_risk_alerts = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM blocked_ips')
    total_blocked = cursor.fetchone()[0]

    conn.close()
    return {
        'total_packets': total_packets,
        'unique_sources': unique_sources,
        'total_alerts': total_alerts,
        'high_risk': high_risk_alerts,
        'total_blocked': total_blocked
    }

def get_traffic_chart_data():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get count of packets grouped by protocol
    cursor.execute('''
        SELECT protocol, COUNT(*) as count FROM packets GROUP BY protocol
    ''')
    protocol_data = {r['protocol']: r['count'] for r in cursor.fetchall()}

    # Get count of alerts by severity
    cursor.execute('''
        SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity
    ''')
    severity_data = {r['severity']: r['count'] for r in cursor.fetchall()}

    # Get last 10 minute intervals of traffic volume
    cursor.execute('''
        SELECT strftime('%H:%M', timestamp) as time_interval, COUNT(*) as pkt_count
        FROM packets
        GROUP BY time_interval
        ORDER BY time_interval DESC
        LIMIT 10
    ''')
    timeline_rows = cursor.fetchall()
    timeline = [{'time': r['time_interval'], 'count': r['pkt_count']} for r in reversed(timeline_rows)]

    conn.close()
    return {
        'protocol_distribution': protocol_data,
        'severity_distribution': severity_data,
        'timeline': timeline
    }
