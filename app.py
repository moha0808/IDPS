from flask import Flask, render_template, jsonify, request
from config import Config
from database.db_manager import (
    init_db, get_dashboard_stats, get_traffic_chart_data,
    get_recent_alerts, get_recent_packets, get_blocked_ips,
    block_ip, unblock_ip, update_alert_status
)
from detector.packet_capture import start_live_sniffing
from detector.traffic_simulator import (
    run_background_simulator, trigger_port_scan,
    trigger_excessive_connections, trigger_icmp_flood,
    trigger_sqli_attack, trigger_xss_attack
)

app = Flask(__name__)
app.config.from_object(Config)

# Initialize SQLite schema
init_db()

# Start background packet ingestion & simulation
start_live_sniffing()
run_background_simulator()

# --- Page Routes ---

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html")

@app.route("/traffic")
def traffic_page():
    return render_template("traffic.html")

@app.route("/prevention")
def prevention_page():
    return render_template("prevention.html")

@app.route("/reports")
def reports_page():
    return render_template("reports.html")

# --- API Endpoints ---

@app.route("/api/stats")
def api_stats():
    stats = get_dashboard_stats()
    charts = get_traffic_chart_data()
    return jsonify({
        'status': 'success',
        'stats': stats,
        'charts': charts
    })

@app.route("/api/alerts")
def api_alerts():
    limit = request.args.get('limit', 50, type=int)
    severity = request.args.get('severity', None)
    status = request.args.get('status', None)
    
    alerts = get_recent_alerts(limit=limit, severity=severity, status=status)
    return jsonify({
        'status': 'success',
        'count': len(alerts),
        'alerts': alerts
    })

@app.route("/api/traffic")
def api_traffic():
    limit = request.args.get('limit', 50, type=int)
    packets = get_recent_packets(limit=limit)
    return jsonify({
        'status': 'success',
        'count': len(packets),
        'packets': packets
    })

@app.route("/api/prevention/blocked", methods=["GET"])
def api_get_blocked():
    blocked = get_blocked_ips()
    return jsonify({
        'status': 'success',
        'blocked_ips': blocked
    })

@app.route("/api/prevention/block", methods=["POST"])
def api_block_ip():
    data = request.get_json() or {}
    ip = data.get("ip")
    reason = data.get("reason", "Manual Admin Block")
    
    if not ip:
        return jsonify({'status': 'error', 'message': 'IP address is required'}), 400

    success = block_ip(ip, reason=reason, blocked_by="SOC Administrator")
    if success:
        return jsonify({'status': 'success', 'message': f'IP {ip} successfully blocked.'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to block IP.'}), 500

@app.route("/api/prevention/unblock", methods=["POST"])
def api_unblock_ip():
    data = request.get_json() or {}
    ip = data.get("ip")
    
    if not ip:
        return jsonify({'status': 'error', 'message': 'IP address is required'}), 400

    unblock_ip(ip)
    return jsonify({'status': 'success', 'message': f'IP {ip} unblocked.'})

@app.route("/api/alert/status", methods=["POST"])
def api_update_alert():
    data = request.get_json() or {}
    alert_id = data.get("alert_id")
    status = data.get("status")
    
    if not alert_id or not status:
        return jsonify({'status': 'error', 'message': 'alert_id and status are required'}), 400

    update_alert_status(alert_id, status)
    return jsonify({'status': 'success', 'message': 'Alert status updated.'})

@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    data = request.get_json() or {}
    attack_type = data.get("type", "port_scan")
    src_ip = data.get("src_ip") or f"192.168.1.{request.args.get('id', 150)}"
    
    msg = ""
    if attack_type == "port_scan":
        msg = trigger_port_scan(attacker_ip=src_ip)
    elif attack_type == "excessive_conn":
        msg = trigger_excessive_connections(attacker_ip=src_ip)
    elif attack_type == "icmp_flood":
        msg = trigger_icmp_flood(attacker_ip=src_ip)
    elif attack_type == "sqli":
        msg = trigger_sqli_attack(attacker_ip=src_ip)
    elif attack_type == "xss":
        msg = trigger_xss_attack(attacker_ip=src_ip)
    else:
        return jsonify({'status': 'error', 'message': 'Unknown simulation type'}), 400

    return jsonify({'status': 'success', 'message': msg})

if __name__ == "__main__":
    print("[+] Starting IDPS Flask Web Application on http://127.0.0.1:5005")
    app.run(host="127.0.0.1", port=5005, debug=True)

