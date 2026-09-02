from config import Config
from database.db_manager import block_ip, is_ip_blocked

def calculate_risk_score(severity, confidence):
    """
    Calculates a numerical risk score (0-100) based on severity and confidence.
    """
    severity_weights = {
        'CRITICAL': 95,
        'HIGH': 80,
        'MEDIUM': 50,
        'LOW': 25
    }

    confidence_multipliers = {
        'HIGH': 1.0,
        'MEDIUM': 0.85,
        'LOW': 0.70
    }

    base_score = severity_weights.get(severity.upper(), 30)
    multiplier = confidence_multipliers.get(confidence.upper(), 0.85)

    risk_score = int(min(100, max(0, base_score * multiplier)))
    return risk_score

def evaluate_risk_and_policy(src_ip, alert):
    """
    Evaluates risk score and determines if prevention action should be triggered.
    """
    severity = alert.get('severity', 'LOW')
    confidence = alert.get('confidence', 'MEDIUM')
    
    score = calculate_risk_score(severity, confidence)
    alert['risk_score'] = score

    # Prevention policy evaluation
    if is_ip_blocked(src_ip):
        alert['action_taken'] = 'BLOCKED'
    elif score >= Config.AUTO_BLOCK_RISK_THRESHOLD:
        # Automated prevention action in lab mode
        block_ip(src_ip, reason=f"Auto-blocked by IDPS: {alert['alert_type']} (Risk Score: {score})", blocked_by='IDPS Auto-Prevention')
        alert['action_taken'] = 'AUTO_BLOCKED'
    elif score >= 50:
        alert['action_taken'] = 'MONITOR'
    else:
        alert['action_taken'] = 'LOGGED'

    return alert
