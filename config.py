import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'idps_cyber_security_secret_key_2026')
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'idps.db')
    
    # Detection Engine Thresholds
    PORT_SCAN_THRESHOLD = 8       # > 8 unique ports from same IP within time window
    PORT_SCAN_WINDOW = 10         # 10 seconds time window
    
    EXCESSIVE_CONN_THRESHOLD = 20 # > 20 connections from same IP within time window
    EXCESSIVE_CONN_WINDOW = 10    # 10 seconds time window
    
    ICMP_FLOOD_THRESHOLD = 15     # > 15 ICMP packets from same IP within time window
    ICMP_FLOOD_WINDOW = 10        # 10 seconds time window
    
    # Risk Engine Configuration
    AUTO_BLOCK_RISK_THRESHOLD = 80 # Automatically recommend block if risk >= 80
    
    # Traffic Simulator Options
    SIMULATOR_INTERVAL = 1.5      # Seconds between simulated background packets
