#!/usr/bin/env python3
"""
COMPLETE ENHANCED HONEYPOT SYSTEM
- SSH proxy with real backend (from honeypot_kali.py)
- FTP honeypot with logging
- Web honeypot
- SQLite database logging
- Desktop notifications
- Threat intelligence (AbuseIPDB)
- Daily reporting
- Chart generation
"""

import socket
import threading
import logging
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import paramiko
from datetime import datetime, timedelta
import os
import sqlite3
import json
import re
import subprocess
import requests
from pathlib import Path
from queue import Queue
from dataclasses import dataclass, asdict
from enum import Enum
import traceback
import atexit
import signal
import sys

# Try to import optional dependencies
try:
    import pandas as pd
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
    FTP_LIB_AVAILABLE = True
except ImportError:
    FTP_LIB_AVAILABLE = False

# ============================================================
# GLOBAL VARIABLES FOR SHUTDOWN HANDLING
# ============================================================
running = True
shutdown_event = threading.Event()

# ============================================================
# ENUMS AND DATA CLASSES FOR DESKTOP ALERTS
# ============================================================

class AlertLevel(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AlertType(Enum):
    SSH_TRIGGER = "SSH Trigger Credentials"
    SSH_BRUTE_FORCE = "SSH Brute Force"
    SSH_COMMAND = "Suspicious SSH Command"
    FTP_LOGIN = "FTP Login Attempt"
    FTP_FILE = "FTP File Operation"
    HTTP_REQUEST = "HTTP Attack"
    HIGH_FREQUENCY = "High Attack Frequency"
    NEW_ATTACKER = "New Attacker Detected"
    THREAT_INTEL = "Threat Intelligence Alert"
    SYSTEM = "System Alert"

@dataclass
class Alert:
    level: AlertLevel
    type: AlertType
    title: str
    message: str
    details: dict
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

# ============================================================
# DESKTOP NOTIFICATION MANAGER
# ============================================================

class DesktopNotificationManager:
    """Main desktop notification manager"""
    
    def __init__(self, gui_check=True):
        self.gui_available = self._check_gui_environment() if gui_check else False
        self.alert_queue = Queue()
        self.running = False
        self.worker_thread = None
        self.notification_backend = self._detect_backend()
        
        # Log file for alerts
        self.log_dir = Path("honeypot_alerts")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Alert counters
        self.stats = {
            'total_alerts': 0,
            'by_level': {level.value: 0 for level in AlertLevel},
            'by_type': {atype.value: 0 for atype in AlertType}
        }
        
        # Notification settings
        self.settings = {
            'enabled': True,
            'timeout': 10000,  # ms
            'urgency_levels': {
                AlertLevel.CRITICAL: 'critical',
                AlertLevel.HIGH: 'critical',
                AlertLevel.MEDIUM: 'normal',
                AlertLevel.LOW: 'normal',
                AlertLevel.INFO: 'low'
            },
            'icons': {
                AlertLevel.CRITICAL: 'security-high',
                AlertLevel.HIGH: 'security-high',
                AlertLevel.MEDIUM: 'security-medium',
                AlertLevel.LOW: 'security-low',
                AlertLevel.INFO: 'dialog-information'
            },
            'max_queue_size': 100,
            'cooldown_per_ip': 300,  # seconds
        }
        
        # Track recent alerts to avoid spam
        self.recent_alerts = {}
        
        logging.info(f"Desktop Notification Manager initialized. GUI Available: {self.gui_available}")
        logging.info(f"Detected backend: {self.notification_backend}")
    
    def _check_gui_environment(self):
        """Check if running in GUI environment"""
        # Check for DISPLAY variable (X11)
        if os.getenv('DISPLAY'):
            return True
        
        # Check for Wayland
        if os.getenv('WAYLAND_DISPLAY'):
            return True
        
        # Check for XDG_SESSION_TYPE
        session_type = os.getenv('XDG_SESSION_TYPE', '').lower()
        if session_type in ['x11', 'wayland']:
            return True
        
        return False
    
    def _detect_backend(self):
        """Detect available notification backend"""
        backends = [
            ('notify-send', self._send_notify_send),
            ('zenity', self._send_zenity),
            ('kdialog', self._send_kdialog),
        ]
        
        for backend_name, _ in backends:
            if self._check_command_exists(backend_name):
                return backend_name
        
        return 'console'
    
    def _check_command_exists(self, command):
        """Check if command exists on system"""
        try:
            subprocess.run(['which', command], 
                          stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL,
                          check=True)
            return True
        except:
            return False
    
    # NOTIFICATION BACKENDS
    def _send_notify_send(self, alert):
        """Send notification using notify-send (Linux)"""
        try:
            cmd = [
                'notify-send',
                '-u', self.settings['urgency_levels'][alert.level],
                '-t', str(self.settings['timeout']),
                '-i', self.settings['icons'][alert.level],
                alert.title,
                f"{alert.message}\n\nType: {alert.type.value}\nTime: {alert.timestamp}"
            ]
            
            subprocess.run(cmd, check=True)
            return True
        except Exception as e:
            logging.error(f"notify-send failed: {e}")
            return False
    
    def _send_zenity(self, alert):
        """Send notification using zenity"""
        try:
            subprocess.run([
                'zenity',
                '--info',
                '--title', alert.title,
                '--text', f"{alert.message}\n\nType: {alert.type.value}",
                '--timeout', str(self.settings['timeout'] // 1000),
                '--width', '400',
                '--height', '200'
            ], check=True)
            return True
        except Exception as e:
            logging.error(f"zenity failed: {e}")
            return False
    
    def _send_kdialog(self, alert):
        """Send notification using kdialog (KDE)"""
        try:
            subprocess.run([
                'kdialog',
                '--title', alert.title,
                '--msgbox', f"{alert.message}\n\nType: {alert.type.value}",
                '--geometry', '400x200'
            ], check=True)
            return True
        except Exception as e:
            logging.error(f"kdialog failed: {e}")
            return False
    
    def _display_console_alert(self, alert):
        """Display alert in console with colors"""
        colors = {
            AlertLevel.CRITICAL: '\033[91m',  # Red
            AlertLevel.HIGH: '\033[93m',      # Yellow
            AlertLevel.MEDIUM: '\033[96m',    # Cyan
            AlertLevel.LOW: '\033[92m',       # Green
            AlertLevel.INFO: '\033[94m',      # Blue
        }
        
        reset = '\033[0m'
        color = colors.get(alert.level, reset)
        
        timestamp = datetime.fromisoformat(alert.timestamp).strftime('%H:%M:%S')
        
        print(f"\n{'='*60}")
        print(f"{color}🚨 HONEYPOT ALERT{reset}")
        print(f"{color}{'='*60}{reset}")
        print(f"{color}Time:     {reset}{timestamp}")
        print(f"{color}Level:    {reset}{alert.level.value}")
        print(f"{color}Type:     {reset}{alert.type.value}")
        print(f"{color}Title:    {reset}{alert.title}")
        print(f"{color}Message:  {reset}{alert.message}")
        
        if alert.details:
            print(f"{color}Details:  {reset}")
            for key, value in alert.details.items():
                print(f"          {key}: {value}")
        
        print(f"{color}{'='*60}{reset}\n")
        
        # System beep for critical alerts
        if alert.level in [AlertLevel.CRITICAL, AlertLevel.HIGH]:
            print('\a', end='')
    
    # ALERT MANAGEMENT
    def queue_alert(self, alert):
        """Queue an alert for display"""
        if not self.settings['enabled']:
            return False
        
        # Check queue size
        if self.alert_queue.qsize() >= self.settings['max_queue_size']:
            logging.warning("Alert queue full, dropping alert")
            return False
        
        # Apply cooldown for similar alerts
        alert_key = f"{alert.type.value}_{alert.details.get('client_ip', '')}"
        current_time = time.time()
        
        if alert_key in self.recent_alerts:
            last_time = self.recent_alerts[alert_key]
            if current_time - last_time < self.settings['cooldown_per_ip']:
                logging.debug(f"Alert cooldown active for {alert_key}")
                return False
        
        self.recent_alerts[alert_key] = current_time
        
        # Clean old entries from recent_alerts
        cutoff_time = current_time - 3600
        self.recent_alerts = {
            k: v for k, v in self.recent_alerts.items() 
            if v > cutoff_time
        }
        
        # Add to queue
        self.alert_queue.put(alert)
        
        # Update stats
        self.stats['total_alerts'] += 1
        self.stats['by_level'][alert.level.value] += 1
        self.stats['by_type'][alert.type.value] += 1
        
        # Log to file
        self._log_alert_to_file(alert)
        
        # Start worker if not running
        if not self.running:
            self.start()
        
        return True
    
    def _log_alert_to_file(self, alert):
        """Log alert to JSON file"""
        try:
            log_file = self.log_dir / f"alerts_{datetime.now().strftime('%Y%m%d')}.json"
            
            alert_dict = asdict(alert)
            alert_dict['level'] = alert.level.value
            alert_dict['type'] = alert.type.value
            
            with open(log_file, 'a') as f:
                f.write(json.dumps(alert_dict) + '\n')
        except Exception as e:
            logging.error(f"Failed to log alert to file: {e}")
    
    def _display_alert(self, alert):
        """Display alert using appropriate backend"""
        if self.gui_available:
            backend_functions = {
                'notify-send': self._send_notify_send,
                'zenity': self._send_zenity,
                'kdialog': self._send_kdialog,
            }
            
            func = backend_functions.get(self.notification_backend)
            if func:
                success = func(alert)
                if not success:
                    self._display_console_alert(alert)
            else:
                self._display_console_alert(alert)
        else:
            self._display_console_alert(alert)
    
    # WORKER THREAD
    def _worker(self):
        """Worker thread that processes alert queue"""
        while self.running or not self.alert_queue.empty():
            try:
                try:
                    alert = self.alert_queue.get(timeout=1)
                except:
                    continue
                
                self._display_alert(alert)
                self.alert_queue.task_done()
                
            except Exception as e:
                logging.error(f"Error in alert worker: {e}")
                traceback.print_exc()
    
    def start(self):
        """Start the notification worker"""
        if self.running:
            return
        
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
        logging.info("Desktop notification worker started")
    
    def stop(self):
        """Stop the notification worker"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        logging.info("Desktop notification worker stopped")
    
    # ALERT GENERATION HELPERS
    def alert_ssh_trigger(self, client_ip, username, password):
        """Alert for SSH trigger credentials"""
        alert = Alert(
            level=AlertLevel.CRITICAL,
            type=AlertType.SSH_TRIGGER,
            title="🚨 TRIGGER CREDENTIALS USED!",
            message=f"Trigger credentials used from {client_ip}",
            details={
                'client_ip': client_ip,
                'username': username,
                'password': password[:20] + '...' if len(password) > 20 else password,
                'service': 'SSH',
                'action': 'BLOCK THIS IP IMMEDIATELY'
            }
        )
        return self.queue_alert(alert)
    
    def alert_ssh_brute_force(self, client_ip, attempts):
        """Alert for SSH brute force"""
        alert = Alert(
            level=AlertLevel.HIGH,
            type=AlertType.SSH_BRUTE_FORCE,
            title="🔐 SSH Brute Force Attack",
            message=f"{attempts} failed attempts from {client_ip}",
            details={
                'client_ip': client_ip,
                'attempts': attempts,
                'service': 'SSH',
                'action': 'Consider rate limiting or blocking'
            }
        )
        return self.queue_alert(alert)
    
    def alert_ftp_login(self, client_ip, username, password=None):
        """Alert for FTP login"""
        alert = Alert(
            level=AlertLevel.MEDIUM,
            type=AlertType.FTP_LOGIN,
            title="📁 FTP Login Attempt",
            message=f"FTP login from {client_ip}",
            details={
                'client_ip': client_ip,
                'username': username,
                'password': '***' if password else 'Not provided',
                'service': 'FTP'
            }
        )
        return self.queue_alert(alert)
    
    def alert_ftp_file_operation(self, client_ip, operation, filename):
        """Alert for FTP file operation"""
        alert = Alert(
            level=AlertLevel.LOW,
            type=AlertType.FTP_FILE,
            title=f"📂 FTP File {operation}",
            message=f"File {operation} from {client_ip}",
            details={
                'client_ip': client_ip,
                'operation': operation,
                'filename': filename,
                'service': 'FTP'
            }
        )
        return self.queue_alert(alert)
    
    def alert_http_attack(self, client_ip, method, path, user_agent):
        """Alert for HTTP attack"""
        alert = Alert(
            level=AlertLevel.LOW,
            type=AlertType.HTTP_REQUEST,
            title="🌐 HTTP Attack Detected",
            message=f"{method} request from {client_ip}",
            details={
                'client_ip': client_ip,
                'method': method,
                'path': path[:50] + '...' if len(path) > 50 else path,
                'user_agent': user_agent[:100] + '...' if len(user_agent) > 100 else user_agent,
                'service': 'HTTP'
            }
        )
        return self.queue_alert(alert)
    
    def alert_threat_intel(self, client_ip, score, reports):
        """Alert for threat intelligence detection"""
        alert = Alert(
            level=AlertLevel.HIGH,
            type=AlertType.THREAT_INTEL,
            title="⚠️  Known Threat Actor",
            message=f"IP {client_ip} has threat score {score}%",
            details={
                'client_ip': client_ip,
                'threat_score': score,
                'total_reports': reports,
                'action': 'Monitor closely'
            }
        )
        return self.queue_alert(alert)

# Create global desktop alert instance
desktop_alerts = DesktopNotificationManager()

# ============================================================
# THREAT INTELLIGENCE (AbuseIPDB)
# ============================================================

class ThreatIntelligence:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.cache = {}
        self.cache_duration = 3600  # 1 hour cache
        self.enabled = api_key is not None
        
    def check_ip_threat(self, ip_address):
        """Check IP against AbuseIPDB with caching"""
        if not self.enabled:
            return False, 0
        
        # Check cache first
        current_time = time.time()
        if ip_address in self.cache:
            cached_data = self.cache[ip_address]
            if current_time - cached_data['timestamp'] < self.cache_duration:
                return cached_data['is_threat'], cached_data['score']
        
        # API call
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {'Key': self.api_key, 'Accept': 'application/json'}
            params = {'ipAddress': ip_address, 'maxAgeInDays': 90}
            
            response = requests.get(url, headers=headers, params=params, timeout=5)
            data = response.json()
            
            score = data['data']['abuseConfidenceScore']
            is_threat = score > 25  # Threshold
            
            # Cache result
            self.cache[ip_address] = {
                'is_threat': is_threat,
                'score': score,
                'timestamp': current_time,
                'total_reports': data['data']['totalReports']
            }
            
            if is_threat:
                desktop_alerts.alert_threat_intel(ip_address, score, data['data']['totalReports'])
                logging.warning(f"🚨 THREAT DETECTED: {ip_address} - Score: {score} - Reports: {data['data']['totalReports']}")
            
            return is_threat, score
            
        except Exception as e:
            logging.error(f"Threat intelligence check failed for {ip_address}: {e}")
            return False, 0

# ============================================================
# CONFIGURATION
# ============================================================

SSH_PORT = 2222
HTTP_PORT = 8080
FTP_PORT = 2121
BACKEND_HOST = "10.0.2.33"  # Real backend server
BACKEND_PORT = 22
HOST_KEY_FILE = "honeypot_rsa_key"
FTP_ROOT = "/opt/ftp_honeypot"
SQLITE_DB = "improved_honeypot.db"
ABUSEIPDB_API_KEY = "c607c7a786f4d688adc263e62a59ff3189bb666fbc56402be750b0e269f946a2f6c18fdc13ee15dd"

TRIGGER_CREDS = {
    "ITSC_student": "123456",      
    "SAIT_prof": "admin446",
    "guest": "babyboss22",
}

# Initialize threat intelligence
threat_intel = ThreatIntelligence(ABUSEIPDB_API_KEY)

# Setup logging
logging.basicConfig(
    filename="honeypot.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ============================================================
# DATABASE MANAGER (from honeypot_kali.py)
# ============================================================

class HoneypotDB:
    def __init__(self, db_path=SQLITE_DB):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # SSH sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ssh_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_ip TEXT,
                    client_port INTEGER,
                    username TEXT,
                    password TEXT,
                    auth_result TEXT,
                    session_start TEXT,
                    session_end TEXT,
                    commands_count INTEGER DEFAULT 0,
                    backend_host TEXT,
                    backend_port INTEGER
                )
            ''')
            
            # FTP sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ftp_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_ip TEXT,
                    client_port INTEGER,
                    username TEXT,
                    password TEXT,
                    session_start TEXT,
                    session_end TEXT,
                    files_downloaded INTEGER DEFAULT 0,
                    files_uploaded INTEGER DEFAULT 0
                )
            ''')
            
            # FTP commands table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ftp_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    client_ip TEXT,
                    command TEXT,
                    parameters TEXT,
                    timestamp TEXT,
                    FOREIGN KEY(session_id) REFERENCES ftp_sessions(id)
                )
            ''')
            
            # HTTP requests table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS http_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_ip TEXT,
                    method TEXT,
                    path TEXT,
                    user_agent TEXT,
                    timestamp TEXT
                )
            ''')
            
            # SSH commands table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ssh_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    client_ip TEXT,
                    command TEXT,
                    direction TEXT,
                    timestamp TEXT,
                    FOREIGN KEY(session_id) REFERENCES ssh_sessions(id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logging.info("SQLite database initialized")
    
    def log_ssh_session(self, client_ip, client_port, username, password, auth_result, backend_host=None, backend_port=None):
        """Log SSH session attempt"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO ssh_sessions 
                (client_ip, client_port, username, password, auth_result, session_start, backend_host, backend_port)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (client_ip, client_port, username, password, auth_result, 
                  datetime.now().isoformat(), backend_host, backend_port))
            session_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return session_id
    
    def update_ssh_session_end(self, session_id):
        """Mark SSH session as ended"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE ssh_sessions SET session_end = ? WHERE id = ?
            ''', (datetime.now().isoformat(), session_id))
            conn.commit()
            conn.close()
    
    def log_ssh_command(self, session_id, client_ip, command, direction="client->backend"):
        """Log SSH command"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO ssh_commands (session_id, client_ip, command, direction, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (session_id, client_ip, command, direction, datetime.now().isoformat()))
            
            cursor.execute('''
                UPDATE ssh_sessions SET commands_count = commands_count + 1 WHERE id = ?
            ''', (session_id,))
            
            conn.commit()
            conn.close()
    
    def log_ftp_session_start(self, client_ip, client_port):
        """Start new FTP session"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO ftp_sessions (client_ip, client_port, session_start)
                VALUES (?, ?, ?)
            ''', (client_ip, client_port, datetime.now().isoformat()))
            session_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return session_id
    
    def log_ftp_credentials(self, session_id, username, password):
        """Update FTP session with credentials"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE ftp_sessions SET username = ?, password = ? WHERE id = ?
            ''', (username, password, session_id))
            conn.commit()
            conn.close()
    
    def log_ftp_command(self, session_id, client_ip, command, parameters=""):
        """Log FTP command"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO ftp_commands (session_id, client_ip, command, parameters, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (session_id, client_ip, command, parameters, datetime.now().isoformat()))
            conn.commit()
            conn.close()
    
    def log_ftp_file_operation(self, session_id, operation_type):
        """Log FTP file download/upload"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            if operation_type == "download":
                cursor.execute('''
                    UPDATE ftp_sessions SET files_downloaded = files_downloaded + 1 WHERE id = ?
                ''', (session_id,))
            elif operation_type == "upload":
                cursor.execute('''
                    UPDATE ftp_sessions SET files_uploaded = files_uploaded + 1 WHERE id = ?
                ''', (session_id,))
            conn.commit()
            conn.close()
    
    def update_ftp_session_end(self, session_id):
        """Mark FTP session as ended"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE ftp_sessions SET session_end = ? WHERE id = ?
            ''', (datetime.now().isoformat(), session_id))
            conn.commit()
            conn.close()
    
    def log_http_request(self, client_ip, method, path, user_agent):
        """Log HTTP request"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO http_requests (client_ip, method, path, user_agent, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (client_ip, method, path, user_agent, datetime.now().isoformat()))
            conn.commit()
            conn.close()

# Initialize database
db = HoneypotDB()

# ============================================================
# SSH HONEYPOT WITH REAL BACKEND (from honeypot_kali.py)
# ============================================================

# Generate or load host key
try:
    host_key = paramiko.RSAKey(filename=HOST_KEY_FILE)
    logging.info(f"Loaded existing host key from {HOST_KEY_FILE}")
except FileNotFoundError:
    logging.info(f"Generating new host key: {HOST_KEY_FILE}")
    host_key = paramiko.RSAKey.generate(2048)
    host_key.write_private_key_file(HOST_KEY_FILE)
    logging.info(f"Host key saved to {HOST_KEY_FILE}")

class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.event = threading.Event()
        self.username = None
        self.password = None
        self.session_id = None
        self.session_started = False
        self.failed_attempts = 0

    def check_auth_password(self, username, password):
        # Check threat intelligence
        is_threat, score = threat_intel.check_ip_threat(self.client_ip)
        if is_threat:
            logging.warning(f"⚠️  Connecting IP {self.client_ip} has threat score {score}")
        
        # Log to file
        logging.info(f"SSH login attempt from {self.client_ip}: {username}/{password}")
        self.username = username
        self.password = password
        
        # Log to database
        auth_result = "trigger_accepted" if username in TRIGGER_CREDS and TRIGGER_CREDS[username] == password else "rejected"
        self.session_id = db.log_ssh_session(
            self.client_ip, self.client_port, username, password, 
            auth_result, BACKEND_HOST, BACKEND_PORT
        )
        
        if auth_result == "trigger_accepted":
            # DESKTOP ALERT
            desktop_alerts.alert_ssh_trigger(self.client_ip, username, password)
            logging.warning(f"TRIGGERED SSH LOGIN from {self.client_ip} with {username}/{password}")
            self.session_started = True
            return paramiko.AUTH_SUCCESSFUL
        else:
            self.failed_attempts += 1
            if self.failed_attempts >= 3:
                desktop_alerts.alert_ssh_brute_force(self.client_ip, self.failed_attempts)
            return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

def forward_between_channels(client_chan, backend_chan, client_ip, session_id):
    """Forward data between client and backend channels with command logging"""
    try:
        while True:
            # Client -> Backend
            if client_chan.recv_ready():
                data = client_chan.recv(4096)
                if not data:
                    break
                
                # Log commands to database
                try:
                    command = data.decode('utf-8', errors='replace').strip()
                    if command and session_id:
                        db.log_ssh_command(session_id, client_ip, command, "client->backend")
                except:
                    pass
                
                backend_chan.send(data)
                
            # Backend -> Client  
            if backend_chan.recv_ready():
                data = backend_chan.recv(4096)
                if not data:
                    break
                
                # Log responses to database
                try:
                    response = data.decode('utf-8', errors='replace').strip()
                    if response and session_id:
                        db.log_ssh_command(session_id, client_ip, response, "backend->client")
                except:
                    pass
                
                client_chan.send(data)
                
            if client_chan.closed or backend_chan.closed:
                break
                
            time.sleep(0.01)
            
    except Exception as e:
        logging.error(f"Forwarding error {client_ip}: {e}")
    finally:
        try:
            client_chan.close()
        except:
            pass
        try:
            backend_chan.close()
        except:
            pass

def handle_ssh_client(client_sock, addr):
    """Handle client and proxy to backend - FROM honeypot_kali.py"""
    client_ip = addr[0]
    client_port = addr[1]
    logging.info(f"SSH connection from {client_ip}")
    
    server = SSHServer(client_ip, client_port)
    
    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(host_key)
        
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as e:
            logging.error(f"{client_ip} SSH negotiation failed: {e}")
            return

        client_chan = transport.accept(20)
        if client_chan is None:
            logging.info(f"{client_ip} Authentication failed or no channel")
            transport.close()
            return

        server.event.wait(10)
        if not server.event.is_set():
            logging.info(f"{client_ip} No shell request")
            transport.close()
            return

        # Only proxy if trigger credentials were used
        if not server.session_started:
            logging.info(f"{client_ip} Non-trigger credentials, closing connection")
            client_chan.close()
            transport.close()
            return

        backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_sock.settimeout(10)
        try:
            backend_sock.connect((BACKEND_HOST, BACKEND_PORT))
            logging.info(f"{client_ip} Connected to backend {BACKEND_HOST}:{BACKEND_PORT}")
        except Exception as e:
            logging.error(f"{client_ip} Backend connection failed: {e}")
            client_chan.send(b"Backend system unavailable\r\n")
            client_chan.close()
            transport.close()
            return

        backend_transport = paramiko.Transport(backend_sock)
        try:
            backend_transport.start_client()
        except Exception as e:
            logging.error(f"{client_ip} Backend transport failed: {e}")
            client_chan.send(b"Backend error\r\n")
            client_chan.close()
            backend_sock.close()
            transport.close()
            return

        if server.username and server.password:
            try:
                backend_transport.auth_password(server.username, server.password)
                logging.info(f"{client_ip} Backend auth successful: {server.username}")
            except Exception as e:
                logging.error(f"{client_ip} Backend auth failed: {e}")
                client_chan.send(b"Authentication failed\r\n")
                client_chan.close()
                backend_transport.close()
                backend_sock.close()
                transport.close()
                return

        try:
            backend_chan = backend_transport.open_session()
            backend_chan.get_pty()
            backend_chan.invoke_shell()
            logging.info(f"{client_ip} Backend shell established")
        except Exception as e:
            logging.error(f"{client_ip} Backend shell failed: {e}")
            client_chan.send(b"Shell allocation failed\r\n")
            client_chan.close()
            backend_transport.close()
            backend_sock.close()
            transport.close()
            return

        logging.info(f"{client_ip} Starting proxy session")
        forward_between_channels(client_chan, backend_chan, client_ip, server.session_id)
        logging.info(f"{client_ip} Proxy session ended")

        # Update session end in database
        if server.session_id:
            db.update_ssh_session_end(server.session_id)

        try:
            backend_transport.close()
        except:
            pass
        try:
            transport.close()
        except:
            pass

    except Exception as e:
        logging.error(f"Exception handling client {client_ip}: {e}")
    finally:
        try:
            client_sock.close()
        except:
            pass

def start_ssh_server():
    ssh_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssh_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssh_socket.bind(("0.0.0.0", SSH_PORT))
    ssh_socket.listen(100)
    logging.info(f"SSH Honeypot listening on port {SSH_PORT}")
    print(f"✅ SSH honeypot active on port {SSH_PORT}")
    while running and not shutdown_event.is_set():
        try:
            ssh_socket.settimeout(1)
            client, addr = ssh_socket.accept()
            threading.Thread(target=handle_ssh_client, args=(client, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception as e:
            if running:
                logging.error(f"SSH server error: {e}")
            break
    ssh_socket.close()
    print("🔒 SSH server stopped")

# ============================================================
# FTP HONEYPOT (if pyftpdlib is available)
# ============================================================

if FTP_LIB_AVAILABLE:
    class HoneypotFTPHandler(FTPHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.username = None
            self.session_id = None

        def on_connect(self):
            client_ip = self.remote_ip
            logging.info(f"FTP connection from {client_ip}:{self.remote_port}")
            print(f"FTP connection from {client_ip}")
            
            # Check threat intelligence
            is_threat, score = threat_intel.check_ip_threat(client_ip)
            
            # Log to database
            self.session_id = db.log_ftp_session_start(client_ip, self.remote_port)

        def on_disconnect(self):
            client_ip = self.remote_ip
            logging.info(f"FTP disconnection from {client_ip}")
            print(f"FTP disconnection from {client_ip}")
            
            # Update database
            if self.session_id:
                db.update_ftp_session_end(self.session_id)

        def on_login(self, username):
            client_ip = self.remote_ip
            self.username = username
            logging.info(f"FTP login attempt from {client_ip}: username={username}")
            print(f"FTP LOGIN ATTEMPT: {client_ip} - username={username}")
            
            # DESKTOP ALERT
            desktop_alerts.alert_ftp_login(client_ip, username)
            
            # Log username to database
            if self.session_id:
                db.log_ftp_command(self.session_id, client_ip, "USER", username)
            
            return True

        def ftp_PASS(self, password):
            """Capture credentials and maintain auth flow"""
            client_ip = self.remote_ip
            
            # Log to file and database
            logging.warning(f"FTP CREDENTIALS from {client_ip}: {self.username}:{password}")
            print(f"FTP CREDENTIALS CAPTURED: {client_ip} - {self.username}:{password}")
            
            # DESKTOP ALERT with password
            desktop_alerts.alert_ftp_login(client_ip, self.username, password)
            
            # Log to database
            if self.session_id:
                db.log_ftp_credentials(self.session_id, self.username, password)
                db.log_ftp_command(self.session_id, client_ip, "PASS", "***")
            
            # Use parent class authentication
            return super().ftp_PASS(password)

        def ftp_RETR(self, file):
            """Capture file download"""
            client_ip = self.remote_ip
            logging.info(f"FTP file download from {client_ip}: {file}")
            print(f"FTP DOWNLOAD: {client_ip} - {file}")
            
            # DESKTOP ALERT
            desktop_alerts.alert_ftp_file_operation(client_ip, "download", file)
            
            if self.session_id:
                db.log_ftp_command(self.session_id, client_ip, "RETR", file)
                db.log_ftp_file_operation(self.session_id, "download")
            
            return super().ftp_RETR(file)

        def ftp_STOR(self, file):
            """Capture file upload"""
            client_ip = self.remote_ip
            logging.warning(f"FTP file upload from {client_ip}: {file}")
            print(f"FTP UPLOAD: {client_ip} - {file}")
            
            # DESKTOP ALERT
            desktop_alerts.alert_ftp_file_operation(client_ip, "upload", file)
            
            if self.session_id:
                db.log_ftp_command(self.session_id, client_ip, "STOR", file)
                db.log_ftp_file_operation(self.session_id, "upload")
            
            return super().ftp_STOR(file)

    def start_ftp_server():
        """Start FTP server"""
        try:
            if not os.path.exists(FTP_ROOT):
                os.makedirs(FTP_ROOT, exist_ok=True)
                # Create some dummy files
                with open(os.path.join(FTP_ROOT, "readme.txt"), "w") as f:
                    f.write("This is a honeypot FTP server\n")
            
            print(f"Using FTP directory: {FTP_ROOT}")
            
            # Create authorizer
            authorizer = DummyAuthorizer()
            authorizer.add_anonymous(FTP_ROOT, perm="elradfmw")
            authorizer.add_user("admin", "password", FTP_ROOT, perm="elradfmw")
            authorizer.add_user("ftp", "ftp", FTP_ROOT, perm="elradfmw")
            
            # Use the handler class
            handler = HoneypotFTPHandler
            handler.authorizer = authorizer
            handler.banner = "220 Welcome to Company Secure FTP Server"
            
            # Configuration
            handler.passive_ports = range(30000, 30010)
            handler.permit_foreign_addresses = True
            handler.timeout = 300
            handler.data_timeout = 60
            
            address = ('0.0.0.0', FTP_PORT)
            server = FTPServer(address, handler)
            server.max_cons = 50
            
            logging.info(f"FTP Honeypot started on port {FTP_PORT}")
            print(f"✅ FTP Honeypot running on port {FTP_PORT}")
            
            # Modified to handle graceful shutdown
            while running and not shutdown_event.is_set():
                server.serve_forever(timeout=1, blocking=False)
                time.sleep(0.1)
            
            server.close_all()
            print("🔒 FTP server stopped")
            
        except Exception as e:
            if running:  # Only log if not shutting down
                logging.error(f"FTP server error: {e}")
                print(f"❌ FTP server error: {e}")
                traceback.print_exc()
else:
    def start_ftp_server():
        print("❌ pyftpdlib not available. FTP server disabled.")
        while running and not shutdown_event.is_set():
            time.sleep(1)
        print("🔒 FTP server stopped")

# ============================================================
# WEB HONEYPOT
# ============================================================

class AttackDetectionWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', 'Unknown')
        
        # Check threat intelligence
        is_threat, score = threat_intel.check_ip_threat(client_ip)
        
        # Log to file
        logging.info(f"HTTP GET from {client_ip} - Path: {self.path} - UA: {user_agent[:50]}")
        
        # DESKTOP ALERT
        desktop_alerts.alert_http_attack(client_ip, "GET", self.path, user_agent)
        
        # Log to database
        db.log_http_request(client_ip, "GET", self.path, user_agent)
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Company Portal</h1><p>Welcome to our system</p></body></html>")

    def log_message(self, format, *args):
        pass

def start_web_server():
    """Start web server with graceful shutdown support"""
    httpd = HTTPServer(("0.0.0.0", HTTP_PORT), AttackDetectionWebHandler)
    httpd.timeout = 1  # Set timeout to check running flag
    
    logging.info(f"Web Honeypot running on port {HTTP_PORT}")
    print(f"✅ Web honeypot active on port {HTTP_PORT}")
    
    while running and not shutdown_event.is_set():
        try:
            httpd.handle_request()
        except Exception as e:
            if running:  # Only log if not shutting down
                logging.error(f"Web server error: {e}")
    
    httpd.server_close()
    print("🔒 Web server stopped")

# ============================================================
# REPORT AND CHART GENERATION FUNCTIONS
# ============================================================

def generate_daily_report():
    """Generate daily report from database"""
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    print(f"📊 Generating daily report for: {yesterday}")
    
    # Connect to database
    conn = sqlite3.connect(SQLITE_DB)
    c = conn.cursor()
    
    # Count attacks
    ssh = c.execute("SELECT COUNT(*) FROM ssh_sessions WHERE DATE(session_start)=?", (yesterday,)).fetchone()[0]
    ftp = c.execute("SELECT COUNT(*) FROM ftp_sessions WHERE DATE(session_start)=?", (yesterday,)).fetchone()[0]
    http = c.execute("SELECT COUNT(*) FROM http_requests WHERE DATE(timestamp)=?", (yesterday,)).fetchone()[0]
    
    # Get top 5 attackers
    c.execute("""
        SELECT client_ip, COUNT(*) as attacks FROM (
            SELECT client_ip FROM ssh_sessions WHERE DATE(session_start)=?
            UNION ALL SELECT client_ip FROM ftp_sessions WHERE DATE(session_start)=?
            UNION ALL SELECT client_ip FROM http_requests WHERE DATE(timestamp)=?
        ) WHERE client_ip IS NOT NULL
        GROUP BY client_ip ORDER BY attacks DESC LIMIT 5
    """, (yesterday, yesterday, yesterday))
    top = c.fetchall()
    
    # Check for trigger credentials
    triggers = c.execute("""
        SELECT COUNT(*) FROM ssh_sessions 
        WHERE DATE(session_start)=? AND auth_result='trigger_accepted'
    """, (yesterday,)).fetchone()[0]
    
    conn.close()
    
    # Create report
    report = {
        "date": yesterday,
        "total_attacks": ssh + ftp + http,
        "ssh_attacks": ssh,
        "ftp_attacks": ftp,
        "http_attacks": http,
        "trigger_events": triggers,
        "top_attackers": [{"ip": ip, "attacks": count} for ip, count in top],
        "generated_at": datetime.now().isoformat()
    }
    
    # Save JSON report
    os.makedirs("daily_reports", exist_ok=True)
    json_file = f"daily_reports/report_{yesterday}.json"
    with open(json_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print(f"✅ Daily report generated: {json_file}")
    print(f"   Total attacks: {report['total_attacks']}")
    print(f"   SSH: {ssh}, FTP: {ftp}, HTTP: {http}")
    print(f"   Trigger events: {triggers}")
    
    return report

def generate_comprehensive_report():
    """Generate comprehensive report with charts"""
    print("\n" + "="*60)
    print("📊 GENERATING COMPREHENSIVE SHUTDOWN REPORT")
    print("="*60)
    
    try:
        # Generate daily report
        print("\n📋 Generating daily report...")
        report = generate_daily_report()
        
        # Generate charts if matplotlib is available
        if MATPLOTLIB_AVAILABLE:
            print("\n📈 Generating charts...")
            generator = SimpleHoneypotChartGenerator()
            generator.create_summary_report()
            
            # Create HTML report that combines both
            create_html_combined_report(report)
        else:
            print("\n⚠️  Matplotlib not available. Charts generation skipped.")
        
        # Also generate a summary of today's activity
        generate_todays_summary()
        
        print("\n" + "="*60)
        print("✅ Shutdown report generation complete!")
        print("="*60)
        
    except Exception as e:
        print(f"❌ Error generating reports: {e}")
        traceback.print_exc()

def generate_todays_summary():
    """Generate summary of today's activity"""
    today = datetime.now().strftime('%Y-%m-%d')
    print(f"\n📅 Today's Activity Summary ({today}):")
    
    conn = sqlite3.connect(SQLITE_DB)
    c = conn.cursor()
    
    # Today's attacks
    ssh_today = c.execute("SELECT COUNT(*) FROM ssh_sessions WHERE DATE(session_start)=?", (today,)).fetchone()[0]
    ftp_today = c.execute("SELECT COUNT(*) FROM ftp_sessions WHERE DATE(session_start)=?", (today,)).fetchone()[0]
    http_today = c.execute("SELECT COUNT(*) FROM http_requests WHERE DATE(timestamp)=?", (today,)).fetchone()[0]
    
    print(f"   Today's attacks: SSH={ssh_today}, FTP={ftp_today}, HTTP={http_today}")
    print(f"   Total today: {ssh_today + ftp_today + http_today}")
    
    # Unique attackers today
    c.execute("""
        SELECT COUNT(DISTINCT client_ip) FROM (
            SELECT client_ip FROM ssh_sessions WHERE DATE(session_start)=?
            UNION SELECT client_ip FROM ftp_sessions WHERE DATE(session_start)=?
            UNION SELECT client_ip FROM http_requests WHERE DATE(timestamp)=?
        )
    """, (today, today, today))
    unique_attackers = c.fetchone()[0]
    print(f"   Unique attackers today: {unique_attackers}")
    
    conn.close()

def create_html_combined_report(report):
    """Create HTML report that combines both charts and data"""
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Shutdown Report - {report['date']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .section {{ background: white; padding: 25px; border-radius: 10px; margin-bottom: 25px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #ecf0f1; padding: 20px; border-radius: 8px; text-align: center; border-left: 5px solid #3498db; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #2c3e50; }}
        .chart-container {{ text-align: center; margin: 30px 0; }}
        img {{ max-width: 90%; height: auto; border: 1px solid #ddd; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; font-weight: bold; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .info {{ color: #95a5a6; font-size: 0.9em; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 Honeypot Shutdown Report</h1>
        <p>Date: {report['date']} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><em>Report generated automatically when honeypot was stopped</em></p>
    </div>
    
    <div class="section">
        <h2>📊 Attack Summary</h2>
        <div class="stats-grid">
            <div class="stat-box">
                <div class="stat-label">Total Attacks</div>
                <div class="stat-value">{report['total_attacks']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">SSH Attacks</div>
                <div class="stat-value">{report['ssh_attacks']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">FTP Attacks</div>
                <div class="stat-value">{report['ftp_attacks']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">HTTP Attacks</div>
                <div class="stat-value">{report['http_attacks']}</div>
            </div>
        </div>
        
        <div class="stat-box" style="border-left-color: #e74c3c;">
            <div class="stat-label">Trigger Events</div>
            <div class="stat-value critical">{report['trigger_events']}</div>
            <div style="font-size: 0.9em; color: #7f8c8d;">Trigger credentials accepted</div>
        </div>
    </div>
    
    <div class="section">
        <h2>🎯 Top Attackers</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Attack Count</th>
                    <th>Threat Level</th>
                </tr>
            </thead>
            <tbody>
"""
    
    # Add top attackers
    for attacker in report['top_attackers']:
        threat_level = "HIGH" if attacker['attacks'] > 10 else "MEDIUM" if attacker['attacks'] > 5 else "LOW"
        html_content += f"""
                <tr>
                    <td>{attacker['ip']}</td>
                    <td>{attacker['attacks']}</td>
                    <td><span class="{'critical' if threat_level == 'HIGH' else ''}">{threat_level}</span></td>
                </tr>
"""
    
    html_content += """
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>📈 Attack Visualizations</h2>
        <div class="chart-container">
            <h3>Daily Attack Frequency</h3>
            <img src="../honeypot_charts/daily_attacks.png" alt="Daily Attack Chart">
        </div>
        
        <div class="chart-container">
            <h3>Service Comparison</h3>
            <img src="../honeypot_charts/service_comparison.png" alt="Service Comparison Chart">
        </div>
    </div>
    
    <div class="section">
        <h2>📋 Report Details</h2>
        <pre style="background: #f8f9fa; padding: 20px; border-radius: 5px; overflow: auto;">
"""
    
    # Add JSON data
    html_content += json.dumps(report, indent=2)
    
    html_content += """
        </pre>
    </div>
    
    <div class="info">
        <p>Report generated automatically when honeypot was stopped</p>
        <p>For security analysis and monitoring purposes only</p>
    </div>
</body>
</html>
"""
    
    # Save HTML report
    os.makedirs("reports", exist_ok=True)
    html_file = f"reports/shutdown_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(html_file, 'w') as f:
        f.write(html_content)
    
    print(f"📄 Shutdown HTML report saved: {html_file}")
    print(f"   Open in browser: file://{os.path.abspath(html_file)}")

# ============================================================
# CHART GENERATOR
# ============================================================

if MATPLOTLIB_AVAILABLE:
    class SimpleHoneypotChartGenerator:
        def __init__(self, db_path=SQLITE_DB):
            self.db_path = db_path
            self.output_dir = "honeypot_charts"
            os.makedirs(self.output_dir, exist_ok=True)
            
            self.colors = {
                'ssh': '#3498db',
                'ftp': '#2ecc71',
                'http': '#e74c3c',
                'total': '#9b59b6'
            }
        
        def create_summary_report(self):
            """Create comprehensive summary report with all charts"""
            print("📊 Generating honeypot attack charts...")
            print("=" * 50)
            
            # Generate charts
            daily_chart = self.create_daily_attack_chart()
            service_chart = self.create_service_comparison_chart()
            
            print("\n" + "=" * 50)
            print("📈 CHART GENERATION COMPLETE")
            print("=" * 50)
            
            charts = [
                ("Daily Attack Frequency", daily_chart),
                ("Service Comparison", service_chart)
            ]
            
            for name, path in charts:
                if path:
                    print(f"✅ {name}: {path}")
                else:
                    print(f"❌ {name}: No data available")
            
            print(f"\n📁 All charts saved in: {self.output_dir}/")
        
        def create_daily_attack_chart(self):
            """Create daily attack frequency chart"""
            conn = sqlite3.connect(self.db_path)
            
            try:
                # Get SSH attacks
                ssh_query = """
                SELECT 
                    DATE(session_start) as date,
                    COUNT(*) as count
                FROM ssh_sessions 
                WHERE session_start IS NOT NULL
                GROUP BY DATE(session_start)
                ORDER BY date
                """
                ssh_data = pd.read_sql_query(ssh_query, conn)
                
                # Get FTP attacks
                ftp_query = """
                SELECT 
                    DATE(session_start) as date,
                    COUNT(*) as count
                FROM ftp_sessions 
                WHERE session_start IS NOT NULL
                GROUP BY DATE(session_start)
                ORDER BY date
                """
                ftp_data = pd.read_sql_query(ftp_query, conn)
                
                # Get HTTP attacks
                http_query = """
                SELECT 
                    DATE(timestamp) as date,
                    COUNT(*) as count
                FROM http_requests 
                WHERE timestamp IS NOT NULL
                GROUP BY DATE(timestamp)
                ORDER BY date
                """
                http_data = pd.read_sql_query(http_query, conn)
                
                # Merge all data
                all_dates = set()
                data_dict = {}
                
                for service, data in [('ssh', ssh_data), ('ftp', ftp_data), ('http', http_data)]:
                    if not data.empty:
                        data_dict[service] = data.set_index('date')['count']
                        all_dates.update(data['date'].tolist())
                
                if not all_dates:
                    print("No attack data found!")
                    return None
                
                # Create figure
                plt.figure(figsize=(12, 6))
                
                # Plot each service
                for service, data in data_dict.items():
                    plt.plot(data.index, data.values, 
                            label=f'{service.upper()} Attacks', 
                            color=self.colors[service],
                            marker='o',
                            linewidth=2)
                
                plt.title('Daily Attack Frequency', fontsize=16, fontweight='bold')
                plt.xlabel('Date', fontsize=12)
                plt.ylabel('Number of Attacks', fontsize=12)
                plt.legend()
                plt.grid(True, alpha=0.3)
                plt.xticks(rotation=45)
                plt.tight_layout()
                
                # Save chart
                output_file = f"{self.output_dir}/daily_attacks.png"
                plt.savefig(output_file, dpi=150, bbox_inches='tight')
                plt.close()
                
                print(f"✅ Daily attack chart saved: {output_file}")
                return output_file
                
            finally:
                conn.close()
        
        def create_service_comparison_chart(self):
            """Create service comparison chart"""
            conn = sqlite3.connect(self.db_path)
            
            try:
                # Get totals
                ssh_total = conn.execute("SELECT COUNT(*) FROM ssh_sessions").fetchone()[0]
                ftp_total = conn.execute("SELECT COUNT(*) FROM ftp_sessions").fetchone()[0]
                http_total = conn.execute("SELECT COUNT(*) FROM http_requests").fetchone()[0]
                
                if ssh_total + ftp_total + http_total == 0:
                    print("No attack data found!")
                    return None
                
                # Create figure
                plt.figure(figsize=(10, 6))
                
                services = ['SSH', 'FTP', 'HTTP']
                totals = [ssh_total, ftp_total, http_total]
                colors = [self.colors['ssh'], self.colors['ftp'], self.colors['http']]
                
                bars = plt.bar(services, totals, color=colors, edgecolor='black', linewidth=1.5)
                
                # Add value labels on bars
                for bar, total in zip(bars, totals):
                    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                            str(int(total)), ha='center', va='bottom', fontweight='bold')
                
                plt.title('Total Attacks by Service', fontsize=16, fontweight='bold')
                plt.xlabel('Service', fontsize=12)
                plt.ylabel('Total Attacks', fontsize=12)
                plt.grid(True, alpha=0.3, axis='y')
                
                output_file = f"{self.output_dir}/service_comparison.png"
                plt.savefig(output_file, dpi=150, bbox_inches='tight')
                plt.close()
                
                print(f"✅ Service comparison chart saved: {output_file}")
                return output_file
                
            finally:
                conn.close()

# ============================================================
# SHUTDOWN HANDLER
# ============================================================

def graceful_shutdown(signum=None, frame=None):
    """Handle graceful shutdown with report generation"""
    global running
    
    if not running:
        return
    
    print("\n\n" + "="*60)
    print("🛑 Honeypot shutdown requested...")
    print("="*60)
    
    # Set shutdown flag
    running = False
    shutdown_event.set()
    
    # Give services time to stop
    time.sleep(1)
    
    # Stop desktop alerts
    desktop_alerts.stop()
    
    # Generate comprehensive report
    generate_comprehensive_report()
    
    print("\n" + "="*60)
    print("✅ Honeypot stopped gracefully")
    print("="*60)
    
    sys.exit(0)

# Register shutdown handlers
def register_shutdown_handlers():
    """Register signal handlers for graceful shutdown"""
    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)
    atexit.register(graceful_shutdown)

# ============================================================
# MAIN EXECUTION
# ============================================================

def start_honeypot():
    """Start all honeypot services"""
    print("🚀 Starting Enhanced Honeypot System...")
    print("=" * 60)
    print(f"SSH Honeypot on port {SSH_PORT}")
    print(f"FTP Honeypot on port {FTP_PORT}")
    print(f"Web Honeypot on port {HTTP_PORT}")
    print(f"Database: {SQLITE_DB}")
    print(f"FTP Directory: {FTP_ROOT}")
    print(f"Backend Server: {BACKEND_HOST}:{BACKEND_PORT}")
    print(f"Trigger Credentials: {len(TRIGGER_CREDS)} sets")
    print(f"Desktop Notifications: {'Enabled' if desktop_alerts.gui_available else 'Console only'}")
    print(f"Threat Intelligence: {'Enabled' if threat_intel.enabled else 'Disabled'}")
    print("=" * 60)
    print("Logging to honeypot.log and SQLite database")
    print("Press Ctrl+C to stop (will generate reports automatically)\n")
    
    # Register shutdown handlers
    register_shutdown_handlers()
    
    # Start desktop alerts
    desktop_alerts.start()
    
    # Start all services in threads
    ssh_thread = threading.Thread(target=start_ssh_server, daemon=True)
    ftp_thread = threading.Thread(target=start_ftp_server, daemon=True)
    
    ssh_thread.start()
    ftp_thread.start()
    
    # Start web server in main thread
    try:
        start_web_server()
    except KeyboardInterrupt:
        graceful_shutdown()
    except Exception as e:
        print(f"❌ Web server error: {e}")
        graceful_shutdown()

def show_help():
    """Show help message with available commands"""
    print("""
    🚀 Enhanced Honeypot System - Usage Guide
    ========================================
    
    Commands:
    ---------
    python3 honeypot_combined.py            Start the honeypot
    python3 honeypot_combined.py --report   Generate daily report only
    python3 honeypot_combined.py --charts   Generate charts only
    python3 honeypot_combined.py --all      Generate both reports AND charts
    python3 honeypot_combined.py --help     Show this help message
    
    Features:
    ---------
    - Automatic report generation on shutdown (Ctrl+C)
    - Desktop notifications for attacks
    - Threat intelligence (AbuseIPDB)
    - Charts and visualizations
    
    Files Generated on Shutdown:
    ---------------------------
    - daily_reports/report_YYYY-MM-DD.json      JSON data report
    - honeypot_charts/daily_attacks.png         Daily attack chart
    - honeypot_charts/service_comparison.png    Service comparison chart
    - reports/shutdown_report_TIMESTAMP.html    Combined HTML report
    """)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--all":
            # Generate both reports and charts
            print("📊 GENERATING COMPREHENSIVE REPORT")
            print("=" * 60)
            
            # Generate daily report
            print("\n📋 Generating daily report...")
            report = generate_daily_report()
            
            # Generate charts if matplotlib is available
            if MATPLOTLIB_AVAILABLE:
                print("\n📈 Generating charts...")
                generator = SimpleHoneypotChartGenerator()
                generator.create_summary_report()
                
                # Create HTML report that combines both
                create_html_combined_report(report)
            else:
                print("\n⚠️  Matplotlib not available. Charts generation skipped.")
            
            print("\n" + "=" * 60)
            print("✅ Report and charts generation complete!")
            print("=" * 60)
            
        elif sys.argv[1] == "--report":
            # Generate daily report only
            report = generate_daily_report()
            print("\n📄 Daily report generated successfully!")
            
        elif sys.argv[1] == "--charts" and MATPLOTLIB_AVAILABLE:
            # Generate charts only
            generator = SimpleHoneypotChartGenerator()
            generator.create_summary_report()
            
        elif sys.argv[1] == "--help" or sys.argv[1] == "-h":
            # Show help
            show_help()
        else:
            print(f"❌ Unknown option: {sys.argv[1]}")
            print("Use --help to see available options")
            sys.exit(1)
    else:
        # Start the honeypot
        try:
            start_honeypot()
        except KeyboardInterrupt:
            # This should be caught by the signal handler
            pass
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            traceback.print_exc()
            sys.exit(1)
