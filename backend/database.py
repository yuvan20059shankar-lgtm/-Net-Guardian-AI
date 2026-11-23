"""
NetGuardian AI - Database Foundation Module
Provides resilient SQLite connection management, parameterized query execution,
schema creation, and automated initial device seeding.
"""

import os
import sqlite3
import logging
from contextlib import contextmanager
from pathlib import Path
from config import get_config

logger = logging.getLogger('netguardian.database')

# Initial seed dataset containing all 10 monitored network devices
INITIAL_DEVICES = [
    {
        'device_name': 'Router 01',
        'ip_address': '192.168.1.1',
        'device_type': 'Router',
        'role': 'Core Gateway Router',
        'status': 'online',
        'traffic_in': '450.2 Mbps',
        'traffic_out': '430.8 Mbps',
        'cpu_usage': 38.0,
        'memory_usage': 44.0,
        'packet_loss': '0.00%',
        'last_active': 'Just now'
    },
    {
        'device_name': 'Server 01',
        'ip_address': '192.168.1.10',
        'device_type': 'Server',
        'role': 'PostgreSQL Database',
        'status': 'online',
        'traffic_in': '284.4 Mbps',
        'traffic_out': '262.1 Mbps',
        'cpu_usage': 52.0,
        'memory_usage': 68.0,
        'packet_loss': '0.00%',
        'last_active': 'Just now'
    },
    {
        'device_name': 'Server 02',
        'ip_address': '192.168.1.11',
        'device_type': 'Server',
        'role': 'Authentication & LDAP Services',
        'status': 'online',
        'traffic_in': '145.8 Mbps',
        'traffic_out': '132.4 Mbps',
        'cpu_usage': 41.0,
        'memory_usage': 56.0,
        'packet_loss': '0.00%',
        'last_active': 'Just now'
    },
    {
        'device_name': 'Server 03',
        'ip_address': '192.168.1.12',
        'device_type': 'Server',
        'role': 'Application Microservices Cluster',
        'status': 'online',
        'traffic_in': '310.5 Mbps',
        'traffic_out': '298.0 Mbps',
        'cpu_usage': 58.0,
        'memory_usage': 62.0,
        'packet_loss': '0.00%',
        'last_active': 'Just now'
    },
    {
        'device_name': 'PC 01',
        'ip_address': '192.168.1.20',
        'device_type': 'Computer',
        'role': 'Finance Dept Workstation',
        'status': 'online',
        'traffic_in': '14.2 Mbps',
        'traffic_out': '8.5 Mbps',
        'cpu_usage': 22.0,
        'memory_usage': 48.0,
        'packet_loss': '0.00%',
        'last_active': '2m ago'
    },
    {
        'device_name': 'PC 02',
        'ip_address': '192.168.1.21',
        'device_type': 'Computer',
        'role': 'Engineering CAD Terminal',
        'status': 'online',
        'traffic_in': '28.6 Mbps',
        'traffic_out': '18.4 Mbps',
        'cpu_usage': 35.0,
        'memory_usage': 55.0,
        'packet_loss': '0.00%',
        'last_active': '1m ago'
    },
    {
        'device_name': 'PC 03',
        'ip_address': '192.168.1.22',
        'device_type': 'Computer',
        'role': 'Executive Workstation',
        'status': 'suspicious',
        'traffic_in': '98.2 Mbps',
        'traffic_out': '142.6 Mbps',
        'cpu_usage': 74.0,
        'memory_usage': 81.0,
        'packet_loss': '1.20%',
        'last_active': 'Just now'
    },
    {
        'device_name': 'PC 04',
        'ip_address': '192.168.1.23',
        'device_type': 'Computer',
        'role': 'DevOps Staging Terminal',
        'status': 'online',
        'traffic_in': '22.4 Mbps',
        'traffic_out': '16.1 Mbps',
        'cpu_usage': 29.0,
        'memory_usage': 50.0,
        'packet_loss': '0.00%',
        'last_active': '4m ago'
    },
    {
        'device_name': 'PC 05',
        'ip_address': '192.168.1.24',
        'device_type': 'Computer',
        'role': 'Admin Ops Terminal',
        'status': 'offline',
        'traffic_in': '0.0 Mbps',
        'traffic_out': '0.0 Mbps',
        'cpu_usage': 0.0,
        'memory_usage': 0.0,
        'packet_loss': '100%',
        'last_active': '1h 22m ago'
    },
    {
        'device_name': 'Firewall 01',
        'ip_address': '192.168.1.254',
        'device_type': 'Firewall',
        'role': 'Edge Perimeter & Deep Packet Inspection (DPI)',
        'status': 'online',
        'traffic_in': '612.9 Mbps',
        'traffic_out': '584.3 Mbps',
        'cpu_usage': 46.0,
        'memory_usage': 58.0,
        'packet_loss': '0.00%',
        'last_active': 'Just now'
    }
]

# Initial network topology interconnects (matching enterprise DMZ/Core/Subnet topology)
INITIAL_CONNECTIONS = [
    # Perimeter (10) <-> Core Router (1)
    {'source_device_id': 10, 'target_device_id': 1, 'bandwidth': '10 Gbps', 'status': 'active'},
    # Core Router (1) <-> Server Enclave (2, 3, 4)
    {'source_device_id': 1, 'target_device_id': 2, 'bandwidth': '1 Gbps', 'status': 'active'},
    {'source_device_id': 1, 'target_device_id': 3, 'bandwidth': '1 Gbps', 'status': 'active'},
    {'source_device_id': 1, 'target_device_id': 4, 'bandwidth': '1 Gbps', 'status': 'standby'},
    # Inter-Server Cluster Links
    {'source_device_id': 2, 'target_device_id': 3, 'bandwidth': '10 Gbps', 'status': 'active'},
    {'source_device_id': 2, 'target_device_id': 4, 'bandwidth': '10 Gbps', 'status': 'active'},
    {'source_device_id': 3, 'target_device_id': 4, 'bandwidth': '10 Gbps', 'status': 'standby'},
    # Core Router (1) <-> Workstation Fleet (5, 6, 7, 8, 9)
    {'source_device_id': 1, 'target_device_id': 5, 'bandwidth': '1 Gbps', 'status': 'active'},
    {'source_device_id': 1, 'target_device_id': 6, 'bandwidth': '1 Gbps', 'status': 'active'},
    {'source_device_id': 1, 'target_device_id': 7, 'bandwidth': '1 Gbps', 'status': 'active'},
    {'source_device_id': 1, 'target_device_id': 8, 'bandwidth': '1 Gbps', 'status': 'active'},
    {'source_device_id': 1, 'target_device_id': 9, 'bandwidth': '1 Gbps', 'status': 'inactive'}
]

# Initial seed dataset for Security Alerts (Prompt 8 Section 1)
INITIAL_ALERTS = [
    {
        'alert_code': 'ALT-1001',
        'device_id': 7,
        'threat_type': 'Data Exfiltration via DNS',
        'description': 'Outbound anomaly on port 53. Exceeds baseline threshold by 940%.',
        'severity': 'CRITICAL',
        'status': 'ACTIVE',
        'detection_source': 'Simulated Heuristic Monitor',
        'recommended_action': 'Isolate host from subnet and block external IP.',
        'created_at': '2026-11-18 09:41:15',
        'resolved_at': None
    },
    {
        'alert_code': 'ALT-1002',
        'device_id': 10,
        'threat_type': 'SYN Flood Ingress',
        'description': 'Rate limiter activated. Scrubbed 142k malicious packets.',
        'severity': 'HIGH',
        'status': 'RESOLVED',
        'detection_source': 'Perimeter DPI Sensor',
        'recommended_action': 'Maintain SYN cookie enforcement.',
        'created_at': '2026-11-18 09:35:40',
        'resolved_at': '2026-11-18 09:40:00'
    },
    {
        'alert_code': 'ALT-1003',
        'device_id': 5,
        'threat_type': 'Internal SMB Sweep',
        'description': 'Host initiated scans toward 192.168.1.10 and 192.168.1.11.',
        'severity': 'MEDIUM',
        'status': 'INVESTIGATING',
        'detection_source': 'Lateral Movement Detector',
        'recommended_action': 'Inspect active processes on PC 01.',
        'created_at': '2026-11-18 09:12:08',
        'resolved_at': None
    },
    {
        'alert_code': 'ALT-1004',
        'device_id': 2,
        'threat_type': 'Repeated Auth Failures',
        'description': 'Source IP 198.51.100.41 blocked at perimeter.',
        'severity': 'LOW',
        'status': 'RESOLVED',
        'detection_source': 'SSH Auth Watchdog',
        'recommended_action': 'Fail2ban 24h block enforced.',
        'created_at': '2026-11-18 08:44:30',
        'resolved_at': '2026-11-18 08:50:00'
    },
    {
        'alert_code': 'ALT-1005',
        'device_id': 9,
        'threat_type': 'Host Unreachable (Keepalive Loss)',
        'description': 'Device timed out on ICMP polling. Scheduled IT maintenance.',
        'severity': 'MEDIUM',
        'status': 'ACTIVE',
        'detection_source': 'ICMP Keepalive Daemon',
        'recommended_action': 'Verify physical link or power state.',
        'created_at': '2026-11-18 08:24:00',
        'resolved_at': None
    },
    {
        'alert_code': 'ALT-1006',
        'device_id': 3,
        'threat_type': 'TLS Certificate Expiry Notice',
        'description': 'Wildcard cert renewed automatically via ACME challenge.',
        'severity': 'LOW',
        'status': 'RESOLVED',
        'detection_source': 'Certificate Health Monitor',
        'recommended_action': 'No action required.',
        'created_at': '2026-11-18 07:15:22',
        'resolved_at': '2026-11-18 07:16:00'
    }
]

# Initial seed dataset for Recovery Logs (Prompt 8 Section 2)
INITIAL_RECOVERY_LOGS = [
    {
        'recovery_code': 'REC-501',
        'device_id': 3,
        'failure_type': 'Kernel Panic / Memory Leak',
        'action_taken': 'Auto-rerouted traffic via Server 03 standby cluster; soft-restarted Docker containers.',
        'original_status': 'offline',
        'final_status': 'online',
        'alternative_route': 'Router 01 -> Server 03 -> Server 02',
        'duration_seconds': 4.8,
        'verification_status': 'VERIFIED',
        'created_at': '2026-11-18 06:14:22'
    },
    {
        'recovery_code': 'REC-500',
        'device_id': 1,
        'failure_type': 'Routing Table Loop Detected',
        'action_taken': 'OSPF route flush & convergence optimization applied.',
        'original_status': 'offline',
        'final_status': 'online',
        'alternative_route': 'Core Loop Resolution',
        'duration_seconds': 2.1,
        'verification_status': 'VERIFIED',
        'created_at': '2026-11-17 21:40:11'
    },
    {
        'recovery_code': 'REC-499',
        'device_id': 10,
        'failure_type': 'DDoS Buffer Exhaustion',
        'action_taken': 'Dynamic syn-proxy filter injected into eBPF XDP layer.',
        'original_status': 'offline',
        'final_status': 'online',
        'alternative_route': 'Perimeter Bypass Buffer',
        'duration_seconds': 1.2,
        'verification_status': 'VERIFIED',
        'created_at': '2026-11-17 14:02:50'
    }
]


def get_db_path():
    """Retrieve and ensure the database directory exists."""
    # Prioritize active Flask application context config (e.g. for TestingConfig)
    try:
        from flask import current_app, has_app_context
        if has_app_context() and 'DATABASE_PATH' in current_app.config:
            db_path = Path(current_app.config['DATABASE_PATH'])
            db_path.parent.mkdir(parents=True, exist_ok=True)
            return str(db_path)
    except Exception:
        pass

    config = get_config()
    db_path = Path(config.DATABASE_PATH)
    
    # Ensure data directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return str(db_path)


def get_db_connection(timeout=10.0):
    """
    Establish a safe SQLite connection with dictionary row access.
    
    Args:
        timeout (float): SQLite busy timeout in seconds.
        
    Returns:
        sqlite3.Connection: Configured database connection.
    """
    db_path = get_db_path()
    try:
        conn = sqlite3.connect(
            db_path,
            timeout=timeout,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        )
        # Enable row access by column name
        conn.row_factory = sqlite3.Row
        
        # Enforce foreign key constraints
        conn.execute('PRAGMA foreign_keys = ON;')
        
        return conn
    except sqlite3.Error as e:
        logger.error(f"Failed to connect to SQLite database at {db_path}: {e}")
        raise


@contextmanager
def get_db():
    """
    Context manager for database transactions.
    Automatically commits on success and rolls back on exception.
    Always closes connection upon exit.
    
    Yields:
        sqlite3.Connection: Active database connection.
    """
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database transaction error: {e}")
        raise
    finally:
        conn.close()


def check_db_connection():
    """
    Verify database availability by executing a simple parameterized test query.
    Used by the /api/health endpoint.
    
    Returns:
        tuple (bool, str): (True, "connected") if healthy, (False, error_message) otherwise.
    """
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 AS status_check;")
            row = cursor.fetchone()
            if row and row['status_check'] == 1:
                return True, "connected"
            return False, "Query executed but returned unexpected payload"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False, str(e)


def init_database(seed_initial_data=True):
    """
    Initializes database schema and populates seed data if empty.
    Guarantees no duplicate records are created upon subsequent restarts.
    """
    db_path = get_db_path()
    logger.info(f"Initializing database foundation at: {db_path}")
    
    try:
        with get_db() as conn:
            # 1. System Metadata table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS _system_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.execute("""
                INSERT OR REPLACE INTO _system_metadata (key, value)
                VALUES ('version', '1.0.0'), ('component', 'foundation');
            """)

            # 2. Devices table (Prompt 6 Section 1)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT NOT NULL,
                    ip_address TEXT NOT NULL UNIQUE,
                    device_type TEXT NOT NULL,
                    role TEXT,
                    status TEXT NOT NULL DEFAULT 'online' CHECK(status IN ('online', 'offline', 'suspicious')),
                    traffic_in TEXT DEFAULT '0.0 Mbps',
                    traffic_out TEXT DEFAULT '0.0 Mbps',
                    cpu_usage REAL DEFAULT 0.0,
                    memory_usage REAL DEFAULT 0.0,
                    packet_loss TEXT DEFAULT '0.00%',
                    last_active TEXT DEFAULT 'Just now',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # 3. Seed initial 10 devices if table is empty (Prompt 6 Section 2)
            if seed_initial_data:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) AS total FROM devices;")
                row = cursor.fetchone()
                device_count = row['total'] if row else 0

                if device_count == 0:
                    logger.info("Devices table is empty. Seeding initial 10 monitored network devices...")
                    for dev in INITIAL_DEVICES:
                        cursor.execute("""
                            INSERT INTO devices (
                                device_name, ip_address, device_type, role, status,
                                traffic_in, traffic_out, cpu_usage, memory_usage,
                                packet_loss, last_active
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """, (
                            dev['device_name'],
                            dev['ip_address'],
                            dev['device_type'],
                            dev['role'],
                            dev['status'],
                            dev['traffic_in'],
                            dev['traffic_out'],
                            dev['cpu_usage'],
                            dev['memory_usage'],
                            dev['packet_loss'],
                            dev['last_active']
                        ))
                    logger.info("Successfully seeded 10 initial network devices into SQLite.")
                else:
                    logger.info(f"Devices table already populated with {device_count} records. Skipping seed.")

            # 4. Traffic Logs table (Prompt 7 Section 3)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    traffic_in REAL NOT NULL DEFAULT 0.0,
                    traffic_out REAL NOT NULL DEFAULT 0.0,
                    packets_sent INTEGER NOT NULL DEFAULT 0,
                    packets_received INTEGER NOT NULL DEFAULT 0,
                    packet_loss REAL NOT NULL DEFAULT 0.0,
                    latency REAL NOT NULL DEFAULT 0.0,
                    cpu_usage REAL NOT NULL DEFAULT 0.0,
                    memory_usage REAL NOT NULL DEFAULT 0.0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_device_id ON traffic_logs (device_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_logs (timestamp);")

            # 5. Network Connections table (Prompt 7 Section 3)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS network_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_device_id INTEGER NOT NULL,
                    target_device_id INTEGER NOT NULL,
                    bandwidth TEXT NOT NULL DEFAULT '1 Gbps',
                    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'inactive', 'standby', 'rerouted-active', 'suspicious')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (source_device_id) REFERENCES devices(id) ON DELETE CASCADE,
                    FOREIGN KEY (target_device_id) REFERENCES devices(id) ON DELETE CASCADE,
                    UNIQUE(source_device_id, target_device_id)
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_conn_source_target ON network_connections (source_device_id, target_device_id);")

            # 6. Seed initial connections if empty
            if seed_initial_data:
                cursor.execute("SELECT COUNT(*) AS total FROM network_connections;")
                conn_count = cursor.fetchone()['total']
                if conn_count == 0:
                    logger.info("network_connections table empty. Seeding initial network topology interconnects...")
                    for c in INITIAL_CONNECTIONS:
                        cursor.execute("""
                            INSERT OR IGNORE INTO network_connections (
                                source_device_id, target_device_id, bandwidth, status
                            ) VALUES (?, ?, ?, ?);
                        """, (
                            c['source_device_id'],
                            c['target_device_id'],
                            c['bandwidth'],
                            c['status']
                        ))
                    logger.info("Successfully seeded initial network topology connections.")
                else:
                    logger.info(f"network_connections table already contains {conn_count} links. Skipping seed.")

            # 7. Security Alerts table (Prompt 8 Section 1 & Prompt 3 AI Threat Classifier)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_code TEXT UNIQUE NOT NULL,
                    device_id INTEGER NOT NULL,
                    threat_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'INVESTIGATING', 'MITIGATED', 'RESOLVED')),
                    detection_source TEXT NOT NULL DEFAULT 'Simulated Heuristic Rule',
                    recommended_action TEXT NOT NULL,
                    anomaly_score REAL DEFAULT 0.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                );
            """)

            # Safe migration: ensure anomaly_score column exists on pre-existing database files
            try:
                conn.execute("ALTER TABLE security_alerts ADD COLUMN anomaly_score REAL DEFAULT 0.0;")
            except sqlite3.OperationalError:
                pass  # column already exists
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts (status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts (severity);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_device_id ON security_alerts (device_id);")

            # Seed initial security alerts if empty
            if seed_initial_data:
                cursor.execute("SELECT COUNT(*) AS total FROM security_alerts;")
                alert_count = cursor.fetchone()['total']
                if alert_count == 0:
                    logger.info("security_alerts table is empty. Seeding initial demonstration security alerts...")
                    for a in INITIAL_ALERTS:
                        cursor.execute("""
                            INSERT OR IGNORE INTO security_alerts (
                                alert_code, device_id, threat_type, description,
                                severity, status, detection_source, recommended_action,
                                created_at, resolved_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """, (
                            a['alert_code'],
                            a['device_id'],
                            a['threat_type'],
                            a['description'],
                            a['severity'],
                            a['status'],
                            a['detection_source'],
                            a['recommended_action'],
                            a['created_at'],
                            a['resolved_at']
                        ))
                    logger.info("Successfully seeded initial security alerts into SQLite.")
                else:
                    logger.info(f"security_alerts table already contains {alert_count} records. Skipping seed.")

            # 8. Recovery Logs table (Prompt 8 Section 2)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS recovery_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recovery_code TEXT UNIQUE NOT NULL,
                    device_id INTEGER NOT NULL,
                    failure_type TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    original_status TEXT NOT NULL,
                    final_status TEXT NOT NULL,
                    alternative_route TEXT,
                    duration_seconds REAL NOT NULL DEFAULT 0.0,
                    verification_status TEXT NOT NULL CHECK(verification_status IN ('VERIFIED', 'FAILED', 'NO_ROUTE')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_recovery_device_id ON recovery_logs (device_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_recovery_created_at ON recovery_logs (created_at);")

            # Seed initial recovery logs if empty
            if seed_initial_data:
                cursor.execute("SELECT COUNT(*) AS total FROM recovery_logs;")
                rec_count = cursor.fetchone()['total']
                if rec_count == 0:
                    logger.info("recovery_logs table is empty. Seeding initial historical recovery operations...")
                    for r in INITIAL_RECOVERY_LOGS:
                        cursor.execute("""
                            INSERT OR IGNORE INTO recovery_logs (
                                recovery_code, device_id, failure_type, action_taken,
                                original_status, final_status, alternative_route,
                                duration_seconds, verification_status, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """, (
                            r['recovery_code'],
                            r['device_id'],
                            r['failure_type'],
                            r['action_taken'],
                            r['original_status'],
                            r['final_status'],
                            r['alternative_route'],
                            r['duration_seconds'],
                            r['verification_status'],
                            r['created_at']
                        ))
                    logger.info("Successfully seeded initial recovery operations into SQLite.")
                else:
                    logger.info(f"recovery_logs table already contains {rec_count} records. Skipping seed.")

            # 9. Threat Intelligence Reports table (AI/ML Prompt 4)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_intelligence_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT UNIQUE NOT NULL,
                    device_id INTEGER NOT NULL,
                    device_ip TEXT,
                    device_name TEXT,
                    threat_indicator TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                    threat_score INTEGER NOT NULL,
                    confidence TEXT NOT NULL CHECK(confidence IN ('LOW', 'MEDIUM', 'HIGH')),
                    explanation TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    recommended_actions_json TEXT NOT NULL,
                    alert_code TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_intel_device_id ON threat_intelligence_reports (device_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_intel_threat_indicator ON threat_intelligence_reports (threat_indicator);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_intel_severity ON threat_intelligence_reports (severity);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_intel_created_at ON threat_intelligence_reports (created_at);")

            # 10. Self-Healing Module 1: Network Failures table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS network_failures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    failure_id TEXT UNIQUE NOT NULL,
                    device_id INTEGER NOT NULL,
                    device_ip TEXT,
                    failure_type TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'INVESTIGATING', 'ISOLATING', 'ISOLATED', 'RECOVERING', 'RESOLVED', 'FAILED', 'MANUAL_INTERVENTION_REQUIRED')),
                    detection_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    affected_connections_json TEXT DEFAULT '[]',
                    description TEXT NOT NULL,
                    recommended_action TEXT,
                    retry_count INTEGER DEFAULT 0,
                    resolved_at TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_failures_status ON network_failures (status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_failures_device_id ON network_failures (device_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_failures_type ON network_failures (failure_type);")

            # 11. Self-Healing Module 2: Device Isolation Logs table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS device_isolation_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    isolation_id TEXT UNIQUE NOT NULL,
                    device_id INTEGER NOT NULL,
                    device_name TEXT,
                    device_ip TEXT,
                    isolation_reason TEXT NOT NULL,
                    isolation_trigger TEXT NOT NULL DEFAULT 'MANUAL',
                    status TEXT NOT NULL DEFAULT 'ISOLATED' CHECK(status IN ('ISOLATED', 'RESTORED')),
                    affected_connections_count INTEGER DEFAULT 0,
                    critical_service_check_passed BOOLEAN DEFAULT 1,
                    isolated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    restored_at TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_isolation_device_id ON device_isolation_logs (device_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_isolation_status ON device_isolation_logs (status);")

            # 12. Self-Healing Module 3: Network Route Changes table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS network_route_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    change_id TEXT UNIQUE NOT NULL,
                    device_id INTEGER NOT NULL,
                    recovery_code TEXT,
                    source_device_id INTEGER NOT NULL,
                    target_device_id INTEGER NOT NULL,
                    original_path TEXT,
                    alternative_path TEXT NOT NULL,
                    path_hops INTEGER DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'REVERTED')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_route_changes_device ON network_route_changes (device_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_route_changes_status ON network_route_changes (status);")

            # Safe migrations for recovery_logs to support full Self-Healing metadata
            for col_def in [
                ("failure_id", "TEXT"),
                ("isolation_id", "TEXT"),
                ("error_description", "TEXT"),
                ("retry_count", "INTEGER DEFAULT 0")
            ]:
                try:
                    conn.execute(f"ALTER TABLE recovery_logs ADD COLUMN {col_def[0]} {col_def[1]};")
                except sqlite3.OperationalError:
                    pass

            # Seed initial network failure if table empty
            if seed_initial_data:
                cursor.execute("SELECT COUNT(*) AS total FROM network_failures;")
                fail_count = cursor.fetchone()['total']
                if fail_count == 0:
                    cursor.execute("""
                        INSERT OR IGNORE INTO network_failures (
                            failure_id, device_id, device_ip, failure_type, severity,
                            status, description, recommended_action, affected_connections_json
                        ) VALUES (
                            'FLR-1001', 9, '192.168.1.24', 'Device Offline', 'MEDIUM',
                            'ACTIVE', 'Keepalive heartbeat timeout on field terminal Smart Meter 05 (Jayanagar). Link unresponsive.',
                            'Initiate automated connectivity verification and test failover route.',
                            '[{\"connection_id\": 11, \"source_device_id\": 1, \"target_device_id\": 9, \"status\": \"inactive\"}]'
                        );
                    """)

        logger.info("Database initialization completed successfully.")
        return True
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        return False
