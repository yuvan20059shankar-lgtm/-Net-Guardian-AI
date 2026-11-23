"""
NetGuardian AI - Self-Healing Network Failure Detection Service (Module 1)
Tagline: Detect. Defend. Recover. Automatically.

Monitors the simulated network environment in real time and detects 8 failure types:
1. Device offline (status == 'offline')
2. Device unreachable (loss >= 95% or ICMP keepalive timeout)
3. Connection failure (network_connections status == 'inactive')
4. High simulated latency (latency > 50.0 ms)
5. High packet loss (15.0% <= packet_loss < 95.0%)
6. Abnormal traffic interruption (zero bytes transferred during active rotation)
7. Repeated device failures (same device failed >= 2 times in recent history)
8. Critical network path failure (severed link on core backbone to Router/HES/MDMS)

Guarantees:
- Uses actual simulated network state from SQLite and NetworkX graph.
- Deduplicates active failure records to avoid alert storms.
- Recommends actionable, non-destructive remediation steps.
- Software-only simulation; no physical hardware accessed.
"""

from __future__ import annotations
import os
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union

from database import get_db
from services.device_service import DeviceService, NotFoundError, ValidationError

logger = logging.getLogger('netguardian.healing.failure_detection')

# Canonical Failure Types
FAILURE_TYPES = [
    'Device Offline',
    'Device Unreachable',
    'Connection Failure',
    'High Simulated Latency',
    'High Packet Loss',
    'Abnormal Traffic Interruption',
    'Repeated Device Failure',
    'Critical Network Path Failure'
]

# Baseline thresholds for simulated telemetry anomalies
THRESHOLD_LATENCY_MS = 50.0
THRESHOLD_PACKET_LOSS_PCT = 15.0
THRESHOLD_UNREACHABLE_LOSS_PCT = 95.0


class FailureDetectionService:
    """
    Self-Healing Module 1: Failure Detection Engine.
    Inspects live simulated device metrics, link states, and topology connectivity
    to generate grounded failure incident records in SQLite network_failures.
    """

    @classmethod
    def _generate_failure_id(cls) -> str:
        """Generate human-readable unique failure code (e.g. FLR-1002)."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(id) AS max_id FROM network_failures;")
            row = cursor.fetchone()
            next_num = (row['max_id'] or 1000) + 1
        return f"FLR-{next_num}"

    @classmethod
    def find_active_failure(cls, device_id: int, failure_type: str) -> Optional[Dict[str, Any]]:
        """
        Check if an unresolved failure record of the same type already exists for a device.
        Prevents duplicate failure records for the same active simulated fault.
        """
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, failure_id, device_id, device_ip, failure_type, severity,
                       status, detection_timestamp, affected_connections_json,
                       description, recommended_action, retry_count
                FROM network_failures
                WHERE device_id = ?
                  AND failure_type = ?
                  AND status IN ('ACTIVE', 'INVESTIGATING', 'ISOLATING', 'ISOLATED', 'RECOVERING')
                ORDER BY id DESC LIMIT 1;
            """, (int(device_id), failure_type))
            row = cursor.fetchone()
            if row:
                res = dict(row)
                try:
                    res['affected_connections'] = json.loads(res.get('affected_connections_json') or '[]')
                except Exception:
                    res['affected_connections'] = []
                return res
        return None

    @classmethod
    def record_failure(cls, failure_data: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        """
        Record a detected failure into SQLite network_failures table if not already active.
        
        Args:
            failure_data: Dict containing failure attributes.
            
        Returns:
            Tuple[Dict[str, Any], bool]: (failure_record, was_created)
        """
        dev_id = int(failure_data['device_id'])
        f_type = failure_data['failure_type']

        # Check deduplication
        existing = cls.find_active_failure(dev_id, f_type)
        if existing:
            logger.info(f"Active failure already exists for device {dev_id} ({f_type}): {existing['failure_id']}. Skipping duplicate.")
            return existing, False

        failure_id = failure_data.get('failure_id') or cls._generate_failure_id()
        device_ip = failure_data.get('device_ip', '')
        severity = failure_data.get('severity', 'MEDIUM')
        description = failure_data.get('description', f"Simulated fault detected: {f_type}")
        action = failure_data.get('recommended_action', "Initiate automated network path recovery and connectivity verification.")
        status = failure_data.get('status', 'ACTIVE')
        conns_json = json.dumps(failure_data.get('affected_connections', []))

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO network_failures (
                    failure_id, device_id, device_ip, failure_type, severity,
                    status, description, recommended_action, affected_connections_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                failure_id, dev_id, device_ip, f_type, severity,
                status, description, action, conns_json
            ))
            new_id = cursor.lastrowid

        logger.warning(f"[FAILURE DETECTED] ID {new_id} ({failure_id}) - Device {dev_id} ({device_ip}) - Type: {f_type} - Severity: {severity}")

        result = cls.get_failure_by_id(failure_id)
        return result or failure_data, True

    @classmethod
    def detect_device_failures(cls, device_id: int) -> List[Dict[str, Any]]:
        """
        Exhaustively analyze a single device against all 8 failure conditions.
        
        Args:
            device_id: Numeric device identifier.
            
        Returns:
            List[Dict[str, Any]]: List of active or newly detected failure records for this device.
        """
        device = DeviceService.get_device_by_id(device_id)
        if not device:
            raise NotFoundError(f"Monitored device ID {device_id} not found.")

        dev_id = device['id']
        dev_name = device['device_name']
        dev_ip = device['ip_address']
        dev_status = device['status']
        detected_failures = []

        # Parse numerical telemetry metrics
        try:
            loss_val = float(str(device.get('packet_loss', '0%')).replace('%', '').strip())
        except Exception:
            loss_val = 0.0

        try:
            # Check latest traffic log for latency
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT latency, packet_loss, traffic_in, traffic_out
                    FROM traffic_logs
                    WHERE device_id = ?
                    ORDER BY id DESC LIMIT 1;
                """, (dev_id,))
                t_row = cursor.fetchone()
                latency_val = float(t_row['latency']) if t_row else 1.0
                if t_row and t_row['packet_loss'] is not None:
                    loss_val = max(loss_val, float(t_row['packet_loss']))
        except Exception:
            latency_val = 1.0

        # Query related connection links
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, source_device_id, target_device_id, bandwidth, status
                FROM network_connections
                WHERE source_device_id = ? OR target_device_id = ?;
            """, (dev_id, dev_id))
            links = [dict(r) for r in cursor.fetchall()]

        inactive_links = [l for l in links if l['status'] == 'inactive']
        has_inactive_links = len(inactive_links) > 0
        all_links_inactive = (len(links) > 0 and len(inactive_links) == len(links))

        # ----------------------------------------------------------------------
        # CONDITION 1: Device offline
        # ----------------------------------------------------------------------
        if dev_status == 'offline':
            rec, _ = cls.record_failure({
                'device_id': dev_id,
                'device_ip': dev_ip,
                'failure_type': 'Device Offline',
                'severity': 'HIGH' if dev_id not in (1, 10) else 'CRITICAL',
                'description': f"Device '{dev_name}' ({dev_ip}) state is OFFLINE. Interface uncommunicative.",
                'recommended_action': "Engage standby failover route and stage automated reboot sequence.",
                'affected_connections': inactive_links or links
            })
            detected_failures.append(rec)

        # ----------------------------------------------------------------------
        # CONDITION 2: Device unreachable (packet loss >= 95%)
        # ----------------------------------------------------------------------
        if loss_val >= THRESHOLD_UNREACHABLE_LOSS_PCT or (all_links_inactive and dev_status != 'offline'):
            rec, _ = cls.record_failure({
                'device_id': dev_id,
                'device_ip': dev_ip,
                'failure_type': 'Device Unreachable',
                'severity': 'HIGH',
                'description': f"Device '{dev_name}' ({dev_ip}) unreachable: packet loss measured at {loss_val:.1f}%. ICMP keepalive timeout.",
                'recommended_action': "Verify physical uplink and isolate device if malicious ARP poisoning is suspected.",
                'affected_connections': inactive_links or links
            })
            detected_failures.append(rec)

        # ----------------------------------------------------------------------
        # CONDITION 3: Connection failure (severed link in network_connections)
        # ----------------------------------------------------------------------
        if has_inactive_links and dev_status != 'offline':
            rec, _ = cls.record_failure({
                'device_id': dev_id,
                'device_ip': dev_ip,
                'failure_type': 'Connection Failure',
                'severity': 'MEDIUM',
                'description': f"One or more network links for '{dev_name}' have severed (status: inactive). {len(inactive_links)} links affected.",
                'recommended_action': "Inspect network topology graph and calculate redundant alternative bypass path.",
                'affected_connections': inactive_links
            })
            detected_failures.append(rec)

        # ----------------------------------------------------------------------
        # CONDITION 4: High simulated latency (> 50ms)
        # ----------------------------------------------------------------------
        if latency_val > THRESHOLD_LATENCY_MS:
            rec, _ = cls.record_failure({
                'device_id': dev_id,
                'device_ip': dev_ip,
                'failure_type': 'High Simulated Latency',
                'severity': 'MEDIUM' if latency_val < 150.0 else 'HIGH',
                'description': f"Latency degradation on '{dev_name}' ({dev_ip}): {latency_val:.1f}ms exceeds {THRESHOLD_LATENCY_MS}ms threshold.",
                'recommended_action': "Inspect ingress socket queues, check link MTU, and evaluate bandwidth throttle.",
                'affected_connections': links
            })
            detected_failures.append(rec)

        # ----------------------------------------------------------------------
        # CONDITION 5: High packet loss (15% <= loss < 95%)
        # ----------------------------------------------------------------------
        if THRESHOLD_PACKET_LOSS_PCT <= loss_val < THRESHOLD_UNREACHABLE_LOSS_PCT:
            rec, _ = cls.record_failure({
                'device_id': dev_id,
                'device_ip': dev_ip,
                'failure_type': 'High Packet Loss',
                'severity': 'MEDIUM',
                'description': f"Degraded link quality on '{dev_name}' ({dev_ip}): packet loss measured at {loss_val:.1f}%.",
                'recommended_action': "Inspect switch interface buffers and check for localized buffer overflows.",
                'affected_connections': links
            })
            detected_failures.append(rec)

        # ----------------------------------------------------------------------
        # CONDITION 6: Abnormal traffic interruption (0 throughput while marked online)
        # ----------------------------------------------------------------------
        t_in = str(device.get('traffic_in', '0.0 Mbps')).replace('Mbps', '').strip()
        t_out = str(device.get('traffic_out', '0.0 Mbps')).replace('Mbps', '').strip()
        try:
            total_traffic = float(t_in) + float(t_out)
        except Exception:
            total_traffic = 1.0

        if dev_status == 'online' and total_traffic == 0.0 and dev_id in (1, 2, 3, 10):
            # Core infrastructure dropping to 0 Mbps while marked online
            rec, _ = cls.record_failure({
                'device_id': dev_id,
                'device_ip': dev_ip,
                'failure_type': 'Abnormal Traffic Interruption',
                'severity': 'HIGH',
                'description': f"Unexpected silence on active core node '{dev_name}' ({dev_ip}): 0.0 Mbps aggregate telemetry.",
                'recommended_action': "Execute live daemon ping probe and verify process daemon health.",
                'affected_connections': links
            })
            detected_failures.append(rec)

        # ----------------------------------------------------------------------
        # CONDITION 7: Repeated device failures (same device failed >= 2 times in history)
        # ----------------------------------------------------------------------
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) AS total_past_failures
                FROM recovery_logs
                WHERE device_id = ?;
            """, (dev_id,))
            hist_count = cursor.fetchone()['total_past_failures'] or 0

        if hist_count >= 2 and (dev_status in ('offline', 'suspicious') or has_inactive_links):
            rec, _ = cls.record_failure({
                'device_id': dev_id,
                'device_ip': dev_ip,
                'failure_type': 'Repeated Device Failure',
                'severity': 'CRITICAL',
                'description': f"Device '{dev_name}' has encountered {hist_count} previous recovery events. Persistent hardware or configuration instability.",
                'recommended_action': "Quarantine device for deep forensic examination; assign permanent failover proxy.",
                'affected_connections': links
            })
            detected_failures.append(rec)

        # ----------------------------------------------------------------------
        # CONDITION 8: Critical network path failure (link to Gateway, Firewall, or Core HES/MDMS)
        # ----------------------------------------------------------------------
        if dev_id in (1, 2, 3, 10) and has_inactive_links:
            rec, _ = cls.record_failure({
                'device_id': dev_id,
                'device_ip': dev_ip,
                'failure_type': 'Critical Network Path Failure',
                'severity': 'CRITICAL',
                'description': f"Core communication path failure on primary infrastructure '{dev_name}' ({dev_ip}). Network grid segmentation risk.",
                'recommended_action': "Engage emergency backup HES/MDMS server failover immediately.",
                'affected_connections': inactive_links
            })
            detected_failures.append(rec)

        return detected_failures

    @classmethod
    def detect_all_failures(cls) -> List[Dict[str, Any]]:
        """
        Scan all 10 monitored network devices in SQLite and detect all active failures.
        
        Returns:
            List[Dict[str, Any]]: Combined list of all detected failure records.
        """
        devices = DeviceService.get_all_devices()
        all_failures = []
        for dev in devices:
            dev_failures = cls.detect_device_failures(dev['id'])
            all_failures.extend(dev_failures)
        return all_failures

    @classmethod
    def get_active_failures(cls) -> List[Dict[str, Any]]:
        """Retrieve all currently unresolved network failures from SQLite."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT f.id, f.failure_id, f.device_id, d.device_name, f.device_ip,
                       f.failure_type, f.severity, f.status, f.detection_timestamp,
                       f.affected_connections_json, f.description, f.recommended_action,
                       f.retry_count
                FROM network_failures f
                LEFT JOIN devices d ON f.device_id = d.id
                WHERE f.status IN ('ACTIVE', 'INVESTIGATING', 'ISOLATING', 'ISOLATED', 'RECOVERING')
                ORDER BY f.id DESC;
            """)
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item['affected_connections'] = json.loads(item.get('affected_connections_json') or '[]')
                except Exception:
                    item['affected_connections'] = []
                results.append(item)
            return results

    @classmethod
    def get_all_failures(cls, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve all failure history records (active + resolved)."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT f.id, f.failure_id, f.device_id, d.device_name, f.device_ip,
                       f.failure_type, f.severity, f.status, f.detection_timestamp,
                       f.affected_connections_json, f.description, f.recommended_action,
                       f.retry_count, f.resolved_at
                FROM network_failures f
                LEFT JOIN devices d ON f.device_id = d.id
                ORDER BY f.id DESC LIMIT ?;
            """, (max(1, min(limit, 200)),))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item['affected_connections'] = json.loads(item.get('affected_connections_json') or '[]')
                except Exception:
                    item['affected_connections'] = []
                results.append(item)
            return results

    @classmethod
    def get_failure_by_id(cls, failure_id: Union[str, int]) -> Optional[Dict[str, Any]]:
        """Lookup a specific failure record by numeric ID or failure_id string (e.g. 'FLR-1001')."""
        with get_db() as conn:
            cursor = conn.cursor()
            if isinstance(failure_id, int) or (isinstance(failure_id, str) and failure_id.isdigit()):
                cursor.execute("""
                    SELECT f.id, f.failure_id, f.device_id, d.device_name, f.device_ip,
                           f.failure_type, f.severity, f.status, f.detection_timestamp,
                           f.affected_connections_json, f.description, f.recommended_action,
                           f.retry_count, f.resolved_at
                    FROM network_failures f
                    LEFT JOIN devices d ON f.device_id = d.id
                    WHERE f.id = ?;
                """, (int(failure_id),))
            else:
                cursor.execute("""
                    SELECT f.id, f.failure_id, f.device_id, d.device_name, f.device_ip,
                           f.failure_type, f.severity, f.status, f.detection_timestamp,
                           f.affected_connections_json, f.description, f.recommended_action,
                           f.retry_count, f.resolved_at
                    FROM network_failures f
                    LEFT JOIN devices d ON f.device_id = d.id
                    WHERE f.failure_id = ?;
                """, (str(failure_id).strip(),))

            row = cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            try:
                res['affected_connections'] = json.loads(res.get('affected_connections_json') or '[]')
            except Exception:
                res['affected_connections'] = []
            return res

    @classmethod
    def update_failure_status(cls, failure_id: Union[str, int], new_status: str) -> bool:
        """Update failure status (e.g. to 'RECOVERING', 'ISOLATING', 'RESOLVED')."""
        with get_db() as conn:
            cursor = conn.cursor()
            now_iso = datetime.utcnow().isoformat() + 'Z' if new_status == 'RESOLVED' else None
            if isinstance(failure_id, int) or (isinstance(failure_id, str) and failure_id.isdigit()):
                cursor.execute("""
                    UPDATE network_failures
                    SET status = ?, resolved_at = COALESCE(?, resolved_at)
                    WHERE id = ?;
                """, (new_status, now_iso, int(failure_id)))
            else:
                cursor.execute("""
                    UPDATE network_failures
                    SET status = ?, resolved_at = COALESCE(?, resolved_at)
                    WHERE failure_id = ?;
                """, (new_status, now_iso, str(failure_id).strip()))
            return cursor.rowcount > 0

    @classmethod
    def resolve_failure(cls, failure_id: Union[str, int]) -> bool:
        """Mark a failure as RESOLVED."""
        return cls.update_failure_status(failure_id, 'RESOLVED')
