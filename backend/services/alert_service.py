"""
NetGuardian AI - Security Alert Management Service
Encapsulates business logic, validation, and database operations for security incident alerts.
"""

import logging
import sqlite3
from database import get_db
from services.device_service import DeviceService, ValidationError, NotFoundError

logger = logging.getLogger('netguardian.alert_service')

VALID_SEVERITIES = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
VALID_STATUSES = {'ACTIVE', 'INVESTIGATING', 'MITIGATED', 'RESOLVED'}


class AlertService:
    """Service layer handling security alerts validation, persistence, and aggregations."""

    @classmethod
    def validate_severity(cls, severity):
        """Validate and normalize alert severity."""
        if not severity or not isinstance(severity, str):
            raise ValidationError("Severity is required and must be a string.")
        norm = severity.strip().upper()
        if norm not in VALID_SEVERITIES:
            raise ValidationError(f"Invalid severity '{severity}'. Must be one of: {sorted(list(VALID_SEVERITIES))}")
        return norm

    @classmethod
    def validate_status(cls, status):
        """Validate and normalize alert operational status."""
        if not status or not isinstance(status, str):
            raise ValidationError("Status is required and must be a string.")
        norm = status.strip().upper()
        if norm not in VALID_STATUSES:
            raise ValidationError(f"Invalid status '{status}'. Must be one of: {sorted(list(VALID_STATUSES))}")
        return norm

    @classmethod
    def get_all_alerts(cls, severity=None, status=None, limit=100, offset=0):
        """
        Fetch all security alerts with optional filtering by severity and status.
        Joins with the devices table to include device details.
        """
        query = """
            SELECT a.id, a.alert_code, a.device_id, d.device_name, d.ip_address, d.device_type,
                   a.threat_type, a.description, a.severity, a.status, a.detection_source,
                   a.recommended_action, a.created_at, a.resolved_at
            FROM security_alerts a
            JOIN devices d ON a.device_id = d.id
            WHERE 1=1
        """
        params = []

        if severity:
            norm_sev = cls.validate_severity(severity)
            query += " AND a.severity = ?"
            params.append(norm_sev)

        if status:
            norm_stat = cls.validate_status(status)
            query += " AND a.status = ?"
            params.append(norm_stat)

        query += " ORDER BY a.id DESC LIMIT ? OFFSET ?;"
        params.extend([max(1, min(limit, 500)), max(0, offset)])

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    @classmethod
    def find_recent_active_alert(cls, device_id: int, threat_type: str, within_seconds: int = 300):
        """
        Check if an identical ACTIVE or INVESTIGATING alert exists for this device and threat type
        within the given time window, preventing duplicate spam.
        """
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT a.id, a.alert_code, a.device_id, d.device_name, d.ip_address, d.device_type,
                       a.threat_type, a.description, a.severity, a.status, a.detection_source,
                       a.recommended_action, a.anomaly_score, a.created_at, a.resolved_at
                FROM security_alerts a
                JOIN devices d ON a.device_id = d.id
                WHERE a.device_id = ?
                  AND a.threat_type = ?
                  AND a.status IN ('ACTIVE', 'INVESTIGATING')
                  AND (strftime('%s', 'now') - strftime('%s', a.created_at)) <= ?
                ORDER BY a.id DESC LIMIT 1;
            """, (int(device_id), str(threat_type), int(within_seconds)))
            row = cursor.fetchone()
            return dict(row) if row else None

    @classmethod
    def get_alert_by_id(cls, alert_id):
        """
        Retrieve a single security alert by its numeric ID or unique alert_code.
        """
        with get_db() as conn:
            cursor = conn.cursor()
            # If alert_id is an integer or can be converted to int
            if isinstance(alert_id, int) or (isinstance(alert_id, str) and alert_id.isdigit()):
                cursor.execute("""
                    SELECT a.id, a.alert_code, a.device_id, d.device_name, d.ip_address, d.device_type,
                           a.threat_type, a.description, a.severity, a.status, a.detection_source,
                           a.recommended_action, a.created_at, a.resolved_at
                    FROM security_alerts a
                    JOIN devices d ON a.device_id = d.id
                    WHERE a.id = ?;
                """, (int(alert_id),))
            else:
                cursor.execute("""
                    SELECT a.id, a.alert_code, a.device_id, d.device_name, d.ip_address, d.device_type,
                           a.threat_type, a.description, a.severity, a.status, a.detection_source,
                           a.recommended_action, a.created_at, a.resolved_at
                    FROM security_alerts a
                    JOIN devices d ON a.device_id = d.id
                    WHERE a.alert_code = ?;
                """, (str(alert_id),))

            row = cursor.fetchone()
            return dict(row) if row else None

    @classmethod
    def create_alert(cls, data):
        """
        Validate and create a new security alert record.
        """
        if not data or not isinstance(data, dict):
            raise ValidationError("Payload must be a valid JSON object.")

        # 1. Validate device_id
        raw_dev_id = data.get('device_id')
        if raw_dev_id is None:
            raise ValidationError("Field 'device_id' is required.")
        try:
            device_id = int(raw_dev_id)
        except (ValueError, TypeError):
            raise ValidationError("Field 'device_id' must be a valid integer.")

        device = DeviceService.get_device_by_id(device_id)
        if not device:
            raise NotFoundError(f"Target device with ID {device_id} does not exist.")

        # 2. Validate textual fields
        threat_type = (data.get('threat_type') or '').strip()
        if not threat_type:
            raise ValidationError("Field 'threat_type' is required.")

        description = (data.get('description') or '').strip()
        if not description:
            raise ValidationError("Field 'description' is required.")

        severity = cls.validate_severity(data.get('severity', 'MEDIUM'))
        status = cls.validate_status(data.get('status', 'ACTIVE'))

        detection_source = (data.get('detection_source') or 'Simulated Heuristic Monitor').strip()
        recommended_action = (data.get('recommended_action') or 'Investigate host activity and check network logs.').strip()
        anomaly_score = float(data.get('anomaly_score', 0.0) or 0.0)

        # 3. Generate unique alert code if not supplied
        alert_code = (data.get('alert_code') or '').strip()
        with get_db() as conn:
            cursor = conn.cursor()
            if not alert_code:
                cursor.execute("SELECT MAX(id) AS max_id FROM security_alerts;")
                max_id = cursor.fetchone()['max_id'] or 1000
                alert_code = f"ALT-{max_id + 1}"

            # Check uniqueness
            cursor.execute("SELECT id FROM security_alerts WHERE alert_code = ?;", (alert_code,))
            if cursor.fetchone():
                cursor.execute("SELECT MAX(id) AS max_id FROM security_alerts;")
                max_id = cursor.fetchone()['max_id'] or 1000
                alert_code = f"ALT-{max_id + 100}"

            resolved_at = None
            if status == 'RESOLVED':
                cursor.execute("SELECT CURRENT_TIMESTAMP AS now;")
                resolved_at = cursor.fetchone()['now']

            cursor.execute("""
                INSERT INTO security_alerts (
                    alert_code, device_id, threat_type, description,
                    severity, status, detection_source, recommended_action,
                    anomaly_score, created_at, resolved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?);
            """, (
                alert_code, device_id, threat_type, description,
                severity, status, detection_source, recommended_action,
                anomaly_score, resolved_at
            ))
            new_id = cursor.lastrowid

        logger.warning(
            f"[AUDIT] Security alert created: ID {new_id} ({alert_code}) - Device: {device['device_name']} "
            f"(ID {device_id}) - Severity: {severity} - Threat: {threat_type}"
        )
        return cls.get_alert_by_id(new_id)

    @classmethod
    def update_alert_status(cls, alert_id, new_status):
        """
        Update the operational status of an existing security alert.
        Handles automated timestamping for resolution.
        """
        norm_status = cls.validate_status(new_status)
        existing = cls.get_alert_by_id(alert_id)
        if not existing:
            raise NotFoundError(f"Security alert '{alert_id}' not found.")

        target_id = existing['id']

        with get_db() as conn:
            cursor = conn.cursor()
            if norm_status == 'RESOLVED':
                cursor.execute("""
                    UPDATE security_alerts
                    SET status = ?, resolved_at = CURRENT_TIMESTAMP
                    WHERE id = ?;
                """, (norm_status, target_id))
            else:
                cursor.execute("""
                    UPDATE security_alerts
                    SET status = ?, resolved_at = NULL
                    WHERE id = ?;
                """, (norm_status, target_id))

        logger.info(
            f"[AUDIT] Security alert status updated: ID {target_id} ({existing['alert_code']}) "
            f"from '{existing['status']}' -> '{norm_status}'"
        )
        return cls.get_alert_by_id(target_id)

    @classmethod
    def get_alerts_summary(cls):
        """
        Aggregate high-level security alert statistics from SQLite.
        """
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    COUNT(*) AS total_alerts,
                    SUM(CASE WHEN status = 'ACTIVE' THEN 1 ELSE 0 END) AS active_alerts,
                    SUM(CASE WHEN status = 'INVESTIGATING' THEN 1 ELSE 0 END) AS investigating_alerts,
                    SUM(CASE WHEN status = 'MITIGATED' THEN 1 ELSE 0 END) AS mitigated_alerts,
                    SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END) AS resolved_alerts,
                    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_alerts,
                    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high_alerts,
                    SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_alerts,
                    SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) AS low_alerts
                FROM security_alerts;
            """)
            row = cursor.fetchone()

        return {
            'total_alerts': row['total_alerts'] or 0,
            'active_alerts': row['active_alerts'] or 0,
            'investigating_alerts': row['investigating_alerts'] or 0,
            'mitigated_alerts': row['mitigated_alerts'] or 0,
            'resolved_alerts': row['resolved_alerts'] or 0,
            'critical_alerts': row['critical_alerts'] or 0,
            'high_alerts': row['high_alerts'] or 0,
            'medium_alerts': row['medium_alerts'] or 0,
            'low_alerts': row['low_alerts'] or 0
        }
