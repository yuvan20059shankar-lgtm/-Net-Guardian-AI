"""
NetGuardian AI - Device Management Service
Encapsulates business logic, data validation, and SQLite queries for network assets.
"""

import ipaddress
import sqlite3
import logging
from datetime import datetime
from database import get_db
from models.device_model import Device

logger = logging.getLogger('netguardian.device_service')

VALID_STATUSES = {'online', 'offline', 'suspicious'}


class ValidationError(Exception):
    """Raised when input payload fails validation checks."""
    pass


class DuplicateError(Exception):
    """Raised when uniqueness constraints (e.g. unique IP) are violated."""
    pass


class NotFoundError(Exception):
    """Raised when an asset does not exist in the database."""
    pass


class DeviceService:
    """Service layer managing device operations, validation, and analytics."""

    @staticmethod
    def parse_device_id(val):
        """Parse raw device ID, handling integers, numeric strings, and 'dev-X' prefixes."""
        if val is None:
            return None
        if isinstance(val, int):
            return val
        s = str(val).strip()
        if s.lower().startswith('dev-'):
            s = s[4:]
        if s.isdigit():
            return int(s)
        return None

    @staticmethod
    def validate_ip_address(ip_str):
        """Validate that the provided string is a valid IPv4 address."""
        if not ip_str or not isinstance(ip_str, str):
            raise ValidationError("IP address is required and must be a string.")
        try:
            ipaddress.IPv4Address(ip_str.strip())
            return ip_str.strip()
        except ValueError:
            raise ValidationError(f"Invalid IPv4 address format: '{ip_str}'")

    @staticmethod
    def validate_status(status_str):
        """Validate device operational status."""
        if not status_str or not isinstance(status_str, str):
            return 'online'
        norm = status_str.strip().lower()
        if norm not in VALID_STATUSES:
            raise ValidationError(
                f"Invalid status '{status_str}'. Allowed values: {sorted(list(VALID_STATUSES))}"
            )
        return norm

    @classmethod
    def get_all_devices(cls):
        """
        Fetch all network devices from SQLite.
        
        Returns:
            list[dict]: List of serialized devices.
        """
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices ORDER BY id ASC;")
            rows = cursor.fetchall()
            return [Device.from_row(row).to_dict() for row in rows]

    @classmethod
    def get_device_by_id(cls, device_id):
        """
        Fetch a single device by primary key ID (supports integer or 'dev-X' prefix).
        
        Returns:
            dict or None: Serialized device or None if not found.
        """
        parsed_id = cls.parse_device_id(device_id)
        if parsed_id is None:
            return None
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE id = ?;", (parsed_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return Device.from_row(row).to_dict()

    @classmethod
    def get_device_by_ip(cls, ip_address):
        """Fetch a single device by its unique IP address."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE ip_address = ?;", (ip_address.strip(),))
            row = cursor.fetchone()
            if not row:
                return None
            return Device.from_row(row).to_dict()

    @classmethod
    def create_device(cls, data):
        """
        Validate and insert a new device into SQLite.
        
        Args:
            data (dict): Incoming device attributes.
            
        Returns:
            dict: The newly created serialized device.
        """
        if not data or not isinstance(data, dict):
            raise ValidationError("Device payload must be a valid JSON object.")

        # Required field validations
        name = data.get('device_name') or data.get('name')
        if not name or not isinstance(name, str) or not name.strip():
            raise ValidationError("Field 'device_name' is required.")
        name = name.strip()

        raw_ip = data.get('ip_address') or data.get('ip')
        valid_ip = cls.validate_ip_address(raw_ip)

        dev_type = data.get('device_type') or data.get('type')
        if not dev_type or not isinstance(dev_type, str) or not dev_type.strip():
            raise ValidationError("Field 'device_type' is required.")
        dev_type = dev_type.strip()

        role = (data.get('role') or 'Workstation Terminal').strip()
        status = cls.validate_status(data.get('status', 'online'))
        traffic_in = str(data.get('traffic_in') or data.get('trafficIn') or '0.0 Mbps')
        traffic_out = str(data.get('traffic_out') or data.get('trafficOut') or '0.0 Mbps')
        cpu_usage = float(data.get('cpu_usage') or data.get('cpuLoad') or 0.0)
        memory_usage = float(data.get('memory_usage') or data.get('memLoad') or 0.0)
        packet_loss = str(data.get('packet_loss') or data.get('packetLoss') or '0.00%')
        last_active = str(data.get('last_active') or data.get('lastActive') or 'Just now')

        # Prevent duplicate IP addresses
        if cls.get_device_by_ip(valid_ip):
            raise DuplicateError(f"A device with IP address '{valid_ip}' already exists in the inventory.")

        with get_db() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO devices (
                        device_name, ip_address, device_type, role, status,
                        traffic_in, traffic_out, cpu_usage, memory_usage,
                        packet_loss, last_active, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
                """, (
                    name, valid_ip, dev_type, role, status,
                    traffic_in, traffic_out, cpu_usage, memory_usage,
                    packet_loss, last_active
                ))
                new_id = cursor.lastrowid
            except sqlite3.IntegrityError as e:
                logger.error(f"Integrity constraint violation on insert: {e}")
                raise DuplicateError(f"Database constraint error: {e}")

        logger.info(f"Created new device: ID {new_id} ({name} - {valid_ip})")
        return cls.get_device_by_id(new_id)

    @classmethod
    def update_device(cls, device_id, data):
        """
        Update attributes of an existing device.
        
        Args:
            device_id (int): Primary key ID of the target device.
            data (dict): Attributes to update.
            
        Returns:
            dict: Updated serialized device.
        """
        existing = cls.get_device_by_id(device_id)
        if not existing:
            raise NotFoundError(f"Device with ID {device_id} not found.")

        if not data or not isinstance(data, dict):
            raise ValidationError("Update payload must be a valid JSON object.")

        updates = []
        params = []

        if 'device_name' in data or 'name' in data:
            name = (data.get('device_name') or data.get('name') or '').strip()
            if not name:
                raise ValidationError("Device name cannot be empty.")
            updates.append("device_name = ?")
            params.append(name)

        if 'ip_address' in data or 'ip' in data:
            raw_ip = data.get('ip_address') or data.get('ip')
            valid_ip = cls.validate_ip_address(raw_ip)
            # Check duplicate IP on another device
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM devices WHERE ip_address = ? AND id != ?;", (valid_ip, device_id))
                if cursor.fetchone():
                    raise DuplicateError(f"IP address '{valid_ip}' is already in use by another device.")
            updates.append("ip_address = ?")
            params.append(valid_ip)

        if 'device_type' in data or 'type' in data:
            dev_type = (data.get('device_type') or data.get('type') or '').strip()
            if not dev_type:
                raise ValidationError("Device type cannot be empty.")
            updates.append("device_type = ?")
            params.append(dev_type)

        if 'role' in data:
            updates.append("role = ?")
            params.append(str(data['role']).strip())

        if 'status' in data:
            valid_status = cls.validate_status(data['status'])
            updates.append("status = ?")
            params.append(valid_status)

        if 'traffic_in' in data or 'trafficIn' in data:
            updates.append("traffic_in = ?")
            params.append(str(data.get('traffic_in') or data.get('trafficIn')))

        if 'traffic_out' in data or 'trafficOut' in data:
            updates.append("traffic_out = ?")
            params.append(str(data.get('traffic_out') or data.get('trafficOut')))

        if 'cpu_usage' in data or 'cpuLoad' in data:
            updates.append("cpu_usage = ?")
            params.append(float(data.get('cpu_usage') or data.get('cpuLoad')))

        if 'memory_usage' in data or 'memLoad' in data:
            updates.append("memory_usage = ?")
            params.append(float(data.get('memory_usage') or data.get('memLoad')))

        if 'packet_loss' in data or 'packetLoss' in data:
            updates.append("packet_loss = ?")
            params.append(str(data.get('packet_loss') or data.get('packetLoss')))

        if 'last_active' in data or 'lastActive' in data:
            updates.append("last_active = ?")
            params.append(str(data.get('last_active') or data.get('lastActive')))

        if not updates:
            return existing

        updates.append("updated_at = CURRENT_TIMESTAMP")
        query = f"UPDATE devices SET {', '.join(updates)} WHERE id = ?;"
        params.append(device_id)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))

        logger.info(f"Updated device ID {device_id}")
        return cls.get_device_by_id(device_id)

    @classmethod
    def delete_device(cls, device_id):
        """
        Delete a device from SQLite.
        
        Returns:
            bool: True if deleted successfully.
        """
        existing = cls.get_device_by_id(device_id)
        if not existing:
            raise NotFoundError(f"Device with ID {device_id} not found.")

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM devices WHERE id = ?;", (device_id,))

        logger.info(f"Deleted device ID {device_id} ({existing['device_name']})")
        return True

    @classmethod
    def update_device_status(cls, device_id, new_status):
        """
        Update the operational status of a device (PATCH /api/devices/:id/status).
        
        Allowed statuses: 'online', 'offline', 'suspicious'
        """
        valid_status = cls.validate_status(new_status)
        existing = cls.get_device_by_id(device_id)
        if not existing:
            raise NotFoundError(f"Device with ID {device_id} not found.")

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE devices
                SET status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?;
            """, (valid_status, device_id))

        logger.info(f"Updated status of device ID {device_id} to '{valid_status}'")
        return cls.get_device_by_id(device_id)

    @classmethod
    def toggle_device_status(cls, device_id):
        """
        Toggle device operational status between online and offline.
        Provides compatibility with frontend POST /api/devices/<id>/toggle.
        """
        existing = cls.get_device_by_id(device_id)
        if not existing:
            raise NotFoundError(f"Device with ID '{device_id}' not found.")

        current = existing['status']
        new_status = 'offline' if current == 'online' else 'online'
        return cls.update_device_status(existing['id'], new_status)

    @classmethod
    def get_dashboard_metrics(cls):
        """
        Calculate SOC Dashboard KPI statistics directly from the SQLite database.
        
        Formula:
        network_health = (online_devices / total_devices) * 100
        
        Returns:
            dict: Computed dashboard metrics (Prompts 6 & 8).
        """
        with get_db() as conn:
            cursor = conn.cursor()
            
            # 1. Device metrics
            cursor.execute("""
                SELECT
                    COUNT(*) AS total_devices,
                    SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) AS online_devices,
                    SUM(CASE WHEN status = 'offline' THEN 1 ELSE 0 END) AS offline_devices,
                    SUM(CASE WHEN status = 'suspicious' THEN 1 ELSE 0 END) AS suspicious_devices
                FROM devices;
            """)
            row = cursor.fetchone()

            # 2. Security alert metrics (Prompt 8)
            cursor.execute("""
                SELECT
                    COUNT(*) AS total_alerts,
                    SUM(CASE WHEN status IN ('ACTIVE', 'INVESTIGATING') THEN 1 ELSE 0 END) AS active_alerts,
                    SUM(CASE WHEN severity = 'CRITICAL' AND status != 'RESOLVED' THEN 1 ELSE 0 END) AS critical_incidents
                FROM security_alerts;
            """)
            alert_row = cursor.fetchone()

            # 3. Recovery metrics (Prompt 8)
            cursor.execute("""
                SELECT
                    SUM(CASE WHEN verification_status = 'VERIFIED' THEN 1 ELSE 0 END) AS successful_recoveries,
                    SUM(CASE WHEN verification_status = 'FAILED' THEN 1 ELSE 0 END) AS failed_recoveries
                FROM recovery_logs;
            """)
            rec_row = cursor.fetchone()

        total = row['total_devices'] if row and row['total_devices'] is not None else 0
        online = row['online_devices'] if row and row['online_devices'] is not None else 0
        offline = row['offline_devices'] if row and row['offline_devices'] is not None else 0
        suspicious = row['suspicious_devices'] if row and row['suspicious_devices'] is not None else 0

        active_alerts = alert_row['active_alerts'] if alert_row and alert_row['active_alerts'] is not None else 0
        critical_incidents = alert_row['critical_incidents'] if alert_row and alert_row['critical_incidents'] is not None else 0
        successful_rec = rec_row['successful_recoveries'] if rec_row and rec_row['successful_recoveries'] is not None else 0
        failed_rec = rec_row['failed_recoveries'] if rec_row and rec_row['failed_recoveries'] is not None else 0

        # Calculate network health percentage safely
        if total > 0:
            health = round((online / total) * 100, 1)
        else:
            health = 0.0

        return {
            'total_devices': total,
            'online_devices': online,
            'offline_devices': offline,
            'suspicious_devices': suspicious,
            'isolated_devices': suspicious,
            'network_health': health,
            'active_security_alerts': active_alerts,
            'critical_incidents': critical_incidents,
            'successful_recovery_count': successful_rec,
            'failed_recovery_count': failed_rec,
            'successful_recoveries': successful_rec,
            'failed_recoveries': failed_rec,
            # CamelCase aliases for frontend SOC dashboard compatibility
            'totalDevices': total,
            'onlineDevices': online,
            'offlineDevices': offline,
            'suspiciousDevices': suspicious,
            'activeThreats': active_alerts,
            'networkHealth': health,
            'successfulRecoveries': successful_rec
        }
