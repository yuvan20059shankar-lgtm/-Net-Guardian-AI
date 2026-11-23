"""
NetGuardian AI - Security Alert Data Model
Defines the schema and serialization for security alerts and incident records.
"""


class Alert:
    """Represents a security incident or advisory in the NetGuardian AI SOC."""

    def __init__(
        self,
        id=None,
        alert_code="",
        device_id=None,
        threat_type="",
        description="",
        severity="MEDIUM",
        status="ACTIVE",
        detection_source="",
        recommended_action="",
        created_at=None,
        resolved_at=None,
        device_name=None,
        ip_address=None
    ):
        self.id = id
        self.alert_code = alert_code
        self.device_id = device_id
        self.threat_type = threat_type
        self.description = description
        self.severity = severity
        self.status = status
        self.detection_source = detection_source
        self.recommended_action = recommended_action
        self.created_at = created_at
        self.resolved_at = resolved_at
        self.device_name = device_name
        self.ip_address = ip_address

    @classmethod
    def from_row(cls, row):
        """Construct an Alert instance from an SQLite Row object."""
        if row is None:
            return None
        keys = row.keys() if hasattr(row, 'keys') else []
        return cls(
            id=row['id'],
            alert_code=row['alert_code'],
            device_id=row['device_id'],
            threat_type=row['threat_type'],
            description=row['description'],
            severity=row['severity'],
            status=row['status'],
            detection_source=row['detection_source'],
            recommended_action=row['recommended_action'],
            created_at=str(row['created_at']) if row['created_at'] else None,
            resolved_at=str(row['resolved_at']) if ('resolved_at' in keys and row['resolved_at']) else None,
            device_name=row['device_name'] if 'device_name' in keys else None,
            ip_address=row['ip_address'] if 'ip_address' in keys else None
        )

    def to_dict(self):
        """Serialize Alert object to dictionary format."""
        return {
            'id': self.id,
            'alert_code': self.alert_code,
            'device_id': self.device_id,
            'threat_type': self.threat_type,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'detection_source': self.detection_source,
            'recommended_action': self.recommended_action,
            'created_at': self.created_at,
            'resolved_at': self.resolved_at,
            'device_name': self.device_name,
            'ip_address': self.ip_address,

            # Frontend compatibility aliases
            'summary': self.description,
            'timestamp': self.created_at
        }
