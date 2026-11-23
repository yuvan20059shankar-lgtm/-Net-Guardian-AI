"""
NetGuardian AI - Recovery Log Data Model
Defines the schema and serialization for autonomous self-healing and failover recovery logs.
"""


class RecoveryLog:
    """Represents a historical self-healing recovery operation in SQLite."""

    def __init__(
        self,
        id=None,
        recovery_code="",
        device_id=None,
        failure_type="",
        action_taken="",
        original_status="offline",
        final_status="online",
        alternative_route=None,
        duration_seconds=0.0,
        verification_status="VERIFIED",
        created_at=None,
        device_name=None,
        ip_address=None
    ):
        self.id = id
        self.recovery_code = recovery_code
        self.device_id = device_id
        self.failure_type = failure_type
        self.action_taken = action_taken
        self.original_status = original_status
        self.final_status = final_status
        self.alternative_route = alternative_route
        self.duration_seconds = duration_seconds
        self.verification_status = verification_status
        self.created_at = created_at
        self.device_name = device_name
        self.ip_address = ip_address

    @classmethod
    def from_row(cls, row):
        """Construct a RecoveryLog instance from an SQLite Row object."""
        if row is None:
            return None
        keys = row.keys() if hasattr(row, 'keys') else []
        return cls(
            id=row['id'],
            recovery_code=row['recovery_code'],
            device_id=row['device_id'],
            failure_type=row['failure_type'],
            action_taken=row['action_taken'],
            original_status=row['original_status'],
            final_status=row['final_status'],
            alternative_route=row['alternative_route'],
            duration_seconds=float(row['duration_seconds']) if row['duration_seconds'] is not None else 0.0,
            verification_status=row['verification_status'],
            created_at=str(row['created_at']) if row['created_at'] else None,
            device_name=row['device_name'] if 'device_name' in keys else None,
            ip_address=row['ip_address'] if 'ip_address' in keys else None
        )

    def to_dict(self):
        """Serialize RecoveryLog object to dictionary format."""
        return {
            'id': self.id,
            'recovery_code': self.recovery_code,
            'device_id': self.device_id,
            'failure_type': self.failure_type,
            'action_taken': self.action_taken,
            'original_status': self.original_status,
            'final_status': self.final_status,
            'alternative_route': self.alternative_route,
            'duration_seconds': self.duration_seconds,
            'verification_status': self.verification_status,
            'created_at': self.created_at,
            'device_name': self.device_name,
            'ip_address': self.ip_address,

            # Frontend compatibility aliases
            'targetDevice': f"{self.device_name} ({self.ip_address})" if self.device_name else f"Device {self.device_id}",
            'faultType': self.failure_type,
            'duration': f"{self.duration_seconds} seconds",
            'timestamp': self.created_at,
            'status': 'SUCCESS' if self.verification_status == 'VERIFIED' else 'FAILED'
        }
