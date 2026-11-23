"""
NetGuardian AI - Device Data Model
Defines the schema, serialization, and representation for network devices.
"""


class Device:
    """Represents a monitored network asset in the NetGuardian AI SOC."""

    def __init__(
        self,
        id=None,
        device_name="",
        ip_address="",
        device_type="",
        role="",
        status="online",
        traffic_in="0.0 Mbps",
        traffic_out="0.0 Mbps",
        cpu_usage=0.0,
        memory_usage=0.0,
        packet_loss="0.00%",
        last_active="Just now",
        created_at=None,
        updated_at=None
    ):
        self.id = id
        self.device_name = device_name
        self.ip_address = ip_address
        self.device_type = device_type
        self.role = role
        self.status = status
        self.traffic_in = traffic_in
        self.traffic_out = traffic_out
        self.cpu_usage = cpu_usage
        self.memory_usage = memory_usage
        self.packet_loss = packet_loss
        self.last_active = last_active
        self.created_at = created_at
        self.updated_at = updated_at

    @classmethod
    def from_row(cls, row):
        """Construct a Device instance from an SQLite Row object."""
        if row is None:
            return None
        return cls(
            id=row['id'],
            device_name=row['device_name'],
            ip_address=row['ip_address'],
            device_type=row['device_type'],
            role=row['role'],
            status=row['status'],
            traffic_in=row['traffic_in'],
            traffic_out=row['traffic_out'],
            cpu_usage=float(row['cpu_usage']) if row['cpu_usage'] is not None else 0.0,
            memory_usage=float(row['memory_usage']) if row['memory_usage'] is not None else 0.0,
            packet_loss=row['packet_loss'],
            last_active=row['last_active'],
            created_at=str(row['created_at']) if row['created_at'] else None,
            updated_at=str(row['updated_at']) if row['updated_at'] else None
        )

    def to_dict(self):
        """
        Serialize Device object to dictionary format.
        Includes standard snake_case fields and camelCase aliases for frontend compatibility.
        """
        return {
            'id': self.id,
            'device_name': self.device_name,
            'ip_address': self.ip_address,
            'device_type': self.device_type,
            'role': self.role,
            'status': self.status,
            'traffic_in': self.traffic_in,
            'traffic_out': self.traffic_out,
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'packet_loss': self.packet_loss,
            'last_active': self.last_active,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            
            # Compatibility aliases for existing UI consumers
            'name': self.device_name,
            'ip': self.ip_address,
            'type': self.device_type,
            'trafficIn': self.traffic_in,
            'trafficOut': self.traffic_out,
            'cpuLoad': self.cpu_usage,
            'memLoad': self.memory_usage,
            'packetLoss': self.packet_loss,
            'lastActive': self.last_active
        }
