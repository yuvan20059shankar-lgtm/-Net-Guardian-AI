"""
NetGuardian AI - Intelligent Device Isolation and Restoration Service (Module 2)
Tagline: Detect. Defend. Recover. Automatically.

Manages simulated quarantine, safe endpoint isolation, and authorized restoration:
- Enforces critical infrastructure protection guards (Router 01 / Firewall 01).
- Evaluates critical network service partition impact prior to isolation.
- Disables active simulated connection links during quarantine.
- Restores nominal device baseline telemetry and re-enables topology links.
- Synchronizes NetworkX graph in real time with SQLite database.
- Audits all isolation and restoration actions in device_isolation_logs.

IMPORTANT: Operates purely on simulated network state. No physical devices affected.
"""

from __future__ import annotations
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union

import networkx as nx
from database import get_db
from services.device_service import DeviceService, NotFoundError, ValidationError
from services.network_simulator import NetworkSimulator

logger = logging.getLogger('netguardian.healing.device_isolation')

# Critical infrastructure devices protected against automated isolation
CORE_PROTECTED_DEVICE_IDS = (1, 10)  # Router 01 / Smart Meter Gateway, BESCOM Security Firewall
CORE_SERVERS_DEVICE_IDS = (2, 3)     # HES Server 01, MDMS Server 02


class DeviceIsolationService:
    """
    Self-Healing Module 2: Intelligent Device Isolation & Restoration Engine.
    Executes simulated quarantine and restoration operations with graph partition safety checks.
    """

    @classmethod
    def _generate_isolation_id(cls) -> str:
        """Generate human-readable unique isolation audit code (e.g. ISO-1001)."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(id) AS max_id FROM device_isolation_logs;")
            row = cursor.fetchone()
            next_num = (row['max_id'] or 1000) + 1
        return f"ISO-{next_num}"

    @classmethod
    def check_critical_service_impact(cls, device_id: int) -> Tuple[bool, str]:
        """
        Safety Rule 2: Evaluate whether isolating this device would partition
        essential network services (Core Gateway Router 1, HES Server 2, MDMS Server 3).
        
        Returns:
            Tuple[bool, str]: (safe_to_isolate, reason_or_warning)
        """
        simulator = NetworkSimulator()
        simulator.sync_graph_from_db()
        graph = simulator.graph.copy()

        # Check core router protection rule 4
        if device_id in CORE_PROTECTED_DEVICE_IDS:
            return False, f"Device ID {device_id} is designated primary infrastructure. Automated isolation prohibited."

        # Simulate graph partition if this node were removed
        if graph.has_node(device_id):
            graph.remove_node(device_id)

        # Verify whether Core Router (1), HES (2), and MDMS (3) remain mutually connected
        essential_nodes = [n for n in (1, 2, 3) if graph.has_node(n)]
        if len(essential_nodes) >= 2:
            base_node = essential_nodes[0]
            for other_node in essential_nodes[1:]:
                if not nx.has_path(graph, base_node, other_node):
                    return False, f"Isolating device ID {device_id} would sever critical path between core components ({base_node} and {other_node})."

        return True, "Safe to isolate: Critical network backbone connectivity preserved."

    @classmethod
    def isolate_device(
        cls,
        device_id: int,
        reason: str = "Security threat quarantine",
        trigger: str = "MANUAL",
        force: bool = False
    ) -> Dict[str, Any]:
        """
        Isolate a simulated device:
        1. Validate device exists.
        2. Enforce infrastructure protection rules.
        3. Evaluate critical service impact.
        4. Update device status = 'suspicious' and disable connected links.
        5. Synchronize NetworkX graph.
        6. Persist audit log in device_isolation_logs.
        
        Args:
            device_id: Numeric device identifier.
            reason: Human-readable isolation justification.
            trigger: Initiation source ('MANUAL', 'AI_THREAT_CRITICAL', 'FAILURE_DETECTION').
            force: Override critical service check (cannot override Router 1 / Firewall 10).
            
        Returns:
            Dict[str, Any]: Isolation result summary.
        """
        device = DeviceService.get_device_by_id(device_id)
        if not device:
            raise NotFoundError(f"Device with ID {device_id} not found in inventory.")

        dev_name = device['device_name']
        dev_ip = device['ip_address']

        # Rule 4: Router 01 and Firewall 01 can NEVER be isolated without explicit prototype guard
        if device['device_type'] in ('Router', 'Firewall') or device_id in CORE_PROTECTED_DEVICE_IDS:
            logger.warning(f"[SECURITY BLOCKED] Attempted isolation of protected core infrastructure: {dev_name} (ID {device_id})")
            raise ValidationError(
                f"Administrative security override required: Isolation of primary infrastructure "
                f"'{dev_name}' is strictly prohibited to prevent complete network blackout."
            )

        # Rule 2: Critical service impact analysis
        is_safe, impact_msg = cls.check_critical_service_impact(device_id)
        if not is_safe and not force:
            logger.warning(f"[ISOLATION BLOCKED] Service impact check failed for device {device_id}: {impact_msg}")
            raise ValidationError(f"Isolation rejected by Safety Policy: {impact_msg}")

        # Check if already isolated
        if device['status'] == 'suspicious':
            logger.info(f"Device {device_id} ({dev_name}) is already isolated. Updating reason.")

        isolation_id = cls._generate_isolation_id()

        # Update SQLite database
        with get_db() as conn:
            cursor = conn.cursor()

            # 1. Update device status to 'suspicious'
            cursor.execute("""
                UPDATE devices
                SET status = 'suspicious',
                    last_active = 'Quarantined / Isolated',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?;
            """, (device_id,))

            # 2. Disable active connections for this device
            cursor.execute("""
                UPDATE network_connections
                SET status = 'inactive'
                WHERE source_device_id = ? OR target_device_id = ?;
            """, (device_id, device_id))

            # Query updated links
            cursor.execute("""
                SELECT id, source_device_id, target_device_id, bandwidth, status
                FROM network_connections
                WHERE source_device_id = ? OR target_device_id = ?;
            """, (device_id, device_id))
            conns = [dict(c) for c in cursor.fetchall()]

            # 3. Insert audit record in device_isolation_logs
            cursor.execute("""
                INSERT INTO device_isolation_logs (
                    isolation_id, device_id, device_name, device_ip,
                    isolation_reason, isolation_trigger, status,
                    affected_connections_count, critical_service_check_passed
                ) VALUES (?, ?, ?, ?, ?, ?, 'ISOLATED', ?, ?);
            """, (
                isolation_id, device_id, dev_name, dev_ip,
                reason, trigger, len(conns), 1 if is_safe else 0
            ))
            new_log_id = cursor.lastrowid

        # Synchronize NetworkX graph
        simulator = NetworkSimulator()
        simulator.sync_graph_from_db()

        logger.warning(
            f"[AUDIT] Device quarantined / isolated: ID {device_id} ({dev_name}) - "
            f"Isolation ID: {isolation_id} - Reason: {reason} - Disabled links: {len(conns)}"
        )

        updated_device = DeviceService.get_device_by_id(device_id)
        return {
            'success': True,
            'isolated': True,
            'isolation_id': isolation_id,
            'device_id': device_id,
            'device_name': dev_name,
            'device_ip': dev_ip,
            'status': 'suspicious',
            'isolation_reason': reason,
            'isolation_trigger': trigger,
            'isolated_at': datetime.utcnow().isoformat() + 'Z',
            'affected_connections_count': len(conns),
            'affected_connections': conns,
            'critical_service_check_passed': is_safe,
            'device': updated_device
        }

    @classmethod
    def restore_device(
        cls,
        device_id: int,
        reason: str = "Authorized manual restoration"
    ) -> Dict[str, Any]:
        """
        Restore an isolated or offline simulated device back to operational baseline:
        1. Validate device exists.
        2. Set status = 'online' and reset metrics.
        3. Re-enable eligible connections (primary to 'active', standby to 'standby').
        4. Re-sync NetworkX graph and verify active edges exist.
        5. Update device_isolation_logs record.
        
        Args:
            device_id: Numeric device identifier.
            reason: Restoration justification.
            
        Returns:
            Dict[str, Any]: Restoration result summary.
        """
        device = DeviceService.get_device_by_id(device_id)
        if not device:
            raise NotFoundError(f"Device with ID {device_id} not found in inventory.")

        dev_name = device['device_name']

        with get_db() as conn:
            cursor = conn.cursor()

            # 1. Set status to 'online' and reset operational counters
            cursor.execute("""
                UPDATE devices
                SET status = 'online',
                    packet_loss = '0.00%',
                    last_active = 'Just now',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?;
            """, (device_id,))

            # 2. Re-enable connections (primary to 'active', standby links 4 and 7 to 'standby')
            cursor.execute("""
                UPDATE network_connections
                SET status = 'active'
                WHERE (source_device_id = ? OR target_device_id = ?)
                  AND id NOT IN (4, 7);
            """, (device_id, device_id))

            cursor.execute("""
                UPDATE network_connections
                SET status = 'standby'
                WHERE (source_device_id = ? OR target_device_id = ?)
                  AND id IN (4, 7);
            """, (device_id, device_id))

            # 3. Update device_isolation_logs if this device was currently isolated
            cursor.execute("""
                UPDATE device_isolation_logs
                SET status = 'RESTORED', restored_at = CURRENT_TIMESTAMP
                WHERE device_id = ? AND status = 'ISOLATED';
            """, (device_id,))

            # Query updated connections
            cursor.execute("""
                SELECT id, source_device_id, target_device_id, bandwidth, status
                FROM network_connections
                WHERE source_device_id = ? OR target_device_id = ?;
            """, (device_id, device_id))
            conns = [dict(c) for c in cursor.fetchall()]

        # Re-sync NetworkX graph
        simulator = NetworkSimulator()
        simulator.sync_graph_from_db()

        # Graph connectivity verification
        graph = simulator.graph
        has_active_link = False
        if graph.has_node(device_id):
            for neighbor in graph.neighbors(device_id):
                edge_data = graph.get_edge_data(device_id, neighbor)
                if edge_data and edge_data.get('status') == 'active':
                    has_active_link = True
                    break

        if not has_active_link:
            logger.error(f"[RESTORE ERROR] Graph verification failed for device {device_id}: No active edges.")
            raise ValidationError(f"Restoration verification failed: Device {device_id} has no active graph edges.")

        logger.info(f"[AUDIT] Device restored: ID {device_id} ({dev_name}) - Connectivity verified. Reason: {reason}")

        updated_device = DeviceService.get_device_by_id(device_id)
        return {
            'success': True,
            'restored': True,
            'verified': True,
            'device_id': device_id,
            'device_name': dev_name,
            'status': 'online',
            'restored_at': datetime.utcnow().isoformat() + 'Z',
            'restoration_reason': reason,
            'connections': conns,
            'device': updated_device
        }

    @classmethod
    def get_isolated_devices(cls) -> List[Dict[str, Any]]:
        """Retrieve list of all currently isolated simulated devices."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT d.id, d.device_name, d.ip_address, d.device_type, d.role,
                       d.status, l.isolation_id, l.isolation_reason, l.isolated_at
                FROM devices d
                JOIN device_isolation_logs l ON d.id = l.device_id
                WHERE d.status = 'suspicious' AND l.status = 'ISOLATED'
                ORDER BY l.id DESC;
            """)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    @classmethod
    def get_isolation_history(cls, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch historical device isolation log events."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, isolation_id, device_id, device_name, device_ip,
                       isolation_reason, isolation_trigger, status,
                       affected_connections_count, critical_service_check_passed,
                       isolated_at, restored_at
                FROM device_isolation_logs
                ORDER BY id DESC LIMIT ?;
            """, (max(1, min(limit, 200)),))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
