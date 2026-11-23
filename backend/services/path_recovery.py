"""
NetGuardian AI - Graph-Based Network Path Recovery Service (Module 3)
Tagline: Detect. Defend. Recover. Automatically.

Analyzes the NetworkX network topology graph and computes dynamic failover paths:
- Identifies failed connections and isolated nodes.
- Computes shortest available alternative paths using NetworkX Dijkstra / BFS.
- Validates candidate paths against failed links and isolated devices.
- Applies simulated rerouting by engaging standby/backup mesh connections.
- Persists all route transitions to network_route_changes.
- Honest failure reporting: If no redundant alternative path exists, reports failure clearly.
"""

from __future__ import annotations
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union

import networkx as nx
from database import get_db
from services.device_service import DeviceService, NotFoundError, ValidationError
from services.network_simulator import NetworkSimulator

logger = logging.getLogger('netguardian.healing.path_recovery')


class PathRecoveryService:
    """
    Self-Healing Module 3: Graph-Based Path Recovery Engine.
    Leverages NetworkX to find, validate, and apply alternative bypass routing.
    """

    @classmethod
    def _generate_change_id(cls) -> str:
        """Generate human-readable route change identifier (e.g. RTE-1001)."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(id) AS max_id FROM network_route_changes;")
            row = cursor.fetchone()
            next_num = (row['max_id'] or 1000) + 1
        return f"RTE-{next_num}"

    @classmethod
    def get_routable_subgraph(
        cls,
        avoid_node_ids: Optional[List[int]] = None,
        avoid_edge_ids: Optional[List[int]] = None
    ) -> nx.Graph:
        """
        Build a routable NetworkX subgraph excluding severed links and offline/isolated nodes.
        
        Args:
            avoid_node_ids: Devices that cannot be traversed (e.g. failed/quarantined node).
            avoid_edge_ids: Specific connection IDs that are down.
            
        Returns:
            nx.Graph: Filtered routable topology.
        """
        avoid_nodes = set(avoid_node_ids or [])
        avoid_edges = set(avoid_edge_ids or [])

        subgraph = nx.Graph()

        with get_db() as conn:
            cursor = conn.cursor()

            # 1. Fetch devices and their statuses
            cursor.execute("SELECT id, device_name, ip_address, status FROM devices;")
            devices = cursor.fetchall()
            for d in devices:
                dev_id = d['id']
                st = d['status']
                # Disallow explicit avoid list, offline nodes, and quarantined (suspicious) nodes
                if dev_id in avoid_nodes or st in ('offline', 'suspicious'):
                    continue
                subgraph.add_node(dev_id, name=d['device_name'], ip=d['ip_address'], status=st)

            # 2. Fetch connection links (active and standby failover links)
            cursor.execute("""
                SELECT id, source_device_id, target_device_id, bandwidth, status
                FROM network_connections;
            """)
            links = cursor.fetchall()
            for l in links:
                edge_id = l['id']
                u = l['source_device_id']
                v = l['target_device_id']
                l_status = l['status']

                # Disallow explicitly severed links or inactive links
                if edge_id in avoid_edges or l_status == 'inactive':
                    continue

                # Both endpoints must exist in routable node set
                if subgraph.has_node(u) and subgraph.has_node(v):
                    # Weight: active links have weight 1.0, standby failover links have weight 1.5
                    w = 1.0 if l_status == 'active' else 1.5
                    subgraph.add_edge(u, v, id=edge_id, bandwidth=l['bandwidth'], status=l_status, weight=w)

        return subgraph

    @classmethod
    def calculate_alternative_path(
        cls,
        source_id: int,
        target_id: int,
        failed_device_id: Optional[int] = None,
        failed_connection_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Calculate shortest available alternative path between source and target nodes.
        
        Returns:
            Dict[str, Any]: Path metadata including hops, route string, node list, and viability.
        """
        avoid_nodes = [failed_device_id] if failed_device_id else []
        avoid_edges = [failed_connection_id] if failed_connection_id else []

        subgraph = cls.get_routable_subgraph(avoid_node_ids=avoid_nodes, avoid_edge_ids=avoid_edges)

        # Source and target endpoints must exist
        if not subgraph.has_node(source_id):
            return {
                'success': False,
                'viable': False,
                'error': f"Source node ID {source_id} is offline or unreachable in topology graph.",
                'alternative_route': None
            }

        if not subgraph.has_node(target_id):
            return {
                'success': False,
                'viable': False,
                'error': f"Target node ID {target_id} is offline or unreachable in topology graph.",
                'alternative_route': None
            }

        try:
            path_ids = nx.shortest_path(subgraph, source=source_id, target=target_id, weight='weight')
            
            # Fetch node details
            path_nodes = []
            with get_db() as conn:
                cursor = conn.cursor()
                for nid in path_ids:
                    cursor.execute("SELECT id, device_name, ip_address FROM devices WHERE id = ?;", (nid,))
                    row = cursor.fetchone()
                    if row:
                        path_nodes.append({
                            'id': row['id'],
                            'name': row['device_name'],
                            'ip': row['ip_address']
                        })

            route_str = " -> ".join([n['name'] for n in path_nodes])
            path_names = [n['name'] for n in path_nodes]

            return {
                'success': True,
                'viable': True,
                'source_id': source_id,
                'target_id': target_id,
                'path_ids': path_ids,
                'path': path_names,
                'path_nodes': path_nodes,
                'hops': len(path_ids) - 1,
                'route_str': route_str,
                'latency_estimate_ms': round((len(path_ids) - 1) * 0.8 + 0.4, 2)
            }
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            logger.warning(f"No alternative path exists between node {source_id} and {target_id} avoiding {failed_device_id}.")
            return {
                'success': False,
                'viable': False,
                'error': f"No alternative route exists in current topology mesh between {source_id} and {target_id}.",
                'alternative_route': None
            }

    @classmethod
    def find_alternative_route_for_device(cls, device_id: int) -> Dict[str, Any]:
        """
        Determine if a device experiencing a fault or isolation can be recovered
        or reached via an alternative route.
        
        Logic:
        - If device is Server 01, 02, or 03 (HES/MDMS/Backup), evaluate failover path from Gateway (ID 1)
          to the active backup/partner server avoiding the degraded node.
        - If device is a smart meter or field endpoint with single-point uplink, report no alternative path.
        """
        device = DeviceService.get_device_by_id(device_id)
        if not device:
            raise NotFoundError(f"Device ID {device_id} not found.")

        dev_type = device['device_type']

        # Single-Point-of-Failure check:
        # Field Smart Meters (5-9) connect exclusively to Smart Meter Gateway (1). If that link is severed, no star bypass exists.
        if dev_type in ('Smart Meter', 'Computer') or device_id in (5, 6, 7, 8, 9):
            logger.info(f"Device {device['device_name']} (ID {device_id}) is a star leaf endpoint. No redundant alternative route exists.")
            return {
                'success': False,
                'viable': False,
                'device_id': device_id,
                'device_name': device['device_name'],
                'is_single_point_of_failure': True,
                'error': f"No alternative route exists for {device['device_name']}. Single uplink to Gateway. Manual link servicing required.",
                'alternative_route': None
            }

        # Core Gateway (ID 1) has no alternate parent gateway
        if device_id == 1:
            return {
                'success': False,
                'viable': False,
                'device_id': 1,
                'device_name': device['device_name'],
                'is_single_point_of_failure': True,
                'error': "Core Smart Meter Gateway is the primary network ingress. No upstream bypass route exists.",
                'alternative_route': None
            }

        # Core Servers (2: HES, 3: MDMS, 4: Backup HES/MDMS)
        # Attempt failover to Server 04 (Backup) or alternate partner
        partner_id = 4 if device_id != 4 else 2
        path_result = cls.calculate_alternative_path(
            source_id=1,
            target_id=partner_id,
            failed_device_id=device_id
        )

        path_result['device_id'] = device_id
        path_result['device_name'] = device['device_name']
        path_result['backup_target_id'] = partner_id
        return path_result

    @classmethod
    def apply_route_recovery(
        cls,
        device_id: int,
        path_result: Dict[str, Any],
        recovery_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Engage and apply the alternative route in the simulated network topology:
        1. Activates the failover connection links in SQLite.
        2. Logs the transition in network_route_changes.
        3. Synchronizes NetworkX graph.
        
        Args:
            device_id: Recovered device ID.
            path_result: Result from calculate_alternative_path or find_alternative_route_for_device.
            recovery_code: Associated recovery log identifier.
            
        Returns:
            Dict[str, Any]: Applied route change details.
        """
        if not path_result.get('viable') or not path_result.get('path_ids'):
            raise ValidationError("Cannot apply an unviable or non-existent alternative path.")

        path_ids = path_result['path_ids']
        route_str = path_result.get('route_str') or " -> ".join(path_result.get('path', []))
        change_id = cls._generate_change_id()
        backup_id = path_result.get('backup_target_id') or path_ids[-1]

        with get_db() as conn:
            cursor = conn.cursor()

            # 1. Activate failover links between Router (1) and Backup / Core Servers
            cursor.execute("""
                UPDATE network_connections
                SET status = 'active'
                WHERE (source_device_id = ? AND target_device_id = ?)
                   OR (source_device_id = ? AND target_device_id = ?);
            """, (device_id, backup_id, backup_id, device_id))

            cursor.execute("""
                UPDATE network_connections
                SET status = 'active'
                WHERE (source_device_id = 1 AND target_device_id = ?)
                   OR (source_device_id = ? AND target_device_id = 1);
            """, (backup_id, backup_id))

            # 2. Record route change in network_route_changes
            cursor.execute("""
                INSERT INTO network_route_changes (
                    change_id, device_id, recovery_code, source_device_id,
                    target_device_id, original_path, alternative_path, path_hops, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE');
            """, (
                change_id, device_id, recovery_code, path_ids[0], path_ids[-1],
                f"Direct Link to Device {device_id}", route_str, len(path_ids) - 1
            ))
            new_change_id = cursor.lastrowid

        # Re-synchronize NetworkX graph
        simulator = NetworkSimulator()
        simulator.sync_graph_from_db()

        logger.info(f"[ROUTE ENGAGED] Change ID: {change_id} - Route [{route_str}] activated for device {device_id}.")

        return {
            'success': True,
            'change_id': change_id,
            'device_id': device_id,
            'recovery_code': recovery_code,
            'route_str': route_str,
            'path_ids': path_ids,
            'hops': len(path_ids) - 1,
            'engaged_at': datetime.utcnow().isoformat() + 'Z'
        }

    @classmethod
    def get_route_changes_history(cls, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch historical route change log entries."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT c.id, c.change_id, c.device_id, d.device_name, c.recovery_code,
                       c.source_device_id, c.target_device_id, c.original_path,
                       c.alternative_path, c.path_hops, c.status, c.created_at
                FROM network_route_changes c
                LEFT JOIN devices d ON c.device_id = d.id
                ORDER BY c.id DESC LIMIT ?;
            """, (max(1, min(limit, 200)),))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
