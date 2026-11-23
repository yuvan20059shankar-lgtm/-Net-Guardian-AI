"""
NetGuardian AI - Network Simulation Engine
Simulates local computer networking dynamics:
- Network topology graph using NetworkX
- Bounded time-varying traffic telemetry (bandwidth, packets, loss, latency, CPU, RAM)
- Thread-safe background simulation with synchronization and duplicate prevention
- Failure injection, link severance, restoration, and graph pathfinding
"""

import time
import math
import random
import logging
import threading
from typing import Optional, Dict, Any, List, Tuple
import networkx as nx
from database import get_db, INITIAL_CONNECTIONS

logger = logging.getLogger('netguardian.simulator')


class NetworkSimulator:
    """
    Central Network Simulation Engine for NetGuardian AI.
    Runs a thread-safe local network simulation over NetworkX graph topology.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """Thread-safe singleton pattern."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(NetworkSimulator, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        
        self.graph = nx.Graph()
        self.is_running = False
        self._thread = None
        self._stop_event = threading.Event()
        self._sim_lock = threading.Lock()
        self._step_counter = 0

        # Base nominal traffic baselines per device ID (in Mbps)
        self.device_baselines = {
            1: {'in': 450.0, 'out': 430.0, 'cpu': 38.0, 'mem': 44.0, 'loss': 0.00, 'latency': 0.8},   # Router 01
            2: {'in': 285.0, 'out': 260.0, 'cpu': 52.0, 'mem': 68.0, 'loss': 0.00, 'latency': 1.1},   # Server 01
            3: {'in': 145.0, 'out': 130.0, 'cpu': 41.0, 'mem': 56.0, 'loss': 0.00, 'latency': 1.2},   # Server 02
            4: {'in': 310.0, 'out': 295.0, 'cpu': 58.0, 'mem': 62.0, 'loss': 0.00, 'latency': 1.4},   # Server 03
            5: {'in': 14.0,  'out': 8.5,   'cpu': 22.0, 'mem': 48.0, 'loss': 0.00, 'latency': 2.1},   # PC 01
            6: {'in': 28.0,  'out': 18.0,  'cpu': 35.0, 'mem': 55.0, 'loss': 0.00, 'latency': 2.4},   # PC 02
            7: {'in': 98.0,  'out': 140.0, 'cpu': 74.0, 'mem': 81.0, 'loss': 1.20, 'latency': 14.5},  # PC 03 (Suspicious)
            8: {'in': 22.0,  'out': 16.0,  'cpu': 29.0, 'mem': 50.0, 'loss': 0.00, 'latency': 1.9},   # PC 04
            9: {'in': 0.0,   'out': 0.0,   'cpu': 0.0,  'mem': 0.0,  'loss': 100.0, 'latency': 0.0},  # PC 05 (Offline)
            10: {'in': 610.0,'out': 585.0, 'cpu': 46.0, 'mem': 58.0, 'loss': 0.00, 'latency': 0.5}   # Firewall 01
        }

        self.sync_graph_from_db()
        self._initialized = True
        logger.info("NetworkSimulator initialized successfully.")

    # --------------------------------------------------------------------------
    # 1. NETWORKX TOPOLOGY GRAPH SYNCHRONIZATION
    # --------------------------------------------------------------------------

    def sync_graph_from_db(self):
        """Build and synchronize the NetworkX graph with current SQLite state."""
        with self._sim_lock:
            self.graph.clear()
            with get_db() as conn:
                cursor = conn.cursor()
                # Load all nodes
                cursor.execute("SELECT id, device_name, ip_address, device_type, role, status FROM devices;")
                devices = cursor.fetchall()
                for dev in devices:
                    self.graph.add_node(
                        dev['id'],
                        name=dev['device_name'],
                        ip=dev['ip_address'],
                        type=dev['device_type'],
                        role=dev['role'],
                        status=dev['status']
                    )

                # Load all links
                cursor.execute("""
                    SELECT id, source_device_id, target_device_id, bandwidth, status
                    FROM network_connections;
                """)
                links = cursor.fetchall()
                for link in links:
                    self.graph.add_edge(
                        link['source_device_id'],
                        link['target_device_id'],
                        id=link['id'],
                        bandwidth=link['bandwidth'],
                        status=link['status']
                    )

        logger.debug(f"NetworkX graph synced: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges.")

    def get_topology(self):
        """
        Return the logical network topology containing nodes and active/standby links.
        
        Returns:
            dict: Topology nodes and connection links.
        """
        self.sync_graph_from_db()
        nodes = []
        links = []

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, device_name, ip_address, device_type, role, status FROM devices ORDER BY id ASC;")
            for r in cursor.fetchall():
                nodes.append({
                    'id': r['id'],
                    'name': r['device_name'],
                    'ip': r['ip_address'],
                    'type': r['device_type'],
                    'role': r['role'],
                    'status': r['status']
                })

            cursor.execute("""
                SELECT c.id, c.source_device_id, c.target_device_id, c.bandwidth, c.status,
                       s.device_name AS source_name, s.ip_address AS source_ip,
                       t.device_name AS target_name, t.ip_address AS target_ip
                FROM network_connections c
                JOIN devices s ON c.source_device_id = s.id
                JOIN devices t ON c.target_device_id = t.id
                ORDER BY c.id ASC;
            """)
            for r in cursor.fetchall():
                links.append({
                    'id': r['id'],
                    'source': r['source_device_id'],
                    'target': r['target_device_id'],
                    'source_name': r['source_name'],
                    'source_ip': r['source_ip'],
                    'target_name': r['target_name'],
                    'target_ip': r['target_ip'],
                    'bandwidth': r['bandwidth'],
                    'status': r['status']
                })

        return {'nodes': nodes, 'connections': links}

    def get_connected_devices(self, device_id):
        """
        Retrieve all devices directly connected to a given device ID.
        
        Returns:
            list[dict]: Directly connected neighbor assets with link bandwidth and status.
        """
        self.sync_graph_from_db()
        neighbors = []
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT c.id AS connection_id, c.bandwidth, c.status AS link_status,
                       CASE WHEN c.source_device_id = ? THEN c.target_device_id ELSE c.source_device_id END AS neighbor_id
                FROM network_connections c
                WHERE c.source_device_id = ? OR c.target_device_id = ?;
            """, (device_id, device_id, device_id))
            links = cursor.fetchall()

            for link in links:
                n_id = link['neighbor_id']
                cursor.execute("SELECT id, device_name, ip_address, device_type, role, status FROM devices WHERE id = ?;", (n_id,))
                dev = cursor.fetchone()
                if dev:
                    neighbors.append({
                        'connection_id': link['connection_id'],
                        'device_id': dev['id'],
                        'device_name': dev['device_name'],
                        'ip_address': dev['ip_address'],
                        'device_type': dev['device_type'],
                        'role': dev['role'],
                        'device_status': dev['status'],
                        'bandwidth': link['bandwidth'],
                        'link_status': link['link_status']
                    })
        return neighbors

    # --------------------------------------------------------------------------
    # 2. PATHFINDING & ROUTING CALCULATIONS (NETWORKX)
    # --------------------------------------------------------------------------

    def calculate_path(self, source_id, target_id, avoid_node_id=None):
        """
        Calculate an active routing path between two network nodes using Dijkstra / BFS.
        Ensures failed nodes and inactive connections are bypassed.
        Returns None if no alternative path exists.
        """
        self.sync_graph_from_db()

        # Build routable subgraph: only active or standby links and non-offline devices
        active_subgraph = nx.Graph()
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, status FROM devices;")
            device_status = {r['id']: r['status'] for r in cursor.fetchall()}

            cursor.execute("SELECT source_device_id, target_device_id, status FROM network_connections;")
            for link in cursor.fetchall():
                u = link['source_device_id']
                v = link['target_device_id']
                l_status = link['status']

                # Disallow severed links
                if l_status == 'inactive':
                    continue

                # Disallow avoided/offline nodes
                if avoid_node_id and (u == avoid_node_id or v == avoid_node_id):
                    continue

                if device_status.get(u) == 'offline' or device_status.get(v) == 'offline':
                    continue

                active_subgraph.add_edge(u, v)

        if not active_subgraph.has_node(source_id) or not active_subgraph.has_node(target_id):
            return None

        try:
            path_ids = nx.shortest_path(active_subgraph, source=source_id, target=target_id)
            # Hydrate path with device details
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
            return {
                'path_ids': path_ids,
                'path_nodes': path_nodes,
                'hops': len(path_ids) - 1,
                'viable': True
            }
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            logger.warning(f"No alternative path between node {source_id} and {target_id} bypassing {avoid_node_id}.")
            return None

    # --------------------------------------------------------------------------
    # 3. FAILURE INJECTION & RESTORATION
    # --------------------------------------------------------------------------

    def simulate_device_failure(self, device_id):
        """
        Simulate sudden hardware fault or link severance on a device.
        - Marks device status = 'offline'
        - Sets related network_connections to 'inactive'
        - Zeroes out throughput and records 100% packet loss
        """
        with self._sim_lock:
            with get_db() as conn:
                cursor = conn.cursor()
                # 1. Update device status
                cursor.execute("""
                    UPDATE devices
                    SET status = 'offline',
                        traffic_in = '0.0 Mbps',
                        traffic_out = '0.0 Mbps',
                        packet_loss = '100%',
                        cpu_usage = 0.0,
                        memory_usage = 0.0,
                        last_active = 'Failure Simulated',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?;
                """, (device_id,))

                # 2. Sever all connected links
                cursor.execute("""
                    UPDATE network_connections
                    SET status = 'inactive'
                    WHERE source_device_id = ? OR target_device_id = ?;
                """, (device_id, device_id))

                # 3. Log event in traffic_logs
                cursor.execute("""
                    INSERT INTO traffic_logs (
                        device_id, traffic_in, traffic_out, packets_sent,
                        packets_received, packet_loss, latency, cpu_usage, memory_usage
                    ) VALUES (?, 0.0, 0.0, 0, 0, 100.0, 0.0, 0.0, 0.0);
                """, (device_id,))

        self.sync_graph_from_db()
        logger.warning(f"Simulated failure on device ID {device_id}. Links severed.")

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE id = ?;", (device_id,))
            dev = cursor.fetchone()
            cursor.execute("SELECT id, source_device_id, target_device_id, status FROM network_connections WHERE source_device_id = ? OR target_device_id = ?;", (device_id, device_id))
            links = cursor.fetchall()

        return {
            'device_id': device_id,
            'device_name': dev['device_name'] if dev else 'Unknown',
            'status': 'offline',
            'affected_connections': [dict(l) for l in links]
        }

    def restore_device(self, device_id):
        """
        Restore a previously failed device back to operational online baseline.
        - Updates status = 'online'
        - Re-enables primary links to 'active' (and redundant links to 'standby')
        """
        with self._sim_lock:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE devices
                    SET status = 'online',
                        packet_loss = '0.00%',
                        last_active = 'Just now',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?;
                """, (device_id,))

                # Re-activate non-redundant links
                cursor.execute("""
                    UPDATE network_connections
                    SET status = 'active'
                    WHERE (source_device_id = ? OR target_device_id = ?)
                      AND id NOT IN (4, 7);
                """, (device_id, device_id))

                # Keep designated failover links in standby
                cursor.execute("""
                    UPDATE network_connections
                    SET status = 'standby'
                    WHERE (source_device_id = ? OR target_device_id = ?)
                      AND id IN (4, 7);
                """, (device_id, device_id))

        self.sync_graph_from_db()
        logger.info(f"Restored device ID {device_id} to operational state.")

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE id = ?;", (device_id,))
            dev = cursor.fetchone()

        return {
            'device_id': device_id,
            'device_name': dev['device_name'] if dev else 'Unknown',
            'status': 'online'
        }

    # --------------------------------------------------------------------------
    # 4. SIMULATION-TO-AI TELEMETRY GENERATION (Prompt 5 Integration)
    # --------------------------------------------------------------------------

    def generate_simulated_telemetry_for_ai(
        self,
        device_id: int,
        threat_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate a fully formed network traffic telemetry dictionary conforming
        to the AI Feature Engineering schema.
        
        Args:
            device_id: Numeric device ID (1-10)
            threat_type: Optional anomaly injection type ('DoS', 'Exfiltration', 'Scan', 'Outbound')
            
        Returns:
            Dict[str, Any]: Telemetry dictionary ready for AIPipelineService.
        """
        base = self.device_baselines.get(device_id, {'in': 25.0, 'out': 20.0, 'cpu': 30.0, 'mem': 45.0})

        if threat_type in ('DoS', 'DoS-like Traffic Spike', 'Denial of Service (DoS) - like traffic spikes'):
            return {
                'device_id': device_id,
                'packet_count': 14000,
                'average_packet_size': 45.0,
                'bytes_transferred': 630000,
                'connection_frequency': 310.0,
                'packet_entropy': 3.1,
                'inbound_bytes': 610000,
                'outbound_bytes': 20000,
                'connection_duration': 0.5
            }
        elif threat_type in ('Exfiltration', 'Potential Data Exfiltration'):
            return {
                'device_id': device_id,
                'packet_count': 2200,
                'average_packet_size': 1350.0,
                'bytes_transferred': 2970000,
                'connection_frequency': 35.0,
                'packet_entropy': 7.6,
                'inbound_bytes': 120000,
                'outbound_bytes': 2850000,
                'connection_duration': 25.0
            }
        elif threat_type in ('Scan', 'Port Scanning'):
            return {
                'device_id': device_id,
                'packet_count': 1500,
                'average_packet_size': 72.0,
                'bytes_transferred': 108000,
                'connection_frequency': 160.0,
                'packet_entropy': 4.1,
                'inbound_bytes': 18000,
                'outbound_bytes': 90000,
                'connection_duration': 5.0
            }
        elif threat_type in ('Outbound', 'Suspicious Outbound Traffic'):
            return {
                'device_id': device_id,
                'packet_count': 1900,
                'average_packet_size': 1100.0,
                'bytes_transferred': 2090000,
                'connection_frequency': 25.0,
                'packet_entropy': 6.2,
                'inbound_bytes': 100000,
                'outbound_bytes': 1990000,
                'connection_duration': 22.0
            }

        # Nominal traffic based on device baseline
        in_mb = max(2.0, base.get('in', 20.0))
        out_mb = max(2.0, base.get('out', 15.0))
        pkts = int(120 * (in_mb + out_mb) / 2)
        total_bytes = int((in_mb + out_mb) * 12500)

        return {
            'device_id': device_id,
            'packet_count': pkts,
            'average_packet_size': 512.0,
            'bytes_transferred': total_bytes,
            'connection_frequency': 16.0,
            'packet_entropy': 4.6,
            'inbound_bytes': int(in_mb * 12500),
            'outbound_bytes': int(out_mb * 12500),
            'connection_duration': 20.0
        }

    # --------------------------------------------------------------------------
    # 5. TELEMETRY GENERATION & BACKGROUND THREAD
    # --------------------------------------------------------------------------

    def _generate_telemetry_tick(self):
        """Generate one iteration of realistic time-varying bounded network telemetry."""
        self._step_counter += 1
        t = self._step_counter

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, device_name, status FROM devices;")
            devices = cursor.fetchall()

            for dev in devices:
                dev_id = dev['id']
                dev_status = dev['status']

                if dev_status == 'offline':
                    # Offline node produces 0 traffic and 100% loss
                    t_in = 0.0
                    t_out = 0.0
                    pkts_tx = 0
                    pkts_rx = 0
                    p_loss = 100.0
                    rtt = 0.0
                    cpu = 0.0
                    mem = 0.0
                elif dev_status == 'suspicious':
                    # Suspicious node has elevated egress and anomaly spikes
                    base = self.device_baselines.get(dev_id, {'in': 50.0, 'out': 100.0, 'cpu': 60.0, 'mem': 70.0})
                    t_in = round(base['in'] + 15.0 * math.sin(t * 0.4) + random.uniform(-5.0, 5.0), 1)
                    t_out = round(base['out'] + 35.0 * math.cos(t * 0.3) + random.uniform(5.0, 25.0), 1)
                    pkts_tx = int(t_out * 125 + random.randint(100, 500))
                    pkts_rx = int(t_in * 120 + random.randint(50, 200))
                    p_loss = round(random.uniform(1.0, 3.5), 2)
                    rtt = round(15.0 + random.uniform(2.0, 15.0), 1)
                    cpu = round(min(98.0, base['cpu'] + random.uniform(5.0, 20.0)), 1)
                    mem = round(min(95.0, base['mem'] + random.uniform(2.0, 10.0)), 1)
                else:
                    # Healthy online node follows bounded cyclical workload
                    base = self.device_baselines.get(dev_id, {'in': 20.0, 'out': 15.0, 'cpu': 30.0, 'mem': 45.0})
                    # Sinusoidal variance with random jitter (bounded within ±12%)
                    variation = math.sin(t * 0.2 + dev_id) * 0.12
                    jitter = random.uniform(-0.04, 0.04)
                    factor = 1.0 + variation + jitter

                    t_in = round(max(1.0, base['in'] * factor), 1)
                    t_out = round(max(1.0, base['out'] * factor), 1)
                    pkts_tx = int(t_out * 120 + random.randint(10, 50))
                    pkts_rx = int(t_in * 120 + random.randint(10, 50))
                    p_loss = 0.00 if random.random() > 0.15 else 0.01
                    rtt = round(max(0.4, base.get('latency', 1.0) * factor), 1)
                    cpu = round(max(5.0, min(95.0, base['cpu'] * (1.0 + variation * 0.5))), 1)
                    mem = round(max(10.0, min(92.0, base['mem'] * (1.0 + variation * 0.2))), 1)

                # 1. Update devices table with current telemetry
                cursor.execute("""
                    UPDATE devices
                    SET traffic_in = ?,
                        traffic_out = ?,
                        cpu_usage = ?,
                        memory_usage = ?,
                        packet_loss = ?,
                        last_active = 'Just now',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?;
                """, (
                    f"{t_in} Mbps",
                    f"{t_out} Mbps",
                    cpu,
                    mem,
                    f"{p_loss:.2f}%",
                    dev_id
                ))

                # 2. Append to traffic_logs table
                cursor.execute("""
                    INSERT INTO traffic_logs (
                        device_id, traffic_in, traffic_out, packets_sent,
                        packets_received, packet_loss, latency, cpu_usage, memory_usage
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    dev_id, t_in, t_out, pkts_tx, pkts_rx, p_loss, rtt, cpu, mem
                ))

            # Maintain maximum log buffer size to keep SQLite lean (retain last 600 records)
            cursor.execute("""
                DELETE FROM traffic_logs
                WHERE id NOT IN (
                    SELECT id FROM traffic_logs ORDER BY id DESC LIMIT 600
                );
            """)

    def _simulation_worker(self):
        """Worker loop executed inside the background thread."""
        logger.info("Network simulation background worker loop started.")
        while not self._stop_event.is_set():
            try:
                self._generate_telemetry_tick()
            except Exception as e:
                logger.error(f"Error during simulation telemetry tick: {e}", exc_info=True)
            self._stop_event.wait(2.5)
        logger.info("Network simulation background worker loop stopped cleanly.")

    def start_simulation(self):
        """
        Start the background simulation thread.
        Thread-safe: Prevents launching duplicate simulation threads.
        """
        with self._sim_lock:
            if self.is_running:
                logger.warning("Simulation thread is already running.")
                return False, "Simulation is already active."

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._simulation_worker,
                name="NetGuardian-SimulatorThread",
                daemon=True
            )
            self._thread.start()
            self.is_running = True
            logger.info("Started network simulation thread.")
            return True, "Network simulation engine started successfully."

    def stop_simulation(self):
        """Stop the background simulation thread gracefully."""
        with self._sim_lock:
            if not self.is_running:
                return False, "Simulation is not currently running."

            self._stop_event.set()
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=3.0)
            self.is_running = False
            self._thread = None
            logger.info("Stopped network simulation thread.")
            return True, "Network simulation engine stopped cleanly."

    # --------------------------------------------------------------------------
    # 5. TELEMETRY & NETWORK SUMMARY QUERIES
    # --------------------------------------------------------------------------

    def get_recent_traffic(self, limit=50):
        """Fetch latest traffic log records from SQLite."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT t.id, t.device_id, d.device_name, d.ip_address,
                       t.traffic_in, t.traffic_out, t.packets_sent, t.packets_received,
                       t.packet_loss, t.latency, t.cpu_usage, t.memory_usage, t.timestamp
                FROM traffic_logs t
                JOIN devices d ON t.device_id = d.id
                ORDER BY t.id DESC
                LIMIT ?;
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_device_traffic_history(self, device_id, limit=30):
        """Fetch traffic history logs for a specific device."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, device_id, traffic_in, traffic_out, packets_sent,
                       packets_received, packet_loss, latency, cpu_usage, memory_usage, timestamp
                FROM traffic_logs
                WHERE device_id = ?
                ORDER BY id DESC
                LIMIT ?;
            """, (device_id, limit))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_network_summary(self):
        """
        Aggregate high-level networking summary:
        - total devices, active devices, offline devices
        - active connections, failed connections
        - total incoming traffic, total outgoing traffic
        """
        with get_db() as conn:
            cursor = conn.cursor()
            # Devices summary
            cursor.execute("""
                SELECT
                    COUNT(*) AS total_devices,
                    SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) AS active_devices,
                    SUM(CASE WHEN status = 'offline' THEN 1 ELSE 0 END) AS offline_devices
                FROM devices;
            """)
            d_row = cursor.fetchone()

            # Connections summary
            cursor.execute("""
                SELECT
                    SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active_connections,
                    SUM(CASE WHEN status = 'inactive' THEN 1 ELSE 0 END) AS failed_connections
                FROM network_connections;
            """)
            c_row = cursor.fetchone()

            # Current aggregated traffic
            cursor.execute("SELECT traffic_in, traffic_out, status FROM devices;")
            dev_rows = cursor.fetchall()

            total_in = 0.0
            total_out = 0.0
            for r in dev_rows:
                if r['status'] != 'offline':
                    try:
                        total_in += float(r['traffic_in'].replace(' Mbps', ''))
                        total_out += float(r['traffic_out'].replace(' Mbps', ''))
                    except (ValueError, AttributeError):
                        pass

        return {
            'total_devices': d_row['total_devices'] if d_row else 0,
            'active_devices': d_row['active_devices'] if d_row else 0,
            'offline_devices': d_row['offline_devices'] if d_row else 0,
            'active_connections': c_row['active_connections'] if c_row and c_row['active_connections'] else 0,
            'failed_connections': c_row['failed_connections'] if c_row and c_row['failed_connections'] else 0,
            'total_incoming_traffic': f"{round(total_in, 1)} Mbps",
            'total_outgoing_traffic': f"{round(total_out, 1)} Mbps"
        }
