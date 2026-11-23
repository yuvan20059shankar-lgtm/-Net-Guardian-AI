"""
NetGuardian AI - Network Simulation Engine & Traffic Monitoring Test Suite (Prompt 7)
Covers all 16 required test scenarios:
1. Network simulation service initializes correctly.
2. NetworkX graph is created with 10 nodes.
3. Connections match the network topology table.
4. Telemetry values are generated within defined ranges.
5. Telemetry values change between simulation cycles.
6. Device failure simulation updates device status to offline.
7. Device failure removes active paths through that node.
8. Device restoration returns status to online.
9. Traffic generation pauses when simulation stops.
10. Traffic generation resumes when simulation starts.
11. GET /api/traffic returns recent traffic logs.
12. GET /api/traffic/<device_id> returns logs for that device.
13. GET /api/topology returns nodes and links.
14. GET /api/network/summary returns network aggregates.
15. GET /api/network/connected/<device_id> returns adjacent devices.
16. POST /api/simulation/failure and restore update graph and database.
"""

import os
import sys
import time
import json
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app import create_app
from config import TestingConfig
from database import get_db, init_database, INITIAL_CONNECTIONS
from services.network_simulator import NetworkSimulator


class NetworkSimulationTestCase(unittest.TestCase):
    """Test suite covering the 16 required test scenarios for Prompt 7."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment and initialize a clean test database."""
        cls.test_db_path = TestingConfig.DATABASE_PATH
        if os.path.exists(cls.test_db_path):
            try:
                os.remove(cls.test_db_path)
            except OSError:
                pass

        cls.app = create_app(TestingConfig)
        cls.client = cls.app.test_client()

        with cls.app.app_context():
            init_database()

    @classmethod
    def tearDownClass(cls):
        """Stop simulator background thread if running and clean up test database."""
        simulator = NetworkSimulator()
        simulator.stop_simulation()
        if os.path.exists(cls.test_db_path):
            try:
                os.remove(cls.test_db_path)
            except OSError:
                pass

    def setUp(self):
        """Ensure clean state and synced graph before each test."""
        self.simulator = NetworkSimulator()
        with self.app.app_context():
            self.simulator.sync_graph_from_db()

    def tearDown(self):
        """Ensure simulation loop is paused after tests."""
        if self.simulator.is_running:
            self.simulator.stop_simulation()

    # --------------------------------------------------------------------------
    # TEST 1: Network simulation service initializes correctly
    # --------------------------------------------------------------------------
    def test_01_simulator_initializes_correctly(self):
        """1. Network simulation service initializes correctly."""
        self.assertIsNotNone(self.simulator)
        self.assertIsNotNone(self.simulator.graph)
        self.assertIsInstance(self.simulator, NetworkSimulator)
        self.assertFalse(self.simulator.is_running)

    # --------------------------------------------------------------------------
    # TEST 2: NetworkX graph is created with 10 nodes
    # --------------------------------------------------------------------------
    def test_02_graph_has_ten_nodes(self):
        """2. NetworkX graph is created with 10 nodes."""
        with self.app.app_context():
            self.simulator.sync_graph_from_db()
            node_count = self.simulator.graph.number_of_nodes()
            self.assertEqual(node_count, 10, f"Expected 10 graph nodes, found {node_count}")
            # Verify router node exists
            self.assertTrue(self.simulator.graph.has_node(1))
            self.assertEqual(self.simulator.graph.nodes[1]['name'], 'Router 01')

    # --------------------------------------------------------------------------
    # TEST 3: Connections match the network topology table
    # --------------------------------------------------------------------------
    def test_03_connections_match_topology_table(self):
        """3. Connections match the network topology table (12 designated links)."""
        with self.app.app_context():
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM network_connections;")
                db_conn_count = cursor.fetchone()['count']
            
            self.assertEqual(db_conn_count, len(INITIAL_CONNECTIONS))
            self.simulator.sync_graph_from_db()
            edge_count = self.simulator.graph.number_of_edges()
            # 12 edges configured in INITIAL_CONNECTIONS
            self.assertEqual(edge_count, 12, f"Expected 12 edges, found {edge_count}")
            # Verify specific links exist: Router (1) <-> Server 01 (2)
            self.assertTrue(self.simulator.graph.has_edge(1, 2))
            # Server 01 (2) <-> Server 02 (3) redundant link
            self.assertTrue(self.simulator.graph.has_edge(2, 3))

    # --------------------------------------------------------------------------
    # TEST 4: Telemetry values are generated within defined ranges
    # --------------------------------------------------------------------------
    def test_04_telemetry_values_within_defined_ranges(self):
        """4. Telemetry values are generated within defined realistic ranges."""
        with self.app.app_context():
            self.simulator._generate_telemetry_tick()
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT 10;")
                logs = cursor.fetchall()
                self.assertGreaterEqual(len(logs), 10)

                for row in logs:
                    dev_id = row['device_id']
                    if dev_id == 9:  # PC 05 is offline
                        self.assertEqual(row['traffic_in'], 0.0)
                        self.assertEqual(row['traffic_out'], 0.0)
                        self.assertEqual(row['packet_loss'], 100.0)
                    else:
                        self.assertGreaterEqual(row['traffic_in'], 0.0)
                        self.assertLessEqual(row['traffic_in'], 1000.0)
                        self.assertGreaterEqual(row['cpu_usage'], 0.0)
                        self.assertLessEqual(row['cpu_usage'], 100.0)
                        self.assertGreaterEqual(row['memory_usage'], 0.0)
                        self.assertLessEqual(row['memory_usage'], 100.0)

    # --------------------------------------------------------------------------
    # TEST 5: Telemetry values change between simulation cycles
    # --------------------------------------------------------------------------
    def test_05_telemetry_values_change_between_cycles(self):
        """5. Telemetry values change dynamically between simulation cycles."""
        with self.app.app_context():
            # First tick
            self.simulator._generate_telemetry_tick()
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT traffic_in, traffic_out, cpu_usage FROM traffic_logs WHERE device_id = 1 ORDER BY id DESC LIMIT 1;")
                t1 = dict(cursor.fetchone())

            # Second tick
            self.simulator._generate_telemetry_tick()
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT traffic_in, traffic_out, cpu_usage FROM traffic_logs WHERE device_id = 1 ORDER BY id DESC LIMIT 1;")
                t2 = dict(cursor.fetchone())

            # Confirm non-static generation (at least one metric varied)
            varied = (t1['traffic_in'] != t2['traffic_in']) or (t1['traffic_out'] != t2['traffic_out']) or (t1['cpu_usage'] != t2['cpu_usage'])
            self.assertTrue(varied, f"Expected variation between ticks: {t1} vs {t2}")

    # --------------------------------------------------------------------------
    # TEST 6: Device failure simulation updates device status to offline
    # --------------------------------------------------------------------------
    def test_06_device_failure_updates_status_offline(self):
        """6. Device failure simulation updates device status to offline."""
        with self.app.app_context():
            res = self.simulator.simulate_device_failure(device_id=4)
            self.assertEqual(res['status'], 'offline')
            self.assertEqual(res['device_id'], 4)

            # Check DB status
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT status, packet_loss, traffic_in FROM devices WHERE id = 4;")
                row = cursor.fetchone()
                self.assertEqual(row['status'], 'offline')
                self.assertEqual(row['packet_loss'], '100%')
                self.assertEqual(row['traffic_in'], '0.0 Mbps')

    # --------------------------------------------------------------------------
    # TEST 7: Device failure removes active paths through that node
    # --------------------------------------------------------------------------
    def test_07_device_failure_removes_active_paths(self):
        """7. Device failure removes active paths through that node."""
        with self.app.app_context():
            # Ensure Server 03 (id 4) is failed
            self.simulator.simulate_device_failure(device_id=4)

            # Calculating direct path to node 4 must return None (unreachable because it's offline)
            path_to_failed = self.simulator.calculate_path(1, 4)
            self.assertIsNone(path_to_failed, "Failed node must not be reached via active routing path")

            # Route between 1 and 2 bypassing node 4 should still be viable via direct link 1-2
            reroute = self.simulator.calculate_path(1, 2, avoid_node_id=4)
            self.assertIsNotNone(reroute)
            self.assertTrue(reroute['viable'])
            self.assertNotIn(4, reroute['path_ids'])

    # --------------------------------------------------------------------------
    # TEST 8: Device restoration returns status to online
    # --------------------------------------------------------------------------
    def test_08_device_restoration_returns_status_online(self):
        """8. Device restoration returns status to online and restores link connectivity."""
        with self.app.app_context():
            res = self.simulator.restore_device(device_id=4)
            self.assertEqual(res['status'], 'online')

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT status FROM devices WHERE id = 4;")
                self.assertEqual(cursor.fetchone()['status'], 'online')

                # Verify connection links are restored
                cursor.execute("SELECT status FROM network_connections WHERE source_device_id = 4 OR target_device_id = 4;")
                statuses = [r['status'] for r in cursor.fetchall()]
                self.assertIn('active', statuses)

    # --------------------------------------------------------------------------
    # TEST 9: Traffic generation pauses when simulation stops
    # --------------------------------------------------------------------------
    def test_09_traffic_generation_pauses_when_simulation_stops(self):
        """9. Traffic generation pauses when simulation stops."""
        with self.app.app_context():
            self.simulator.start_simulation()
            self.assertTrue(self.simulator.is_running)

            self.simulator.stop_simulation()
            self.assertFalse(self.simulator.is_running)

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM traffic_logs;")
                count_at_stop = cursor.fetchone()['count']

            # Wait short duration to ensure no background writes occur
            time.sleep(0.5)

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM traffic_logs;")
                count_after_wait = cursor.fetchone()['count']

            self.assertEqual(count_at_stop, count_after_wait)

    # --------------------------------------------------------------------------
    # TEST 10: Traffic generation resumes when simulation starts
    # --------------------------------------------------------------------------
    def test_10_traffic_generation_resumes_when_simulation_starts(self):
        """10. Traffic generation resumes when simulation starts."""
        with self.app.app_context():
            started, msg = self.simulator.start_simulation()
            self.assertTrue(started)
            self.assertTrue(self.simulator.is_running)

            # Let it run briefly to produce records
            time.sleep(3.0)

            self.simulator.stop_simulation()
            self.assertFalse(self.simulator.is_running)

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM traffic_logs;")
                self.assertGreater(cursor.fetchone()['count'], 0)

    # --------------------------------------------------------------------------
    # TEST 11: GET /api/traffic returns recent traffic logs
    # --------------------------------------------------------------------------
    def test_11_get_traffic_returns_recent_logs(self):
        """11. GET /api/traffic returns recent traffic logs."""
        response = self.client.get('/api/traffic?limit=10')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertIn('traffic', data)
        self.assertIsInstance(data['traffic'], list)
        if len(data['traffic']) > 0:
            sample = data['traffic'][0]
            self.assertIn('traffic_in', sample)
            self.assertIn('traffic_out', sample)
            self.assertIn('device_id', sample)

    # --------------------------------------------------------------------------
    # TEST 12: GET /api/traffic/<device_id> returns logs for that device
    # --------------------------------------------------------------------------
    def test_12_get_device_traffic_history(self):
        """12. GET /api/traffic/<device_id> returns logs for that specific device."""
        response = self.client.get('/api/traffic/1')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['device_id'], 1)
        self.assertIn('traffic', data)

        # Non-existent device returns 404
        err_res = self.client.get('/api/traffic/9999')
        self.assertEqual(err_res.status_code, 404)

    # --------------------------------------------------------------------------
    # TEST 13: GET /api/topology returns nodes and links
    # --------------------------------------------------------------------------
    def test_13_get_topology_returns_nodes_and_links(self):
        """13. GET /api/topology returns nodes and links."""
        response = self.client.get('/api/topology')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertIn('nodes', data)
        self.assertIn('links', data)
        self.assertEqual(len(data['nodes']), 10)
        self.assertEqual(len(data['links']), 12)
        # Check node schema
        first_node = data['nodes'][0]
        self.assertIn('id', first_node)
        self.assertIn('name', first_node)
        self.assertIn('ip', first_node)
        self.assertIn('type', first_node)
        self.assertIn('status', first_node)

    # --------------------------------------------------------------------------
    # TEST 14: GET /api/network/summary returns network aggregates
    # --------------------------------------------------------------------------
    def test_14_get_network_summary(self):
        """14. GET /api/network/summary returns network aggregates."""
        response = self.client.get('/api/network/summary')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['total_devices'], 10)
        self.assertIn('active_devices', data)
        self.assertIn('offline_devices', data)
        self.assertIn('active_connections', data)
        self.assertIn('failed_connections', data)
        self.assertIn('total_incoming_traffic', data)
        self.assertIn('total_outgoing_traffic', data)

    # --------------------------------------------------------------------------
    # TEST 15: GET /api/network/connected/<device_id> returns adjacent devices
    # --------------------------------------------------------------------------
    def test_15_get_connected_devices(self):
        """15. GET /api/network/connected/<device_id> returns adjacent devices."""
        # Router 01 (ID 1) connects to 9 devices (3 servers, 5 PCs, 1 firewall)
        response = self.client.get('/api/network/connected/1')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['device_id'], 1)
        self.assertEqual(data['count'], 9)
        self.assertIsInstance(data['connected_devices'], list)

        # Non-existent device returns 404
        err_res = self.client.get('/api/network/connected/999')
        self.assertEqual(err_res.status_code, 404)

    # --------------------------------------------------------------------------
    # TEST 16: POST /api/simulation/failure and restore update graph and database
    # --------------------------------------------------------------------------
    def test_16_post_simulation_failure_and_restore(self):
        """16. POST /api/simulation/failure and restore update graph and database."""
        # 1. Trigger failure on Server 02 (ID 3)
        fail_res = self.client.post('/api/simulation/failure',
                                    data=json.dumps({'device_id': 3}),
                                    content_type='application/json')
        self.assertEqual(fail_res.status_code, 200)
        fail_data = fail_res.get_json()
        self.assertEqual(fail_data['status'], 'success')
        self.assertEqual(fail_data['device_id'], 3)
        self.assertEqual(fail_data['device_status'], 'offline')

        # Check DB reflects offline
        dev_res = self.client.get('/api/devices/3')
        self.assertEqual(dev_res.get_json()['data']['status'], 'offline')

        # 2. Trigger restore on Server 02 (ID 3)
        restore_res = self.client.post('/api/simulation/restore',
                                       data=json.dumps({'device_id': 3}),
                                       content_type='application/json')
        self.assertEqual(restore_res.status_code, 200)
        restore_data = restore_res.get_json()
        self.assertEqual(restore_data['status'], 'success')
        self.assertEqual(restore_data['device_id'], 3)
        self.assertEqual(restore_data['device_status'], 'online')

        # Check DB reflects online
        dev_res_after = self.client.get('/api/devices/3')
        self.assertEqual(dev_res_after.get_json()['data']['status'], 'online')


if __name__ == '__main__':
    unittest.main()
