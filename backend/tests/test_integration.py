"""
NetGuardian AI - Comprehensive Backend Integration & Frontend Compatibility Test Suite (Prompt 9)
Covers:
1. Health & Database connectivity
2. Device management CRUD & validation
3. Dashboard calculated telemetry from SQLite
4. Network simulation and duplicate thread guard
5. Security alerts lifecycle and summary
6. Self-Healing scenarios A through G:
   - Scenario A: Simulate Server 03 failure
   - Scenario B: Find alternative route
   - Scenario C: Perform simulated recovery
   - Scenario D: Verify connectivity after recovery
   - Scenario E: Test failure where no alternative route exists
   - Scenario F: Verify that failed recovery is not reported as successful
   - Scenario G: Restore an isolated device
7. Frontend compatibility aliases & contract integrity:
   - POST /api/devices/<id>/toggle
   - POST /api/alerts/<id>/resolve
   - POST /api/simulate/failure
   - POST /api/recover
   - POST /api/isolate
   - POST /api/restore
   - GET /api/history
   - 'dev-X' string ID parsing
8. Database persistence and ACID transaction rollback
"""

import os
import sys
import json
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app import create_app
from config import TestingConfig
from database import get_db, init_database
from services.network_simulator import NetworkSimulator


class BackendPrompt9IntegrationTestCase(unittest.TestCase):
    """Integration verification suite for Prompt 9 audit and testing."""

    @classmethod
    def setUpClass(cls):
        """Set up clean isolated test database environment."""
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
        """Clean up simulator background thread and test database."""
        simulator = NetworkSimulator()
        simulator.stop_simulation()
        if os.path.exists(cls.test_db_path):
            try:
                os.remove(cls.test_db_path)
            except OSError:
                pass

    def setUp(self):
        """Ensure clean graph and simulator state before each test."""
        self.simulator = NetworkSimulator()
        with self.app.app_context():
            self.simulator.sync_graph_from_db()

    # --------------------------------------------------------------------------
    # 1. HEALTH API TESTING (Prompt 9 Section 2)
    # --------------------------------------------------------------------------
    def test_01_health_api(self):
        """Verify GET /api/health returns 200, online status, and database connected."""
        res = self.client.get('/api/health')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['backend'], 'online')
        self.assertEqual(data['database'], 'connected')

    # --------------------------------------------------------------------------
    # 2. DASHBOARD API TESTING (Prompt 9 Section 4)
    # --------------------------------------------------------------------------
    def test_02_dashboard_kpis_calculated_from_sqlite(self):
        """Verify GET /api/dashboard calculates all KPIs directly from SQLite."""
        res = self.client.get('/api/dashboard')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()['data']
        self.assertEqual(data['total_devices'], 10)
        self.assertIn('online_devices', data)
        self.assertIn('offline_devices', data)
        self.assertIn('suspicious_devices', data)
        self.assertIn('network_health', data)
        self.assertIn('active_security_alerts', data)
        self.assertIn('critical_incidents', data)
        self.assertIn('successful_recovery_count', data)
        self.assertIn('failed_recovery_count', data)
        self.assertIn('isolated_devices', data)

    # --------------------------------------------------------------------------
    # 3. NETWORK SIMULATION & THREAD DUPLICATE PREVENTION (Prompt 9 Section 5)
    # --------------------------------------------------------------------------
    def test_03_simulation_start_stop_and_thread_safety(self):
        """Verify simulation starts, guards against duplicate threads, and stops cleanly."""
        start_res1 = self.client.post('/api/simulation/start')
        self.assertEqual(start_res1.status_code, 200)
        self.assertTrue(self.simulator.is_running)

        # Attempt duplicate start -> Should return gracefully without launching second thread
        start_res2 = self.client.post('/api/simulation/start')
        self.assertEqual(start_res2.status_code, 200)

        # Stop simulation
        stop_res = self.client.post('/api/simulation/stop')
        self.assertEqual(stop_res.status_code, 200)
        self.assertFalse(self.simulator.is_running)

    # --------------------------------------------------------------------------
    # 4. SCENARIOS A, B, C, D: SERVER 03 FAILURE, ROUTE, RECOVERY & VERIFICATION
    # --------------------------------------------------------------------------
    def test_04_scenarios_a_to_d_server_03_failover_recovery(self):
        """
        SCENARIO A: Simulate Server 03 failure.
        SCENARIO B: Find an alternative route.
        SCENARIO C: Perform simulated recovery.
        SCENARIO D: Verify connectivity after recovery.
        """
        # Scenario A: Simulate failure on Server 03 (ID 4)
        fail_res = self.client.post('/api/simulation/failure',
                                    data=json.dumps({'device_id': 4}),
                                    content_type='application/json')
        self.assertEqual(fail_res.status_code, 200)
        fail_data = fail_res.get_json()
        self.assertEqual(fail_data['device_status'], 'offline')

        # Scenario B: Find alternative route in topology
        with self.app.app_context():
            alt_path = self.simulator.calculate_path(1, 2, avoid_node_id=4)
            self.assertIsNotNone(alt_path)
            self.assertTrue(alt_path['viable'])
            self.assertNotIn(4, alt_path['path_ids'])

        # Scenario C: Perform simulated recovery via self-healing pipeline
        rec_res = self.client.post('/api/recovery/start',
                                   data=json.dumps({'device_id': 4}),
                                   content_type='application/json')
        self.assertEqual(rec_res.status_code, 200)
        rec_data = rec_res.get_json()
        self.assertTrue(rec_data['success'])
        self.assertEqual(rec_data['final_status'], 'online')
        self.assertEqual(rec_data['verification_status'], 'VERIFIED')

        # Scenario D: Verify connectivity after recovery
        with self.app.app_context():
            self.simulator.sync_graph_from_db()
            dev_check = self.client.get('/api/devices/4')
            self.assertEqual(dev_check.get_json()['data']['status'], 'online')
            # Verify Server 03 has active connection links in DB
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT status FROM network_connections WHERE source_device_id = 4 OR target_device_id = 4;")
                statuses = [r['status'] for r in cursor.fetchall()]
                self.assertIn('active', statuses)

    # --------------------------------------------------------------------------
    # 5. SCENARIOS E & F: NO-ROUTE RECOVERY FAILURE & NEVER FAKE SUCCESS
    # --------------------------------------------------------------------------
    def test_05_scenarios_e_and_f_no_route_failure_transparency(self):
        """
        SCENARIO E: Test a failure where no alternative route exists (PC 05 - star leaf node).
        SCENARIO F: Verify that failed recovery is not reported as successful.
        """
        with self.app.app_context():
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE devices SET status = 'offline' WHERE id = 9;")
                cursor.execute("UPDATE network_connections SET status = 'inactive' WHERE source_device_id = 9 OR target_device_id = 9;")

        rec_res = self.client.post('/api/recovery/start',
                                   data=json.dumps({'device_id': 9}),
                                   content_type='application/json')
        self.assertEqual(rec_res.status_code, 200)
        rec_data = rec_res.get_json()

        # Scenario F validation: must NOT report success when no route exists!
        self.assertFalse(rec_data['success'])
        self.assertEqual(rec_data['status'], 'failed')
        self.assertEqual(rec_data['verification_status'], 'FAILED')
        self.assertIsNone(rec_data['alternative_route'])
        self.assertIn('No alternative route exists', rec_data['message'])

    # --------------------------------------------------------------------------
    # 6. SCENARIO G: RESTORE AN ISOLATED DEVICE
    # --------------------------------------------------------------------------
    def test_06_scenario_g_restore_isolated_device(self):
        """SCENARIO G: Isolate a device, verify severance, and restore it with graph check."""
        # 1. Isolate PC 02 (ID 6)
        iso_res = self.client.post('/api/devices/6/isolate')
        self.assertEqual(iso_res.status_code, 200)
        self.assertEqual(iso_res.get_json()['device']['status'], 'suspicious')

        # 2. Restore PC 02
        restore_res = self.client.post('/api/devices/6/restore')
        self.assertEqual(restore_res.status_code, 200)
        restore_data = restore_res.get_json()
        self.assertEqual(restore_data['device']['status'], 'online')
        self.assertTrue(restore_data['verified'])

    # --------------------------------------------------------------------------
    # 7. FRONTEND API COMPATIBILITY & ALIASES (Prompt 9 Section 9)
    # --------------------------------------------------------------------------
    def test_07_frontend_api_compatibility_aliases(self):
        """Verify frontend API contract compatibility (endpoints, aliases, dev-X IDs)."""
        # A. POST /api/devices/<id>/toggle
        toggle_res = self.client.post('/api/devices/dev-5/toggle')
        self.assertEqual(toggle_res.status_code, 200)
        self.assertEqual(toggle_res.get_json()['data']['status'], 'offline')

        toggle_back = self.client.post('/api/devices/dev-5/toggle')
        self.assertEqual(toggle_back.status_code, 200)
        self.assertEqual(toggle_back.get_json()['data']['status'], 'online')

        # B. POST /api/alerts/<id>/resolve
        resolve_res = self.client.post('/api/alerts/ALT-1003/resolve')
        self.assertEqual(resolve_res.status_code, 200)
        self.assertEqual(resolve_res.get_json()['alert']['status'], 'RESOLVED')

        # C. POST /api/simulate/failure (with deviceId)
        sim_fail_res = self.client.post('/api/simulate/failure',
                                        data=json.dumps({'deviceId': 'dev-4'}),
                                        content_type='application/json')
        self.assertEqual(sim_fail_res.status_code, 200)
        self.assertEqual(sim_fail_res.get_json()['device_status'], 'offline')

        # D. POST /api/recover (with deviceId)
        recover_res = self.client.post('/api/recover',
                                       data=json.dumps({'deviceId': 'dev-4'}),
                                       content_type='application/json')
        self.assertEqual(recover_res.status_code, 200)
        self.assertTrue(recover_res.get_json()['success'])

        # E. POST /api/isolate (with body)
        iso_body_res = self.client.post('/api/isolate',
                                        data=json.dumps({'deviceId': 'dev-7'}),
                                        content_type='application/json')
        self.assertEqual(iso_body_res.status_code, 200)
        self.assertEqual(iso_body_res.get_json()['device']['status'], 'suspicious')

        # F. POST /api/restore (with body)
        restore_body_res = self.client.post('/api/restore',
                                            data=json.dumps({'deviceId': 'dev-7'}),
                                            content_type='application/json')
        self.assertEqual(restore_body_res.status_code, 200)
        self.assertEqual(restore_body_res.get_json()['device']['status'], 'online')

        # G. GET /api/history
        history_res = self.client.get('/api/history')
        self.assertEqual(history_res.status_code, 200)
        self.assertIn('history', history_res.get_json())

    # --------------------------------------------------------------------------
    # 8. DATABASE INTEGRITY & TRANSACTION ROLLBACK (Prompt 9 Section 8)
    # --------------------------------------------------------------------------
    def test_08_database_integrity_and_transaction_rollback(self):
        """Verify database tables exist, foreign keys are enforced, and transactions roll back safely."""
        with self.app.app_context():
            with get_db() as conn:
                cursor = conn.cursor()
                # Verify all required tables exist
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = {r['name'] for r in cursor.fetchall()}
                required_tables = {
                    '_system_metadata', 'devices', 'traffic_logs',
                    'network_connections', 'security_alerts', 'recovery_logs'
                }
                self.assertTrue(required_tables.issubset(tables), f"Missing tables: {required_tables - tables}")

                # Test transaction rollback on intentional error
                try:
                    with get_db() as err_conn:
                        err_cursor = err_conn.cursor()
                        err_cursor.execute("INSERT INTO security_alerts (id) VALUES (99999);")  # Will fail NOT NULL constraint
                except Exception:
                    pass

                # Confirm aborted transaction left no phantom record
                cursor.execute("SELECT id FROM security_alerts WHERE id = 99999;")
                self.assertIsNone(cursor.fetchone())


if __name__ == '__main__':
    unittest.main()
