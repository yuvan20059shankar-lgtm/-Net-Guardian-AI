"""
NetGuardian AI - Security Alert Management & Recovery Test Suite (Prompt 8)
Covers all 17 required test scenarios:
1. Security alert creation.
2. Retrieve all alerts.
3. Retrieve alert by ID.
4. Alert status update.
5. Severity filtering.
6. Alert summary calculation.
7. Device isolation.
8. Device connection disabling.
9. Device restoration.
10. Recovery start.
11. Alternative route validation.
12. No-route recovery failure.
13. Recovery history creation.
14. Recovery history retrieval.
15. Dashboard alert statistics.
16. Duplicate recovery prevention.
17. Database persistence.
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


class SecurityAlertAndRecoveryTestCase(unittest.TestCase):
    """Integration test suite covering all 17 test requirements from Prompt 8."""

    @classmethod
    def setUpClass(cls):
        """Set up isolated test database environment."""
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
        """Re-sync network simulator graph from test database."""
        self.simulator = NetworkSimulator()
        with self.app.app_context():
            self.simulator.sync_graph_from_db()

    # --------------------------------------------------------------------------
    # TEST 1: Security alert creation
    # --------------------------------------------------------------------------
    def test_01_security_alert_creation(self):
        """1. Security alert creation with input validation."""
        payload = {
            'device_id': 6,
            'threat_type': 'Unauthorized SSH Key Injection',
            'description': 'Repeated anomalous public key installation attempts.',
            'severity': 'HIGH',
            'status': 'ACTIVE',
            'detection_source': 'Simulated Host Intrusion Detection',
            'recommended_action': 'Rotate SSH keys and inspect authorized_keys on PC 02.'
        }
        res = self.client.post('/api/alerts', data=json.dumps(payload), content_type='application/json')
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertIn('alert', data)
        self.assertEqual(data['alert']['threat_type'], payload['threat_type'])
        self.assertEqual(data['alert']['device_id'], 6)
        self.assertTrue(data['alert']['alert_code'].startswith('ALT-'))

        # Validation test: invalid severity rejected
        bad_payload = payload.copy()
        bad_payload['severity'] = 'SUPER_DANGEROUS'
        bad_res = self.client.post('/api/alerts', data=json.dumps(bad_payload), content_type='application/json')
        self.assertEqual(bad_res.status_code, 400)

    # --------------------------------------------------------------------------
    # TEST 2: Retrieve all alerts
    # --------------------------------------------------------------------------
    def test_02_retrieve_all_alerts(self):
        """2. Retrieve all security alerts."""
        res = self.client.get('/api/alerts')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertIn('alerts', data)
        self.assertGreaterEqual(len(data['alerts']), 6)
        # Check joined device information
        first = data['alerts'][0]
        self.assertIn('device_name', first)
        self.assertIn('ip_address', first)

    # --------------------------------------------------------------------------
    # TEST 3: Retrieve alert by ID
    # --------------------------------------------------------------------------
    def test_03_retrieve_alert_by_id(self):
        """3. Retrieve alert by ID or alert code."""
        # By numeric ID
        res = self.client.get('/api/alerts/1')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['alert']['id'], 1)

        # By alert_code
        res_code = self.client.get('/api/alerts/ALT-1001')
        self.assertEqual(res_code.status_code, 200)
        data_code = res_code.get_json()
        self.assertEqual(data_code['alert']['alert_code'], 'ALT-1001')

        # Non-existent alert returns 404
        err_res = self.client.get('/api/alerts/ALT-999999')
        self.assertEqual(err_res.status_code, 404)

    # --------------------------------------------------------------------------
    # TEST 4: Alert status update
    # --------------------------------------------------------------------------
    def test_04_alert_status_update(self):
        """4. Alert status update and automated resolved_at timestamp."""
        patch_payload = {'status': 'RESOLVED'}
        res = self.client.patch('/api/alerts/ALT-1001/status',
                                data=json.dumps(patch_payload),
                                content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['alert']['status'], 'RESOLVED')
        self.assertIsNotNone(data['alert']['resolved_at'])

        # Invalid status rejection
        bad_res = self.client.patch('/api/alerts/ALT-1001/status',
                                    data=json.dumps({'status': 'FAKE_STATUS'}),
                                    content_type='application/json')
        self.assertEqual(bad_res.status_code, 400)

    # --------------------------------------------------------------------------
    # TEST 5: Severity filtering
    # --------------------------------------------------------------------------
    def test_05_severity_filtering(self):
        """5. Severity filtering on GET /api/alerts."""
        res = self.client.get('/api/alerts?severity=CRITICAL')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        for a in data['alerts']:
            self.assertEqual(a['severity'], 'CRITICAL')

    # --------------------------------------------------------------------------
    # TEST 6: Alert summary calculation
    # --------------------------------------------------------------------------
    def test_06_alert_summary_calculation(self):
        """6. Alert summary calculation directly from SQLite."""
        res = self.client.get('/api/alerts/summary')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertIn('total_alerts', data)
        self.assertIn('active_alerts', data)
        self.assertIn('critical_alerts', data)
        self.assertIn('high_alerts', data)
        self.assertIn('medium_alerts', data)
        self.assertIn('low_alerts', data)
        self.assertIn('resolved_alerts', data)
        self.assertGreaterEqual(data['total_alerts'], 6)

    # --------------------------------------------------------------------------
    # TEST 7: Device isolation & Core Infrastructure Guard
    # --------------------------------------------------------------------------
    def test_07_device_isolation(self):
        """7. Device isolation and core infrastructure protection."""
        # Isolate PC 01 (ID 5)
        res = self.client.post('/api/devices/5/isolate')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['device']['status'], 'suspicious')

        # Security rule: Core infrastructure (Router 01 or Firewall 01) cannot be isolated
        router_res = self.client.post('/api/devices/1/isolate')
        self.assertEqual(router_res.status_code, 400)

        firewall_res = self.client.post('/api/devices/10/isolate')
        self.assertEqual(firewall_res.status_code, 400)

    # --------------------------------------------------------------------------
    # TEST 8: Device connection disabling
    # --------------------------------------------------------------------------
    def test_08_device_connection_disabling(self):
        """8. Device connection disabling upon isolation."""
        with self.app.app_context():
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT status FROM network_connections
                    WHERE source_device_id = 5 OR target_device_id = 5;
                """)
                statuses = [r['status'] for r in cursor.fetchall()]
                self.assertGreater(len(statuses), 0)
                for s in statuses:
                    self.assertEqual(s, 'inactive')

    # --------------------------------------------------------------------------
    # TEST 9: Device restoration
    # --------------------------------------------------------------------------
    def test_09_device_restoration(self):
        """9. Device restoration returns status to online and re-enables connections."""
        res = self.client.post('/api/devices/5/restore')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['device']['status'], 'online')
        self.assertTrue(data['verified'])

        # Check in DB that status is online and connection is active
        with self.app.app_context():
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT status FROM devices WHERE id = 5;")
                self.assertEqual(cursor.fetchone()['status'], 'online')

                cursor.execute("SELECT status FROM network_connections WHERE source_device_id = 5 OR target_device_id = 5;")
                statuses = [r['status'] for r in cursor.fetchall()]
                self.assertIn('active', statuses)

    # --------------------------------------------------------------------------
    # TEST 10: Recovery start
    # --------------------------------------------------------------------------
    def test_10_recovery_start(self):
        """10. Autonomous self-healing recovery pipeline."""
        # 1. Simulate failure on Server 03 (ID 4)
        self.client.post('/api/simulation/failure',
                         data=json.dumps({'device_id': 4}),
                         content_type='application/json')

        # 2. Trigger self-healing recovery
        res = self.client.post('/api/recovery/start',
                               data=json.dumps({'device_id': 4}),
                               content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['final_status'], 'online')
        self.assertEqual(data['verification_status'], 'VERIFIED')
        self.assertIsNotNone(data['alternative_route'])

    # --------------------------------------------------------------------------
    # TEST 11: Alternative route validation
    # --------------------------------------------------------------------------
    def test_11_alternative_route_validation(self):
        """11. Alternative route validation via NetworkX pathfinding."""
        with self.app.app_context():
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT alternative_route, verification_status FROM recovery_logs WHERE device_id = 4 ORDER BY id DESC LIMIT 1;")
                row = cursor.fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row['verification_status'], 'VERIFIED')
                self.assertIn('Server', row['alternative_route'])

    # --------------------------------------------------------------------------
    # TEST 12: No-route recovery failure
    # --------------------------------------------------------------------------
    def test_12_no_route_recovery_failure(self):
        """12. No-route recovery failure (Never generate fake successful recovery)."""
        with self.app.app_context():
            # Set PC 05 (ID 9) to offline
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE devices SET status = 'offline' WHERE id = 9;")
                cursor.execute("UPDATE network_connections SET status = 'inactive' WHERE source_device_id = 9 OR target_device_id = 9;")

        # Attempt recovery on star-topology leaf node with no redundant link
        res = self.client.post('/api/recovery/start',
                               data=json.dumps({'device_id': 9}),
                               content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        # Must clearly report failure rather than faking success
        self.assertFalse(data['success'])
        self.assertEqual(data['status'], 'failed')
        self.assertEqual(data['verification_status'], 'FAILED')
        self.assertIsNone(data['alternative_route'])

    # --------------------------------------------------------------------------
    # TEST 13: Recovery history creation
    # --------------------------------------------------------------------------
    def test_13_recovery_history_creation(self):
        """13. Recovery history creation in SQLite recovery_logs."""
        with self.app.app_context():
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) AS total FROM recovery_logs;")
                count = cursor.fetchone()['total']
                # Initial 3 seeded + at least 2 runs from test 10 and test 12
                self.assertGreaterEqual(count, 5)

    # --------------------------------------------------------------------------
    # TEST 14: Recovery history retrieval
    # --------------------------------------------------------------------------
    def test_14_recovery_history_retrieval(self):
        """14. Recovery history retrieval endpoint."""
        res = self.client.get('/api/recovery/history')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertIn('history', data)
        self.assertGreater(len(data['history']), 0)

        # Single record by code
        res_single = self.client.get('/api/recovery/history/REC-501')
        self.assertEqual(res_single.status_code, 200)
        self.assertEqual(res_single.get_json()['record']['recovery_code'], 'REC-501')

    # --------------------------------------------------------------------------
    # TEST 15: Dashboard alert statistics
    # --------------------------------------------------------------------------
    def test_15_dashboard_alert_statistics(self):
        """15. Dashboard alert and recovery statistics calculated from SQLite."""
        res = self.client.get('/api/dashboard')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()['data']
        self.assertIn('active_security_alerts', data)
        self.assertIn('critical_incidents', data)
        self.assertIn('successful_recovery_count', data)
        self.assertIn('failed_recovery_count', data)
        self.assertIn('isolated_devices', data)
        self.assertGreaterEqual(data['successful_recovery_count'], 1)
        self.assertGreaterEqual(data['failed_recovery_count'], 1)

    # --------------------------------------------------------------------------
    # TEST 16: Duplicate recovery prevention
    # --------------------------------------------------------------------------
    def test_16_duplicate_recovery_prevention(self):
        """16. Duplicate recovery prevention when target device is already online."""
        # Ensure Server 01 (ID 2) is online
        with self.app.app_context():
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE devices SET status = 'online' WHERE id = 2;")

        res = self.client.post('/api/recovery/start',
                               data=json.dumps({'device_id': 2}),
                               content_type='application/json')
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data['success'])
        self.assertIn('already operational and online', data['message'])

    # --------------------------------------------------------------------------
    # TEST 17: Database persistence
    # --------------------------------------------------------------------------
    def test_17_database_persistence(self):
        """17. Database persistence across application restarts."""
        # Create a new app instance pointing to the same test database
        new_app = create_app(TestingConfig)
        new_client = new_app.test_client()

        res_alerts = new_client.get('/api/alerts')
        self.assertEqual(res_alerts.status_code, 200)
        self.assertGreaterEqual(len(res_alerts.get_json()['alerts']), 6)

        res_recovery = new_client.get('/api/recovery/history')
        self.assertEqual(res_recovery.status_code, 200)
        self.assertGreaterEqual(len(res_recovery.get_json()['history']), 5)


if __name__ == '__main__':
    unittest.main()
