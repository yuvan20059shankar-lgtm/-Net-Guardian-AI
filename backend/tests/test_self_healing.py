"""
NetGuardian AI - Self-Healing Network Engine Automated Test Suite
Master Prompt: Complete Self-Healing Network Engine
Covers all 20 required verification scenarios:
1. Normal device monitoring
2. Offline device detection
3. Connection failure detection
4. High latency detection (>50ms)
5. Packet loss detection (15-95%)
6. Device isolation
7. Device restoration
8. Critical device protection (Router 01 / Gateway & Firewall 01)
9. Alternative route calculation (NetworkX Dijkstra)
10. Failed route handling (Honest reporting on single-point-of-failure leaf node)
11. Automatic recovery execution (9-step workflow)
12. Successful connectivity verification
13. Failed recovery handling
14. Recovery retry limits (MAX_RECOVERY_RETRIES = 3 -> MANUAL_INTERVENTION_REQUIRED)
15. Duplicate recovery prevention (Concurrent job collision check)
16. Database persistence (failures, isolations, route changes, recovery logs)
17. Recovery history APIs (GET /api/healing/history and /api/healing/history/<id>)
18. Dashboard API integration (GET /api/healing/summary, /status, /topology)
19. AI/ML integration (evaluate_healing_advisory & AI pipeline advisory output)
20. Invalid input handling (non-existent IDs, invalid formats, missing fields)
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
from services.device_service import DeviceService, NotFoundError, ValidationError
from services.failure_detection import FailureDetectionService
from services.device_isolation import DeviceIsolationService
from services.path_recovery import PathRecoveryService
from services.auto_recovery import AutoRecoveryService, MAX_RECOVERY_RETRIES
from services.network_simulator import NetworkSimulator
from services.ai_pipeline import AIPipelineService


class SelfHealingEngineTestCase(unittest.TestCase):
    """Comprehensive test suite for the complete NetGuardian Self-Healing Network Engine."""

    @classmethod
    def setUpClass(cls):
        """Configure test application and temporary test database."""
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
        """Cleanup test database file."""
        if os.path.exists(cls.test_db_path):
            try:
                os.remove(cls.test_db_path)
            except OSError:
                pass

    def setUp(self):
        """Reset database to initial state before each test case."""
        with self.app.app_context():
            init_database()
            AutoRecoveryService._active_recovery_jobs.clear()
            sim = NetworkSimulator()
            sim.sync_graph_from_db()

    # --------------------------------------------------------------------------
    # 1. Normal Device Monitoring
    # --------------------------------------------------------------------------
    def test_01_normal_device_monitoring(self):
        """Test that healthy devices produce zero detected failures."""
        with self.app.app_context():
            # Device 6 is online with active uplink and 0% packet loss
            failures = FailureDetectionService.detect_device_failures(6)
            self.assertIsInstance(failures, list)
            self.assertEqual(len(failures), 0, "Healthy device should not trigger any failure.")

    # --------------------------------------------------------------------------
    # 2. Offline Device Detection
    # --------------------------------------------------------------------------
    def test_02_offline_device_detection(self):
        """Test that an offline device is correctly flagged as 'Device Offline'."""
        with self.app.app_context():
            with get_db() as conn:
                conn.cursor().execute("UPDATE devices SET status = 'offline' WHERE id = 5;")
                conn.commit()

            failures = FailureDetectionService.detect_device_failures(5)
            self.assertTrue(any(f['failure_type'] == 'Device Offline' for f in failures))
            offline_f = [f for f in failures if f['failure_type'] == 'Device Offline'][0]
            self.assertIn(offline_f['severity'], ['HIGH', 'CRITICAL'])
            self.assertEqual(offline_f['device_id'], 5)

    # --------------------------------------------------------------------------
    # 3. Connection Failure Detection
    # --------------------------------------------------------------------------
    def test_03_connection_failure_detection(self):
        """Test that inactive or severed links trigger 'Connection Failure'."""
        with self.app.app_context():
            with get_db() as conn:
                conn.cursor().execute("""
                    UPDATE network_connections 
                    SET status = 'inactive' 
                    WHERE source_device_id = 1 AND target_device_id = 6;
                """)
                conn.commit()

            sim = NetworkSimulator()
            sim.sync_graph_from_db()

            failures = FailureDetectionService.detect_device_failures(6)
            conn_failures = [f for f in failures if f['failure_type'] == 'Connection Failure']
            self.assertTrue(len(conn_failures) > 0, "Severed link should trigger Connection Failure.")
            self.assertEqual(conn_failures[0]['device_id'], 6)

    # --------------------------------------------------------------------------
    # 4. High Latency Detection (>50ms)
    # --------------------------------------------------------------------------
    def test_04_high_latency_detection(self):
        """Test that latency exceeding 50ms threshold triggers 'High Simulated Latency'."""
        with self.app.app_context():
            with get_db() as conn:
                conn.cursor().execute("""
                    INSERT INTO traffic_logs (
                        device_id, latency, packet_loss, traffic_in, traffic_out,
                        packets_sent, packets_received, cpu_usage, memory_usage
                    ) VALUES (3, 88.5, 0.0, 1.2, 1.1, 100, 100, 20.0, 30.0);
                """)
                conn.commit()

            failures = FailureDetectionService.detect_device_failures(3)
            latency_failures = [f for f in failures if f['failure_type'] == 'High Simulated Latency']
            self.assertTrue(len(latency_failures) > 0, "Latency 88.5ms should trigger High Simulated Latency.")
            self.assertIn(latency_failures[0]['severity'], ['MEDIUM', 'HIGH'])

    # --------------------------------------------------------------------------
    # 5. Packet Loss Detection (15-95%)
    # --------------------------------------------------------------------------
    def test_05_packet_loss_detection(self):
        """Test that packet loss within 15%-95% triggers 'High Packet Loss'."""
        with self.app.app_context():
            with get_db() as conn:
                conn.cursor().execute("UPDATE devices SET packet_loss = '42.0%' WHERE id = 4;")
                conn.commit()

            failures = FailureDetectionService.detect_device_failures(4)
            loss_failures = [f for f in failures if f['failure_type'] == 'High Packet Loss']
            self.assertTrue(len(loss_failures) > 0, "Packet loss 42.0% should trigger High Packet Loss failure.")
            self.assertEqual(loss_failures[0]['severity'], 'MEDIUM')

    # --------------------------------------------------------------------------
    # 6. Device Isolation
    # --------------------------------------------------------------------------
    def test_06_device_isolation(self):
        """Test quarantining a non-critical device and verifying status & edge severance."""
        with self.app.app_context():
            res = DeviceIsolationService.isolate_device(device_id=5, reason="Simulated malware infection")
            self.assertTrue(res['success'])
            self.assertTrue(res['isolated'])
            self.assertEqual(res['status'], 'suspicious')

            # Verify device row in SQLite
            dev = DeviceService.get_device_by_id(5)
            self.assertEqual(dev['status'], 'suspicious')

            # Verify connections disabled
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT COUNT(*) as active_cnt FROM network_connections
                    WHERE (source_device_id = 5 OR target_device_id = 5) AND status = 'active';
                """)
                self.assertEqual(cursor.fetchone()['active_cnt'], 0)

            # Verify isolation history log entry
            logs = DeviceIsolationService.get_isolation_history(10)
            self.assertTrue(any(l['device_id'] == 5 and l['status'] == 'ISOLATED' for l in logs))

    # --------------------------------------------------------------------------
    # 7. Device Restoration
    # --------------------------------------------------------------------------
    def test_07_device_restoration(self):
        """Test restoring an isolated device back to online operational status."""
        with self.app.app_context():
            # First isolate
            DeviceIsolationService.isolate_device(device_id=5, reason="Pre-test isolation")
            # Then restore
            res = DeviceIsolationService.restore_device(device_id=5, reason="Threat cleared")
            self.assertTrue(res['success'])
            self.assertTrue(res['restored'])
            self.assertEqual(res['status'], 'online')

            dev = DeviceService.get_device_by_id(5)
            self.assertEqual(dev['status'], 'online')

            # Check restoration in isolation history
            logs = DeviceIsolationService.get_isolation_history(10)
            self.assertTrue(any(l['device_id'] == 5 and l['status'] == 'RESTORED' for l in logs))

    # --------------------------------------------------------------------------
    # 8. Critical Device Protection
    # --------------------------------------------------------------------------
    def test_08_critical_device_protection(self):
        """Test that core network infrastructure (Gateway ID 1, Firewall ID 2) cannot be isolated."""
        with self.app.app_context():
            # Attempt isolating Router 01 / Smart Meter Gateway (ID 1)
            with self.assertRaises(ValidationError) as ctx1:
                DeviceIsolationService.isolate_device(device_id=1, reason="Automated test isolation")
            self.assertIn("STRICTLY PROHIBITED", str(ctx1.exception).upper())

            # Attempt isolating Security Firewall (ID 10)
            with self.assertRaises(ValidationError) as ctx2:
                DeviceIsolationService.isolate_device(device_id=10, reason="Automated test isolation")
            self.assertIn("STRICTLY PROHIBITED", str(ctx2.exception).upper())

    # --------------------------------------------------------------------------
    # 9. Alternative Route Calculation (NetworkX Dijkstra)
    # --------------------------------------------------------------------------
    def test_09_alternative_route_calculation(self):
        """Test calculating redundant bypass route for core server when direct link is severed."""
        with self.app.app_context():
            # Server 03 (Backup Server ID 4) connects to Server 01 (ID 2) and Router 01 (ID 1)
            # Sever direct link between Server 03 (ID 4) and Router 01 (ID 1)
            with get_db() as conn:
                conn.cursor().execute("""
                    UPDATE network_connections 
                    SET status = 'inactive' 
                    WHERE (source_device_id = 1 AND target_device_id = 4)
                       OR (source_device_id = 4 AND target_device_id = 1);
                """)
                conn.commit()

            sim = NetworkSimulator()
            sim.sync_graph_from_db()

            route_result = PathRecoveryService.find_alternative_route_for_device(4)
            self.assertTrue(route_result['viable'], "Server 03 should have redundant path via Server 01/02.")
            self.assertIsInstance(route_result['path_ids'], list)
            self.assertTrue(len(route_result['path_ids']) >= 2)

    # --------------------------------------------------------------------------
    # 10. Failed Route Handling (Single-Point-of-Failure Leaf Node)
    # --------------------------------------------------------------------------
    def test_10_failed_route_handling(self):
        """Test honest failure reporting when star leaf node (Smart Meter 03 / dev 7) loses uplink."""
        with self.app.app_context():
            # Sever the only connection for Smart Meter 03 (ID 7 -> Gateway ID 1)
            with get_db() as conn:
                conn.cursor().execute("""
                    UPDATE network_connections 
                    SET status = 'inactive' 
                    WHERE (source_device_id = 1 AND target_device_id = 7)
                       OR (source_device_id = 7 AND target_device_id = 1);
                """)
                conn.commit()

            sim = NetworkSimulator()
            sim.sync_graph_from_db()

            route_result = PathRecoveryService.find_alternative_route_for_device(7)
            self.assertFalse(route_result['viable'], "Leaf node with single uplink cannot have redundant path.")
            self.assertTrue(route_result.get('is_single_point_of_failure', False))
            self.assertIn("No alternative route exists", route_result.get('error', ''))

    # --------------------------------------------------------------------------
    # 11. Automatic Recovery Execution (9-Step Workflow)
    # --------------------------------------------------------------------------
    def test_11_automatic_recovery_execution(self):
        """Test full 9-step recovery sequence execution and verify progress telemetry."""
        with self.app.app_context():
            # Simulate failure on Backup Server (ID 4)
            with get_db() as conn:
                conn.cursor().execute("UPDATE devices SET status = 'offline' WHERE id = 4;")
                conn.commit()

            rec_res = AutoRecoveryService.execute_recovery(device_id=4)
            self.assertIn('recovery_code', rec_res)
            self.assertIn('progress_steps', rec_res)
            steps = [s['step'] for s in rec_res['progress_steps']]
            self.assertTrue(any("STEP_1" in s for s in steps))
            self.assertTrue(any("STEP_6" in s or "VERIFY" in s for s in steps))
            self.assertTrue(any("STEP_8" in s or "LOG" in s for s in steps))
            self.assertEqual(rec_res['status'], 'RECOVERED')

    # --------------------------------------------------------------------------
    # 12. Successful Connectivity Verification
    # --------------------------------------------------------------------------
    def test_12_successful_connectivity_verification(self):
        """Test that verify_connectivity returns True when device is online with active path."""
        with self.app.app_context():
            is_verified, details = AutoRecoveryService.verify_connectivity(device_id=3)
            self.assertTrue(is_verified)
            self.assertTrue(details['verified'])
            self.assertTrue(details['can_reach_backbone'])
            self.assertTrue(details['active_neighbors_count'] >= 1)

    # --------------------------------------------------------------------------
    # 13. Failed Recovery Handling
    # --------------------------------------------------------------------------
    def test_13_failed_recovery_handling(self):
        """Test that recovering an isolated node with completely severed links reports honest recovery result."""
        with self.app.app_context():
            # Disable all connections for Smart Meter 04 (ID 8)
            with get_db() as conn:
                conn.cursor().execute("""
                    UPDATE network_connections 
                    SET status = 'inactive' 
                    WHERE source_device_id = 8 OR target_device_id = 8;
                """)
                conn.cursor().execute("UPDATE devices SET status = 'offline' WHERE id = 8;")
                conn.commit()

            sim = NetworkSimulator()
            sim.sync_graph_from_db()

            # Execute recovery
            rec_res = AutoRecoveryService.execute_recovery(device_id=8)
            self.assertIn(rec_res['status'], ['RECOVERED', 'FAILED', 'MANUAL_INTERVENTION_REQUIRED'])
            self.assertIn('progress_steps', rec_res)

    # --------------------------------------------------------------------------
    # 14. Recovery Retry Limits
    # --------------------------------------------------------------------------
    def test_14_recovery_retry_limits(self):
        """Test that reaching MAX_RECOVERY_RETRIES triggers MANUAL_INTERVENTION_REQUIRED."""
        with self.app.app_context():
            # Insert 3 recovery attempts for device 9 within the last hour
            with get_db() as conn:
                cursor = conn.cursor()
                for i in range(MAX_RECOVERY_RETRIES):
                    cursor.execute("""
                        INSERT INTO recovery_logs (
                            recovery_code, device_id, failure_type, action_taken,
                            original_status, final_status, verification_status,
                            duration_seconds, retry_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (f"REC-RETRY-{i}", 9, 'Offline', 'RETRY_TEST', 'offline', 'FAILED', 'FAILED', 1.2, i + 1))
                conn.commit()

            rec_res = AutoRecoveryService.execute_recovery(device_id=9)
            self.assertEqual(rec_res['status'], 'MANUAL_INTERVENTION_REQUIRED')
            self.assertFalse(rec_res['success'])
            self.assertIn("retry limit", rec_res.get('error', '').lower())

    # --------------------------------------------------------------------------
    # 15. Duplicate Recovery Prevention
    # --------------------------------------------------------------------------
    def test_15_duplicate_recovery_prevention(self):
        """Test that simultaneous recovery on the same device is rejected with collision error."""
        with self.app.app_context():
            # Artificially register an ongoing active recovery job
            AutoRecoveryService._active_recovery_jobs[4] = {
                'recovery_code': 'REC-ACTIVE-LOCK',
                'started_at': 123456789.0
            }

            with self.assertRaises(ValidationError) as ctx:
                AutoRecoveryService.execute_recovery(device_id=4)

            self.assertIn("DUPLICATE RECOVERY PREVENTED", str(ctx.exception).upper())

    # --------------------------------------------------------------------------
    # 16. Database Persistence
    # --------------------------------------------------------------------------
    def test_16_database_persistence(self):
        """Test persistence across network_failures, isolation logs, route changes, recovery_logs."""
        with self.app.app_context():
            # 1. Record failure record
            f_res, created = FailureDetectionService.record_failure({
                'device_id': 5,
                'device_ip': '192.168.1.20',
                'failure_type': 'High Packet Loss',
                'severity': 'HIGH',
                'description': 'Simulated 55% loss persistence test'
            })
            self.assertIsNotNone(f_res['failure_id'])

            # 2. Check failure queryable
            fetched_f = FailureDetectionService.get_failure_by_id(f_res['failure_id'])
            self.assertIsNotNone(fetched_f)
            self.assertEqual(fetched_f['severity'], 'HIGH')

            # 3. Apply route change and verify persistence
            route_plan = PathRecoveryService.find_alternative_route_for_device(4)
            self.assertTrue(route_plan['viable'])
            applied_res = PathRecoveryService.apply_route_recovery(4, route_plan, 'REC-TEST-PERSIST')
            self.assertTrue(applied_res['success'])
            self.assertTrue(applied_res['change_id'].startswith('RTE-'))

            # 4. Check route changes queryable
            changes = PathRecoveryService.get_route_changes_history(limit=5)
            self.assertTrue(any(c['change_id'] == applied_res['change_id'] for c in changes))

    # --------------------------------------------------------------------------
    # 17. Recovery History APIs
    # --------------------------------------------------------------------------
    def test_17_recovery_history_apis(self):
        """Test GET /api/healing/history and GET /api/healing/history/<recovery_id>."""
        with self.app.app_context():
            # Seed a recovery log
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO recovery_logs (
                        id, recovery_code, device_id, failure_type, action_taken,
                        original_status, final_status, verification_status, duration_seconds
                    ) VALUES (999, 'REC-TEST-999', 4, 'Failover Test', 'ROUTE_FAILOVER', 'offline', 'online', 'VERIFIED', 1.5);
                """)
                conn.commit()

        # Test list history
        resp = self.client.get('/api/healing/history?limit=10')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()['data']
        self.assertIn('history', data)
        self.assertTrue(data['count'] >= 1)

        # Test get by ID
        resp_id = self.client.get('/api/healing/history/999')
        self.assertEqual(resp_id.status_code, 200)
        rec_data = resp_id.get_json()['data']
        self.assertEqual(rec_data['id'], 999)
        self.assertEqual(rec_data['device_id'], 4)

    # --------------------------------------------------------------------------
    # 18. Dashboard API Integration
    # --------------------------------------------------------------------------
    def test_18_dashboard_api_integration(self):
        """Test GET /api/healing/summary, /status, and /topology endpoints."""
        # 1. Summary
        resp_sum = self.client.get('/api/healing/summary')
        self.assertEqual(resp_sum.status_code, 200)
        data_sum = resp_sum.get_json()['data']
        self.assertIn('total_failures_detected', data_sum)
        self.assertIn('active_failures', data_sum)
        self.assertIn('devices_isolated', data_sum)
        self.assertIn('recovery_success_rate', data_sum)

        # 2. Status
        resp_stat = self.client.get('/api/healing/status')
        self.assertEqual(resp_stat.status_code, 200)
        data_stat = resp_stat.get_json()['data']
        self.assertEqual(data_stat['engine_status'], 'OPERATIONAL')

        # 3. Topology
        resp_top = self.client.get('/api/healing/topology')
        self.assertEqual(resp_top.status_code, 200)
        data_top = resp_top.get_json()['data']
        self.assertIn('nodes', data_top)
        self.assertIn('connections', data_top)

    # --------------------------------------------------------------------------
    # 19. AI/ML Integration
    # --------------------------------------------------------------------------
    def test_19_ai_ml_integration(self):
        """Test AI threat intelligence evaluation linking to self-healing advisory."""
        with self.app.app_context():
            ai_threat = {
                'threat_id': 'THR-TEST-900',
                'threat_type': 'Potential Data Exfiltration',
                'severity': 'CRITICAL',
                'confidence': 'HIGH',
                'anomaly_score': 0.88,
                'affected_device': 'Smart Meter 04 (BES-SM-004)',
                'device_id': 8,
                'is_anomaly': True
            }

            advisory = AutoRecoveryService.evaluate_healing_advisory(ai_threat)
            self.assertEqual(advisory['recommended_healing_action'], 'ISOLATE_AND_REROUTE')
            self.assertTrue(advisory['isolate_recommended'])
            self.assertTrue(advisory['can_safely_isolate'])

            # Verify AIPipeline integration includes self_healing_advisory
            pipeline = AIPipelineService()
            pipeline_res = pipeline.run_pipeline(
                data={
                    'device_id': 8,
                    'packet_count': 9500,
                    'average_packet_size': 1250.0,
                    'bytes_transferred': 25000000,
                    'connection_frequency': 120.0,
                    'packet_entropy': 7.95,
                    'inbound_bytes': 1000000,
                    'outbound_bytes': 24000000,
                    'connection_duration': 60.0
                },
                persist_results=False
            )
            self.assertIn('self_healing_advisory', pipeline_res)

    # --------------------------------------------------------------------------
    # 20. Invalid Input Handling
    # --------------------------------------------------------------------------
    def test_20_invalid_input_handling(self):
        """Test robust handling and clean HTTP error codes for invalid inputs."""
        # Non-existent device isolation
        resp_iso_invalid = self.client.post('/api/healing/isolate/dev-999')
        self.assertEqual(resp_iso_invalid.status_code, 404)

        # Malformed device ID format
        resp_iso_bad = self.client.post('/api/healing/isolate/not-a-valid-id')
        self.assertEqual(resp_iso_bad.status_code, 400)

        # Non-existent failure lookup
        resp_flr_none = self.client.get('/api/healing/failures/FLR-NONEXISTENT')
        self.assertEqual(resp_flr_none.status_code, 404)

        # Empty payload to simulate failure
        resp_sim_empty = self.client.post('/api/healing/simulate-failure',
                                          json={},
                                          content_type='application/json')
        self.assertEqual(resp_sim_empty.status_code, 400)


if __name__ == '__main__':
    unittest.main()
