"""
NetGuardian AI - Unified AI/ML Pipeline Integration Tests (Prompt 5)
Tagline: Detect. Defend. Recover. Automatically.

Verifies end-to-end integration:
1. Normal traffic through complete pipeline
2. Anomalous traffic through complete pipeline
3. Suspicious outbound traffic
4. Abnormal connection frequency
5. Threat classification integration
6. Threat intelligence integration
7. Alert creation
8. Database persistence
9. Duplicate alert prevention
10. Unknown device handling
11. Invalid request handling
12. Missing model handling
13. Model loading failure
14. Simulation-to-AI integration
15. Existing API compatibility
16. Frontend API response compatibility
"""

import os
import sys
import json
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app import create_app
from config import TestingConfig
from database import get_db, init_database
from services.ai_pipeline import (
    AIPipelineService,
    AIPipelineError,
    ModelUnavailableError,
    execute_ai_pipeline
)
from services.network_simulator import NetworkSimulator
from services.device_service import NotFoundError, ValidationError


class AIPipelineIntegrationTestCase(unittest.TestCase):
    """Integration Test Suite covering all 16 Prompt 5 test scenarios."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment and initialize isolated SQLite database."""
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

    def setUp(self):
        """Clean alerts and intelligence reports before each test to maintain isolation."""
        with self.app.app_context():
            with get_db() as db:
                db.execute("DELETE FROM threat_intelligence_reports")
                db.execute("DELETE FROM security_alerts")
                db.commit()

    # --------------------------------------------------------------------------
    # Test 1: Normal traffic through complete pipeline
    # --------------------------------------------------------------------------
    def test_01_normal_traffic_complete_pipeline(self):
        """Test 1: Normal traffic completes Stages 1-6 with NORMAL prediction and LOW severity."""
        normal_telemetry = {
            'device_id': 1,
            'packet_count': 320,
            'average_packet_size': 512.0,
            'bytes_transferred': 163840,
            'connection_frequency': 15.0,
            'packet_entropy': 4.5,
            'inbound_bytes': 98304,
            'outbound_bytes': 65536,
            'connection_duration': 20.0
        }

        with self.app.app_context():
            result = execute_ai_pipeline(normal_telemetry, persist=True)

            self.assertEqual(result['device_id'], 1)
            self.assertEqual(result['device_name'], 'Router 01')
            self.assertEqual(result['analysis']['prediction'], 'NORMAL')
            self.assertEqual(result['analysis']['severity'], 'LOW')
            self.assertEqual(result['analysis']['threat_indicator'], 'Nominal Traffic')
            self.assertLessEqual(result['analysis']['threat_score'], 35)
            self.assertFalse(result['alert_created'])
            self.assertIsNone(result['alert_code'])
            self.assertIsInstance(result['recommended_actions'], list)

    # --------------------------------------------------------------------------
    # Test 2: Anomalous traffic through complete pipeline
    # --------------------------------------------------------------------------
    def test_02_anomalous_traffic_complete_pipeline(self):
        """Test 2: Anomalous traffic completes all stages with ANOMALY prediction and creates alert."""
        anomalous_telemetry = {
            'device_id': 2,
            'packet_count': 12000,
            'average_packet_size': 48.0,
            'bytes_transferred': 576000,
            'connection_frequency': 260.0,
            'packet_entropy': 3.2,
            'inbound_bytes': 550000,
            'outbound_bytes': 26000,
            'connection_duration': 0.5
        }

        with self.app.app_context():
            result = execute_ai_pipeline(anomalous_telemetry, persist=True)

            self.assertEqual(result['device_id'], 2)
            self.assertEqual(result['analysis']['prediction'], 'ANOMALY')
            self.assertIn(result['analysis']['severity'], ['HIGH', 'CRITICAL'])
            self.assertGreaterEqual(result['analysis']['threat_score'], 70)
            self.assertTrue(result['alert_created'])
            self.assertIsNotNone(result['alert_code'])

    # --------------------------------------------------------------------------
    # Test 3: Suspicious outbound traffic
    # --------------------------------------------------------------------------
    def test_03_suspicious_outbound_traffic(self):
        """Test 3: Heavy asymmetric outbound egress triggers Suspicious Outbound Traffic or Data Exfiltration."""
        outbound_telemetry = {
            'device_id': 3,
            'packet_count': 1800,
            'average_packet_size': 1200.0,
            'bytes_transferred': 2160000,
            'connection_frequency': 25.0,
            'packet_entropy': 6.2,
            'inbound_bytes': 100000,
            'outbound_bytes': 2060000,
            'connection_duration': 30.0
        }

        with self.app.app_context():
            result = execute_ai_pipeline(outbound_telemetry, persist=False)

            indicator = result['analysis']['threat_indicator']
            self.assertIn(indicator, ['Suspicious Outbound Traffic', 'Potential Data Exfiltration'])
            self.assertIn(result['analysis']['severity'], ['MEDIUM', 'HIGH', 'CRITICAL'])
            self.assertGreaterEqual(result['analysis']['threat_score'], 50)
            self.assertGreaterEqual(result['evidence']['outbound_bytes'], 1000000)

    # --------------------------------------------------------------------------
    # Test 4: Abnormal connection frequency
    # --------------------------------------------------------------------------
    def test_04_abnormal_connection_frequency(self):
        """Test 4: High connection frequency triggers Abnormal Connection Frequency indicator."""
        freq_telemetry = {
            'device_id': 4,
            'packet_count': 850,
            'average_packet_size': 320.0,
            'bytes_transferred': 272000,
            'connection_frequency': 95.0,
            'packet_entropy': 4.8,
            'inbound_bytes': 150000,
            'outbound_bytes': 122000,
            'connection_duration': 10.0
        }

        with self.app.app_context():
            result = execute_ai_pipeline(freq_telemetry, persist=False)

            self.assertIn(
                result['analysis']['threat_indicator'],
                ['Abnormal Connection Frequency', 'Port Scanning', 'Suspicious Network Communication']
            )
            self.assertGreaterEqual(result['evidence']['connection_frequency'], 75.0)

    # --------------------------------------------------------------------------
    # Test 5: Threat classification integration
    # --------------------------------------------------------------------------
    def test_05_threat_classification_integration(self):
        """Test 5: Stage 4 accurately integrates Prompt 3 ThreatClassifierService."""
        telemetry = {
            'device_id': 5,
            'packet_count': 15000,
            'average_packet_size': 42.0,
            'bytes_transferred': 630000,
            'connection_frequency': 320.0,
            'packet_entropy': 3.1,
            'inbound_bytes': 610000,
            'outbound_bytes': 20000,
            'connection_duration': 0.5
        }

        with self.app.app_context():
            result = execute_ai_pipeline(telemetry, persist=False)

            self.assertEqual(result['analysis']['threat_type'], 'Denial of Service (DoS) - like traffic spikes')
            self.assertEqual(result['analysis']['threat_indicator'], 'DoS-like Traffic Spike')
            self.assertEqual(result['analysis']['severity'], 'CRITICAL')

    # --------------------------------------------------------------------------
    # Test 6: Threat intelligence integration
    # --------------------------------------------------------------------------
    def test_06_threat_intelligence_integration(self):
        """Test 6: Stage 5 accurately integrates Prompt 4 ThreatIntelligenceService."""
        telemetry = {
            'device_id': 6,
            'packet_count': 1900,
            'average_packet_size': 1100.0,
            'bytes_transferred': 2090000,
            'connection_frequency': 25.0,
            'packet_entropy': 6.2,
            'inbound_bytes': 100000,
            'outbound_bytes': 1990000,
            'connection_duration': 22.0
        }

        with self.app.app_context():
            result = execute_ai_pipeline(telemetry, persist=False)

            self.assertIsInstance(result['analysis']['threat_score'], int)
            self.assertGreaterEqual(result['analysis']['threat_score'], 0)
            self.assertLessEqual(result['analysis']['threat_score'], 100)
            self.assertIn(result['analysis']['confidence'], ['LOW', 'MEDIUM', 'HIGH'])
            self.assertIsInstance(result['recommended_actions'], list)
            self.assertGreater(len(result['recommended_actions']), 0)
            self.assertIn('PC 02', result['analysis']['explanation'])

    # --------------------------------------------------------------------------
    # Test 7: Alert creation
    # --------------------------------------------------------------------------
    def test_07_alert_creation(self):
        """Test 7: Stage 6 creates active alert in SQLite security_alerts upon elevated threat."""
        telemetry = {
            'device_id': 7,
            'packet_count': 11000,
            'average_packet_size': 50.0,
            'bytes_transferred': 550000,
            'connection_frequency': 280.0,
            'packet_entropy': 3.2,
            'inbound_bytes': 530000,
            'outbound_bytes': 20000,
            'connection_duration': 0.5
        }

        with self.app.app_context():
            result = execute_ai_pipeline(telemetry, persist=True)

            self.assertTrue(result['alert_created'])
            self.assertIsNotNone(result['alert_code'])

            # Verify in SQLite directly
            with get_db() as db:
                cursor = db.cursor()
                cursor.execute("SELECT * FROM security_alerts WHERE alert_code = ?;", (result['alert_code'],))
                row = cursor.fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row['device_id'], 7)
                self.assertEqual(row['status'], 'ACTIVE')

    # --------------------------------------------------------------------------
    # Test 8: Database persistence
    # --------------------------------------------------------------------------
    def test_08_database_persistence(self):
        """Test 8: Both security alerts and threat intelligence reports are persisted in SQLite."""
        telemetry = {
            'device_id': 8,
            'packet_count': 4200,
            'average_packet_size': 95.0,
            'bytes_transferred': 399000,
            'connection_frequency': 115.0,
            'packet_entropy': 6.1,
            'inbound_bytes': 70000,
            'outbound_bytes': 329000,
            'connection_duration': 4.0
        }

        with self.app.app_context():
            execute_ai_pipeline(telemetry, persist=True)

            with get_db() as db:
                cursor = db.cursor()
                # Check threat_intelligence_reports
                cursor.execute("SELECT COUNT(*) AS cnt FROM threat_intelligence_reports WHERE device_id = 8;")
                intel_cnt = cursor.fetchone()['cnt']
                self.assertGreaterEqual(intel_cnt, 1)

                # Check security_alerts
                cursor.execute("SELECT COUNT(*) AS cnt FROM security_alerts WHERE device_id = 8;")
                alert_cnt = cursor.fetchone()['cnt']
                self.assertGreaterEqual(alert_cnt, 1)

    # --------------------------------------------------------------------------
    # Test 9: Duplicate alert prevention
    # --------------------------------------------------------------------------
    def test_09_duplicate_alert_prevention(self):
        """Test 9: Calling pipeline repeatedly within 300s suppresses duplicate alerts."""
        telemetry = {
            'device_id': 10,
            'packet_count': 13000,
            'average_packet_size': 46.0,
            'bytes_transferred': 598000,
            'connection_frequency': 290.0,
            'packet_entropy': 3.1,
            'inbound_bytes': 578000,
            'outbound_bytes': 20000,
            'connection_duration': 0.5
        }

        with self.app.app_context():
            # First call creates the alert
            res1 = execute_ai_pipeline(telemetry, persist=True)
            self.assertTrue(res1['alert_created'])
            first_code = res1['alert_code']

            # Second call within 300s suppresses duplicate
            res2 = execute_ai_pipeline(telemetry, persist=True)
            self.assertFalse(res2['alert_created'])
            self.assertEqual(res2['alert_code'], first_code)

            # Check database alert count for device 10 is strictly 1
            with get_db() as db:
                cursor = db.cursor()
                cursor.execute("SELECT COUNT(*) AS cnt FROM security_alerts WHERE device_id = 10;")
                cnt = cursor.fetchone()['cnt']
                self.assertEqual(cnt, 1)

    # --------------------------------------------------------------------------
    # Test 10: Unknown device handling
    # --------------------------------------------------------------------------
    def test_10_unknown_device_handling(self):
        """Test 10: Unknown device ID raises NotFoundError at service level and returns 404 in API."""
        unknown_telemetry = {
            'device_id': 9999,
            'packet_count': 500,
            'average_packet_size': 512.0,
            'bytes_transferred': 256000,
            'connection_frequency': 20.0,
            'packet_entropy': 4.5,
            'inbound_bytes': 150000,
            'outbound_bytes': 106000,
            'connection_duration': 15.0
        }

        # Service level
        with self.app.app_context():
            with self.assertRaises(NotFoundError):
                execute_ai_pipeline(unknown_telemetry, persist=False)

        # API level
        resp = self.client.post(
            '/api/ai/analyze',
            data=json.dumps(unknown_telemetry),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 404)
        self.assertFalse(resp.get_json()['success'])

    # --------------------------------------------------------------------------
    # Test 11: Invalid request handling
    # --------------------------------------------------------------------------
    def test_11_invalid_request_handling(self):
        """Test 11: Non-JSON, empty, or missing telemetry fields return HTTP 400 Bad Request."""
        # Non-JSON
        resp1 = self.client.post('/api/ai/analyze', data="bad_data")
        self.assertEqual(resp1.status_code, 400)

        # Empty JSON
        resp2 = self.client.post(
            '/api/ai/analyze',
            data=json.dumps({}),
            content_type='application/json'
        )
        self.assertEqual(resp2.status_code, 400)

        # Missing required telemetry fields
        resp3 = self.client.post(
            '/api/ai/analyze',
            data=json.dumps({'device_id': 1, 'packet_count': 100}),
            content_type='application/json'
        )
        self.assertEqual(resp3.status_code, 400)

    # --------------------------------------------------------------------------
    # Test 12: Missing model handling
    # --------------------------------------------------------------------------
    def test_12_missing_model_handling(self):
        """Test 12: When model artifact is missing, pipeline raises ModelUnavailableError / HTTP 500."""
        telemetry = {
            'device_id': 1,
            'packet_count': 320,
            'average_packet_size': 512.0,
            'bytes_transferred': 163840,
            'connection_frequency': 15.0,
            'packet_entropy': 4.5,
            'inbound_bytes': 98304,
            'outbound_bytes': 65536,
            'connection_duration': 20.0
        }

        pipeline = AIPipelineService()
        with patch.object(pipeline._anomaly_service, 'detect', side_effect=AIPipelineError("Model file missing")):
            with self.app.app_context():
                with self.assertRaises(AIPipelineError):
                    pipeline.run_pipeline(telemetry, persist_results=False)

    # --------------------------------------------------------------------------
    # Test 13: Model loading failure
    # --------------------------------------------------------------------------
    def test_13_model_loading_failure(self):
        """Test 13: Graceful exception handling when anomaly detector raises unexpected error."""
        telemetry = {
            'device_id': 2,
            'packet_count': 400,
            'average_packet_size': 500.0,
            'bytes_transferred': 200000,
            'connection_frequency': 12.0,
            'packet_entropy': 4.5,
            'inbound_bytes': 100000,
            'outbound_bytes': 100000,
            'connection_duration': 20.0
        }

        pipeline = AIPipelineService()
        with patch.object(pipeline._anomaly_service, 'detect', side_effect=RuntimeError("Joblib unpickle failure")):
            with self.app.app_context():
                with self.assertRaises(ModelUnavailableError):
                    pipeline.run_pipeline(telemetry, persist_results=False)

    # --------------------------------------------------------------------------
    # Test 14: Simulation-to-AI integration
    # --------------------------------------------------------------------------
    def test_14_simulation_to_ai_integration(self):
        """Test 14: NetworkSimulator generated telemetry flows directly into AIPipelineService and /simulate/threat."""
        simulator = NetworkSimulator()

        # Generate telemetry directly from simulator
        sim_telemetry = simulator.generate_simulated_telemetry_for_ai(device_id=3, threat_type='DoS')
        self.assertEqual(sim_telemetry['device_id'], 3)
        self.assertGreaterEqual(sim_telemetry['packet_count'], 10000)

        with self.app.app_context():
            result = execute_ai_pipeline(sim_telemetry, persist=False)
            self.assertEqual(result['analysis']['prediction'], 'ANOMALY')
            self.assertEqual(result['analysis']['threat_indicator'], 'DoS-like Traffic Spike')

        # Test POST /api/simulate/threat endpoint
        resp = self.client.post(
            '/api/simulate/threat',
            data=json.dumps({'deviceId': 'dev-3', 'threatType': 'DoS'}),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 200)
        json_data = resp.get_json()
        self.assertTrue(json_data['success'])
        self.assertIn('analysis', json_data)

    # --------------------------------------------------------------------------
    # Test 15: Existing API compatibility
    # --------------------------------------------------------------------------
    def test_15_existing_api_compatibility(self):
        """Test 15: Verify all existing Prompt 1-4 and Prompt 5-8 backend endpoints remain operational."""
        # 1. Health
        res_health = self.client.get('/api/health')
        self.assertEqual(res_health.status_code, 200)

        # 2. Devices
        res_dev = self.client.get('/api/devices')
        self.assertEqual(res_dev.status_code, 200)

        # 3. Dashboard
        res_dash = self.client.get('/api/dashboard')
        self.assertEqual(res_dash.status_code, 200)

        # 4. Traffic
        res_traf = self.client.get('/api/traffic')
        self.assertEqual(res_traf.status_code, 200)

        # 5. Alerts
        res_alerts = self.client.get('/api/alerts')
        self.assertEqual(res_alerts.status_code, 200)

        # 6. Intelligence summary
        res_intel = self.client.get('/api/intelligence/summary')
        self.assertEqual(res_intel.status_code, 200)

        # 7. AI Model metadata
        res_model = self.client.get('/api/ai/model')
        self.assertEqual(res_model.status_code, 200)

    # --------------------------------------------------------------------------
    # Test 16: Frontend API response compatibility
    # --------------------------------------------------------------------------
    def test_16_frontend_api_response_compatibility(self):
        """Test 16: Verify POST /api/ai/analyze matches exact Prompt 5 Section 3 contract and /api/threats renders for frontend."""
        payload = {
            "device_id": "PC03",
            "traffic_data": {
                "packet_count": 1500,
                "average_packet_size": 1200.0,
                "bytes_transferred": 850000,
                "connection_frequency": 95.0,
                "packet_entropy": 7.2,
                "inbound_bytes": 120000,
                "outbound_bytes": 730000,
                "connection_duration": 45.0
            }
        }

        resp = self.client.post(
            '/api/ai/analyze',
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        # Verify top-level structure required by Prompt 5 Section 3
        self.assertTrue(data['success'])
        self.assertEqual(data['device_id'], 7)  # PC 03 resolves to ID 7
        self.assertIn('device_status', data)
        self.assertIn('analysis', data)
        self.assertIn('evidence', data)
        self.assertIn('recommended_actions', data)
        self.assertIn('alert_created', data)
        self.assertIn('timestamp', data)

        analysis = data['analysis']
        self.assertIn('prediction', analysis)
        self.assertIn('anomaly_score', analysis)
        self.assertIn('threat_type', analysis)
        self.assertIn('severity', analysis)
        self.assertIn('threat_score', analysis)
        self.assertIn('confidence', analysis)
        self.assertIn('explanation', analysis)

        # Verify GET /api/threats for frontend ThreatsView
        threats_resp = self.client.get('/api/threats')
        self.assertEqual(threats_resp.status_code, 200)
        threats_json = threats_resp.get_json()
        self.assertTrue(threats_json['success'])
        self.assertIn('threats', threats_json)
        if len(threats_json['threats']) > 0:
            first = threats_json['threats'][0]
            self.assertIn('threatType', first)
            self.assertIn('affectedDeviceName', first)
            self.assertIn('anomalyScore', first)
            self.assertIn('explanation', first)


if __name__ == '__main__':
    unittest.main()
