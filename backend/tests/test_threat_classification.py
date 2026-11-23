"""
NetGuardian AI - Intelligent AI Threat Classification Engine Tests (Prompt 3)
Verifies:
1. Normal traffic classification -> 'Nominal Traffic' with LOW severity
2. Anomalous traffic classification -> correctly detects anomaly and assigns threat category
3. Suspicious outbound traffic classification -> high outbound traffic ratio triggers correct category
4. Abnormal connection frequency classification -> rapid connection attempts trigger correct category
5. Traffic spike / DoS detection -> massive packet count / throughput triggers DoS category
6. Severity calculation rules -> verify LOW, MEDIUM, HIGH, CRITICAL thresholds
7. Threat explanation and evidence generation -> verify explanation and evidence fields
8. Security recommendation generation -> verify non-destructive action is recommended
9. Database alert creation -> verify alert is stored in security_alerts table
10. Duplicate alert prevention -> verify second identical threat within time window suppresses duplicate
11. Flask API POST /api/ai/analyze -> test HTTP endpoint with valid payload, verify response format and status code
12. Invalid traffic input handling -> test endpoint with missing/invalid fields, verify 400 Bad Request
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
from services.threat_classifier import (
    THREAT_CATEGORIES,
    SEVERITY_THRESHOLDS,
    calculate_threat_severity,
    recommend_security_action,
    classify_threat,
    ThreatClassifierService,
    analyze_threat
)
from services.alert_service import AlertService


class ThreatClassificationTestCase(unittest.TestCase):
    """Integration and Unit Test Suite for AI Threat Classification Engine."""

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
        """Clean alerts table before each test to maintain strict isolation."""
        with self.app.app_context():
            with get_db() as db:
                db.execute("DELETE FROM security_alerts")
                db.commit()

    # --------------------------------------------------------------------------
    # Test 1: Normal traffic classification
    # --------------------------------------------------------------------------
    def test_01_normal_traffic_classification(self):
        """Test 1: Normal baseline traffic should be classified as 'Nominal Traffic' with LOW severity."""
        normal_traffic = {
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
            result = analyze_threat(normal_traffic, create_alert=False)

            self.assertEqual(result['threat_type'], 'Nominal Traffic')
            self.assertEqual(result['severity'], 'LOW')
            self.assertEqual(result['prediction'], 'NORMAL')
            self.assertFalse(result['is_confirmed_attack'])
            self.assertIn('normal', result['explanation'].lower())
            self.assertIn('No immediate action required', result['recommended_action'])
            self.assertFalse(result['alert_created'])

    # --------------------------------------------------------------------------
    # Test 2: Anomalous traffic classification
    # --------------------------------------------------------------------------
    def test_02_anomalous_traffic_classification(self):
        """Test 2: Correctly detects anomaly and assigns an appropriate threat category."""
        anomaly_traffic = {
            'device_id': 2,
            'packet_count': 4500,
            'average_packet_size': 85.0,
            'bytes_transferred': 382500,
            'connection_frequency': 120.0,
            'packet_entropy': 6.8,
            'inbound_bytes': 50000,
            'outbound_bytes': 332500,
            'connection_duration': 5.0
        }

        with self.app.app_context():
            result = analyze_threat(anomaly_traffic, create_alert=False)

            self.assertIn(result['threat_type'], THREAT_CATEGORIES)
            self.assertNotEqual(result['threat_type'], 'Nominal Traffic')
            self.assertIn(result['severity'], ['MEDIUM', 'HIGH', 'CRITICAL'])
            self.assertGreater(result['anomaly_score'], 0.45)
            self.assertIsInstance(result['explanation'], str)
            self.assertGreater(len(result['explanation']), 10)

    # --------------------------------------------------------------------------
    # Test 3: Suspicious outbound traffic classification
    # --------------------------------------------------------------------------
    def test_03_suspicious_outbound_traffic(self):
        """Test 3: High outbound traffic volume and ratio triggers 'Suspicious Outbound Traffic' or 'Potential Data Exfiltration'."""
        outbound_heavy_traffic = {
            'device_id': 3,
            'packet_count': 1800,
            'average_packet_size': 1200.0,
            'bytes_transferred': 2160000,
            'connection_frequency': 25.0,
            'packet_entropy': 6.0,
            'inbound_bytes': 100000,
            'outbound_bytes': 2060000,  # ~95% outbound
            'connection_duration': 30.0
        }

        with self.app.app_context():
            result = analyze_threat(outbound_heavy_traffic, create_alert=False)

            self.assertIn(
                result['threat_type'],
                ['Suspicious Outbound Traffic', 'Potential Data Exfiltration']
            )
            self.assertIn(result['severity'], ['MEDIUM', 'HIGH', 'CRITICAL'])
            self.assertGreaterEqual(result['features']['outbound_traffic_percentage'], 70.0)
            self.assertIn('outbound', result['explanation'].lower())

    # --------------------------------------------------------------------------
    # Test 4: Abnormal connection frequency classification
    # --------------------------------------------------------------------------
    def test_04_abnormal_connection_frequency(self):
        """Test 4: High connection frequency triggers 'Abnormal Connection Frequency' or 'Port Scanning'."""
        rapid_connections = {
            'device_id': 4,
            'packet_count': 850,
            'average_packet_size': 320.0,
            'bytes_transferred': 272000,
            'connection_frequency': 95.0,  # Elevated frequency
            'packet_entropy': 4.8,
            'inbound_bytes': 150000,
            'outbound_bytes': 122000,
            'connection_duration': 10.0
        }

        with self.app.app_context():
            result = analyze_threat(rapid_connections, create_alert=False)

            self.assertIn(
                result['threat_type'],
                ['Abnormal Connection Frequency', 'Port Scanning', 'Suspicious Network Communication']
            )
            self.assertGreaterEqual(result['features']['connection_frequency'], 75.0)

    # --------------------------------------------------------------------------
    # Test 5: Traffic spike / DoS detection
    # --------------------------------------------------------------------------
    def test_05_traffic_spike_dos_detection(self):
        """Test 5: Massive packet count / extreme packet rate triggers DoS category."""
        dos_flood = {
            'device_id': 5,
            'packet_count': 12500,
            'average_packet_size': 48.0,
            'bytes_transferred': 600000,
            'connection_frequency': 280.0,
            'packet_entropy': 3.2,
            'inbound_bytes': 580000,
            'outbound_bytes': 20000,
            'connection_duration': 0.8  # ~15,625 packets/sec
        }

        with self.app.app_context():
            result = analyze_threat(dos_flood, create_alert=False)

            self.assertEqual(result['threat_type'], 'Denial of Service (DoS) - like traffic spikes')
            self.assertEqual(result['severity'], 'CRITICAL')
            self.assertIn('flood', result['explanation'].lower())

    # --------------------------------------------------------------------------
    # Test 6: Severity calculation rules
    # --------------------------------------------------------------------------
    def test_06_severity_calculation_rules(self):
        """Test 6: Verify LOW, MEDIUM, HIGH, CRITICAL severity evaluation thresholds."""
        features_sample = {'packet_entropy': 4.0, 'outbound_bytes': 1000, 'packets_per_second': 100}

        # Nominal / Low Score -> LOW
        sev_low = calculate_threat_severity(0.20, features_sample, 'Nominal Traffic')
        self.assertEqual(sev_low, 'LOW')

        # Score in [0.52, 0.68) -> MEDIUM
        sev_med = calculate_threat_severity(0.58, features_sample, 'Abnormal Connection Frequency')
        self.assertEqual(sev_med, 'MEDIUM')

        # Score in [0.68, 0.80) -> HIGH
        sev_high = calculate_threat_severity(0.72, features_sample, 'Suspicious Outbound Traffic')
        self.assertEqual(sev_high, 'HIGH')

        # Score >= 0.80 -> CRITICAL
        sev_crit = calculate_threat_severity(0.85, features_sample, 'Suspicious Outbound Traffic')
        self.assertEqual(sev_crit, 'CRITICAL')

        # Specific threat escalation: High-entropy Data Exfiltration -> CRITICAL
        exfil_features = {'packet_entropy': 7.95, 'outbound_bytes': 15_000_000}
        sev_exfil = calculate_threat_severity(0.70, exfil_features, 'Potential Data Exfiltration')
        self.assertEqual(sev_exfil, 'CRITICAL')

        # Specific threat escalation: Massive DoS -> CRITICAL
        dos_features = {'packets_per_second': 12000.0}
        sev_dos = calculate_threat_severity(0.65, dos_features, 'Denial of Service (DoS) - like traffic spikes')
        self.assertEqual(sev_dos, 'CRITICAL')

    # --------------------------------------------------------------------------
    # Test 7: Threat explanation and evidence generation
    # --------------------------------------------------------------------------
    def test_07_threat_explanation_and_evidence(self):
        """Test 7: Verify explanation and evidence fields are present and mathematically grounded."""
        traffic_data = {
            'device_id': 6,
            'packet_count': 5500,
            'average_packet_size': 120.0,
            'bytes_transferred': 660000,
            'connection_frequency': 110.0,
            'packet_entropy': 7.4,
            'inbound_bytes': 50000,
            'outbound_bytes': 610000,
            'connection_duration': 2.0
        }

        with self.app.app_context():
            result = analyze_threat(traffic_data, create_alert=False)

            self.assertIn('explanation', result)
            self.assertIn('evidence', result)
            self.assertIsInstance(result['evidence'], dict)

            # Check evidence fields
            evidence = result['evidence']
            self.assertIn('anomaly_score', evidence)
            self.assertIn('outbound_bytes', evidence)
            self.assertIn('inbound_bytes', evidence)
            self.assertIn('packet_entropy', evidence)
            self.assertIn('connection_frequency', evidence)

            # Check that explanation is substantive prose with numbers
            self.assertGreater(len(result['explanation']), 20)

    # --------------------------------------------------------------------------
    # Test 8: Security recommendation generation
    # --------------------------------------------------------------------------
    def test_08_security_recommendation_generation(self):
        """Test 8: Verify actionable, non-destructive security recommendations."""
        # Low severity
        rec_nominal = recommend_security_action('Nominal Traffic', 'LOW')
        self.assertIn('No immediate action required', rec_nominal)

        # DoS recommendation
        rec_dos = recommend_security_action('Denial of Service (DoS) - like traffic spikes', 'CRITICAL')
        self.assertIn('rate-limiting', rec_dos.lower())

        # Data Exfiltration recommendation
        rec_exfil = recommend_security_action('Potential Data Exfiltration', 'HIGH')
        self.assertIn('egress', rec_exfil.lower())

        # Port scanning recommendation
        rec_scan = recommend_security_action('Port Scanning', 'MEDIUM')
        self.assertIn('sweep', rec_scan.lower())

    # --------------------------------------------------------------------------
    # Test 9: Database alert creation
    # --------------------------------------------------------------------------
    def test_09_database_alert_creation(self):
        """Test 9: Verify alert is stored in security_alerts table upon anomaly detection."""
        malicious_traffic = {
            'device_id': 1,
            'packet_count': 10000,
            'average_packet_size': 50.0,
            'bytes_transferred': 500000,
            'connection_frequency': 250.0,
            'packet_entropy': 3.5,
            'inbound_bytes': 480000,
            'outbound_bytes': 20000,
            'connection_duration': 0.5
        }

        with self.app.app_context():
            result = analyze_threat(malicious_traffic, create_alert=True)

            self.assertTrue(result['alert_created'])
            self.assertIsNotNone(result['alert_code'])
            self.assertTrue(result['alert_code'].startswith('ALT-'))

            # Check SQLite security_alerts database directly
            with get_db() as db:
                cursor = db.cursor()
                cursor.execute("SELECT * FROM security_alerts WHERE alert_code = ?", (result['alert_code'],))
                row = cursor.fetchone()

                self.assertIsNotNone(row)
                self.assertEqual(row['device_id'], 1)
                self.assertEqual(row['threat_type'], result['threat_type'])
                self.assertEqual(row['severity'], result['severity'])
                self.assertEqual(row['status'], 'ACTIVE')
                self.assertGreater(row['anomaly_score'], 0.0)

    # --------------------------------------------------------------------------
    # Test 10: Duplicate alert prevention
    # --------------------------------------------------------------------------
    def test_10_duplicate_alert_prevention(self):
        """Test 10: Second identical threat within time window suppresses duplicate alert."""
        repeated_traffic = {
            'device_id': 2,
            'packet_count': 9500,
            'average_packet_size': 45.0,
            'bytes_transferred': 427500,
            'connection_frequency': 220.0,
            'packet_entropy': 3.5,
            'inbound_bytes': 410000,
            'outbound_bytes': 17500,
            'connection_duration': 0.5
        }

        with self.app.app_context():
            # First call creates the alert
            res1 = analyze_threat(repeated_traffic, create_alert=True)
            self.assertTrue(res1['alert_created'])
            self.assertFalse(res1['duplicate_suppressed'])
            first_alert_code = res1['alert_code']

            # Second call within 300s suppresses duplicate alert
            res2 = analyze_threat(repeated_traffic, create_alert=True)
            self.assertFalse(res2['alert_created'])
            self.assertTrue(res2['duplicate_suppressed'])
            self.assertEqual(res2['alert_code'], first_alert_code)

            # Verify only 1 alert exists in database for this device & threat type
            with get_db() as db:
                cursor = db.cursor()
                cursor.execute("SELECT COUNT(*) as cnt FROM security_alerts WHERE device_id = 2")
                count = cursor.fetchone()['cnt']
                self.assertEqual(count, 1)

    # --------------------------------------------------------------------------
    # Test 11: Flask API POST /api/ai/analyze (Nested and Flat formats)
    # --------------------------------------------------------------------------
    def test_11_flask_api_analyze_endpoint(self):
        """Test 11: Test POST /api/ai/analyze endpoint with valid payload, verifying HTTP 200 and schema."""
        # 1. Test nested payload format
        nested_payload = {
            "device_id": 3,
            "traffic_data": {
                "packet_count": 9200,
                "average_packet_size": 42.0,
                "bytes_transferred": 386400,
                "connection_frequency": 240.0,
                "packet_entropy": 3.8,
                "inbound_bytes": 380000,
                "outbound_bytes": 6400,
                "connection_duration": 0.4
            }
        }

        response = self.client.post(
            '/api/ai/analyze',
            data=json.dumps(nested_payload),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()

        self.assertTrue(json_data['success'])
        data = json_data['data']
        self.assertEqual(data['device_id'], 3)
        self.assertIn('prediction', data)
        self.assertIn('threat_type', data)
        self.assertIn('severity', data)
        self.assertIn('anomaly_score', data)
        self.assertIn('explanation', data)
        self.assertIn('recommended_action', data)
        self.assertIn('evidence', data)
        self.assertIn('features', data)

        # 2. Test flat payload format
        flat_payload = {
            "device_id": 4,
            "packet_count": 300,
            "average_packet_size": 500.0,
            "bytes_transferred": 150000,
            "connection_frequency": 12.0,
            "packet_entropy": 4.5,
            "inbound_bytes": 90000,
            "outbound_bytes": 60000,
            "connection_duration": 15.0
        }

        flat_response = self.client.post(
            '/api/ai/analyze',
            data=json.dumps(flat_payload),
            content_type='application/json'
        )
        self.assertEqual(flat_response.status_code, 200)
        flat_data = flat_response.get_json()['data']
        self.assertEqual(flat_data['device_id'], 4)
        self.assertEqual(flat_data['threat_type'], 'Nominal Traffic')

    # --------------------------------------------------------------------------
    # Test 12: Invalid traffic input handling
    # --------------------------------------------------------------------------
    def test_12_invalid_traffic_input_handling(self):
        """Test 12: Test endpoint with missing/invalid fields, verify 400 Bad Request."""
        # Non-JSON content type
        resp_non_json = self.client.post('/api/ai/analyze', data="not-json")
        self.assertEqual(resp_non_json.status_code, 400)
        self.assertFalse(resp_non_json.get_json()['success'])

        # Empty JSON object
        resp_empty = self.client.post(
            '/api/ai/analyze',
            data=json.dumps({}),
            content_type='application/json'
        )
        self.assertEqual(resp_empty.status_code, 400)

        # Missing required telemetry fields
        resp_missing = self.client.post(
            '/api/ai/analyze',
            data=json.dumps({'device_id': 5, 'packet_count': 100}),
            content_type='application/json'
        )
        self.assertEqual(resp_missing.status_code, 400)
        self.assertIn('Validation error', resp_missing.get_json()['message'])

        # Non-numeric telemetry field
        resp_invalid_type = self.client.post(
            '/api/ai/analyze',
            data=json.dumps({
                'device_id': 5,
                'packet_count': "many_packets",
                'average_packet_size': 500.0,
                'bytes_transferred': 150000,
                'connection_frequency': 12.0,
                'packet_entropy': 4.5,
                'inbound_bytes': 90000,
                'outbound_bytes': 60000,
                'connection_duration': 15.0
            }),
            content_type='application/json'
        )
        self.assertEqual(resp_invalid_type.status_code, 400)

    # --------------------------------------------------------------------------
    # Bonus Test: Threat categories endpoint
    # --------------------------------------------------------------------------
    def test_13_categories_endpoint(self):
        """Verify GET /api/ai/categories returns canonical threat categories."""
        resp = self.client.get('/api/ai/categories')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()['data']
        self.assertEqual(len(data['categories']), 8)
        self.assertIn('Port Scanning', data['categories'])
        self.assertIn('Denial of Service (DoS) - like traffic spikes', data['categories'])


if __name__ == '__main__':
    unittest.main()
