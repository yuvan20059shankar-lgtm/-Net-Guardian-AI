"""
NetGuardian AI - AI Threat Intelligence Engine Tests (AI/ML Prompt 4)
Tagline: Detect. Defend. Recover. Automatically.

Verifies:
1. Normal traffic intelligence analysis
2. Suspicious outbound traffic
3. Abnormal connection frequency
4. DoS-like traffic spike
5. Repeated anomalies
6. Threat score calculation
7. Confidence calculation
8. Evidence generation
9. Dynamic threat explanations
10. Recommended security actions
11. Historical threat analysis
12. Missing historical data
13. Invalid device ID
14. Invalid API input
15. Flask API response structure
16. Database persistence
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
from services.threat_intelligence import (
    THREAT_INDICATORS,
    CATEGORY_TO_INDICATOR_MAP,
    ThreatIntelligenceService,
    analyze_intelligence
)
from services.device_service import NotFoundError, ValidationError


class ThreatIntelligenceTestCase(unittest.TestCase):
    """Test suite covering all 16 test requirements for the Threat Intelligence Engine."""

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
        """Reset alerts and intelligence reports before each test to maintain strict isolation."""
        with self.app.app_context():
            with get_db() as db:
                db.execute("DELETE FROM threat_intelligence_reports")
                db.execute("DELETE FROM security_alerts")
                db.commit()

    # --------------------------------------------------------------------------
    # Test 1: Normal traffic intelligence analysis
    # --------------------------------------------------------------------------
    def test_01_normal_traffic_intelligence(self):
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
            result = analyze_intelligence(normal_traffic, persist=False)

            self.assertEqual(result['threat_indicator'], 'Nominal Traffic')
            self.assertEqual(result['severity'], 'LOW')
            self.assertLessEqual(result['threat_score'], 35)
            self.assertIn(result['confidence'], ['LOW', 'MEDIUM', 'HIGH'])
            self.assertIn('routine monitoring', result['recommended_actions'][0].lower())
            self.assertIn('standard operational parameters', result['explanation'])

    # --------------------------------------------------------------------------
    # Test 2: Suspicious outbound traffic
    # --------------------------------------------------------------------------
    def test_02_suspicious_outbound_traffic(self):
        """Test 2: High outbound traffic volume triggers 'Suspicious Outbound Traffic' or 'Potential Data Exfiltration'."""
        outbound_traffic = {
            'device_id': 3,
            'packet_count': 1800,
            'average_packet_size': 1200.0,
            'bytes_transferred': 2160000,
            'connection_frequency': 25.0,
            'packet_entropy': 6.2,
            'inbound_bytes': 100000,
            'outbound_bytes': 2060000,  # ~95% outbound
            'connection_duration': 30.0
        }

        with self.app.app_context():
            result = analyze_intelligence(outbound_traffic, persist=False)

            self.assertIn(
                result['threat_indicator'],
                ['Suspicious Outbound Traffic', 'Potential Data Exfiltration']
            )
            self.assertIn(result['severity'], ['MEDIUM', 'HIGH', 'CRITICAL'])
            self.assertGreaterEqual(result['threat_score'], 50)
            self.assertGreaterEqual(result['evidence']['outbound_bytes'], 1000000)

    # --------------------------------------------------------------------------
    # Test 3: Abnormal connection frequency
    # --------------------------------------------------------------------------
    def test_03_abnormal_connection_frequency(self):
        """Test 3: Rapid connection bursts trigger 'Abnormal Connection Frequency' or related indicator."""
        rapid_connections = {
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
            result = analyze_intelligence(rapid_connections, persist=False)

            self.assertIn(
                result['threat_indicator'],
                ['Abnormal Connection Frequency', 'Port Scanning', 'Suspicious Network Communication']
            )
            self.assertGreaterEqual(result['evidence']['connection_frequency'], 75.0)

    # --------------------------------------------------------------------------
    # Test 4: DoS-like traffic spike
    # --------------------------------------------------------------------------
    def test_04_dos_like_traffic_spike(self):
        """Test 4: Massive packet flood triggers 'DoS-like Traffic Spike' with CRITICAL severity."""
        dos_flood = {
            'device_id': 5,
            'packet_count': 14000,
            'average_packet_size': 45.0,
            'bytes_transferred': 630000,
            'connection_frequency': 310.0,
            'packet_entropy': 3.1,
            'inbound_bytes': 610000,
            'outbound_bytes': 20000,
            'connection_duration': 0.5  # 28,000 packets/sec
        }

        with self.app.app_context():
            result = analyze_intelligence(dos_flood, persist=False)

            self.assertEqual(result['threat_indicator'], 'DoS-like Traffic Spike')
            self.assertEqual(result['severity'], 'CRITICAL')
            self.assertGreaterEqual(result['threat_score'], 80)
            self.assertIn('flood', result['explanation'].lower())

    # --------------------------------------------------------------------------
    # Test 5: Repeated anomalies
    # --------------------------------------------------------------------------
    def test_05_repeated_anomalies(self):
        """Test 5: Device with multiple historical alerts triggers 'Repeated Anomalous Behaviour'."""
        with self.app.app_context():
            # Seed 2 historical alerts for Device 2
            with get_db() as db:
                db.execute("""
                    INSERT INTO security_alerts (
                        alert_code, device_id, threat_type, description,
                        severity, status, detection_source, recommended_action
                    ) VALUES 
                    ('ALT-H1', 2, 'Suspicious Outbound Traffic', 'Prior outbound spike', 'HIGH', 'ACTIVE', 'Test Sensor', 'Monitor'),
                    ('ALT-H2', 2, 'Abnormal Connection Frequency', 'Prior sweep', 'MEDIUM', 'ACTIVE', 'Test Sensor', 'Inspect');
                """)
                db.commit()

            # Now send new anomalous traffic for Device 2
            repeated_traffic = {
                'device_id': 2,
                'packet_count': 5000,
                'average_packet_size': 90.0,
                'bytes_transferred': 450000,
                'connection_frequency': 130.0,
                'packet_entropy': 6.5,
                'inbound_bytes': 80000,
                'outbound_bytes': 370000,
                'connection_duration': 4.0
            }

            result = analyze_intelligence(repeated_traffic, persist=False)

            self.assertEqual(result['threat_indicator'], 'Repeated Anomalous Behaviour')
            self.assertGreaterEqual(result['threat_score'], 70)
            self.assertIn('recurring', result['explanation'].lower())
            self.assertGreaterEqual(result['evidence']['related_historical_alerts_count'], 2)

    # --------------------------------------------------------------------------
    # Test 6: Threat score calculation
    # --------------------------------------------------------------------------
    def test_06_threat_score_calculation(self):
        """Test 6: Verify 0-100 composite threat score calculation across behavioral tiers."""
        features = {
            'traffic_volume_deviation': 5.2,
            'connection_rate_deviation': 4.1,
            'traffic_entropy_deviation': 1.8
        }

        # 1. Nominal low score
        score_nominal = ThreatIntelligenceService.calculate_threat_score(
            anomaly_score=0.20,
            traffic_features={'traffic_volume_deviation': 0.5, 'connection_rate_deviation': 0.2, 'traffic_entropy_deviation': 0.1},
            indicator='Nominal Traffic',
            historical_alerts_count=0
        )
        self.assertLessEqual(score_nominal, 25)
        self.assertGreaterEqual(score_nominal, 0)

        # 2. Elevated anomaly with high deviation and historical alerts
        score_high = ThreatIntelligenceService.calculate_threat_score(
            anomaly_score=0.82,
            traffic_features=features,
            indicator='DoS-like Traffic Spike',
            historical_alerts_count=2
        )
        self.assertGreaterEqual(score_high, 80)
        self.assertLessEqual(score_high, 100)

        # 3. Repeated anomalous behaviour baseline
        score_repeat = ThreatIntelligenceService.calculate_threat_score(
            anomaly_score=0.60,
            traffic_features=features,
            indicator='Repeated Anomalous Behaviour',
            historical_alerts_count=3
        )
        self.assertGreaterEqual(score_repeat, 70)

    # --------------------------------------------------------------------------
    # Test 7: Confidence calculation
    # --------------------------------------------------------------------------
    def test_07_confidence_calculation(self):
        """Test 7: Verify confidence reflects evidence factors (HIGH: >=3 factors, MEDIUM: 1-2, LOW: 0)."""
        # Multi-factor corroboration: baseline present + vol dev >= 2 + conn dev >= 2 + out_pct >= 75%
        multi_factor_features = {
            'traffic_volume_deviation': 3.5,
            'connection_rate_deviation': 2.8,
            'traffic_entropy_deviation': 0.5,
            'outbound_traffic_percentage': 88.0,
            'inbound_outbound_ratio': 0.12,
            'packets_per_second': 4200.0
        }
        conf_high = ThreatIntelligenceService.calculate_confidence(
            traffic_features=multi_factor_features,
            anomaly_score=0.75,
            has_baseline=True,
            historical_alerts_count=1
        )
        self.assertEqual(conf_high, 'HIGH')

        # Single factor
        single_factor_features = {
            'traffic_volume_deviation': 0.5,
            'connection_rate_deviation': 0.4,
            'traffic_entropy_deviation': 0.2,
            'outbound_traffic_percentage': 52.0,
            'inbound_outbound_ratio': 0.95,
            'packets_per_second': 120.0
        }
        conf_med = ThreatIntelligenceService.calculate_confidence(
            traffic_features=single_factor_features,
            anomaly_score=0.65,
            has_baseline=True,  # 1 factor
            historical_alerts_count=0
        )
        self.assertEqual(conf_med, 'MEDIUM')

        # Zero factors
        conf_low = ThreatIntelligenceService.calculate_confidence(
            traffic_features=single_factor_features,
            anomaly_score=0.65,
            has_baseline=False,
            historical_alerts_count=0
        )
        self.assertEqual(conf_low, 'LOW')

    # --------------------------------------------------------------------------
    # Test 8: Evidence generation
    # --------------------------------------------------------------------------
    def test_08_evidence_generation(self):
        """Test 8: Verify evidence collection contains all available real telemetry and device fields."""
        traffic = {
            'device_id': 1,
            'packet_count': 6000,
            'average_packet_size': 110.0,
            'bytes_transferred': 660000,
            'connection_frequency': 140.0,
            'packet_entropy': 7.1,
            'inbound_bytes': 60000,
            'outbound_bytes': 600000,
            'connection_duration': 3.0
        }

        with self.app.app_context():
            result = analyze_intelligence(traffic, persist=False)
            evidence = result['evidence']

            self.assertIn('device_id', evidence)
            self.assertIn('device_name', evidence)
            self.assertIn('device_ip', evidence)
            self.assertIn('packet_count', evidence)
            self.assertIn('average_packet_size', evidence)
            self.assertIn('inbound_bytes', evidence)
            self.assertIn('outbound_bytes', evidence)
            self.assertIn('connection_frequency', evidence)
            self.assertIn('traffic_volume_deviation', evidence)
            self.assertIn('anomaly_score', evidence)
            self.assertIn('threat_classification', evidence)
            self.assertIn('detection_timestamp', evidence)
            self.assertIn('related_historical_alerts_count', evidence)

    # --------------------------------------------------------------------------
    # Test 9: Dynamic threat explanations
    # --------------------------------------------------------------------------
    def test_09_dynamic_threat_explanations(self):
        """Test 9: Verify dynamic threat explanations contain actual metrics and non-definitive wording."""
        features = {
            'outbound_bytes': 2500000,
            'inbound_bytes': 100000,
            'outbound_traffic_percentage': 96.1,
            'connection_frequency': 85.0,
            'packets_per_second': 5200.0,
            'average_packet_size': 480.0,
            'packet_entropy': 7.6,
            'traffic_volume_deviation': 4.8,
            'connection_rate_deviation': 3.2
        }

        explanation = ThreatIntelligenceService.generate_threat_explanation(
            device_name="Server 01",
            device_ip="192.168.1.10",
            indicator="Potential Data Exfiltration",
            severity="CRITICAL",
            features=features,
            anomaly_score=0.85,
            historical_count=1
        )

        self.assertIn("Server 01", explanation)
        self.assertIn("192.168.1.10", explanation)
        self.assertIn("2,500,000 bytes", explanation)
        self.assertIn("96.1%", explanation)
        self.assertIn("requires investigation", explanation.lower())

    # --------------------------------------------------------------------------
    # Test 10: Recommended security actions
    # --------------------------------------------------------------------------
    def test_10_recommended_security_actions(self):
        """Test 10: Verify non-destructive recommendations return a list tailored to indicator and severity."""
        # Low severity
        actions_low = ThreatIntelligenceService.get_recommended_actions('Nominal Traffic', 'LOW')
        self.assertIsInstance(actions_low, list)
        self.assertGreaterEqual(len(actions_low), 2)
        self.assertIn("Continue routine monitoring", actions_low[0])

        # Critical DoS
        actions_dos = ThreatIntelligenceService.get_recommended_actions('DoS-like Traffic Spike', 'CRITICAL')
        self.assertIsInstance(actions_dos, list)
        self.assertTrue(any("rate-limiting" in a.lower() for a in actions_dos))
        self.assertTrue(any("simulated isolation" in a.lower() for a in actions_dos))

        # High Exfiltration
        actions_exfil = ThreatIntelligenceService.get_recommended_actions('Potential Data Exfiltration', 'HIGH')
        self.assertTrue(any("entropy" in a.lower() for a in actions_exfil))

    # --------------------------------------------------------------------------
    # Test 11: Historical threat analysis
    # --------------------------------------------------------------------------
    def test_11_historical_threat_analysis(self):
        """Test 11: Verify historical threat analysis summarizes recurring trends when records exist."""
        with self.app.app_context():
            # Seed 3 historical alerts
            with get_db() as db:
                db.execute("""
                    INSERT INTO security_alerts (
                        alert_code, device_id, threat_type, description,
                        severity, status, detection_source, recommended_action
                    ) VALUES 
                    ('ALT-T1', 1, 'Denial of Service (DoS) - like traffic spikes', 'Ingress surge', 'CRITICAL', 'ACTIVE', 'Sensor', 'Rate limit'),
                    ('ALT-T2', 1, 'Denial of Service (DoS) - like traffic spikes', 'Repeat surge', 'HIGH', 'ACTIVE', 'Sensor', 'Rate limit'),
                    ('ALT-T3', 2, 'Suspicious Outbound Traffic', 'Data burst', 'MEDIUM', 'ACTIVE', 'Sensor', 'Review');
                """)
                db.commit()

            history = ThreatIntelligenceService.analyze_history()

            self.assertEqual(history['status'], 'sufficient_data')
            self.assertGreaterEqual(history['total_records'], 3)
            self.assertGreater(len(history['frequently_detected_indicators']), 0)
            self.assertGreater(len(history['repeated_anomalies']), 0)
            self.assertEqual(history['repeated_anomalies'][0]['device_id'], 1)

    # --------------------------------------------------------------------------
    # Test 12: Missing historical data
    # --------------------------------------------------------------------------
    def test_12_missing_historical_data(self):
        """Test 12: When database has < 2 records, analyze_history() returns informative message."""
        with self.app.app_context():
            # Table is empty due to setUp()
            history = ThreatIntelligenceService.analyze_history()

            self.assertEqual(history['status'], 'insufficient_data')
            self.assertIn("Insufficient historical threat data", history['message'])
            self.assertEqual(history['repeated_anomalies'], [])

    # --------------------------------------------------------------------------
    # Test 13: Invalid device ID
    # --------------------------------------------------------------------------
    def test_13_invalid_device_id(self):
        """Test 13: Non-existent device ID raises NotFoundError or returns 404 in API."""
        # Service level
        with self.app.app_context():
            with self.assertRaises(NotFoundError):
                ThreatIntelligenceService.get_device_intelligence_profile(999)

        # API level
        resp = self.client.get('/api/intelligence/device/999')
        self.assertEqual(resp.status_code, 404)
        self.assertFalse(resp.get_json()['success'])

    # --------------------------------------------------------------------------
    # Test 14: Invalid API input
    # --------------------------------------------------------------------------
    def test_14_invalid_api_input(self):
        """Test 14: Test POST /api/intelligence/analyze with invalid payloads, verifying 400 Bad Request."""
        # Non-JSON content type
        resp_non_json = self.client.post('/api/intelligence/analyze', data="non-json")
        self.assertEqual(resp_non_json.status_code, 400)

        # Empty JSON
        resp_empty = self.client.post(
            '/api/intelligence/analyze',
            data=json.dumps({}),
            content_type='application/json'
        )
        self.assertEqual(resp_empty.status_code, 400)

        # Missing required telemetry fields
        resp_missing = self.client.post(
            '/api/intelligence/analyze',
            data=json.dumps({'device_id': 1, 'packet_count': 100}),
            content_type='application/json'
        )
        self.assertEqual(resp_missing.status_code, 400)

    # --------------------------------------------------------------------------
    # Test 15: Flask API response structure
    # --------------------------------------------------------------------------
    def test_15_flask_api_response_structure(self):
        """Test 15: Verify POST /api/intelligence/analyze conforms to Prompt 4 response contract."""
        payload = {
            "device_id": 3,
            "traffic_data": {
                "packet_count": 850,
                "average_packet_size": 1200.0,
                "bytes_transferred": 1020000,
                "connection_frequency": 95.0,
                "packet_entropy": 6.8,
                "inbound_bytes": 120000,
                "outbound_bytes": 900000,
                "connection_duration": 15.0
            }
        }

        resp = self.client.post(
            '/api/intelligence/analyze',
            data=json.dumps(payload),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 200)
        json_data = resp.get_json()

        self.assertTrue(json_data['success'])
        data = json_data['data']

        # Verify exact required fields
        self.assertEqual(data['device_id'], 3)
        self.assertIn('device_ip', data)
        self.assertIn('threat_indicator', data)
        self.assertIn('severity', data)
        self.assertIn('threat_score', data)
        self.assertIn('confidence', data)
        self.assertIn('explanation', data)
        self.assertIn('evidence', data)
        self.assertIn('recommended_actions', data)
        self.assertIn('timestamp', data)

        self.assertIsInstance(data['threat_score'], int)
        self.assertIn(data['confidence'], ['LOW', 'MEDIUM', 'HIGH'])
        self.assertIsInstance(data['recommended_actions'], list)

    # --------------------------------------------------------------------------
    # Test 16: Database persistence
    # --------------------------------------------------------------------------
    def test_16_database_persistence(self):
        """Test 16: Verify report is persisted in threat_intelligence_reports and retrievable via API."""
        traffic = {
            'device_id': 2,
            'packet_count': 4000,
            'average_packet_size': 120.0,
            'bytes_transferred': 480000,
            'connection_frequency': 110.0,
            'packet_entropy': 6.2,
            'inbound_bytes': 80000,
            'outbound_bytes': 400000,
            'connection_duration': 5.0
        }

        # Analyze and persist
        resp = self.client.post(
            '/api/intelligence/analyze',
            data=json.dumps(traffic),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 200)

        # Check GET /api/intelligence/threats
        threats_resp = self.client.get('/api/intelligence/threats')
        self.assertEqual(threats_resp.status_code, 200)
        threats_data = threats_resp.get_json()['data']
        self.assertGreaterEqual(threats_data['count'], 1)

        # Check GET /api/intelligence/summary
        sum_resp = self.client.get('/api/intelligence/summary')
        self.assertEqual(sum_resp.status_code, 200)
        sum_data = sum_resp.get_json()['data']
        self.assertGreaterEqual(sum_data['total_reports'], 1)

        # Check SQLite database directly
        with self.app.app_context():
            with get_db() as db:
                cursor = db.cursor()
                cursor.execute("SELECT COUNT(*) AS cnt FROM threat_intelligence_reports;")
                count = cursor.fetchone()['cnt']
                self.assertGreaterEqual(count, 1)


if __name__ == '__main__':
    unittest.main()
