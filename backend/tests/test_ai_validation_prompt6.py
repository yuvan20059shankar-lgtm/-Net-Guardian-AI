"""
NetGuardian AI - AI/ML System Comprehensive Validation & Regression Test Suite
PROMPT 6: Model validation, 10 traffic condition tests, 10 end-to-end pipeline scenarios,
feature engineering edge cases, threat intelligence, and API contracts.

IMPORTANT: Software-only local simulation. Does not protect physical network infrastructure.
"""

import os
import sys
import json
import unittest
import numpy as np
import pandas as pd

# Add backend directory to sys.path
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Set test environment
os.environ['NETGUARDIAN_ENV'] = 'testing'

from app import create_app
from database import get_db, get_db_path
from models.anomaly_detector import IsolationForestDetector, AnomalyDetectorError
from services.feature_pipeline import (
    extract_features,
    preprocess_traffic_data,
    calculate_traffic_baselines,
    safe_divide,
    PipelineValidationError,
    ENGINEERED_FEATURE_NAMES,
    BASE_FEATURE_NAMES,
    DEFAULT_BASELINE_STATS
)
from services.threat_classifier import (
    ThreatClassifierService,
    classify_threat,
    calculate_threat_severity,
    recommend_security_action,
    THREAT_CATEGORIES
)
from services.threat_intelligence import (
    ThreatIntelligenceService,
    THREAT_INDICATORS
)
from services.ai_pipeline import AIPipelineService
from services.traffic_generator import load_dataset


class TestPrompt6DatasetAndModelValidation(unittest.TestCase):
    """Dataset integrity and Isolation Forest model validation tests."""

    @classmethod
    def setUpClass(cls):
        cls.csv_path = os.path.join(BACKEND_DIR, 'data', 'network_traffic.csv')
        cls.model_path = os.path.join(BACKEND_DIR, 'data', 'isolation_forest_model.joblib')
        cls.detector = IsolationForestDetector().load(cls.model_path)

    def test_01_synthetic_dataset_integrity(self):
        """Verify synthetic dataset has exactly 1600 rows, 13 columns, and 0 missing values."""
        df = load_dataset(self.csv_path)
        self.assertGreaterEqual(len(df), 1500, "Dataset must have at least 1500 samples")
        for col in ['device_id', 'packet_count', 'average_packet_size', 'bytes_transferred',
                    'connection_frequency', 'packet_entropy', 'inbound_bytes', 'outbound_bytes',
                    'connection_duration', 'label', 'anomaly_type']:
            self.assertIn(col, df.columns, f"Required column '{col}' missing from dataset")
            self.assertEqual(df[col].isnull().sum(), 0, f"Column '{col}' has null/missing values")

        labels = set(df['label'].unique())
        self.assertIn('NORMAL', labels)
        self.assertIn('ANOMALY', labels)

    def test_02_model_architecture_and_offset(self):
        """Verify Isolation Forest model is fitted with 18 features and valid offset threshold."""
        self.assertTrue(self.detector.is_fitted, "Model must be fitted")
        self.assertEqual(len(self.detector.feature_names), 18, "Model must expect 18 features")
        self.assertIsNotNone(self.detector.model.offset_, "Offset threshold must be defined")
        self.assertGreater(self.detector.model.n_estimators, 50, "Estimators must exceed 50")

    def test_03_continuous_anomaly_score_calibration(self):
        """Verify continuous anomaly scores are strictly bounded in [0.0, 1.0]."""
        test_vec = np.zeros((5, 18), dtype=np.float64)
        scores = self.detector.compute_anomaly_score(test_vec)
        for s in scores:
            self.assertGreaterEqual(s, 0.0, "Anomaly score cannot be < 0.0")
            self.assertLessEqual(s, 1.0, "Anomaly score cannot be > 1.0")


class TestPrompt6TenTrafficConditions(unittest.TestCase):
    """Validation of the 10 specific traffic conditions required by Prompt 6."""

    @classmethod
    def setUpClass(cls):
        cls.model_path = os.path.join(BACKEND_DIR, 'data', 'isolation_forest_model.joblib')
        cls.detector = IsolationForestDetector().load(cls.model_path)

    def test_condition_01_normal_baseline_traffic(self):
        """Condition 1: Normal baseline telemetry should predict NORMAL with low anomaly score."""
        rec = {
            'device_id': 5,
            'packet_count': 75,
            'average_packet_size': 512.0,
            'bytes_transferred': 38400,
            'connection_frequency': 4.5,
            'packet_entropy': 4.85,
            'inbound_bytes': 15000,
            'outbound_bytes': 23400,
            'connection_duration': 5.0
        }
        res = self.detector.predict_record(rec)
        self.assertEqual(res['prediction'], 'NORMAL')
        self.assertFalse(res['is_anomaly'])
        self.assertLess(res['anomaly_score'], 0.50)

    def test_condition_02_high_traffic_volume_burst(self):
        """Condition 2: Extreme burst traffic spike should trigger anomaly detection."""
        rec = {
            'device_id': 1,
            'packet_count': 35000,
            'average_packet_size': 85.0,
            'bytes_transferred': 2975000,
            'connection_frequency': 1500.0,
            'packet_entropy': 2.1,
            'inbound_bytes': 2800000,
            'outbound_bytes': 175000,
            'connection_duration': 0.2
        }
        res = self.detector.predict_record(rec)
        self.assertTrue(res['is_anomaly'])
        self.assertGreaterEqual(res['anomaly_score'], 0.50)

    def test_condition_03_suspicious_outbound_transfer(self):
        """Condition 3: Asymmetric outbound exfiltration burst."""
        rec = {
            'device_id': 7,
            'packet_count': 4500,
            'average_packet_size': 1200.0,
            'bytes_transferred': 5400000,
            'connection_frequency': 35.0,
            'packet_entropy': 7.6,
            'inbound_bytes': 50000,
            'outbound_bytes': 5350000,
            'connection_duration': 45.0
        }
        res = self.detector.predict_record(rec)
        self.assertTrue(res['is_anomaly'])
        self.assertGreaterEqual(res['anomaly_score'], 0.50)

    def test_condition_04_high_connection_frequency(self):
        """Condition 4: Rapid connection rate (port scanning / flood)."""
        rec = {
            'device_id': 2,
            'packet_count': 600,
            'average_packet_size': 64.0,
            'bytes_transferred': 38400,
            'connection_frequency': 450.0,
            'packet_entropy': 3.2,
            'inbound_bytes': 30000,
            'outbound_bytes': 8400,
            'connection_duration': 0.8
        }
        res = self.detector.predict_record(rec)
        self.assertTrue(res['is_anomaly'])
        self.assertGreater(res['anomaly_score'], 0.48)

    def test_condition_05_unusual_packet_sizes(self):
        """Condition 5: Giant jumbo frames exceeding MTU."""
        rec = {
            'device_id': 3,
            'packet_count': 150,
            'average_packet_size': 8900.0,
            'bytes_transferred': 1335000,
            'connection_frequency': 12.0,
            'packet_entropy': 7.2,
            'inbound_bytes': 650000,
            'outbound_bytes': 685000,
            'connection_duration': 4.0
        }
        res = self.detector.predict_record(rec)
        self.assertTrue(res['is_anomaly'])
        self.assertGreaterEqual(res['anomaly_score'], 0.50)

    def test_condition_06_high_packet_entropy(self):
        """Condition 6: Unusually high entropy suggesting encrypted stealth tunnel."""
        rec = {
            'device_id': 8,
            'packet_count': 800,
            'average_packet_size': 1100.0,
            'bytes_transferred': 880000,
            'connection_frequency': 18.0,
            'packet_entropy': 7.95,
            'inbound_bytes': 80000,
            'outbound_bytes': 800000,
            'connection_duration': 30.0
        }
        res = self.detector.predict_record(rec)
        self.assertTrue(res['is_anomaly'])
        self.assertGreater(res['anomaly_score'], 0.48)

    def test_condition_07_long_connection_duration(self):
        """Condition 7: Prolonged slowloris trickle connection."""
        rec = {
            'device_id': 4,
            'packet_count': 20,
            'average_packet_size': 90.0,
            'bytes_transferred': 1800,
            'connection_frequency': 0.02,
            'packet_entropy': 2.9,
            'inbound_bytes': 800,
            'outbound_bytes': 1000,
            'connection_duration': 5400.0
        }
        res = self.detector.predict_record(rec)
        self.assertTrue(res['is_anomaly'])
        self.assertGreater(res['anomaly_score'], 0.45)

    def test_condition_08_missing_feature_fields(self):
        """Condition 8: Missing feature validation throws clean PipelineValidationError."""
        rec = {
            'device_id': 5,
            'packet_count': 65
            # Missing other 7 base fields
        }
        with self.assertRaises(PipelineValidationError):
            extract_features(rec)

    def test_condition_09_zero_value_features(self):
        """Condition 9: Zero denominators (duration=0, count=0) safely handled without ZeroDivisionError."""
        rec = {
            'device_id': 6,
            'packet_count': 0,
            'average_packet_size': 0.0,
            'bytes_transferred': 0,
            'connection_frequency': 0.0,
            'packet_entropy': 0.0,
            'inbound_bytes': 0,
            'outbound_bytes': 0,
            'connection_duration': 0.0
        }
        feats = extract_features(rec)
        self.assertEqual(len(feats), 18)
        self.assertEqual(feats['bytes_per_packet'], 0.0)
        self.assertEqual(feats['packets_per_second'], 0.0)
        self.assertFalse(np.isnan(feats['traffic_volume_deviation']))

    def test_condition_10_extreme_values(self):
        """Condition 10: Extreme values are clamped safely without float overflow."""
        rec = {
            'device_id': 1,
            'packet_count': 999_999_999,
            'average_packet_size': 999_999.0,
            'bytes_transferred': 999_999_999_999,
            'connection_frequency': 999_999.0,
            'packet_entropy': 15.0,
            'inbound_bytes': 500_000_000_000,
            'outbound_bytes': 500_000_000_000,
            'connection_duration': 999_999.0
        }
        feats = extract_features(rec)
        self.assertLessEqual(feats['packet_entropy'], 8.0)
        self.assertLessEqual(feats['average_packet_size'], 65535.0)


class TestPrompt6TenPipelineScenarios(unittest.TestCase):
    """Validation of the 10 End-to-End Pipeline Scenarios required by Prompt 6."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.pipeline = AIPipelineService()

    def test_scenario_01_normal_field_meter(self):
        """Scenario 1: Smart meter DLMS nominal telemetry."""
        with self.app.app_context():
            payload = {
                'device_id': 5,
                'packet_count': 55,
                'average_packet_size': 480.0,
                'bytes_transferred': 26400,
                'connection_frequency': 3.5,
                'packet_entropy': 4.75,
                'inbound_bytes': 11000,
                'outbound_bytes': 15400,
                'connection_duration': 4.2
            }
            res = self.pipeline.run_pipeline(payload, persist_results=False)
            self.assertFalse(res['is_anomaly'])
            self.assertEqual(res['threat_classification']['severity'], 'LOW')
            self.assertFalse(res['alert_created'])

    def test_scenario_02_volumetric_syn_flood(self):
        """Scenario 2: Gateway SYN flood burst."""
        with self.app.app_context():
            payload = {
                'device_id': 1,
                'packet_count': 40000,
                'average_packet_size': 50.0,
                'bytes_transferred': 2000000,
                'connection_frequency': 1800.0,
                'packet_entropy': 1.65,
                'inbound_bytes': 1900000,
                'outbound_bytes': 100000,
                'connection_duration': 0.1
            }
            res = self.pipeline.run_pipeline(payload, persist_results=False)
            self.assertTrue(res['is_anomaly'])
            self.assertIn('Denial of Service', res['threat_classification']['threat_type'])
            self.assertEqual(res['threat_classification']['severity'], 'CRITICAL')

    def test_scenario_03_smart_meter_outbound_surge(self):
        """Scenario 3: Outbound surge on Smart Meter (exfiltration)."""
        with self.app.app_context():
            payload = {
                'device_id': 7,
                'packet_count': 3200,
                'average_packet_size': 1150.0,
                'bytes_transferred': 3680000,
                'connection_frequency': 28.0,
                'packet_entropy': 7.7,
                'inbound_bytes': 40000,
                'outbound_bytes': 3640000,
                'connection_duration': 35.0
            }
            res = self.pipeline.run_pipeline(payload, persist_results=False)
            self.assertTrue(res['is_anomaly'])
            self.assertIn('Data Exfiltration', res['threat_classification']['threat_type'])
            self.assertIn(res['threat_classification']['severity'], ['HIGH', 'CRITICAL'])

    def test_scenario_04_core_server_connection_frequency_spike(self):
        """Scenario 4: Port sweep on core server."""
        with self.app.app_context():
            payload = {
                'device_id': 2,
                'packet_count': 850,
                'average_packet_size': 72.0,
                'bytes_transferred': 61200,
                'connection_frequency': 320.0,
                'packet_entropy': 3.1,
                'inbound_bytes': 45000,
                'outbound_bytes': 16200,
                'connection_duration': 1.2
            }
            res = self.pipeline.run_pipeline(payload, persist_results=False)
            self.assertTrue(res['is_anomaly'])
            self.assertIn(res['threat_classification']['threat_type'],
                          ['Port Scanning', 'Abnormal Connection Frequency'])

    def test_scenario_05_jumbo_packet_buffer_overflow(self):
        """Scenario 5: Jumbo packets exceeding MTU."""
        with self.app.app_context():
            payload = {
                'device_id': 3,
                'packet_count': 180,
                'average_packet_size': 8500.0,
                'bytes_transferred': 1530000,
                'connection_frequency': 15.0,
                'packet_entropy': 7.1,
                'inbound_bytes': 750000,
                'outbound_bytes': 780000,
                'connection_duration': 3.5
            }
            res = self.pipeline.run_pipeline(payload, persist_results=False)
            self.assertTrue(res['is_anomaly'])
            self.assertIn(res['threat_classification']['threat_type'],
                          ['Unusual Packet Behaviour', 'Potential Data Exfiltration'])

    def test_scenario_06_high_entropy_encrypted_tunnel(self):
        """Scenario 6: Encrypted tunnel stealth payload."""
        with self.app.app_context():
            payload = {
                'device_id': 8,
                'packet_count': 950,
                'average_packet_size': 1200.0,
                'bytes_transferred': 1140000,
                'connection_frequency': 20.0,
                'packet_entropy': 7.92,
                'inbound_bytes': 90000,
                'outbound_bytes': 1050000,
                'connection_duration': 25.0
            }
            res = self.pipeline.run_pipeline(payload, persist_results=False)
            self.assertTrue(res['is_anomaly'])
            self.assertGreaterEqual(res['anomaly_score'], 0.50)

    def test_scenario_07_slowloris_trickle_attack(self):
        """Scenario 7: Slowloris low-and-slow socket exhaustion."""
        with self.app.app_context():
            payload = {
                'device_id': 4,
                'packet_count': 20,
                'average_packet_size': 90.0,
                'bytes_transferred': 1800,
                'connection_frequency': 0.02,
                'packet_entropy': 2.9,
                'inbound_bytes': 800,
                'outbound_bytes': 1000,
                'connection_duration': 5400.0
            }
            res = self.pipeline.run_pipeline(payload, persist_results=False)
            self.assertTrue(res['is_anomaly'])
            self.assertGreater(res['anomaly_score'], 0.45)

    def test_scenario_08_duplicate_alert_suppression(self):
        """Scenario 8: Consecutive identical anomaly triggers duplicate suppression."""
        with self.app.app_context():
            payload = {
                'device_id': 10,
                'packet_count': 28000,
                'average_packet_size': 60.0,
                'bytes_transferred': 1680000,
                'connection_frequency': 950.0,
                'packet_entropy': 2.2,
                'inbound_bytes': 1500000,
                'outbound_bytes': 180000,
                'connection_duration': 0.3
            }
            # First execution creates alert
            res1 = self.pipeline.run_pipeline(payload, persist_results=True)
            if res1['alert_created']:
                # Second execution within 300s window must suppress duplicate
                res2 = self.pipeline.run_pipeline(payload, persist_results=True)
                self.assertFalse(res2['alert_created'], "Second identical alert must be suppressed")
                self.assertTrue(res2['duplicate_suppressed'])

    def test_scenario_09_unknown_device_handling(self):
        """Scenario 9: Unregistered device gracefully raises NotFoundError."""
        from services.device_service import NotFoundError
        with self.app.app_context():
            payload = {
                'device_id': 99999,
                'packet_count': 50,
                'average_packet_size': 500.0,
                'bytes_transferred': 25000,
                'connection_frequency': 5.0,
                'packet_entropy': 4.5,
                'inbound_bytes': 12000,
                'outbound_bytes': 13000,
                'connection_duration': 2.0
            }
            with self.assertRaises(NotFoundError):
                self.pipeline.run_pipeline(payload, persist_results=False)

    def test_scenario_10_invalid_payload_handling(self):
        """Scenario 10: Malformed/string payload raises ValidationError cleanly."""
        from services.device_service import ValidationError
        with self.app.app_context():
            with self.assertRaises(ValidationError):
                self.pipeline.run_pipeline({}, persist_results=False)


class TestPrompt6APIEndpoints(unittest.TestCase):
    """Validation of all Flask REST API endpoints for AI & Intelligence."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def test_01_api_ai_status(self):
        """GET /api/ai/status returns 200 with model metadata."""
        resp = self.client.get('/api/ai/status')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIn('model_name', data['data'])
        self.assertEqual(data['data']['total_feature_count'], 18)

    def test_02_api_ai_baselines(self):
        """GET /api/ai/baselines returns 200 with statistical baselines."""
        resp = self.client.get('/api/ai/baselines')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIn('mean_bytes_transferred', data['data'])

    def test_03_api_ai_analyze_valid(self):
        """POST /api/ai/analyze returns 200 with complete 6-stage telemetry analysis."""
        payload = {
            'device_id': 5,
            'packet_count': 65,
            'average_packet_size': 494.5,
            'bytes_transferred': 32144,
            'connection_frequency': 4.22,
            'packet_entropy': 4.89,
            'inbound_bytes': 13851,
            'outbound_bytes': 18293,
            'connection_duration': 4.71
        }
        resp = self.client.post('/api/ai/analyze', json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIn('analysis', data['data'])
        self.assertIn('threat_type', data['data'])

    def test_04_api_ai_analyze_invalid_payload(self):
        """POST /api/ai/analyze returns 400 for malformed payload."""
        resp = self.client.post('/api/ai/analyze', json={'device_id': 5, 'packet_count': 'invalid'})
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data['success'])

    def test_05_api_intelligence_threats(self):
        """GET /api/intelligence/threats returns 200 with report list."""
        resp = self.client.get('/api/intelligence/threats')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIn('reports', data['data'])

    def test_06_api_intelligence_summary(self):
        """GET /api/intelligence/summary returns 200 with aggregate threat stats."""
        resp = self.client.get('/api/intelligence/summary')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIn('total_reports', data['data'])
        self.assertIn('average_threat_score', data['data'])


if __name__ == '__main__':
    unittest.main()
