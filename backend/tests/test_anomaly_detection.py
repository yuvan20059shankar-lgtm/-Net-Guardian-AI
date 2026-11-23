"""
NetGuardian AI - AI / Machine Learning Anomaly Detection Unit & Integration Tests
Verifies:
1. Synthetic traffic dataset generation (reproducibility & features)
2. Feature extraction, validation, and boundary handling
3. Invalid / missing input error handling
4. Isolation Forest model training on normal baseline data
5. Model serialization and deserialization via Joblib
6. Nominal traffic prediction (NORMAL classification)
7. Suspicious traffic prediction (ANOMALY classification)
8. Module-level detect_anomalies() function contract
9. API endpoint POST /api/ai/detect single record
10. API endpoint POST /api/ai/detect anomaly record
11. API endpoint POST /api/ai/detect batch records
12. API error handling for malformed / non-numeric input
13. API endpoint GET /api/ai/model metadata
"""

import os
import sys
import shutil
import tempfile
import unittest
from pathlib import Path
import numpy as np

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app import create_app
from config import TestingConfig
from services.feature_extractor import FeatureExtractor, FeatureExtractionError, FEATURE_NAMES
from services.traffic_generator import TrafficDatasetGenerator, load_dataset
from models.anomaly_detector import IsolationForestDetector, AnomalyDetectorError
from services.anomaly_service import AnomalyService, detect_anomalies


class AnomalyDetectionTestCase(unittest.TestCase):
    """Test suite for AI Anomaly Detection components."""

    @classmethod
    def setUpClass(cls):
        """Prepare temporary test directory for datasets and model artifacts."""
        cls.test_dir = tempfile.mkdtemp(prefix='netguardian_ai_test_')
        cls.test_csv = os.path.join(cls.test_dir, 'test_network_traffic.csv')
        cls.test_model = os.path.join(cls.test_dir, 'test_isolation_forest.joblib')

        # Generate a small test dataset
        generator = TrafficDatasetGenerator(random_state=42)
        generator.generate_and_save(cls.test_csv, n_samples=400, anomaly_ratio=0.10)

        # Initialize Flask test client with TestingConfig
        cls.app = create_app(TestingConfig)
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        """Clean up temporary test artifacts."""
        if os.path.exists(cls.test_dir):
            shutil.rmtree(cls.test_dir, ignore_errors=True)

    # --------------------------------------------------------------------------
    # 1. DATASET GENERATION TESTS
    # --------------------------------------------------------------------------

    def test_01_dataset_generation_and_features(self):
        """Verify synthetic network traffic generator outputs all 8 features plus metadata."""
        df = load_dataset(self.test_csv)
        self.assertEqual(len(df), 400)
        
        # Check all 8 required features exist in CSV
        for feat in FEATURE_NAMES:
            self.assertIn(feat, df.columns, f"Feature '{feat}' missing from dataset")
            
        # Check metadata columns
        self.assertIn('device_id', df.columns)
        self.assertIn('timestamp', df.columns)
        self.assertIn('label', df.columns)
        self.assertIn('anomaly_type', df.columns)

        # Check simulation header exists in file
        with open(self.test_csv, 'r', encoding='utf-8') as f:
            header_lines = [f.readline(), f.readline()]
            self.assertTrue(any('SIMULATED' in line for line in header_lines))

    # --------------------------------------------------------------------------
    # 2. FEATURE EXTRACTION & VALIDATION TESTS
    # --------------------------------------------------------------------------

    def test_02_feature_extraction_valid_record(self):
        """Verify feature extractor extracts ordered vector from valid dictionary."""
        valid_rec = {
            'packet_count': 100,
            'average_packet_size': 750.5,
            'bytes_transferred': 75050,
            'connection_frequency': 12.4,
            'packet_entropy': 4.85,
            'inbound_bytes': 45000,
            'outbound_bytes': 30050,
            'connection_duration': 3.2
        }
        vec, cleaned = FeatureExtractor.extract_single_record(valid_rec)
        self.assertEqual(len(vec), 8)
        self.assertEqual(vec[0], 100.0)
        self.assertEqual(vec[1], 750.5)
        self.assertEqual(vec[4], 4.85)

    def test_03_feature_extraction_imputation_and_bounds(self):
        """Verify feature extractor graceful imputation when partial fields provided."""
        partial_rec = {
            'packet_count': 80,
            'average_packet_size': 600.0,
            'connection_frequency': 5.0,
            'packet_entropy': 4.2
        }
        vec, cleaned = FeatureExtractor.extract_single_record(partial_rec, allow_imputation=True)
        self.assertEqual(len(vec), 8)
        self.assertGreater(cleaned['bytes_transferred'], 0)
        self.assertGreater(cleaned['inbound_bytes'], 0)

    def test_04_feature_extraction_invalid_inputs(self):
        """Verify feature extractor raises FeatureExtractionError on non-numeric or empty input."""
        # Non-numeric string
        with self.assertRaises(FeatureExtractionError):
            FeatureExtractor.extract_single_record({'packet_count': 'NOT_A_NUMBER'})

        # Empty dictionary
        with self.assertRaises(FeatureExtractionError):
            FeatureExtractor.extract_single_record({})

        # Non-dictionary input
        with self.assertRaises(FeatureExtractionError):
            FeatureExtractor.extract_single_record("invalid_string_type")

        # NaN / Infinity
        with self.assertRaises(FeatureExtractionError):
            FeatureExtractor.extract_single_record({'packet_count': float('nan')})

    # --------------------------------------------------------------------------
    # 3. ISOLATION FOREST MODEL TRAINING & PERSISTENCE
    # --------------------------------------------------------------------------

    def test_05_isolation_forest_training_on_normal_samples(self):
        """Verify Isolation Forest trains properly on normal baseline traffic."""
        df_normal = load_dataset(self.test_csv, normal_only=True)
        X_train = df_normal[FEATURE_NAMES].values

        detector = IsolationForestDetector(contamination=0.08, random_state=42)
        summary = detector.train(X_train)

        self.assertTrue(detector.is_fitted)
        self.assertIsNotNone(detector.model)
        self.assertEqual(summary['model_name'], "Isolation Forest Anomaly Detector")
        self.assertEqual(summary['training_sample_count'], len(X_train))

    def test_06_isolation_forest_save_and_load(self):
        """Verify model serialization and deserialization via Joblib."""
        df_normal = load_dataset(self.test_csv, normal_only=True)
        X_train = df_normal[FEATURE_NAMES].values

        detector1 = IsolationForestDetector(contamination=0.08, random_state=42)
        detector1.train(X_train)
        detector1.save(self.test_model)
        self.assertTrue(os.path.exists(self.test_model))

        detector2 = IsolationForestDetector()
        detector2.load(self.test_model)
        self.assertTrue(detector2.is_fitted)
        self.assertEqual(detector2.training_sample_count, detector1.training_sample_count)

        # Test predictions from both match
        sample = {
            'packet_count': 60,
            'average_packet_size': 500.0,
            'bytes_transferred': 30000,
            'connection_frequency': 4.0,
            'packet_entropy': 4.5,
            'inbound_bytes': 18000,
            'outbound_bytes': 12000,
            'connection_duration': 2.0
        }
        pred1 = detector1.predict_record(sample)
        pred2 = detector2.predict_record(sample)
        self.assertEqual(pred1['prediction'], pred2['prediction'])
        self.assertEqual(pred1['anomaly_score'], pred2['anomaly_score'])

    # --------------------------------------------------------------------------
    # 4. PREDICTION TESTS (NORMAL VS ANOMALOUS)
    # --------------------------------------------------------------------------

    def test_07_normal_traffic_prediction(self):
        """Verify normal nominal traffic record is classified as NORMAL."""
        detector = IsolationForestDetector().load(self.test_model)
        normal_telemetry = {
            'device_id': 5,
            'packet_count': 50,
            'average_packet_size': 450.0,
            'bytes_transferred': 22500,
            'connection_frequency': 3.5,
            'packet_entropy': 4.2,
            'inbound_bytes': 13500,
            'outbound_bytes': 9000,
            'connection_duration': 2.1
        }
        result = detector.predict_record(normal_telemetry)
        self.assertEqual(result['prediction'], 'NORMAL')
        self.assertFalse(result['is_anomaly'])
        self.assertLess(result['anomaly_score'], 0.60)
        self.assertEqual(result['model_version'], '1.0.0')

    def test_08_suspicious_traffic_prediction(self):
        """Verify severe anomalous traffic record (e.g. data exfiltration) is classified as ANOMALY."""
        detector = IsolationForestDetector().load(self.test_model)
        suspicious_telemetry = {
            'device_id': 7,
            'packet_count': 8500,
            'average_packet_size': 1480.0,
            'bytes_transferred': 12580000,
            'connection_frequency': 85.0,
            'packet_entropy': 7.95,        # Extreme Shannon entropy
            'inbound_bytes': 25000,
            'outbound_bytes': 12555000,     # 99.8% outbound exfiltration
            'connection_duration': 450.0
        }
        result = detector.predict_record(suspicious_telemetry)
        self.assertEqual(result['prediction'], 'ANOMALY')
        self.assertTrue(result['is_anomaly'])
        self.assertGreater(result['anomaly_score'], 0.50)

    def test_09_detect_anomalies_function_contract(self):
        """Verify module-level detect_anomalies() function contract."""
        telemetry = {
            'device_id': 'dev-1',
            'packet_count': 120,
            'average_packet_size': 850.0,
            'bytes_transferred': 102000,
            'connection_frequency': 15.0,
            'packet_entropy': 4.9,
            'inbound_bytes': 51000,
            'outbound_bytes': 51000,
            'connection_duration': 4.0
        }
        res = detect_anomalies(telemetry)
        self.assertIn('device_id', res)
        self.assertIn('prediction', res)
        self.assertIn('anomaly_score', res)
        self.assertIn('timestamp', res)
        self.assertIn('features', res)
        self.assertIn('model_name', res)
        self.assertIn('model_version', res)

    # --------------------------------------------------------------------------
    # 5. FLASK API INTEGRATION TESTS
    # --------------------------------------------------------------------------

    def test_10_api_detect_normal_record(self):
        """Verify POST /api/ai/detect handles valid normal telemetry with HTTP 200."""
        payload = {
            'device_id': 6,
            'packet_count': 45,
            'average_packet_size': 500.0,
            'bytes_transferred': 22500,
            'connection_frequency': 4.0,
            'packet_entropy': 4.3,
            'inbound_bytes': 13500,
            'outbound_bytes': 9000,
            'connection_duration': 2.0
        }
        res = self.client.post('/api/ai/detect', json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['prediction'], 'NORMAL')
        self.assertFalse(data['data']['is_anomaly'])

    def test_11_api_detect_anomaly_record(self):
        """Verify POST /api/ai/detect flags suspicious data exfiltration payload."""
        payload = {
            'device_id': 7,
            'packet_count': 9200,
            'average_packet_size': 1485.0,
            'bytes_transferred': 13662000,
            'connection_frequency': 95.0,
            'packet_entropy': 7.96,
            'inbound_bytes': 15000,
            'outbound_bytes': 13647000,
            'connection_duration': 520.0
        }
        res = self.client.post('/api/ai/detect', json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['prediction'], 'ANOMALY')
        self.assertTrue(data['data']['is_anomaly'])
        self.assertGreater(data['data']['anomaly_score'], 0.50)

    def test_12_api_detect_batch_records(self):
        """Verify POST /api/ai/detect processes batch traffic records."""
        payload = {
            'traffic_data': [
                {
                    'device_id': 5,
                    'packet_count': 40,
                    'average_packet_size': 420.0,
                    'bytes_transferred': 16800,
                    'connection_frequency': 2.5,
                    'packet_entropy': 4.1,
                    'inbound_bytes': 10000,
                    'outbound_bytes': 6800,
                    'connection_duration': 1.8
                },
                {
                    'device_id': 10,
                    'packet_count': 45000,
                    'average_packet_size': 54.0,   # SYN Flood
                    'bytes_transferred': 2430000,
                    'connection_frequency': 1800.0,
                    'packet_entropy': 1.85,
                    'inbound_bytes': 2400000,
                    'outbound_bytes': 30000,
                    'connection_duration': 0.1
                }
            ]
        }
        res = self.client.post('/api/ai/detect', json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertIsInstance(data['data'], list)
        self.assertEqual(len(data['data']), 2)

    def test_13_api_detect_validation_errors(self):
        """Verify POST /api/ai/detect returns HTTP 400 on malformed input."""
        # Non-JSON content-type
        res = self.client.post('/api/ai/detect', data="Not JSON", content_type="text/plain")
        self.assertEqual(res.status_code, 400)
        self.assertFalse(res.get_json()['success'])

        # Empty payload
        res = self.client.post('/api/ai/detect', json={})
        self.assertEqual(res.status_code, 400)
        self.assertFalse(res.get_json()['success'])

        # Non-numeric feature value
        res = self.client.post('/api/ai/detect', json={'packet_count': 'invalid_string'})
        self.assertEqual(res.status_code, 400)
        self.assertFalse(res.get_json()['success'])

    def test_14_api_model_info_endpoint(self):
        """Verify GET /api/ai/model returns model metadata."""
        res = self.client.get('/api/ai/model')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['model_name'], "Isolation Forest Anomaly Detector")
        self.assertEqual(data['data']['model_version'], "1.0.0")
        self.assertIn(len(data['data']['feature_names']), [8, 18])


if __name__ == '__main__':
    unittest.main()
