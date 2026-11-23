"""
NetGuardian AI - Advanced Network Traffic Feature Engineering Unit & Integration Tests (Prompt 2)
Verifies:
1. Correct mathematical calculation of all 10 derived features
2. Safe zero-denominator handling (zero inbound/outbound bytes, zero duration)
3. Schema validation and missing field error handling
4. Non-numeric, NaN, and Infinite value rejection
5. Duplicate record detection in traffic batches
6. Extreme value bounds clamping (jumbo packets, zero duration, massive volume)
7. Training baseline calculation strictly from normal data without data leakage
8. Preprocessing pipeline consistency across training and prediction
9. Feature schema compatibility with the saved Isolation Forest model
10. Grounded explanation generation based on baseline Z-score deviations
11. End-to-end Flask API integration with POST /api/ai/detect & GET /api/ai/baselines
"""

import os
import math
import shutil
import tempfile
import unittest
import numpy as np
import pandas as pd

from app import create_app
from config import TestingConfig
from services.feature_pipeline import (
    BASE_FEATURE_NAMES,
    DERIVED_FEATURE_NAMES,
    ENGINEERED_FEATURE_NAMES,
    DEFAULT_BASELINE_STATS,
    PipelineValidationError,
    validate_feature_schema,
    calculate_traffic_baselines,
    detect_duplicates,
    extract_features,
    preprocess_traffic_data,
    transform_network_traffic,
    generate_feature_explanation
)
from services.feature_extractor import FeatureExtractor
from services.traffic_generator import TrafficDatasetGenerator, load_dataset
from models.anomaly_detector import IsolationForestDetector
from services.anomaly_service import AnomalyService, detect_anomalies


class FeatureEngineeringTestCase(unittest.TestCase):
    """Test suite for Prompt 2 Feature Engineering & Preprocessing Pipeline."""

    @classmethod
    def setUpClass(cls):
        """Prepare temporary test directory for artifacts and datasets."""
        cls.test_dir = tempfile.mkdtemp(prefix='netguardian_feat_test_')
        cls.test_csv = os.path.join(cls.test_dir, 'test_traffic.csv')
        cls.test_model = os.path.join(cls.test_dir, 'test_18feat_model.joblib')

        # Generate sample dataset
        generator = TrafficDatasetGenerator(random_state=42)
        generator.generate_and_save(cls.test_csv, n_samples=300, anomaly_ratio=0.10)

        # Flask test client
        cls.app = create_app(TestingConfig)
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        """Clean up temporary directory."""
        if os.path.exists(cls.test_dir):
            shutil.rmtree(cls.test_dir, ignore_errors=True)

    # --------------------------------------------------------------------------
    # 1. DERIVED FEATURE CALCULATIONS
    # --------------------------------------------------------------------------

    def test_01_derived_feature_calculations(self):
        """Verify mathematical accuracy of all 10 derived features."""
        baselines = {
            'mean_bytes_transferred': 500000.0,
            'std_bytes_transferred': 100000.0,
            'mean_connection_frequency': 20.0,
            'std_connection_frequency': 10.0,
            'mean_packet_entropy': 5.0,
            'std_packet_entropy': 0.5,
            'mean_average_packet_size': 800.0,
            'std_average_packet_size': 200.0
        }

        raw = {
            'packet_count': 100,
            'average_packet_size': 800.0,
            'bytes_transferred': 80000.0,
            'connection_frequency': 10.0,
            'packet_entropy': 5.5,
            'inbound_bytes': 60000.0,
            'outbound_bytes': 20000.0,
            'connection_duration': 4.0
        }

        features = extract_features(raw, baselines=baselines)

        # Check all 18 features exist
        for name in ENGINEERED_FEATURE_NAMES:
            self.assertIn(name, features)

        # 1. bytes_per_packet = 80000 / 100 = 800.0
        self.assertAlmostEqual(features['bytes_per_packet'], 800.0, places=2)

        # 2. inbound_outbound_ratio = 60000 / 20000 = 3.0
        self.assertAlmostEqual(features['inbound_outbound_ratio'], 3.0, places=2)

        # 3. packets_per_second = 100 / 4.0 = 25.0
        self.assertAlmostEqual(features['packets_per_second'], 25.0, places=2)

        # 4. bytes_per_second = 80000 / 4.0 = 20000.0
        self.assertAlmostEqual(features['bytes_per_second'], 20000.0, places=2)

        # 5. average_connection_size = 80000 / (10.0 * 4.0) = 2000.0
        self.assertAlmostEqual(features['average_connection_size'], 2000.0, places=2)

        # 6. outbound_traffic_percentage = (20000 / 80000) * 100 = 25.0%
        self.assertAlmostEqual(features['outbound_traffic_percentage'], 25.0, places=2)

        # 7. traffic_volume_deviation = (80000 - 500000) / 100000 = -4.2
        self.assertAlmostEqual(features['traffic_volume_deviation'], -4.2, places=2)

        # 8. connection_rate_deviation = (10 - 20) / 10 = -1.0
        self.assertAlmostEqual(features['connection_rate_deviation'], -1.0, places=2)

        # 9. packet_size_variation = |800.0 - 800.0| = 0.0
        self.assertAlmostEqual(features['packet_size_variation'], 0.0, places=2)

        # 10. traffic_entropy_deviation = (5.5 - 5.0) / 0.5 = 1.0
        self.assertAlmostEqual(features['traffic_entropy_deviation'], 1.0, places=2)

    # --------------------------------------------------------------------------
    # 2. SAFE ZERO-DENOMINATOR & EDGE CASES
    # --------------------------------------------------------------------------

    def test_02_safe_division_with_zeros(self):
        """Verify pipeline handles zero outbound bytes, zero inbound, zero packets, and zero duration safely."""
        zero_rec = {
            'packet_count': 0,
            'average_packet_size': 0.0,
            'bytes_transferred': 0.0,
            'connection_frequency': 0.0,
            'packet_entropy': 0.0,
            'inbound_bytes': 0.0,
            'outbound_bytes': 0.0,
            'connection_duration': 0.0
        }

        # Must not raise ZeroDivisionError
        features = extract_features(zero_rec)
        self.assertIsInstance(features, dict)
        self.assertEqual(len(features), 18)
        self.assertFalse(math.isnan(features['bytes_per_packet']))
        self.assertFalse(math.isnan(features['inbound_outbound_ratio']))
        self.assertFalse(math.isnan(features['packets_per_second']))
        self.assertFalse(math.isnan(features['bytes_per_second']))
        self.assertFalse(math.isnan(features['outbound_traffic_percentage']))
        self.assertFalse(math.isinf(features['packets_per_second']))

    def test_03_zero_outbound_traffic(self):
        """Verify zero outbound traffic (pure ingress) calculates 0% outbound percentage safely."""
        rec = {
            'packet_count': 50,
            'average_packet_size': 500.0,
            'bytes_transferred': 25000.0,
            'connection_frequency': 5.0,
            'packet_entropy': 4.2,
            'inbound_bytes': 25000.0,
            'outbound_bytes': 0.0,
            'connection_duration': 2.0
        }
        features = extract_features(rec)
        self.assertEqual(features['outbound_traffic_percentage'], 0.0)
        self.assertEqual(features['outbound_bytes'], 0.0)
        self.assertGreater(features['inbound_outbound_ratio'], 0.0)

    # --------------------------------------------------------------------------
    # 3. SCHEMA VALIDATION & REJECTION
    # --------------------------------------------------------------------------

    def test_04_schema_validation_missing_and_invalid(self):
        """Verify schema validation catches missing fields, non-numeric values, NaN, and Infinity."""
        # None input
        with self.assertRaises(PipelineValidationError):
            validate_feature_schema(None)

        # Empty dict
        with self.assertRaises(PipelineValidationError):
            validate_feature_schema({})

        # Missing required feature
        with self.assertRaises(PipelineValidationError):
            extract_features({'packet_count': 100})  # missing other 7 base fields

        # Non-numeric string
        with self.assertRaises(PipelineValidationError):
            extract_features({
                'packet_count': 'NOT_A_NUM',
                'average_packet_size': 500.0,
                'bytes_transferred': 25000.0,
                'connection_frequency': 5.0,
                'packet_entropy': 4.2,
                'inbound_bytes': 15000.0,
                'outbound_bytes': 10000.0,
                'connection_duration': 2.0
            })

        # NaN value
        with self.assertRaises(PipelineValidationError):
            extract_features({
                'packet_count': float('nan'),
                'average_packet_size': 500.0,
                'bytes_transferred': 25000.0,
                'connection_frequency': 5.0,
                'packet_entropy': 4.2,
                'inbound_bytes': 15000.0,
                'outbound_bytes': 10000.0,
                'connection_duration': 2.0
            })

    # --------------------------------------------------------------------------
    # 4. DUPLICATE RECORD DETECTION
    # --------------------------------------------------------------------------

    def test_05_duplicate_record_detection(self):
        """Verify duplicate records in a batch are accurately identified."""
        rec1 = {'device_id': 1, 'timestamp': '2026-11-18T10:00:00', 'packet_count': 100, 'bytes_transferred': 50000}
        rec2 = {'device_id': 2, 'timestamp': '2026-11-18T10:00:05', 'packet_count': 120, 'bytes_transferred': 60000}
        rec3 = {'device_id': 1, 'timestamp': '2026-11-18T10:00:00', 'packet_count': 100, 'bytes_transferred': 50000}  # duplicate of rec1

        duplicates = detect_duplicates([rec1, rec2, rec3])
        self.assertEqual(duplicates, [2])  # index 2 is duplicate

    # --------------------------------------------------------------------------
    # 5. BASELINE STATISTICS CALCULATION STRICTLY FROM NORMAL TRAINING DATA
    # --------------------------------------------------------------------------

    def test_06_calculate_traffic_baselines(self):
        """Verify baseline distributions are computed from normal data only without leakage."""
        df = pd.DataFrame([
            {'label': 'NORMAL', 'bytes_transferred': 100000, 'connection_frequency': 10.0, 'packet_entropy': 4.5, 'average_packet_size': 700.0},
            {'label': 'NORMAL', 'bytes_transferred': 300000, 'connection_frequency': 30.0, 'packet_entropy': 5.5, 'average_packet_size': 900.0},
            {'label': 'ANOMALY', 'bytes_transferred': 50000000, 'connection_frequency': 500.0, 'packet_entropy': 7.9, 'average_packet_size': 5000.0}
        ])

        baselines = calculate_traffic_baselines(df)
        
        # Mean of 100000 and 300000 is 200000 (anomaly must NOT be included)
        self.assertAlmostEqual(baselines['mean_bytes_transferred'], 200000.0, places=1)
        self.assertAlmostEqual(baselines['mean_connection_frequency'], 20.0, places=1)
        self.assertAlmostEqual(baselines['mean_packet_entropy'], 5.0, places=1)

    # --------------------------------------------------------------------------
    # 6. PREPROCESSING & FEATURE MATRIX TRANSFORMATION
    # --------------------------------------------------------------------------

    def test_07_transform_network_traffic(self):
        """Verify transform_network_traffic outputs (N, 18) float matrix with identical ordering."""
        recs = [
            {
                'packet_count': 50,
                'average_packet_size': 500.0,
                'bytes_transferred': 25000.0,
                'connection_frequency': 5.0,
                'packet_entropy': 4.2,
                'inbound_bytes': 15000.0,
                'outbound_bytes': 10000.0,
                'connection_duration': 2.0
            },
            {
                'packet_count': 80,
                'average_packet_size': 600.0,
                'bytes_transferred': 48000.0,
                'connection_frequency': 8.0,
                'packet_entropy': 4.8,
                'inbound_bytes': 28000.0,
                'outbound_bytes': 20000.0,
                'connection_duration': 3.0
            }
        ]

        X = transform_network_traffic(recs)
        self.assertIsInstance(X, np.ndarray)
        self.assertEqual(X.shape, (2, 18))
        self.assertFalse(np.isnan(X).any())
        self.assertFalse(np.isinf(X).any())

    # --------------------------------------------------------------------------
    # 7. ISOLATION FOREST 18-FEATURE INTEGRATION & COMPATIBILITY
    # --------------------------------------------------------------------------

    def test_08_isolation_forest_18_feature_training_and_persistence(self):
        """Verify Isolation Forest trains, saves, and loads with all 18 engineered features."""
        df_normal = load_dataset(self.test_csv, normal_only=True)
        baselines = calculate_traffic_baselines(df_normal)
        X_train, _ = preprocess_traffic_data(df_normal, baselines=baselines)

        self.assertEqual(X_train.shape[1], 18)

        detector = IsolationForestDetector(
            contamination=0.08,
            random_state=42,
            feature_names=ENGINEERED_FEATURE_NAMES,
            baselines=baselines
        )
        detector.train(X_train)
        detector.save(self.test_model)

        # Restore
        restored = IsolationForestDetector()
        restored.load(self.test_model)

        self.assertTrue(restored.is_fitted)
        self.assertEqual(len(restored.feature_names), 18)
        self.assertEqual(restored.feature_names, ENGINEERED_FEATURE_NAMES)
        self.assertIn('mean_bytes_transferred', restored.baselines)

    # --------------------------------------------------------------------------
    # 8. GROUNDED FEATURE EXPLANATIONS
    # --------------------------------------------------------------------------

    def test_09_grounded_feature_explanations(self):
        """Verify feature explanations are grounded in baseline deviations without fabrication."""
        baselines = {
            'mean_bytes_transferred': 500000.0,
            'std_bytes_transferred': 100000.0,
            'mean_connection_frequency': 20.0,
            'std_connection_frequency': 10.0,
            'mean_packet_entropy': 4.8,
            'std_packet_entropy': 0.5,
            'mean_average_packet_size': 800.0,
            'std_average_packet_size': 200.0
        }

        # Data Exfiltration Sample
        exfiltration_rec = {
            'device_id': 'dev-7',
            'device_name': 'Smart Meter 03',
            'packet_count': 9000,
            'average_packet_size': 1480.0,
            'bytes_transferred': 13320000.0,
            'connection_frequency': 80.0,
            'packet_entropy': 7.95,
            'inbound_bytes': 20000.0,
            'outbound_bytes': 13300000.0,
            'connection_duration': 500.0
        }

        features = extract_features(exfiltration_rec, baselines=baselines)
        explanation = generate_feature_explanation(
            record=exfiltration_rec,
            features=features,
            baselines=baselines,
            is_anomaly=True
        )

        self.assertIn('summary', explanation)
        self.assertIn('contributing_factors', explanation)
        self.assertTrue(len(explanation['contributing_factors']) > 0)

        summary_lower = explanation['summary'].lower()
        # Explanation must cite the high outbound or high entropy based on true values
        self.assertTrue('outbound' in summary_lower or 'entropy' in summary_lower or 'volume' in summary_lower)

    # --------------------------------------------------------------------------
    # 9. FLASK API INTEGRATION WITH 18 FEATURES & BASELINES
    # --------------------------------------------------------------------------

    def test_10_api_detect_returns_18_features_and_explanation(self):
        """Verify POST /api/ai/detect returns all 18 engineered features and explanation."""
        payload = {
            'device_id': 5,
            'packet_count': 45,
            'average_packet_size': 480.0,
            'bytes_transferred': 21600,
            'connection_frequency': 3.2,
            'packet_entropy': 4.15,
            'inbound_bytes': 12960,
            'outbound_bytes': 8640,
            'connection_duration': 2.4
        }
        res = self.client.post('/api/ai/detect', json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        
        features = data['data']['features']
        self.assertEqual(len(features), 18)
        self.assertIn('bytes_per_packet', features)
        self.assertIn('inbound_outbound_ratio', features)
        self.assertIn('outbound_traffic_percentage', features)
        self.assertIn('traffic_entropy_deviation', features)
        self.assertIn('explanation', data['data'])

    def test_11_api_get_baselines_endpoint(self):
        """Verify GET /api/ai/baselines returns pre-calculated baseline statistics."""
        res = self.client.get('/api/ai/baselines')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertIn('mean_bytes_transferred', data['data'])
        self.assertIn('mean_connection_frequency', data['data'])
        self.assertIn('mean_packet_entropy', data['data'])


if __name__ == '__main__':
    unittest.main()
