"""
NetGuardian AI - AI Anomaly Detection Service
Provides high-level service layer for:
- Initializing and maintaining the Isolation Forest model lifecycle
- Automatic dataset synthesis and initial model training with 18 engineered features
- Calculating training baselines strictly from normal traffic to prevent data leakage
- Executing standalone or batch anomaly predictions with grounded explanations
- Standardized data formatting for API responses
"""

from __future__ import annotations
import os
import json
import logging
import threading
from typing import Dict, List, Any, Optional, Union

from models.anomaly_detector import IsolationForestDetector, AnomalyDetectorError
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

logger = logging.getLogger('netguardian.ai.service')

# Paths for dataset, baselines, and serialized model artifacts
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DATASET_PATH = os.path.join(BASE_DIR, 'data', 'network_traffic.csv')
DEFAULT_MODEL_PATH = os.path.join(BASE_DIR, 'data', 'isolation_forest_model.joblib')
DEFAULT_BASELINES_PATH = os.path.join(BASE_DIR, 'data', 'traffic_baselines.json')


class AnomalyService:
    """
    Central AI service orchestrator for NetGuardian AI.
    Provides thread-safe access to the trained Isolation Forest detector.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(AnomalyService, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(
        self,
        model_path: Optional[str] = None,
        dataset_path: Optional[str] = None,
        baselines_path: Optional[str] = None
    ):
        if getattr(self, '_initialized', False):
            return

        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.dataset_path = dataset_path or DEFAULT_DATASET_PATH
        self.baselines_path = baselines_path or DEFAULT_BASELINES_PATH
        self.detector = IsolationForestDetector(
            contamination=0.08,
            random_state=42,
            feature_names=ENGINEERED_FEATURE_NAMES
        )
        self._ensure_model_ready()
        self._initialized = True

    def _ensure_model_ready(self):
        """Load trained model if present; otherwise generate dataset and train."""
        if os.path.exists(self.model_path):
            try:
                self.detector.load(self.model_path)
                # Check if loaded model uses 18 features
                if len(self.detector.feature_names) == len(ENGINEERED_FEATURE_NAMES):
                    logger.info(f"Loaded existing 18-feature Isolation Forest model from {self.model_path}")
                    return
                else:
                    logger.info("Found legacy model schema. Retraining with 18 engineered features...")
            except Exception as e:
                logger.warning(f"Could not load existing model ({e}). Triggering retraining...")

        # If model doesn't exist, ensure dataset exists
        if not os.path.exists(self.dataset_path):
            logger.info(f"Dataset not found at {self.dataset_path}. Synthesizing reproducible training traffic...")
            generator = TrafficDatasetGenerator(random_state=42)
            generator.generate_and_save(self.dataset_path, n_samples=1600, anomaly_ratio=0.08)

        # Train model using normal baseline samples only
        self.train_model(self.dataset_path)

    def train_model(
        self,
        dataset_path: Optional[str] = None,
        contamination: float = 0.08,
        random_state: int = 42
    ) -> Dict[str, Any]:
        """
        Train the Isolation Forest on normal baseline traffic records using 18 engineered features.
        IMPORTANT: Baselines and transformations fitted on NORMAL samples only (no data leakage).
        
        Args:
            dataset_path: Path to CSV dataset.
            contamination: Contamination parameter (expected anomaly ratio in production).
            random_state: Seed for reproducible tree partitions.
            
        Returns:
            Dict[str, Any]: Training performance and summary metrics.
        """
        path = dataset_path or self.dataset_path
        if not os.path.exists(path):
            generator = TrafficDatasetGenerator(random_state=random_state)
            generator.generate_and_save(path, n_samples=1600, anomaly_ratio=contamination)

        # 1. Load clean normal baseline traffic only (prevents contamination of baseline stats)
        df_normal = load_dataset(path, normal_only=True)
        
        # 2. Calculate baseline statistical distributions strictly from normal training samples
        baselines = calculate_traffic_baselines(df_normal)
        
        # Save baselines artifact
        try:
            with open(self.baselines_path, 'w', encoding='utf-8') as f:
                json.dump(baselines, f, indent=2)
            logger.info(f"Saved traffic baselines to: {self.baselines_path}")
        except Exception as e:
            logger.warning(f"Could not save baselines JSON: {e}")

        # 3. Preprocess and extract all 18 features
        X_train, _ = preprocess_traffic_data(df_normal, baselines=baselines)

        # 4. Fit Isolation Forest with exact 18-feature schema
        self.detector.contamination = contamination
        self.detector.random_state = random_state
        self.detector.feature_names = list(ENGINEERED_FEATURE_NAMES)
        metrics = self.detector.train(X_train, baselines=baselines)

        # 5. Persist model artifact
        self.detector.save(self.model_path)
        logger.info(f"Trained 18-feature Isolation Forest saved to: {self.model_path}")

        metrics['baselines'] = baselines
        metrics['derived_feature_count'] = len(DERIVED_FEATURE_NAMES)
        return metrics

    def detect(self, traffic_data: Union[Dict[str, Any], List[Dict[str, Any]]]) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Execute anomaly detection on single record or batch.
        
        Args:
            traffic_data: Single dictionary or list of dictionaries.
            
        Returns:
            Structured prediction result(s) containing device_id, prediction, anomaly_score, timestamp, features, and explanation.
        """
        if not self.detector.is_fitted:
            self._ensure_model_ready()

        if isinstance(traffic_data, dict):
            # Check if wrapped in container like {'traffic_data': [...]}
            if 'traffic_data' in traffic_data and isinstance(traffic_data['traffic_data'], list):
                return self.detector.predict_batch(traffic_data['traffic_data'])
            return self.detector.predict_record(traffic_data)
        elif isinstance(traffic_data, list):
            return self.detector.predict_batch(traffic_data)
        else:
            raise PipelineValidationError(f"Unsupported data format: {type(traffic_data).__name__}")

    def get_model_info(self) -> Dict[str, Any]:
        """Return operational metadata about the current model and feature engineering pipeline."""
        return {
            'model_name': self.detector.MODEL_NAME,
            'model_version': self.detector.MODEL_VERSION,
            'is_fitted': self.detector.is_fitted,
            'contamination': self.detector.contamination,
            'random_state': self.detector.random_state,
            'total_feature_count': len(self.detector.feature_names),
            'feature_names': self.detector.feature_names,
            'base_features': list(BASE_FEATURE_NAMES),
            'derived_features': list(DERIVED_FEATURE_NAMES),
            'baselines': self.detector.baselines,
            'trained_at': self.detector.trained_at,
            'training_sample_count': self.detector.training_sample_count,
            'model_path': self.model_path,
            'dataset_path': self.dataset_path,
            'baselines_path': self.baselines_path
        }


# Module-level convenience functions matching Prompt 2 requirements:
def detect_anomalies(traffic_data: Union[Dict[str, Any], List[Dict[str, Any]]]) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Module-level reusable anomaly detection function.
    Returns:
    - Device ID
    - Prediction: NORMAL or ANOMALY
    - Anomaly score
    - Timestamp
    - Relevant traffic features (18 features)
    - Grounded feature explanation
    - Model name & version
    """
    service = AnomalyService()
    return service.detect(traffic_data)
