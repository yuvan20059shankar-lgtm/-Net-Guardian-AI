"""
NetGuardian AI - Isolation Forest Anomaly Detector
Machine Learning Model implementation for detecting volumetric, temporal,
and entropy anomalies across network traffic telemetry.

Technology:
- Python
- Scikit-learn (IsolationForest)
- NumPy
- Joblib

Isolation Forest recursively partitions feature space. Anomalies are isolated
with significantly fewer splits (shorter path lengths) compared to nominal traffic.
"""

from __future__ import annotations
import os
import datetime
import logging
from typing import Dict, List, Any, Optional, Union, Tuple
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

from services.feature_pipeline import (
    ENGINEERED_FEATURE_NAMES,
    BASE_FEATURE_NAMES,
    DEFAULT_BASELINE_STATS,
    generate_feature_explanation
)
from services.feature_extractor import FeatureExtractor, FeatureExtractionError

logger = logging.getLogger('netguardian.ai.model')


class AnomalyDetectorError(RuntimeError):
    """Raised when model inference or training encounters an unrecoverable condition."""
    pass


class IsolationForestDetector:
    """
    Production-ready wrapper around Scikit-learn's Isolation Forest algorithm.
    Features:
    - Independent training and inference interfaces
    - Configurable contamination parameter and reproducible random_state
    - Serialization and deserialization via Joblib with model metadata & baselines
    - Seamless support for 18 engineered features (8 raw + 10 derived)
    - Grounded feature explanation generation based on baseline Z-score deviations
    - Calibrated 0.0 - 1.0 continuous anomaly score output
    """

    MODEL_NAME = "Isolation Forest Anomaly Detector"
    MODEL_VERSION = "1.0.0"

    def __init__(
        self,
        contamination: float = 0.08,
        random_state: int = 42,
        n_estimators: int = 150,
        max_samples: Union[str, int, float] = 'auto',
        feature_names: Optional[List[str]] = None,
        baselines: Optional[Dict[str, float]] = None
    ):
        self.contamination = contamination
        self.random_state = random_state
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.feature_names = list(feature_names) if feature_names is not None else None
        self.baselines = dict(baselines) if baselines else dict(DEFAULT_BASELINE_STATS)
        
        self.model: Optional[Any] = None
        self.is_fitted = False
        self.trained_at: Optional[str] = None
        self.training_sample_count: int = 0

    def train(
        self,
        X_train: Union[List[List[float]], Any],
        baselines: Optional[Dict[str, float]] = None
    ) -> Dict[str, Any]:
        """
        Train the Isolation Forest model on nominal (normal baseline) traffic.
        
        Args:
            X_train: 2D array-like of shape (n_samples, n_features) containing baseline traffic features.
            baselines: Pre-calculated baseline statistics from training data.
            
        Returns:
            Dict[str, Any]: Training summary metrics.
        """
        if baselines:
            self.baselines = dict(baselines)

        # Convert to numpy array
        if not isinstance(X_train, np.ndarray):
            X_train = np.array(X_train, dtype=np.float64)

        if X_train.ndim != 2:
            raise AnomalyDetectorError(f"Expected 2D feature matrix, got ndim={X_train.ndim}")

        # Auto-configure feature names to match input dimensions if not pinned
        if self.feature_names is None or len(self.feature_names) != X_train.shape[1]:
            if X_train.shape[1] == len(ENGINEERED_FEATURE_NAMES):
                self.feature_names = list(ENGINEERED_FEATURE_NAMES)
            elif X_train.shape[1] == len(BASE_FEATURE_NAMES):
                self.feature_names = list(BASE_FEATURE_NAMES)
            else:
                self.feature_names = [f"feat_{i}" for i in range(X_train.shape[1])]

        if len(X_train) < 10:
            raise AnomalyDetectorError(f"Insufficient training samples: {len(X_train)}. Minimum is 10.")

        logger.info(
            f"Training {self.MODEL_NAME} v{self.MODEL_VERSION} on {len(X_train)} samples "
            f"with {len(self.feature_names)} features (contamination={self.contamination}, seed={self.random_state})..."
        )

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            max_samples=self.max_samples,
            n_jobs=-1
        )

        self.model.fit(X_train)
        self.is_fitted = True
        self.trained_at = datetime.datetime.now().isoformat()
        self.training_sample_count = len(X_train)

        logger.info(f"Model training complete. Offset threshold: {self.model.offset_:.4f}")

        return {
            'model_name': self.MODEL_NAME,
            'model_version': self.MODEL_VERSION,
            'training_sample_count': self.training_sample_count,
            'feature_count': len(self.feature_names),
            'feature_names': self.feature_names,
            'contamination': self.contamination,
            'random_state': self.random_state,
            'offset_threshold': float(self.model.offset_),
            'trained_at': self.trained_at
        }

    def save(self, filepath: str) -> str:
        """
        Serialize model, metadata, and baseline statistics to disk using Joblib.
        
        Args:
            filepath: Target file path (.joblib).
            
        Returns:
            str: Absolute path of saved model file.
        """
        if not self.is_fitted or self.model is None:
            raise AnomalyDetectorError("Cannot save unfitted model. Call train() first.")

        abs_path = os.path.abspath(filepath)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)

        package = {
            'model': self.model,
            'baselines': self.baselines,
            'metadata': {
                'model_name': self.MODEL_NAME,
                'model_version': self.MODEL_VERSION,
                'contamination': self.contamination,
                'random_state': self.random_state,
                'n_estimators': self.n_estimators,
                'feature_names': self.feature_names,
                'trained_at': self.trained_at,
                'training_sample_count': self.training_sample_count,
                'offset_threshold': float(self.model.offset_) if hasattr(self.model, 'offset_') else None
            }
        }

        joblib.dump(package, abs_path)
        logger.info(f"Model successfully saved to: {abs_path}")
        return abs_path

    def load(self, filepath: str) -> 'IsolationForestDetector':
        """
        Load trained model artifact, metadata, and baselines from disk.
        
        Args:
            filepath: Path to the .joblib file.
            
        Returns:
            self: The restored detector instance.
        """
        abs_path = os.path.abspath(filepath)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Model file not found at: {abs_path}")

        loaded = joblib.load(abs_path)

        if isinstance(loaded, dict) and 'model' in loaded:
            self.model = loaded['model']
            self.baselines = loaded.get('baselines', dict(DEFAULT_BASELINE_STATS))
            meta = loaded.get('metadata', {})
            self.contamination = meta.get('contamination', self.contamination)
            self.random_state = meta.get('random_state', self.random_state)
            self.n_estimators = meta.get('n_estimators', self.n_estimators)
            self.feature_names = meta.get('feature_names')
            self.trained_at = meta.get('trained_at')
            self.training_sample_count = meta.get('training_sample_count', 0)
        else:
            self.model = loaded

        # Ensure feature_names matches model dimension
        if hasattr(self.model, 'n_features_in_'):
            if not self.feature_names or len(self.feature_names) != self.model.n_features_in_:
                if self.model.n_features_in_ == len(ENGINEERED_FEATURE_NAMES):
                    self.feature_names = list(ENGINEERED_FEATURE_NAMES)
                else:
                    self.feature_names = list(BASE_FEATURE_NAMES)
        elif not self.feature_names:
            self.feature_names = list(ENGINEERED_FEATURE_NAMES)

        self.is_fitted = True
        logger.info(f"Model loaded successfully from: {abs_path} (features: {len(self.feature_names)})")
        return self

    def compute_anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """
        Compute a continuous anomaly score between 0.0 (strictly nominal) and 1.0 (extreme anomaly).
        
        Uses decision_function values:
        - raw_decision > 0: Inlier / Normal
        - raw_decision < 0: Outlier / Anomaly
        
        We map raw decision to calibrated probability-like continuous score:
        score = 0.5 - (raw_decision * 1.5), clipped to [0.0, 1.0]
        """
        raw_decision = self.model.decision_function(X)
        scores = 0.5 - (raw_decision * 1.5)
        return np.clip(scores, 0.0, 1.0)

    def predict_record(
        self,
        record: Dict[str, Any],
        device_id: Optional[Union[int, str]] = None,
        timestamp: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Predict whether a single network traffic record is NORMAL or an ANOMALY.
        Automatically applies 18-feature engineering and generates human-readable explanation.
        """
        if not self.is_fitted or self.model is None:
            raise AnomalyDetectorError("Model has not been trained or loaded yet.")

        engineered = (len(self.feature_names) == len(ENGINEERED_FEATURE_NAMES))
        vector, cleaned_features = FeatureExtractor.extract_single_record(
            record,
            allow_imputation=True,
            baselines=self.baselines,
            engineered=engineered
        )
        X = np.array([vector], dtype=np.float64)

        # Scikit-learn predict: 1 for normal, -1 for anomaly
        raw_pred = self.model.predict(X)[0]
        is_anomaly = bool(raw_pred == -1)
        prediction = 'ANOMALY' if is_anomaly else 'NORMAL'

        anomaly_score = float(self.compute_anomaly_score(X)[0])

        dev_id = device_id if device_id is not None else record.get('device_id', 'unknown')
        if hasattr(dev_id, 'item'):
            dev_id = dev_id.item()
        ts = str(timestamp or record.get('timestamp') or datetime.datetime.now().isoformat())

        # Generate feature explanation based on baselines
        explanation_data = generate_feature_explanation(
            record=record,
            features=cleaned_features,
            baselines=self.baselines,
            is_anomaly=is_anomaly
        )

        return {
            'device_id': dev_id,
            'prediction': prediction,
            'is_anomaly': is_anomaly,
            'anomaly_score': float(round(anomaly_score, 4)),
            'timestamp': ts,
            'features': {k: float(v) for k, v in cleaned_features.items()},
            'explanation': explanation_data['summary'],
            'explanation_details': explanation_data,
            'model_name': str(self.MODEL_NAME),
            'model_version': str(self.MODEL_VERSION)
        }

    def predict_batch(
        self,
        records: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Perform batch prediction across multiple traffic records with explanations.
        """
        if not self.is_fitted or self.model is None:
            raise AnomalyDetectorError("Model has not been trained or loaded yet.")

        engineered = (len(self.feature_names) == len(ENGINEERED_FEATURE_NAMES))
        vectors, cleaned_records = FeatureExtractor.extract_features(
            records,
            allow_imputation=True,
            baselines=self.baselines,
            engineered=engineered
        )
        X = np.array(vectors, dtype=np.float64)

        raw_preds = self.model.predict(X)
        scores = self.compute_anomaly_score(X)

        results = []
        for i, rec in enumerate(records):
            is_anomaly = bool(raw_preds[i] == -1)
            dev_id = rec.get('device_id', 'unknown')
            if hasattr(dev_id, 'item'):
                dev_id = dev_id.item()

            explanation_data = generate_feature_explanation(
                record=rec,
                features=cleaned_records[i],
                baselines=self.baselines,
                is_anomaly=is_anomaly
            )

            results.append({
                'device_id': dev_id,
                'prediction': 'ANOMALY' if is_anomaly else 'NORMAL',
                'is_anomaly': is_anomaly,
                'anomaly_score': float(round(float(scores[i]), 4)),
                'timestamp': str(rec.get('timestamp') or datetime.datetime.now().isoformat()),
                'features': {k: float(v) for k, v in cleaned_records[i].items()},
                'explanation': explanation_data['summary'],
                'explanation_details': explanation_data,
                'model_name': str(self.MODEL_NAME),
                'model_version': str(self.MODEL_VERSION)
            })

        return results
