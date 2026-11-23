"""
NetGuardian AI - Feature Extraction & Advanced Pipeline Facade
Provides unified interface for both base telemetry extraction (8 features)
and advanced engineered pipeline (18 features: 8 base + 10 derived).
"""

from __future__ import annotations
import math
import logging
from typing import Dict, List, Any, Tuple, Union, Optional

from services.feature_pipeline import (
    BASE_FEATURE_NAMES,
    DERIVED_FEATURE_NAMES,
    ENGINEERED_FEATURE_NAMES,
    DEFAULT_BASELINE_STATS,
    FEATURE_VALUE_BOUNDS,
    PipelineValidationError,
    validate_feature_schema,
    calculate_traffic_baselines,
    detect_duplicates,
    extract_features as pipeline_extract_features,
    preprocess_traffic_data as pipeline_preprocess_traffic_data,
    transform_network_traffic as pipeline_transform_network_traffic,
    generate_feature_explanation
)

logger = logging.getLogger('netguardian.ai.features')

# Aliases for backward compatibility
FEATURE_NAMES = list(BASE_FEATURE_NAMES)
ALL_FEATURE_NAMES = list(ENGINEERED_FEATURE_NAMES)
FeatureExtractionError = PipelineValidationError


class FeatureExtractor:
    """
    Unified Feature Extraction & Preprocessing Facade.
    Supports both 8-feature raw extraction and 18-feature advanced pipeline.
    """

    @classmethod
    def get_feature_names(cls, engineered: bool = False) -> List[str]:
        """Return ordered feature names (8 base by default, 18 if engineered=True)."""
        return list(ENGINEERED_FEATURE_NAMES if engineered else BASE_FEATURE_NAMES)

    @classmethod
    def extract_single_record(
        cls,
        record: Dict[str, Any],
        allow_imputation: bool = True,
        baselines: Optional[Dict[str, float]] = None,
        engineered: bool = False
    ) -> Tuple[List[float], Dict[str, Any]]:
        """
        Extract features from a single dictionary record.
        
        Args:
            record: Dict containing traffic telemetry.
            allow_imputation: If True, missing non-critical features use defaults.
            baselines: Pre-calculated baseline statistics from training data.
            engineered: If True, extracts all 18 features (base + derived);
                        if False, extracts 8 base features.
                        
        Returns:
            Tuple[List[float], Dict[str, Any]]: (feature vector, cleaned features dict)
        """
        if not isinstance(record, dict):
            raise FeatureExtractionError(f"Expected dict record, received {type(record).__name__}")

        if not record:
            raise FeatureExtractionError("Empty traffic record payload provided")

        # Validate non-numeric or NaN values in base fields
        for feat in BASE_FEATURE_NAMES:
            if feat in record and record[feat] is not None:
                val = record[feat]
                try:
                    num_val = float(val)
                except (ValueError, TypeError):
                    raise FeatureExtractionError(f"Invalid non-numeric value for feature '{feat}': '{val}'")
                if math.isnan(num_val) or math.isinf(num_val):
                    raise FeatureExtractionError(f"Feature '{feat}' contains invalid NaN or Infinity value")

        rec_copy = dict(record)
        missing_base = [f for f in BASE_FEATURE_NAMES if rec_copy.get(f) is None]

        if missing_base:
            if len(missing_base) == len(BASE_FEATURE_NAMES):
                raise FeatureExtractionError("All 8 network traffic features are missing from record")
            if not allow_imputation:
                raise FeatureExtractionError(f"Missing required traffic features: {', '.join(missing_base)}")
            
            # Safe median fallbacks
            defaults = {
                'packet_count': 64.0,
                'average_packet_size': 750.0,
                'bytes_transferred': 48000.0,
                'connection_frequency': 10.0,
                'packet_entropy': 4.8,
                'inbound_bytes': 28800.0,
                'outbound_bytes': 19200.0,
                'connection_duration': 2.5
            }
            for m in missing_base:
                rec_copy[m] = defaults.get(m, 0.0)

            # Reconcile bytes transferred if missing
            if 'bytes_transferred' in missing_base:
                in_b = rec_copy.get('inbound_bytes', 0.0)
                out_b = rec_copy.get('outbound_bytes', 0.0)
                rec_copy['bytes_transferred'] = in_b + out_b if (in_b > 0 or out_b > 0) else rec_copy['packet_count'] * rec_copy['average_packet_size']

        if engineered:
            features_dict = pipeline_extract_features(rec_copy, baselines=baselines)
            feature_names = ENGINEERED_FEATURE_NAMES
        else:
            features_dict = {f: float(rec_copy[f]) for f in BASE_FEATURE_NAMES}
            feature_names = BASE_FEATURE_NAMES

        vector = [features_dict[name] for name in feature_names]
        return vector, features_dict

    @classmethod
    def extract_features(
        cls,
        data: Union[Dict[str, Any], List[Dict[str, Any]]],
        allow_imputation: bool = True,
        baselines: Optional[Dict[str, float]] = None,
        engineered: bool = False
    ) -> Tuple[List[List[float]], List[Dict[str, Any]]]:
        """
        Extract feature vectors from either a single record or a list of records.
        """
        if isinstance(data, dict):
            if 'traffic_data' in data and isinstance(data['traffic_data'], list):
                records = data['traffic_data']
            elif 'records' in data and isinstance(data['records'], list):
                records = data['records']
            else:
                records = [data]
        elif isinstance(data, list):
            records = data
        else:
            raise FeatureExtractionError(f"Invalid input type: {type(data).__name__}. Expected dict or list.")

        if not records:
            raise FeatureExtractionError("No traffic records to extract features from")

        vectors = []
        cleaned_records = []

        for idx, rec in enumerate(records):
            try:
                vec, cleaned = cls.extract_single_record(
                    rec,
                    allow_imputation=allow_imputation,
                    baselines=baselines,
                    engineered=engineered
                )
                vectors.append(vec)
                cleaned_records.append(cleaned)
            except FeatureExtractionError as e:
                raise FeatureExtractionError(f"Error at record index {idx}: {str(e)}")

        return vectors, cleaned_records


# Top-level functional exports matching Prompt 2 requirement:
extract_features = pipeline_extract_features
preprocess_traffic_data = pipeline_preprocess_traffic_data
transform_network_traffic = pipeline_transform_network_traffic
