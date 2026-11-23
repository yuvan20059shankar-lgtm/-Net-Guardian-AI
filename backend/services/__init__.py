"""
NetGuardian AI - Services Package
"""

from .response_service import success_response, error_response
from .device_service import DeviceService, ValidationError, DuplicateError, NotFoundError
from .feature_extractor import FeatureExtractor, FeatureExtractionError, FEATURE_NAMES
from .feature_pipeline import (
    BASE_FEATURE_NAMES,
    DERIVED_FEATURE_NAMES,
    ENGINEERED_FEATURE_NAMES,
    PipelineValidationError,
    validate_feature_schema,
    calculate_traffic_baselines,
    detect_duplicates,
    extract_features,
    preprocess_traffic_data,
    transform_network_traffic,
    generate_feature_explanation
)
from .traffic_generator import TrafficDatasetGenerator, load_dataset
from .anomaly_service import AnomalyService, detect_anomalies
from .threat_classifier import (
    THREAT_CATEGORIES,
    SEVERITY_THRESHOLDS,
    calculate_threat_severity,
    recommend_security_action,
    classify_threat,
    ThreatClassifierService,
    analyze_threat
)
from .threat_intelligence import (
    THREAT_INDICATORS,
    CATEGORY_TO_INDICATOR_MAP,
    ThreatIntelligenceService,
    analyze_intelligence
)
from .ai_pipeline import (
    AIPipelineService,
    AIPipelineError,
    ModelUnavailableError,
    execute_ai_pipeline
)

__all__ = [
    'success_response',
    'error_response',
    'DeviceService',
    'ValidationError',
    'DuplicateError',
    'NotFoundError',
    'FeatureExtractor',
    'FeatureExtractionError',
    'FEATURE_NAMES',
    'BASE_FEATURE_NAMES',
    'DERIVED_FEATURE_NAMES',
    'ENGINEERED_FEATURE_NAMES',
    'PipelineValidationError',
    'validate_feature_schema',
    'calculate_traffic_baselines',
    'detect_duplicates',
    'extract_features',
    'preprocess_traffic_data',
    'transform_network_traffic',
    'generate_feature_explanation',
    'TrafficDatasetGenerator',
    'load_dataset',
    'AnomalyService',
    'detect_anomalies',
    'THREAT_CATEGORIES',
    'SEVERITY_THRESHOLDS',
    'calculate_threat_severity',
    'recommend_security_action',
    'classify_threat',
    'ThreatClassifierService',
    'analyze_threat',
    'THREAT_INDICATORS',
    'CATEGORY_TO_INDICATOR_MAP',
    'ThreatIntelligenceService',
    'analyze_intelligence',
    'AIPipelineService',
    'AIPipelineError',
    'ModelUnavailableError',
    'execute_ai_pipeline'
]
