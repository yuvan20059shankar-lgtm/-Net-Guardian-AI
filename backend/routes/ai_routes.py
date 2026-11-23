"""
NetGuardian AI - AI / Machine Learning API Routes
Provides REST endpoints for:
- POST /api/ai/detect: Runs live anomaly detection on network traffic telemetry
- GET /api/ai/model: Returns current model metadata and training parameters
- POST /api/ai/train: Triggers retraining on clean normal traffic baseline
"""

import logging
from flask import Blueprint, request, jsonify

from services.response_service import success_response, error_response
from services.anomaly_service import AnomalyService, detect_anomalies
from services.feature_extractor import FeatureExtractionError
from services.feature_pipeline import PipelineValidationError
from services.threat_classifier import ThreatClassifierService, THREAT_CATEGORIES, analyze_threat
from services.device_service import NotFoundError, ValidationError
from services.ai_pipeline import AIPipelineService, AIPipelineError, ModelUnavailableError
from models.anomaly_detector import AnomalyDetectorError

logger = logging.getLogger('netguardian.ai.routes')

ai_bp = Blueprint('ai_bp', __name__, url_prefix='/api/ai')


@ai_bp.route('/detect', methods=['POST'])
def detect_traffic_anomaly():
    """
    POST /api/ai/detect
    
    Accepts JSON network traffic telemetry for single or batch records.
    Validates features, passes data to the trained Isolation Forest model,
    and returns anomaly classification and score.
    
    Example Single Payload:
    {
        "device_id": 7,
        "packet_count": 850,
        "average_packet_size": 1420.5,
        "bytes_transferred": 1207425,
        "connection_frequency": 65.2,
        "packet_entropy": 7.85,
        "inbound_bytes": 12400,
        "outbound_bytes": 1195025,
        "connection_duration": 48.5
    }
    
    Example Batch Payload:
    {
        "traffic_data": [ ... ]
    }
    """
    if not request.is_json:
        return error_response(
            message="Invalid request: Content-Type must be application/json",
            status_code=400
        )

    payload = request.get_json(silent=True)
    if payload is None:
        return error_response(
            message="Malformed or empty JSON payload",
            status_code=400
        )

    if not payload:
        return error_response(
            message="Empty traffic payload provided. Please supply traffic telemetry fields.",
            status_code=400
        )

    try:
        service = AnomalyService()
        result = service.detect(payload)
        
        is_batch = isinstance(result, list)
        msg = f"Successfully evaluated {len(result)} traffic records" if is_batch else "Anomaly detection evaluation completed"
        
        return success_response(
            data=result,
            message=msg,
            status_code=200
        )

    except FeatureExtractionError as fe:
        logger.warning(f"Feature extraction validation failed: {fe}")
        return error_response(
            message=f"Validation error: {str(fe)}",
            status_code=400
        )

    except AnomalyDetectorError as ae:
        logger.error(f"Anomaly detector operational failure: {ae}", exc_info=True)
        return error_response(
            message=f"Model execution error: {str(ae)}",
            status_code=500
        )

    except Exception as ex:
        logger.error(f"Unexpected anomaly detection error: {ex}", exc_info=True)
        return error_response(
            message=f"Internal inference error: {str(ex)}",
            status_code=500
        )


@ai_bp.route('/model', methods=['GET'])
@ai_bp.route('/status', methods=['GET'])
def get_model_info():
    """
    GET /api/ai/model
    
    Returns metadata about the active Isolation Forest model:
    version, contamination, training timestamp, training sample count, and input features.
    """
    try:
        service = AnomalyService()
        info = service.get_model_info()
        return success_response(
            data=info,
            message="Active model metadata retrieved successfully",
            status_code=200
        )
    except Exception as ex:
        logger.error(f"Failed to retrieve model info: {ex}", exc_info=True)
        return error_response(
            message=f"Could not retrieve model information: {str(ex)}",
            status_code=500
        )


@ai_bp.route('/baselines', methods=['GET'])
def get_baselines():
    """
    GET /api/ai/baselines
    
    Returns pre-calculated statistical baseline distributions from training data.
    """
    try:
        service = AnomalyService()
        info = service.get_model_info()
        return success_response(
            data=info.get('baselines', {}),
            message="Training traffic baselines retrieved successfully",
            status_code=200
        )
    except Exception as ex:
        logger.error(f"Failed to retrieve baselines: {ex}", exc_info=True)
        return error_response(
            message=f"Could not retrieve baselines: {str(ex)}",
            status_code=500
        )


@ai_bp.route('/categories', methods=['GET'])
def get_threat_categories():
    """
    GET /api/ai/categories
    
    Returns the supported canonical threat categories and severity definitions.
    """
    return success_response(
        data={
            'categories': THREAT_CATEGORIES,
            'severities': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        },
        message="Supported threat categories retrieved successfully",
        status_code=200
    )


@ai_bp.route('/analyze', methods=['POST'])
def analyze_network_traffic():
    """
    POST /api/ai/analyze
    
    Executes the complete 6-stage Unified AI/ML Pipeline:
    Traffic Input -> Feature Engineering -> Anomaly Detection -> Threat Classification ->
    Threat Intelligence -> Database Storage & Deduplication.
    
    Accepts both:
    1. Wrapped format:
       {
           "device_id": "PC03",
           "traffic_data": {
               "packet_count": 9200,
               "average_packet_size": 42.0,
               ...
           }
       }
    2. Flat format:
       {
           "device_id": 5,
           "packet_count": 9200,
           ...
       }
    """
    if not request.is_json:
        return error_response(
            message="Invalid request: Content-Type must be application/json",
            status_code=400
        )

    payload = request.get_json(silent=True)
    if payload is None:
        return error_response(
            message="Malformed or empty JSON payload",
            status_code=400
        )

    if not isinstance(payload, dict) or not payload:
        return error_response(
            message="Empty or invalid traffic payload provided. Please supply traffic telemetry fields.",
            status_code=400
        )

    # Validate that if traffic_data is supplied, it is a non-empty dictionary
    if 'traffic_data' in payload:
        if not isinstance(payload['traffic_data'], dict) or not payload['traffic_data']:
            return error_response(
                message="Nested 'traffic_data' must be a non-empty JSON object.",
                status_code=400
            )

    try:
        pipeline = AIPipelineService()
        result = pipeline.run_pipeline(payload, persist_results=True)

        response_dict = {
            "success": True,
            "message": "Unified AI/ML pipeline analysis completed successfully",
            "data": result,
            "device_id": result['device_id'],
            "device_status": result['device_status'],
            "analysis": result['analysis'],
            "evidence": result['evidence'],
            "recommended_actions": result['recommended_actions'],
            "alert_created": result['alert_created'],
            "self_healing_advisory": result.get('self_healing_advisory'),
            "timestamp": result['timestamp']
        }
        return jsonify(response_dict), 200

    except NotFoundError as nfe:
        return error_response(
            message=str(nfe),
            status_code=404
        )

    except (PipelineValidationError, FeatureExtractionError, ValidationError, ValueError) as ve:
        logger.warning(f"Traffic telemetry validation failed: {ve}")
        return error_response(
            message=f"Validation error: {str(ve)}",
            status_code=400
        )

    except (ModelUnavailableError, AnomalyDetectorError) as ae:
        logger.error(f"Anomaly detector operational failure in threat analysis: {ae}", exc_info=True)
        return error_response(
            message=f"AI Model execution error: {str(ae)}",
            status_code=500
        )

    except Exception as ex:
        logger.error(f"Unexpected threat analysis error: {ex}", exc_info=True)
        return error_response(
            message=f"Internal threat analysis error: {str(ex)}",
            status_code=500
        )


@ai_bp.route('/train', methods=['POST'])
def retrain_model():
    """
    POST /api/ai/train
    
    Retrains the Isolation Forest model on normal baseline traffic samples.
    Optional JSON parameters:
    - contamination (float, default 0.08)
    - random_state (int, default 42)
    """
    payload = request.get_json(silent=True) or {}
    contamination = float(payload.get('contamination', 0.08))
    random_state = int(payload.get('random_state', 42))

    if contamination <= 0.0 or contamination >= 0.5:
        return error_response(
            message="Contamination parameter must be between 0.0 and 0.5",
            status_code=400
        )

    try:
        service = AnomalyService()
        metrics = service.train_model(contamination=contamination, random_state=random_state)
        return success_response(
            data=metrics,
            message="Model successfully trained and saved",
            status_code=200
        )
    except Exception as ex:
        logger.error(f"Model retraining failed: {ex}", exc_info=True)
        return error_response(
            message=f"Model retraining failed: {str(ex)}",
            status_code=500
        )
