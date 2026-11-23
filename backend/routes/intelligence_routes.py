"""
NetGuardian AI - AI Threat Intelligence API Routes (AI/ML Prompt 4)
Tagline: Detect. Defend. Recover. Automatically.

Provides REST endpoints for:
- GET  /api/intelligence/summary: High-level intelligence KPIs and status across the network
- GET  /api/intelligence/threats: Searchable, filterable list of threat intelligence reports
- GET  /api/intelligence/device/<device_id>: In-depth threat intelligence profile for a specific device
- GET  /api/intelligence/history: Historical anomaly trends, recurring devices, and indicator rankings
- POST /api/intelligence/analyze: Ingests traffic telemetry to generate a grounded intelligence report
"""

import logging
from flask import Blueprint, request

from services.response_service import success_response, error_response
from services.threat_intelligence import ThreatIntelligenceService, THREAT_INDICATORS
from services.device_service import ValidationError, NotFoundError
from services.feature_pipeline import PipelineValidationError
from services.feature_extractor import FeatureExtractionError

logger = logging.getLogger('netguardian.ai.intelligence.routes')

intelligence_bp = Blueprint('intelligence_bp', __name__, url_prefix='/api/intelligence')


@intelligence_bp.route('/summary', methods=['GET'])
def get_intelligence_summary():
    """
    GET /api/intelligence/summary
    
    Returns high-level threat intelligence summary: total reports, severity distributions,
    average threat score, top indicators, and recurring devices.
    """
    try:
        service = ThreatIntelligenceService()
        summary = service.get_summary()
        return success_response(
            data=summary,
            message="Threat intelligence summary retrieved successfully",
            status_code=200
        )
    except Exception as ex:
        logger.error(f"Failed to retrieve threat intelligence summary: {ex}", exc_info=True)
        return error_response(
            message=f"Could not retrieve intelligence summary: {str(ex)}",
            status_code=500
        )


@intelligence_bp.route('/threats', methods=['GET'])
def get_intelligence_threats():
    """
    GET /api/intelligence/threats
    
    Returns list of threat intelligence reports with optional filtering.
    Query parameters:
    - severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
    - threat_indicator: Filter by threat indicator name
    - device_id: Filter by monitored device ID
    - limit: Max reports to return (default 50, max 200)
    - offset: Pagination offset (default 0)
    """
    try:
        severity = request.args.get('severity')
        threat_indicator = request.args.get('threat_indicator')
        raw_dev_id = request.args.get('device_id')
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))

        device_id = None
        if raw_dev_id is not None and str(raw_dev_id).strip():
            try:
                device_id = int(str(raw_dev_id).replace('dev-', ''))
            except ValueError:
                return error_response(message=f"Invalid device_id filter: '{raw_dev_id}'", status_code=400)

        service = ThreatIntelligenceService()
        reports = service.get_reports(
            severity=severity,
            threat_indicator=threat_indicator,
            device_id=device_id,
            limit=limit,
            offset=offset
        )

        return success_response(
            data={
                'reports': reports,
                'count': len(reports),
                'limit': limit,
                'offset': offset
            },
            message="Threat intelligence reports retrieved successfully",
            status_code=200
        )
    except Exception as ex:
        logger.error(f"Failed to retrieve intelligence reports: {ex}", exc_info=True)
        return error_response(
            message=f"Could not retrieve threat reports: {str(ex)}",
            status_code=500
        )


@intelligence_bp.route('/device/<device_id>', methods=['GET'])
def get_device_intelligence(device_id):
    """
    GET /api/intelligence/device/<device_id>
    
    Returns comprehensive threat intelligence profile for a specific device,
    including recurring alert history, average risk score, and severity distribution.
    """
    try:
        service = ThreatIntelligenceService()
        profile = service.get_device_intelligence_profile(device_id)
        return success_response(
            data=profile,
            message=f"Threat intelligence profile for device '{device_id}' retrieved successfully",
            status_code=200
        )
    except NotFoundError as nfe:
        return error_response(
            message=str(nfe),
            status_code=404
        )
    except ValidationError as ve:
        return error_response(
            message=str(ve),
            status_code=400
        )
    except Exception as ex:
        logger.error(f"Error fetching device intelligence for '{device_id}': {ex}", exc_info=True)
        return error_response(
            message=f"Failed to retrieve device intelligence: {str(ex)}",
            status_code=500
        )


@intelligence_bp.route('/history', methods=['GET'])
def get_intelligence_history():
    """
    GET /api/intelligence/history
    
    Analyzes historical alerts and intelligence reports from SQLite.
    Returns trend patterns, recurring devices, and indicator rankings.
    If historical data is insufficient (< 2 records), returns clear status message.
    """
    try:
        service = ThreatIntelligenceService()
        history = service.analyze_history()
        return success_response(
            data=history,
            message="Historical threat analysis retrieved successfully",
            status_code=200
        )
    except Exception as ex:
        logger.error(f"Failed to retrieve historical threat analysis: {ex}", exc_info=True)
        return error_response(
            message=f"Could not retrieve historical analysis: {str(ex)}",
            status_code=500
        )


@intelligence_bp.route('/analyze', methods=['POST'])
def analyze_threat_intelligence():
    """
    POST /api/intelligence/analyze
    
    Ingests live network traffic telemetry for deep threat intelligence analysis.
    Synthesizes AI anomaly detection, feature engineering, classification,
    and historical recurrence to produce an evidence-based intelligence report.
    
    Accepts:
    1. Nested format:
       {
           "device_id": "PC03",
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
    2. Flat format:
       {
           "device_id": 5,
           "packet_count": 850, ...
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
            message="Empty or invalid payload provided. Please supply traffic telemetry fields.",
            status_code=400
        )

    # Validate nested traffic_data if provided
    if 'traffic_data' in payload:
        if not isinstance(payload['traffic_data'], dict) or not payload['traffic_data']:
            return error_response(
                message="Nested 'traffic_data' must be a non-empty JSON object.",
                status_code=400
            )

    try:
        service = ThreatIntelligenceService()
        report = service.analyze_intelligence(payload, persist_report=True)

        return success_response(
            data=report,
            message="Threat intelligence analysis generated successfully",
            status_code=200
        )

    except NotFoundError as nfe:
        return error_response(
            message=str(nfe),
            status_code=404
        )

    except (ValidationError, PipelineValidationError, FeatureExtractionError, ValueError) as ve:
        logger.warning(f"Telemetry validation failed during threat intelligence analysis: {ve}")
        return error_response(
            message=f"Validation error: {str(ve)}",
            status_code=400
        )

    except Exception as ex:
        logger.error(f"Unexpected error in threat intelligence analysis: {ex}", exc_info=True)
        return error_response(
            message=f"Internal threat intelligence error: {str(ex)}",
            status_code=500
        )
