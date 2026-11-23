"""
NetGuardian AI - Unified AI/ML Pipeline Service (Prompt 5)
Tagline: Detect. Defend. Recover. Automatically.

Integrates all 4 AI/ML modules into a single, cohesive, production-ready pipeline:
- Stage 1: Traffic Input & Device Validation (SQLite devices)
- Stage 2: Feature Engineering (Prompt 2 Feature Pipeline, 18 features + baseline deviations)
- Stage 3: Anomaly Detection (Prompt 1 Isolation Forest Model)
- Stage 4: Threat Classification (Prompt 3 Heuristic Categorization & Severity)
- Stage 5: Threat Intelligence (Prompt 4 Scoring 0-100, Multi-Factor Confidence, Evidence & Non-Destructive Advisories)
- Stage 6: Result Storage & Deduplication (SQLite security_alerts & threat_intelligence_reports)
"""

from __future__ import annotations
import os
import time
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union

from config import get_config
from database import get_db
from models.anomaly_detector import AnomalyDetectorError
from services.device_service import DeviceService, ValidationError, NotFoundError
from services.feature_pipeline import (
    BASE_FEATURE_NAMES,
    DERIVED_FEATURE_NAMES,
    ENGINEERED_FEATURE_NAMES,
    PipelineValidationError,
    validate_feature_schema,
    extract_features
)
from services.feature_extractor import FeatureExtractionError
from services.anomaly_service import AnomalyService
from services.threat_classifier import ThreatClassifierService, THREAT_CATEGORIES
from services.threat_intelligence import ThreatIntelligenceService, THREAT_INDICATORS

logger = logging.getLogger('netguardian.ai.pipeline')


class AIPipelineError(Exception):
    """Base exception for unified pipeline errors."""
    pass


class ModelUnavailableError(AIPipelineError):
    """Raised when model artifact cannot be found or loaded."""
    pass


class AIPipelineService:
    """
    Unified AI/ML Pipeline Engine for NetGuardian AI.
    Executes Stages 1 through 6 sequentially with thread-safe caching and validation.
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(AIPipelineService, cls).__new__(cls)
            cls._instance._anomaly_service = None
            cls._instance._threat_classifier = None
            cls._instance._threat_intelligence = None
        return cls._instance

    def __init__(self):
        # Lazy initialization of component services
        if self._anomaly_service is None:
            self._anomaly_service = AnomalyService()
        if self._threat_classifier is None:
            self._threat_classifier = ThreatClassifierService()
        if self._threat_intelligence is None:
            self._threat_intelligence = ThreatIntelligenceService()

    # --------------------------------------------------------------------------
    # STAGE 1: TRAFFIC INPUT & DEVICE VALIDATION
    # --------------------------------------------------------------------------
    def stage_1_validate_input(self, data: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Stage 1: Validate input payload and resolve source device in SQLite.
        
        Args:
            data: Raw request dictionary.
            
        Returns:
            Tuple[Dict[str, Any], Dict[str, Any]]: (device_record, traffic_record)
        """
        if not data or not isinstance(data, dict):
            raise ValidationError("Traffic payload must be a non-empty JSON object.")

        # Handle nested wrapper: {'device_id': 'PC03', 'traffic_data': {...}}
        record = dict(data)
        raw_dev_id = record.get('device_id')
        if 'traffic_data' in record and isinstance(record['traffic_data'], dict):
            nested = dict(record['traffic_data'])
            if raw_dev_id is not None and 'device_id' not in nested:
                nested['device_id'] = raw_dev_id
            record = nested

        # Resolve device ID
        dev_id_val = raw_dev_id if raw_dev_id is not None else record.get('device_id')
        if dev_id_val is None:
            # Default to primary core router if omitted
            dev_id_val = 1

        # Normalize string identifiers: "PC03" -> 7, "PC 03" -> 7, "dev-3" -> 3, "3" -> 3
        device = None
        parsed_num = DeviceService.parse_device_id(dev_id_val)

        if parsed_num is not None:
            device = DeviceService.get_device_by_id(parsed_num)

        # Fallback: Lookup by device name (e.g. "PC 03", "PC03", "Server 01", "Router 01")
        if not device:
            cleaned_name = str(dev_id_val).strip()
            # Try matching with or without space (e.g. PC03 -> PC 03)
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM devices WHERE LOWER(device_name) = LOWER(?);", (cleaned_name,))
                row = cursor.fetchone()
                if not row and len(cleaned_name) >= 3:
                    # Try inserting space if format is like PC03 or Server01
                    import re
                    match = re.match(r"^([a-zA-Z]+)(\d+)$", cleaned_name)
                    if match:
                        spaced_name = f"{match.group(1)} {match.group(2).zfill(2)}"
                        cursor.execute("SELECT * FROM devices WHERE LOWER(device_name) = LOWER(?);", (spaced_name,))
                        row = cursor.fetchone()
                        if not row:
                            spaced_name_simple = f"{match.group(1)} {int(match.group(2))}"
                            cursor.execute("SELECT * FROM devices WHERE LOWER(device_name) = LOWER(?);", (spaced_name_simple,))
                            row = cursor.fetchone()

                if row:
                    from models.device_model import Device
                    device = Device.from_row(row).to_dict()

        if not device:
            raise NotFoundError(f"Monitored network device '{dev_id_val}' not found in database inventory.")

        # Ensure numeric device_id is attached to record
        record['device_id'] = device['id']
        return device, record

    # --------------------------------------------------------------------------
    # STAGE 2: FEATURE ENGINEERING
    # --------------------------------------------------------------------------
    def stage_2_feature_engineering(
        self,
        record: Dict[str, Any]
    ) -> Dict[str, float]:
        """
        Stage 2: Extract & calculate 18 engineered features, preserving model feature order.
        """
        try:
            baselines = self._anomaly_service.detector.baselines
        except Exception:
            baselines = None

        features = extract_features(record, baselines=baselines)
        return features

    # --------------------------------------------------------------------------
    # STAGE 3: ANOMALY DETECTION
    # --------------------------------------------------------------------------
    def stage_3_anomaly_detection(
        self,
        record: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Stage 3: Run Isolation Forest inference with cached model artifact.
        """
        try:
            result = self._anomaly_service.detect(record)
            if isinstance(result, list):
                result = result[0]
            return result
        except AnomalyDetectorError as ade:
            raise ModelUnavailableError(f"Isolation Forest inference failed: {ade}")
        except Exception as e:
            raise ModelUnavailableError(f"Model execution error: {e}")

    # --------------------------------------------------------------------------
    # STAGE 4: THREAT CLASSIFICATION
    # --------------------------------------------------------------------------
    def stage_4_threat_classification(
        self,
        anomaly_result: Dict[str, Any],
        features: Dict[str, float]
    ) -> Dict[str, Any]:
        """
        Stage 4: Map multivariate telemetry to canonical threat category and baseline severity.
        """
        from services.threat_classifier import classify_threat
        return classify_threat(anomaly_result, features)

    # --------------------------------------------------------------------------
    # STAGE 5: THREAT INTELLIGENCE
    # --------------------------------------------------------------------------
    def stage_5_threat_intelligence(
        self,
        device: Dict[str, Any],
        features: Dict[str, float],
        anomaly_result: Dict[str, Any],
        classification: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Stage 5: Synthesize grounded evidence, calculate 0-100 threat score,
        determine multi-factor confidence, and assemble non-destructive advisories.
        """
        device_id = device['id']
        device_name = device['device_name']
        device_ip = device['ip_address']

        # Historical alerts count
        historical_alerts = ThreatIntelligenceService.get_device_historical_alerts(device_id, limit=10)
        historical_count = len(historical_alerts)
        recent_alert_codes = [a['alert_code'] for a in historical_alerts[:3]]

        classified_threat = classification['threat_type']
        anomaly_score = float(anomaly_result.get('anomaly_score', 0.0))

        # Check for Repeated Anomalous Behaviour indicator
        if classified_threat != 'Nominal Traffic' and historical_count >= 2:
            indicator = 'Repeated Anomalous Behaviour'
        else:
            from services.threat_intelligence import CATEGORY_TO_INDICATOR_MAP
            indicator = CATEGORY_TO_INDICATOR_MAP.get(classified_threat, 'Suspicious Network Communication')

        # Threat Score (0 - 100)
        threat_score = ThreatIntelligenceService.calculate_threat_score(
            anomaly_score=anomaly_score,
            traffic_features=features,
            indicator=indicator,
            historical_alerts_count=historical_count
        )

        # Severity
        severity = ThreatIntelligenceService.calculate_severity(
            threat_score=threat_score,
            indicator=indicator,
            base_severity=classification.get('severity')
        )

        # Confidence (Multi-factor)
        has_baseline = bool(features.get('traffic_volume_deviation') is not None)
        confidence = ThreatIntelligenceService.calculate_confidence(
            traffic_features=features,
            anomaly_score=anomaly_score,
            has_baseline=has_baseline,
            historical_alerts_count=historical_count
        )

        # Dynamic Explanation
        explanation = ThreatIntelligenceService.generate_threat_explanation(
            device_name=device_name,
            device_ip=device_ip,
            indicator=indicator,
            severity=severity,
            features=features,
            anomaly_score=anomaly_score,
            historical_count=historical_count
        )

        # Recommended Actions (Non-destructive)
        actions = ThreatIntelligenceService.get_recommended_actions(indicator, severity)

        # Evidence
        evidence = {
            'device_id': device_id,
            'device_name': device_name,
            'device_ip': device_ip,
            'packet_count': features.get('packet_count', 0),
            'average_packet_size': features.get('average_packet_size', 0.0),
            'inbound_bytes': features.get('inbound_bytes', 0),
            'outbound_bytes': features.get('outbound_bytes', 0),
            'connection_frequency': features.get('connection_frequency', 0.0),
            'traffic_volume_deviation': features.get('traffic_volume_deviation', 0.0),
            'anomaly_score': round(anomaly_score, 4),
            'threat_classification': classified_threat,
            'detection_timestamp': datetime.utcnow().isoformat() + 'Z',
            'related_historical_alerts_count': historical_count,
            'related_historical_alert_codes': recent_alert_codes
        }

        return {
            'threat_indicator': indicator,
            'threat_type': classified_threat,
            'severity': severity,
            'threat_score': threat_score,
            'confidence': confidence,
            'explanation': explanation,
            'evidence': evidence,
            'recommended_actions': actions
        }

    # --------------------------------------------------------------------------
    # STAGE 6: RESULT STORAGE & DEDUPLICATION
    # --------------------------------------------------------------------------
    def stage_6_result_storage(
        self,
        device: Dict[str, Any],
        intel_result: Dict[str, Any],
        is_anomaly: bool,
        anomaly_score: float,
        features: Dict[str, float]
    ) -> Tuple[bool, Optional[str], Optional[int]]:
        """
        Stage 6: Save valid analysis results in SQLite database with duplicate suppression.
        
        Returns:
            Tuple[bool, Optional[str], Optional[int]]: (alert_created, alert_code, alert_id)
        """
        device_id = device['id']
        device_name = device['device_name']
        device_ip = device['ip_address']
        indicator = intel_result['threat_indicator']
        severity = intel_result['severity']
        threat_score = intel_result['threat_score']
        confidence = intel_result['confidence']
        explanation = intel_result['explanation']
        evidence = intel_result['evidence']
        actions = intel_result['recommended_actions']

        alert_created = False
        alert_code = None
        alert_id = None

        # 1. Alert persistence with 300s deduplication (if anomalous and severity >= MEDIUM)
        if is_anomaly and severity in ('MEDIUM', 'HIGH', 'CRITICAL'):
            from services.alert_service import AlertService
            try:
                recent_alert = AlertService.find_recent_active_alert(
                    device_id=device_id,
                    threat_type=intel_result['threat_type'],
                    within_seconds=300
                )
                if recent_alert:
                    alert_created = False
                    alert_code = recent_alert['alert_code']
                    alert_id = recent_alert['id']
                else:
                    new_alert = AlertService.create_alert({
                        'device_id': device_id,
                        'threat_type': intel_result['threat_type'],
                        'description': explanation,
                        'severity': severity,
                        'status': 'ACTIVE',
                        'detection_source': 'NetGuardian Unified AI/ML Pipeline',
                        'recommended_action': actions[0] if actions else "Review device telemetry.",
                        'anomaly_score': anomaly_score
                    })
                    alert_created = True
                    alert_code = new_alert['alert_code']
                    alert_id = new_alert['id']
            except Exception as e:
                logger.warning(f"Could not persist alert in SQLite: {e}")

        # 2. Intelligence report persistence
        try:
            report_data = {
                'report_id': f"TIR-{uuid.uuid4().hex[:8].upper()}",
                'device_id': device_id,
                'device_ip': device_ip,
                'device_name': device_name,
                'threat_indicator': indicator,
                'severity': severity,
                'threat_score': threat_score,
                'confidence': confidence,
                'explanation': explanation,
                'evidence': evidence,
                'recommended_actions': actions,
                'alert_code': alert_code
            }
            ThreatIntelligenceService.save_report(report_data)
        except Exception as e:
            logger.warning(f"Could not persist intelligence report in SQLite: {e}")

        return alert_created, alert_code, alert_id

    # --------------------------------------------------------------------------
    # COMPLETE UNIFIED PIPELINE EXECUTION
    # --------------------------------------------------------------------------
    def run_pipeline(
        self,
        data: Dict[str, Any],
        persist_results: bool = True
    ) -> Dict[str, Any]:
        """
        Execute the complete 6-stage AI/ML pipeline.
        
        Args:
            data: Telemetry request dict.
            persist_results: Whether to save alerts and reports to SQLite.
            
        Returns:
            Dict[str, Any]: Unified API response payload conforming to Prompt 5 Section 3.
        """
        # Stage 1: Validate input & resolve device
        device, record = self.stage_1_validate_input(data)

        # Stage 2: Feature engineering
        features = self.stage_2_feature_engineering(record)

        # Stage 3: Anomaly detection
        anomaly_result = self.stage_3_anomaly_detection(record)
        is_anomaly = anomaly_result.get('is_anomaly', False)
        anomaly_score = float(anomaly_result.get('anomaly_score', 0.0))
        prediction = anomaly_result.get('prediction', 'NORMAL')

        # Stage 4: Threat classification
        classification = self.stage_4_threat_classification(anomaly_result, features)

        # Stage 5: Threat intelligence
        intel = self.stage_5_threat_intelligence(
            device=device,
            features=features,
            anomaly_result=anomaly_result,
            classification=classification
        )

        # Stage 6: Storage & deduplication
        alert_created = False
        alert_code = None
        alert_id = None
        if persist_results:
            alert_created, alert_code, alert_id = self.stage_6_result_storage(
                device=device,
                intel_result=intel,
                is_anomaly=is_anomaly,
                anomaly_score=anomaly_score,
                features=features
            )

        timestamp = intel['evidence'].get('detection_timestamp', datetime.utcnow().isoformat() + 'Z')

        # AI/ML - Self-Healing Bridge Advisory
        try:
            from services.auto_recovery import AutoRecoveryService
            healing_advisory = AutoRecoveryService.evaluate_healing_advisory({
                'device_id': device['id'],
                'severity': intel['severity'],
                'confidence': intel['confidence'],
                'threat_type': intel['threat_type'],
                'is_anomaly': is_anomaly
            })
        except Exception:
            healing_advisory = {'recommended_healing_action': 'MONITOR', 'isolate_recommended': False}

        # Assemble unified response structure matching Prompt 5 Section 3
        # Supports both nested and flat access patterns for full frontend/testing compatibility
        unified_output = {
            'device_id': device['id'],
            'device_name': device['device_name'],
            'device_ip': device['ip_address'],
            'device_status': device['status'],
            'self_healing_advisory': healing_advisory,
            'analysis': {
                'prediction': prediction,
                'anomaly_score': round(anomaly_score, 4),
                'threat_type': intel['threat_type'],
                'threat_indicator': intel['threat_indicator'],
                'severity': intel['severity'],
                'threat_score': intel['threat_score'],
                'confidence': intel['confidence'],
                'explanation': intel['explanation']
            },
            'evidence': intel['evidence'],
            'recommended_actions': intel['recommended_actions'],
            'alert_created': alert_created,
            'alert_code': alert_code,
            'alert_id': alert_id,
            'timestamp': timestamp,
            # Flat attributes for Prompt 3 & legacy API backwards compatibility:
            'is_anomaly': is_anomaly,
            'duplicate_suppressed': bool(persist_results and not alert_created and is_anomaly and intel['severity'] in ('MEDIUM', 'HIGH', 'CRITICAL')),
            'threat_classification': {
                'threat_type': intel['threat_type'],
                'severity': intel['severity'],
                'explanation': intel['explanation']
            },
            'threat_type': intel['threat_type'],
            'threat_indicator': intel['threat_indicator'],
            'severity': intel['severity'],
            'threat_score': intel['threat_score'],
            'confidence': intel['confidence'],
            'anomaly_score': round(anomaly_score, 4),
            'prediction': prediction,
            'explanation': intel['explanation'],
            'recommended_action': intel['recommended_actions'][0] if intel['recommended_actions'] else "Monitor device telemetry.",
            'features': features
        }

        return unified_output


# Convenience helper function:
def execute_ai_pipeline(data: Dict[str, Any], persist: bool = True) -> Dict[str, Any]:
    """Execute the unified 6-stage AI pipeline on telemetry input."""
    pipeline = AIPipelineService()
    return pipeline.run_pipeline(data, persist_results=persist)
