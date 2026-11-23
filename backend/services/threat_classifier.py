"""
NetGuardian AI - Intelligent AI Threat Classification Engine
Transforms Isolation Forest predictions and engineered traffic features into:
- Actionable security threat categories
- Configurable severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- Mathematically grounded threat explanations and evidence
- Non-destructive security recommendations
- Automated database alert creation with duplicate suppression
"""

from __future__ import annotations
import math
import logging
from typing import Dict, List, Any, Optional, Tuple, Union

from services.feature_pipeline import (
    BASE_FEATURE_NAMES,
    DERIVED_FEATURE_NAMES,
    ENGINEERED_FEATURE_NAMES,
    PipelineValidationError,
    validate_feature_schema,
    extract_features
)
from services.anomaly_service import AnomalyService
from services.alert_service import AlertService
from services.device_service import DeviceService

logger = logging.getLogger('netguardian.ai.classifier')

# Canonical Threat Categories (Prompt 3 Section 2)
THREAT_CATEGORIES = [
    'Port Scanning',
    'Denial of Service (DoS) - like traffic spikes',
    'Suspicious Outbound Traffic',
    'Potential Data Exfiltration',
    'Unusual Packet Behaviour',
    'Abnormal Connection Frequency',
    'Suspicious Network Communication',
    'Nominal Traffic'
]

# Configurable Severity Thresholds
SEVERITY_THRESHOLDS = {
    'CRITICAL': 0.80,
    'HIGH': 0.68,
    'MEDIUM': 0.52,
    'LOW': 0.00
}


def calculate_threat_severity(
    anomaly_score: float,
    traffic_features: Dict[str, float],
    threat_type: str
) -> str:
    """
    Calculate threat severity (LOW, MEDIUM, HIGH, CRITICAL) based on anomaly score,
    specific threat category, and observed feature deviations.
    
    IMPORTANT: Based on configurable operational thresholds, not fabricated attack probabilities.
    """
    score = float(anomaly_score or 0.0)

    # Escalation Rule 1: Extreme volume or entropy data exfiltration
    if threat_type == 'Potential Data Exfiltration':
        if score >= 0.72 or traffic_features.get('packet_entropy', 0.0) >= 7.85 or traffic_features.get('outbound_bytes', 0.0) >= 10_000_000:
            return 'CRITICAL'
        return 'HIGH'

    # Escalation Rule 2: Massive packet flood DoS
    if threat_type == 'Denial of Service (DoS) - like traffic spikes':
        if score >= 0.78 or traffic_features.get('packets_per_second', 0.0) >= 10_000.0:
            return 'CRITICAL'
        return 'HIGH'

    # Escalation Rule 3: Severe port sweep
    if threat_type == 'Port Scanning':
        if traffic_features.get('connection_frequency', 0.0) >= 200.0 or score >= 0.75:
            return 'HIGH'
        return 'MEDIUM'

    # General threshold mapping
    if score >= SEVERITY_THRESHOLDS['CRITICAL']:
        return 'CRITICAL'
    elif score >= SEVERITY_THRESHOLDS['HIGH']:
        return 'HIGH'
    elif score >= SEVERITY_THRESHOLDS['MEDIUM']:
        return 'MEDIUM'
    else:
        return 'LOW'


def recommend_security_action(threat_type: str, severity: str) -> str:
    """
    Generate actionable, non-destructive security recommendations.
    Actual isolation and recovery are handled by the Self-Healing Engine.
    """
    if threat_type == 'Nominal Traffic' or severity == 'LOW':
        return "Monitor the device and continue routine telemetry logging. No immediate action required."

    if threat_type == 'Potential Data Exfiltration':
        if severity == 'CRITICAL':
            return "Generate critical SOC incident alert, verify destination IP reputation at perimeter firewall, and consider preparing simulated device quarantine."
        return "Review active egress sockets, inspect user authentication logs, and monitor outbound bandwidth quota."

    if threat_type == 'Denial of Service (DoS) - like traffic spikes':
        if severity == 'CRITICAL':
            return "Activate rate-limiting rate buckets and syn-cookies on perimeter firewall; consider simulated device isolation."
        return "Inspect ingress packet queues, apply dynamic rate limiting, and review server resource utilization."

    if threat_type == 'Port Scanning':
        return "Restrict sweep egress on subnet switch, inspect running processes on host, and monitor connection attempts."

    if threat_type == 'Suspicious Outbound Traffic':
        return "Investigate host outbound socket activity, review user processes, and check network destination logs."

    if threat_type == 'Abnormal Connection Frequency':
        return "Review connection activity, check for automated script loops, and inspect connection state table."

    if threat_type == 'Unusual Packet Behaviour':
        return "Inspect network interface MTU parameters and perform deep packet inspection on frame headers."

    # General Fallback
    if severity in ('HIGH', 'CRITICAL'):
        return "Investigate the device and consider temporary isolation in the simulated network."
    return "Review connection activity and continue behavioral monitoring."


def classify_threat(
    anomaly_result: Dict[str, Any],
    traffic_features: Dict[str, float]
) -> Dict[str, Any]:
    """
    Classify anomaly into a concrete security threat category based on transparent rules.
    
    Args:
        anomaly_result: Output from Isolation Forest detector (prediction, anomaly_score, etc.).
        traffic_features: Cleaned 18-feature dictionary.
        
    Returns:
        Dict[str, Any]: Classified threat details (threat_type, severity, explanation, recommendations, evidence).
    """
    is_anomaly = anomaly_result.get('is_anomaly', False)
    anomaly_score = float(anomaly_result.get('anomaly_score', 0.0))

    # Features
    pkt_count = traffic_features.get('packet_count', 0.0)
    avg_pkt_size = traffic_features.get('average_packet_size', 0.0)
    bytes_trans = traffic_features.get('bytes_transferred', 0.0)
    conn_freq = traffic_features.get('connection_frequency', 0.0)
    pkt_entropy = traffic_features.get('packet_entropy', 0.0)
    in_bytes = traffic_features.get('inbound_bytes', 0.0)
    out_bytes = traffic_features.get('outbound_bytes', 0.0)
    out_pct = traffic_features.get('outbound_traffic_percentage', 0.0)
    pps = traffic_features.get('packets_per_second', 0.0)
    vol_dev = traffic_features.get('traffic_volume_deviation', 0.0)
    conn_dev = traffic_features.get('connection_rate_deviation', 0.0)
    ent_dev = traffic_features.get('traffic_entropy_deviation', 0.0)

    # 1. Nominal Traffic check
    if not is_anomaly and anomaly_score < 0.48 and out_pct < 80.0 and conn_freq < 60.0 and pps < 3000.0:
        threat_type = 'Nominal Traffic'
        severity = 'LOW'
        explanation = "Traffic conforms to normal behavioral baseline. No security threat indicators detected."
        action = recommend_security_action(threat_type, severity)
        return {
            'threat_type': threat_type,
            'severity': severity,
            'is_confirmed_attack': False,
            'explanation': explanation,
            'recommended_action': action,
            'evidence': {
                'model_prediction': 'NORMAL',
                'anomaly_score': round(anomaly_score, 4),
                'outbound_bytes': round(out_bytes, 2),
                'inbound_bytes': round(in_bytes, 2),
                'connection_frequency': round(conn_freq, 2),
                'packet_entropy': round(pkt_entropy, 2)
            }
        }

    # 2. Rule: Denial of Service (DoS) - like traffic spikes
    if pps >= 3500.0 or (pkt_count >= 8000.0 and avg_pkt_size <= 120.0 and conn_freq >= 200.0) or (vol_dev >= 5.0 and traffic_features.get('connection_duration', 1.0) <= 0.5):
        threat_type = 'Denial of Service (DoS) - like traffic spikes'
        explanation = (
            f"Severe packet throughput surge ({pps:,.0f} pkts/sec, {conn_freq:.1f} conn/s) with minimal packet payload ({avg_pkt_size:.0f} B), "
            f"indicating high-rate connection or SYN exhaustion flooding."
        )

    # 3. Rule: Potential Data Exfiltration
    elif out_pct >= 85.0 and (pkt_entropy >= 7.3 or out_bytes >= 5_000_000.0):
        threat_type = 'Potential Data Exfiltration'
        explanation = (
            f"Outbound egress is unusually asymmetric ({out_pct:.1f}% outbound, {out_bytes:,.0f} bytes) "
            f"combined with elevated Shannon entropy ({pkt_entropy:.2f}), indicative of compressed/encrypted exfiltration over unauthorized channels."
        )

    # 4. Rule: Port Scanning
    elif conn_freq >= 60.0 and avg_pkt_size <= 150.0 and traffic_features.get('inbound_outbound_ratio', 1.0) <= 0.35:
        threat_type = 'Port Scanning'
        explanation = (
            f"High connection frequency ({conn_freq:.1f} conn/s) with small packet probes ({avg_pkt_size:.0f} B) and near-zero response data, "
            f"matching horizontal or vertical subnet reconnaissance scanning."
        )

    # 5. Rule: Suspicious Outbound Traffic
    elif out_pct >= 70.0 and (out_bytes >= 1_000_000.0 or vol_dev >= 2.5):
        threat_type = 'Suspicious Outbound Traffic'
        explanation = (
            f"Outbound traffic ({out_bytes:,.0f} bytes, {out_pct:.1f}% egress) is significantly higher than the configured normal baseline for this host."
        )

    # 6. Rule: Abnormal Connection Frequency
    elif conn_freq >= 75.0 or conn_dev >= 3.0:
        threat_type = 'Abnormal Connection Frequency'
        explanation = (
            f"Connection rate ({conn_freq:.1f} conn/s) deviates by {conn_dev:.1f}σ above normal baseline distribution, indicating automated connection bursts."
        )

    # 7. Rule: Unusual Packet Behaviour
    elif avg_pkt_size >= 3500.0 or traffic_features.get('packet_size_variation', 0.0) >= 800.0 or pkt_entropy >= 7.6:
        threat_type = 'Unusual Packet Behaviour'
        explanation = (
            f"Unusual packet attributes observed: average packet size ({avg_pkt_size:.0f} bytes) or payload entropy ({pkt_entropy:.2f}) deviates from standard network profiles."
        )

    # 8. Rule: Suspicious Network Communication (Multidimensional outlier)
    else:
        threat_type = 'Suspicious Network Communication'
        explanation = (
            f"Isolation Forest flagged multidimensional anomaly (score: {anomaly_score:.4f}): feature vector significantly deviates from normal baseline clusters."
        )

    # Determine severity
    severity = calculate_threat_severity(anomaly_score, traffic_features, threat_type)
    action = recommend_security_action(threat_type, severity)

    return {
        'threat_type': threat_type,
        'severity': severity,
        'is_confirmed_attack': False,  # Distinguish detected anomaly from confirmed attack
        'explanation': explanation,
        'recommended_action': action,
        'evidence': {
            'model_prediction': 'ANOMALY' if is_anomaly else 'NORMAL',
            'anomaly_score': round(anomaly_score, 4),
            'outbound_bytes': round(out_bytes, 2),
            'inbound_bytes': round(in_bytes, 2),
            'outbound_traffic_percentage': round(out_pct, 2),
            'connection_frequency': round(conn_freq, 2),
            'packet_entropy': round(pkt_entropy, 2),
            'packets_per_second': round(pps, 2),
            'traffic_volume_deviation': round(vol_dev, 2),
            'connection_rate_deviation': round(conn_dev, 2),
            'traffic_entropy_deviation': round(ent_dev, 2)
        }
    }


class ThreatClassifierService:
    """
    Threat Classification Service orchestrating:
    - Feature extraction & preprocessing
    - Isolation Forest inference
    - Threat categorization & severity assignment
    - SQLite security_alerts database integration with duplicate prevention
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(ThreatClassifierService, cls).__new__(cls)
        return cls._instance

    def analyze_threat(
        self,
        data: Dict[str, Any],
        create_alert_if_anomalous: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze traffic telemetry record, classify threat category & severity,
        and optionally persist security alert in SQLite.
        
        Args:
            data: Telemetry record dict (can contain 'traffic_data' wrapper or flat features).
            create_alert_if_anomalous: If True, saves alert to SQLite when severity is MEDIUM/HIGH/CRITICAL.
            
        Returns:
            Dict[str, Any]: Comprehensive analysis results conforming to API contract.
        """
        if not data or not isinstance(data, dict):
            raise PipelineValidationError("Traffic payload must be a non-empty JSON dictionary.")

        # Unpack nested wrapper if present: {'device_id': 5, 'traffic_data': {...}}
        record = dict(data)
        device_id = record.get('device_id')
        if 'traffic_data' in record and isinstance(record['traffic_data'], dict):
            nested = dict(record['traffic_data'])
            if device_id is not None and 'device_id' not in nested:
                nested['device_id'] = device_id
            record = nested

        # Fallback device_id if still missing
        if device_id is None:
            device_id = record.get('device_id', 1)

        # 1. Feature Extraction & Validation (Prompt 2 Pipeline)
        anomaly_service = AnomalyService()
        baselines = anomaly_service.detector.baselines

        features = extract_features(record, baselines=baselines)

        # 2. Run Isolation Forest Detection (Prompt 1)
        anomaly_result = anomaly_service.detect(record)
        if isinstance(anomaly_result, list):
            anomaly_result = anomaly_result[0]

        # 3. Classify Threat Category, Severity, and Grounded Explanation (Prompt 3)
        threat_info = classify_threat(anomaly_result, features)

        threat_type = threat_info['threat_type']
        severity = threat_info['severity']
        is_anomaly = anomaly_result.get('is_anomaly', False)
        anomaly_score = float(anomaly_result.get('anomaly_score', 0.0))

        # 4. Database Alert Integration & Duplicate Alert Prevention
        alert_created = False
        alert_code = None
        alert_id = None
        duplicate_suppressed = False

        if create_alert_if_anomalous and is_anomaly and severity in ('MEDIUM', 'HIGH', 'CRITICAL'):
            try:
                # Normalize numeric device ID for foreign key
                dev_int_id = int(str(device_id).replace('dev-', '')) if str(device_id).replace('dev-', '').isdigit() else 1
                
                # Check for duplicate recent active alert (within 300 seconds)
                recent_alert = AlertService.find_recent_active_alert(
                    device_id=dev_int_id,
                    threat_type=threat_type,
                    within_seconds=300
                )

                if recent_alert:
                    # Suppress duplicate alert creation
                    duplicate_suppressed = True
                    alert_created = False
                    alert_code = recent_alert['alert_code']
                    alert_id = recent_alert['id']
                    logger.info(
                        f"Duplicate alert suppressed for device {dev_int_id} ({threat_type}). "
                        f"Existing active alert: {alert_code}"
                    )
                else:
                    # Create new alert in SQLite security_alerts table
                    created = AlertService.create_alert({
                        'device_id': dev_int_id,
                        'threat_type': threat_type,
                        'description': threat_info['explanation'],
                        'severity': severity,
                        'status': 'ACTIVE',
                        'detection_source': 'AI Isolation Forest & Threat Classifier',
                        'recommended_action': threat_info['recommended_action'],
                        'anomaly_score': anomaly_score
                    })
                    alert_created = True
                    alert_code = created['alert_code']
                    alert_id = created['id']
            except Exception as e:
                logger.warning(f"Could not persist alert to database: {e}")

        response_data = {
            'device_id': device_id,
            'prediction': anomaly_result.get('prediction', 'NORMAL'),
            'threat_type': threat_type,
            'severity': severity,
            'anomaly_score': round(anomaly_score, 4),
            'is_confirmed_attack': False,
            'explanation': threat_info['explanation'],
            'recommended_action': threat_info['recommended_action'],
            'evidence': threat_info['evidence'],
            'features': features,
            'alert_created': alert_created,
            'alert_code': alert_code,
            'alert_id': alert_id,
            'duplicate_suppressed': duplicate_suppressed,
            'timestamp': anomaly_result.get('timestamp')
        }

        return response_data


# Module-level convenience functions matching Prompt 3:
def analyze_threat(traffic_data: Dict[str, Any], create_alert: bool = True) -> Dict[str, Any]:
    """Convenience function to analyze and classify network traffic threats."""
    classifier = ThreatClassifierService()
    return classifier.analyze_threat(traffic_data, create_alert_if_anomalous=create_alert)
