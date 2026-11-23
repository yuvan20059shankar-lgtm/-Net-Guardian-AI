"""
NetGuardian AI - AI Threat Intelligence Engine (AI/ML Prompt 4)
Tagline: Detect. Defend. Recover. Automatically.

Provides evidence-based security threat intelligence by synthesizing:
- Isolation Forest AI anomaly detection results (Prompt 1)
- Advanced engineered traffic features & statistical deviations (Prompt 2)
- Intelligent threat classification categories (Prompt 3)
- Monitored network device profiles from SQLite
- Historical security alerts and recurrence analysis
- Configurable threat scoring (0-100) and multi-factor confidence assessment
- Grounded, dynamic threat explanations and actionable non-destructive security recommendations
- Historical pattern detection and persistent intelligence reporting
"""

from __future__ import annotations
import json
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union

from config import get_config
from database import get_db
from services.device_service import DeviceService, ValidationError, NotFoundError
from services.alert_service import AlertService
from services.threat_classifier import ThreatClassifierService, THREAT_CATEGORIES
from services.feature_pipeline import (
    BASE_FEATURE_NAMES,
    DERIVED_FEATURE_NAMES,
    ENGINEERED_FEATURE_NAMES,
    PipelineValidationError,
    extract_features
)

logger = logging.getLogger('netguardian.ai.intelligence')

# Canonical Threat Intelligence Indicators (Prompt 4 Section 2)
THREAT_INDICATORS = [
    'Port Scanning',
    'DoS-like Traffic Spike',
    'Suspicious Outbound Traffic',
    'Potential Data Exfiltration',
    'Unusual Packet Behaviour',
    'Abnormal Connection Frequency',
    'Suspicious Network Communication',
    'Repeated Anomalous Behaviour'
]

# Mapping Prompt 3 classification categories to Prompt 4 indicators
CATEGORY_TO_INDICATOR_MAP = {
    'Denial of Service (DoS) - like traffic spikes': 'DoS-like Traffic Spike',
    'Port Scanning': 'Port Scanning',
    'Suspicious Outbound Traffic': 'Suspicious Outbound Traffic',
    'Potential Data Exfiltration': 'Potential Data Exfiltration',
    'Unusual Packet Behaviour': 'Unusual Packet Behaviour',
    'Abnormal Connection Frequency': 'Abnormal Connection Frequency',
    'Suspicious Network Communication': 'Suspicious Network Communication',
    'Nominal Traffic': 'Nominal Traffic'
}


class ThreatIntelligenceService:
    """
    Threat Intelligence Engine synthesizing AI anomaly detection, feature engineering,
    threat classification, device telemetry, and historical security alert records.
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(ThreatIntelligenceService, cls).__new__(cls)
        return cls._instance

    @staticmethod
    def _get_config():
        """Retrieve active configuration."""
        try:
            from flask import current_app, has_app_context
            if has_app_context():
                return current_app.config
        except Exception:
            pass
        return get_config()

    # --------------------------------------------------------------------------
    # 1. THREAT SCORING & SEVERITY
    # --------------------------------------------------------------------------
    @classmethod
    def calculate_threat_score(
        cls,
        anomaly_score: float,
        traffic_features: Dict[str, float],
        indicator: str,
        historical_alerts_count: int = 0
    ) -> int:
        """
        Generate a composite threat intelligence score from 0 to 100.
        
        IMPORTANT:
        The threat score must NOT be presented as a calibrated probability of an attack.
        It is a heuristic risk indicator synthesizing anomaly intensity, feature
        deviations, and device historical recurrence.
        """
        score = float(anomaly_score or 0.0)

        # 1. Base Anomaly Component (0 - 45 points)
        base_component = int(min(max(score, 0.0), 1.0) * 45)

        # 2. Deviation Magnitude Component (0 - 30 points)
        vol_dev = abs(float(traffic_features.get('traffic_volume_deviation', 0.0)))
        conn_dev = abs(float(traffic_features.get('connection_rate_deviation', 0.0)))
        ent_dev = abs(float(traffic_features.get('traffic_entropy_deviation', 0.0)))
        max_dev = max(vol_dev, conn_dev, ent_dev)

        if max_dev >= 5.0:
            dev_component = 30
        elif max_dev >= 3.0:
            dev_component = 22
        elif max_dev >= 1.5:
            dev_component = 12
        else:
            dev_component = 4

        # 3. Historical Recurrence Component (0 - 25 points)
        if historical_alerts_count >= 3:
            hist_component = 25
        elif historical_alerts_count == 2:
            hist_component = 18
        elif historical_alerts_count == 1:
            hist_component = 10
        else:
            hist_component = 0

        # Special case: Clean nominal traffic
        if indicator == 'Nominal Traffic' or (score < 0.40 and max_dev < 1.5 and historical_alerts_count == 0):
            return max(5, int(score * 25))

        total_score = base_component + dev_component + hist_component

        # Active threat indicator floor
        if indicator != 'Nominal Traffic':
            total_score = max(total_score, 50)

        # Extreme indicator escalation floor
        if indicator in ('DoS-like Traffic Spike', 'Potential Data Exfiltration') and score >= 0.70:
            total_score = max(total_score, 80)
        elif indicator == 'Repeated Anomalous Behaviour':
            total_score = max(total_score, 70)

        return min(max(total_score, 0), 100)

    @classmethod
    def calculate_severity(cls, threat_score: int, indicator: str, base_severity: Optional[str] = None) -> str:
        """
        Determine threat severity (LOW, MEDIUM, HIGH, CRITICAL) using configurable thresholds
        and corroborating classification baseline.
        """
        config = cls._get_config()
        thresholds = getattr(config, 'THREAT_INTEL_SCORE_THRESHOLDS', {
            'CRITICAL': 80,
            'HIGH': 65,
            'MEDIUM': 45,
            'LOW': 0
        })

        if indicator == 'Nominal Traffic':
            return 'LOW'

        sev_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        order_to_sev = {0: 'LOW', 1: 'MEDIUM', 2: 'HIGH', 3: 'CRITICAL'}

        if threat_score >= thresholds.get('CRITICAL', 80):
            computed = 'CRITICAL'
        elif threat_score >= thresholds.get('HIGH', 65):
            computed = 'HIGH'
        elif threat_score >= thresholds.get('MEDIUM', 45):
            computed = 'MEDIUM'
        else:
            computed = 'LOW'

        if base_severity and base_severity in sev_order:
            max_rank = max(sev_order[computed], sev_order[base_severity])
            return order_to_sev[max_rank]

        return computed

    # --------------------------------------------------------------------------
    # 2. CONFIDENCE LEVEL CALCULATION
    # --------------------------------------------------------------------------
    @classmethod
    def calculate_confidence(
        cls,
        traffic_features: Dict[str, float],
        anomaly_score: float,
        has_baseline: bool,
        historical_alerts_count: int = 0
    ) -> str:
        """
        Calculate intelligence confidence level (LOW, MEDIUM, HIGH).
        
        IMPORTANT:
        Confidence reflects the amount and quality of supporting evidence,
        not simply the anomaly score.
        
        Evaluated corroborating factors:
        1. Statistical baseline availability
        2. Volume deviation >= 2.0 sigma
        3. Connection rate deviation >= 2.0 sigma
        4. Entropy deviation >= 1.5 sigma
        5. Extreme asymmetric ratio (outbound_pct >= 75% or in_out_ratio <= 0.35)
        6. Packet throughput burst (pps >= 3500 or avg_packet_size anomaly)
        7. Corroborating historical alerts (>= 1 prior alert)
        """
        factors = 0

        if has_baseline:
            factors += 1

        vol_dev = abs(float(traffic_features.get('traffic_volume_deviation', 0.0)))
        if vol_dev >= 2.0:
            factors += 1

        conn_dev = abs(float(traffic_features.get('connection_rate_deviation', 0.0)))
        if conn_dev >= 2.0:
            factors += 1

        ent_dev = abs(float(traffic_features.get('traffic_entropy_deviation', 0.0)))
        if ent_dev >= 1.5:
            factors += 1

        out_pct = float(traffic_features.get('outbound_traffic_percentage', 50.0))
        in_out = float(traffic_features.get('inbound_outbound_ratio', 1.0))
        if out_pct >= 75.0 or in_out <= 0.35:
            factors += 1

        pps = float(traffic_features.get('packets_per_second', 0.0))
        if pps >= 3500.0:
            factors += 1

        if historical_alerts_count >= 1:
            factors += 1

        # High confidence requires at least 3 corroborating factors
        if factors >= 3:
            return 'HIGH'
        elif factors >= 1:
            return 'MEDIUM'
        else:
            return 'LOW'

    # --------------------------------------------------------------------------
    # 3. DYNAMIC THREAT EXPLANATIONS
    # --------------------------------------------------------------------------
    @classmethod
    def generate_threat_explanation(
        cls,
        device_name: str,
        device_ip: str,
        indicator: str,
        severity: str,
        features: Dict[str, float],
        anomaly_score: float,
        historical_count: int = 0
    ) -> str:
        """
        Dynamically generate an understandable, mathematically grounded explanation.
        
        Uses non-absolute threat wording:
        - Possible threat indicator
        - Suspicious traffic pattern
        - Potential security risk
        - Requires investigation
        """
        out_bytes = features.get('outbound_bytes', 0.0)
        in_bytes = features.get('inbound_bytes', 0.0)
        out_pct = features.get('outbound_traffic_percentage', 50.0)
        conn_freq = features.get('connection_frequency', 0.0)
        pps = features.get('packets_per_second', 0.0)
        avg_size = features.get('average_packet_size', 0.0)
        entropy = features.get('packet_entropy', 0.0)
        vol_dev = features.get('traffic_volume_deviation', 0.0)
        conn_dev = features.get('connection_rate_deviation', 0.0)

        if indicator == 'Nominal Traffic':
            return (
                f"Device '{device_name}' ({device_ip}) exhibits network traffic within standard operational "
                f"parameters (anomaly score: {anomaly_score:.4f}). No elevated security risk indicators observed."
            )

        if indicator == 'Repeated Anomalous Behaviour':
            return (
                f"Device '{device_name}' ({device_ip}) has demonstrated recurring anomalous traffic patterns across "
                f"{historical_count} security incidents in the monitoring window. This persistent behavioural anomaly "
                f"represents an escalating potential security risk and requires thorough investigation."
            )

        if indicator == 'DoS-like Traffic Spike':
            return (
                f"Device '{device_name}' ({device_ip}) experienced a sudden surge in packet throughput "
                f"({pps:,.0f} packets/sec, {conn_freq:.1f} conn/s) with average frame size of {avg_size:.0f} bytes. "
                f"This suspicious traffic pattern matches connection flood behavior, poses a potential security risk of "
                f"service degradation, and requires investigation."
            )

        if indicator == 'Potential Data Exfiltration':
            return (
                f"Device '{device_name}' ({device_ip}) generated heavily asymmetric outbound egress "
                f"({out_bytes:,.0f} bytes, {out_pct:.1f}% outbound) with elevated Shannon entropy ({entropy:.2f}). "
                f"This possible threat indicator suggests potential unauthorized data transfer and requires investigation."
            )

        if indicator == 'Port Scanning':
            return (
                f"Device '{device_name}' ({device_ip}) initiated rapid connection attempts ({conn_freq:.1f} conn/s) "
                f"with small packet probes ({avg_size:.0f} bytes) and minimal response data. "
                f"This suspicious traffic pattern is a possible threat indicator of network reconnaissance and requires investigation."
            )

        if indicator == 'Suspicious Outbound Traffic':
            return (
                f"Device '{device_name}' ({device_ip}) transmitted unusually high outbound network traffic "
                f"({out_bytes:,.0f} bytes, {out_pct:.1f}% egress, {vol_dev:.1f}σ deviation from baseline). "
                f"This behaviour may indicate suspicious data transfer activity and represents a potential security risk that requires investigation."
            )

        if indicator == 'Abnormal Connection Frequency':
            return (
                f"Device '{device_name}' ({device_ip}) exhibited an abnormal connection frequency of {conn_freq:.1f} conn/s "
                f"({conn_dev:.1f}σ above normal baseline). This possible threat indicator indicates rapid automated polling "
                f"or beaconing activity and requires investigation."
            )

        if indicator == 'Unusual Packet Behaviour':
            return (
                f"Device '{device_name}' ({device_ip}) generated unusual frame characteristics "
                f"(average packet size: {avg_size:.0f} bytes, entropy: {entropy:.2f}). "
                f"This suspicious traffic pattern deviates from standard communication profiles and represents a potential security risk requiring investigation."
            )

        # Fallback for Suspicious Network Communication
        return (
            f"Device '{device_name}' ({device_ip}) produced a multidimensional traffic anomaly "
            f"(anomaly score: {anomaly_score:.4f}, volume deviation: {vol_dev:.1f}σ). "
            f"This possible threat indicator deviates from established traffic baselines and requires investigation."
        )

    # --------------------------------------------------------------------------
    # 4. RECOMMENDED SECURITY ACTIONS
    # --------------------------------------------------------------------------
    @classmethod
    def get_recommended_actions(cls, indicator: str, severity: str) -> List[str]:
        """
        Generate actionable, non-destructive security recommendations based on threat indicator and severity.
        
        IMPORTANT:
        This stage only recommends actions. Does not automatically isolate devices
        or execute destructive commands.
        """
        actions = []

        if indicator == 'Nominal Traffic' or severity == 'LOW':
            return [
                "Continue routine monitoring of device telemetry.",
                "Record the unusual behaviour in telemetry audit logs."
            ]

        if severity == 'MEDIUM':
            actions.append("Investigate the device and review recent network socket activity.")
            actions.append("Review recent traffic activity and host system logs.")
        elif severity == 'HIGH':
            actions.append("Generate a high-priority security alert for SOC incident review.")
            actions.append("Inspect outbound connections and evaluate destination IP reputations.")
            actions.append("Consider simulated device isolation in the test network environment.")
        elif severity == 'CRITICAL':
            actions.append("Generate a critical security incident alert immediately.")
            actions.append("Recommend immediate investigation by SOC incident response team.")
            actions.append("Recommend simulated isolation if supported by the existing network environment.")

        # Indicator-specific guidance
        if indicator == 'DoS-like Traffic Spike':
            actions.append("Evaluate perimeter rate-limiting and SYN flood controls on gateway.")
        elif indicator == 'Potential Data Exfiltration':
            actions.append("Inspect egress payload entropy and block suspicious remote ports.")
        elif indicator == 'Port Scanning':
            actions.append("Inspect host sweep behavior and restrict egress port probes.")
        elif indicator == 'Suspicious Outbound Traffic':
            actions.append("Review active egress sockets and compare against authorized baseline services.")
        elif indicator == 'Repeated Anomalous Behaviour':
            actions.append("Conduct deep behavioral forensic audit on device host processes.")

        return actions

    # --------------------------------------------------------------------------
    # 5. HISTORICAL THREAT & RECURRENCE ANALYSIS
    # --------------------------------------------------------------------------
    @classmethod
    def get_device_historical_alerts(cls, device_id: int, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieve recent historical alerts for a given device from SQLite."""
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, alert_code, device_id, threat_type, description,
                           severity, status, detection_source, recommended_action,
                           anomaly_score, created_at, resolved_at
                    FROM security_alerts
                    WHERE device_id = ?
                    ORDER BY id DESC LIMIT ?;
                """, (int(device_id), int(limit)))
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"Error querying historical alerts for device {device_id}: {e}")
            return []

    @classmethod
    def analyze_history(cls) -> Dict[str, Any]:
        """
        Analyze historical alerts and intelligence reports from the existing SQLite database.
        
        Identifies:
        - Repeated anomalies from the same device
        - Frequently detected threat indicators
        - Devices with recurring suspicious activity
        - Changes in threat severity over time
        - Repeated high-risk traffic patterns
        
        Returns insufficient-data message if < 2 historical records exist.
        """
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Count total alerts
            cursor.execute("SELECT COUNT(*) AS total FROM security_alerts;")
            row = cursor.fetchone()
            total_alerts = row['total'] if row else 0

            cursor.execute("SELECT COUNT(*) AS total FROM threat_intelligence_reports;")
            rep_row = cursor.fetchone()
            total_reports = rep_row['total'] if rep_row else 0

            total_historical_records = total_alerts + total_reports

            if total_historical_records < 2:
                return {
                    'status': 'insufficient_data',
                    'message': 'Insufficient historical threat data to identify recurring trends (minimum 2 historical records required).',
                    'total_records': total_historical_records,
                    'repeated_anomalies': [],
                    'frequently_detected_indicators': [],
                    'recurring_devices': [],
                    'severity_trends': {},
                    'high_risk_patterns': []
                }

            # 1. Frequently detected threat indicators (from alerts and reports)
            cursor.execute("""
                SELECT threat_type AS indicator, COUNT(*) AS count
                FROM security_alerts
                GROUP BY threat_type
                ORDER BY count DESC;
            """)
            freq_indicators = [dict(r) for r in cursor.fetchall()]

            # 2. Repeated anomalies and recurring devices (device_id with count >= 2)
            cursor.execute("""
                SELECT a.device_id, d.device_name, d.ip_address, d.device_type,
                       COUNT(*) AS alert_count,
                       SUM(CASE WHEN a.severity IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) AS high_risk_count,
                       MAX(a.created_at) AS last_incident_at
                FROM security_alerts a
                JOIN devices d ON a.device_id = d.id
                GROUP BY a.device_id
                ORDER BY alert_count DESC;
            """)
            device_recurrences = [dict(r) for r in cursor.fetchall()]
            repeated_anomalies = [d for d in device_recurrences if d['alert_count'] >= 2]

            # 3. Severity trends over time
            cursor.execute("""
                SELECT severity, COUNT(*) AS count
                FROM security_alerts
                GROUP BY severity;
            """)
            sev_rows = cursor.fetchall()
            severity_trends = {r['severity']: r['count'] for r in sev_rows}

            # 4. Repeated high-risk traffic patterns
            cursor.execute("""
                SELECT threat_type, COUNT(*) AS recurrence_count
                FROM security_alerts
                WHERE severity IN ('HIGH', 'CRITICAL')
                GROUP BY threat_type
                HAVING COUNT(*) >= 2
                ORDER BY recurrence_count DESC;
            """)
            high_risk_patterns = [dict(r) for r in cursor.fetchall()]

            return {
                'status': 'sufficient_data',
                'message': 'Historical threat analysis computed successfully.',
                'total_records': total_historical_records,
                'total_alerts': total_alerts,
                'total_reports': total_reports,
                'frequently_detected_indicators': freq_indicators,
                'recurring_devices': device_recurrences,
                'repeated_anomalies': repeated_anomalies,
                'severity_trends': severity_trends,
                'high_risk_patterns': high_risk_patterns
            }

    # --------------------------------------------------------------------------
    # 6. REPORT PERSISTENCE & RETRIEVAL
    # --------------------------------------------------------------------------
    @classmethod
    def save_report(cls, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save a generated threat intelligence report to SQLite."""
        report_id = report_data.get('report_id') or f"TIR-{uuid.uuid4().hex[:8].upper()}"
        device_id = int(report_data['device_id'])
        device_ip = report_data.get('device_ip', '')
        device_name = report_data.get('device_name', '')
        indicator = report_data['threat_indicator']
        severity = report_data['severity']
        score = int(report_data['threat_score'])
        confidence = report_data['confidence']
        explanation = report_data['explanation']
        evidence_json = json.dumps(report_data.get('evidence', {}))
        actions_json = json.dumps(report_data.get('recommended_actions', []))
        alert_code = report_data.get('alert_code')

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO threat_intelligence_reports (
                    report_id, device_id, device_ip, device_name, threat_indicator,
                    severity, threat_score, confidence, explanation,
                    evidence_json, recommended_actions_json, alert_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                report_id, device_id, device_ip, device_name, indicator,
                severity, score, confidence, explanation,
                evidence_json, actions_json, alert_code
            ))

        report_data['report_id'] = report_id
        return report_data

    @classmethod
    def get_reports(
        cls,
        severity: Optional[str] = None,
        threat_indicator: Optional[str] = None,
        device_id: Optional[int] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Retrieve stored threat intelligence reports with optional filters."""
        query = """
            SELECT id, report_id, device_id, device_ip, device_name, threat_indicator,
                   severity, threat_score, confidence, explanation, evidence_json,
                   recommended_actions_json, alert_code, created_at
            FROM threat_intelligence_reports
            WHERE 1=1
        """
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity.strip().upper())

        if threat_indicator:
            query += " AND threat_indicator = ?"
            params.append(threat_indicator.strip())

        if device_id is not None:
            query += " AND device_id = ?"
            params.append(int(device_id))

        query += " ORDER BY id DESC LIMIT ? OFFSET ?;"
        params.extend([max(1, min(limit, 200)), max(0, offset)])

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

        results = []
        for r in rows:
            item = dict(r)
            try:
                item['evidence'] = json.loads(item.pop('evidence_json', '{}'))
            except Exception:
                item['evidence'] = {}
            try:
                item['recommended_actions'] = json.loads(item.pop('recommended_actions_json', '[]'))
            except Exception:
                item['recommended_actions'] = []
            results.append(item)

        return results

    # --------------------------------------------------------------------------
    # 7. HIGH-LEVEL INTELLIGENCE ANALYSIS PIPELINE
    # --------------------------------------------------------------------------
    def analyze_intelligence(
        self,
        data: Dict[str, Any],
        persist_report: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze traffic telemetry, perform threat intelligence synthesis, and generate
        a structured intelligence report matching Prompt 4 API contract.
        
        Args:
            data: Telemetry dictionary (can contain nested 'traffic_data' or flat features).
            persist_report: If True, writes the intelligence report to SQLite.
            
        Returns:
            Dict[str, Any]: Structured threat intelligence report.
        """
        if not data or not isinstance(data, dict):
            raise ValidationError("Traffic payload must be a non-empty JSON dictionary.")

        # Unpack nested payload if present: {'device_id': 5, 'traffic_data': {...}}
        record = dict(data)
        raw_device_id = record.get('device_id')
        if 'traffic_data' in record and isinstance(record['traffic_data'], dict):
            nested = dict(record['traffic_data'])
            if raw_device_id is not None and 'device_id' not in nested:
                nested['device_id'] = raw_device_id
            record = nested

        # 1. Resolve Device Details from SQLite
        parsed_id = DeviceService.parse_device_id(raw_device_id if raw_device_id is not None else record.get('device_id'))
        device_id = parsed_id if parsed_id is not None else 1
        device = DeviceService.get_device_by_id(device_id)

        if not device:
            # Device must exist in system
            raise NotFoundError(f"Monitored network device with ID '{device_id}' does not exist.")

        device_name = device.get('device_name', f'Device-{device_id}')
        device_ip = device.get('ip_address', '192.168.1.1')

        # 2. Query Historical Security Alerts for Device
        historical_alerts = self.get_device_historical_alerts(device_id, limit=10)
        historical_alerts_count = len(historical_alerts)
        recent_alert_codes = [a['alert_code'] for a in historical_alerts[:3]]

        # 3. Run Prompt 3 Threat Classification Engine
        classifier = ThreatClassifierService()
        threat_analysis = classifier.analyze_threat(record, create_alert_if_anomalous=True)

        features = threat_analysis.get('features', {})
        anomaly_score = float(threat_analysis.get('anomaly_score', 0.0))
        classified_threat = threat_analysis.get('threat_type', 'Nominal Traffic')
        alert_code = threat_analysis.get('alert_code')

        # 4. Map Classification to Threat Intelligence Indicator
        # Check for Repeated Anomalous Behaviour condition
        if classified_threat != 'Nominal Traffic' and historical_alerts_count >= 2:
            indicator = 'Repeated Anomalous Behaviour'
        else:
            indicator = CATEGORY_TO_INDICATOR_MAP.get(classified_threat, 'Suspicious Network Communication')

        # 5. Compute Intelligence Threat Score (0 - 100)
        threat_score = self.calculate_threat_score(
            anomaly_score=anomaly_score,
            traffic_features=features,
            indicator=indicator,
            historical_alerts_count=historical_alerts_count
        )

        # 6. Compute Severity using Configurable Thresholds
        severity = self.calculate_severity(
            threat_score,
            indicator,
            base_severity=threat_analysis.get('severity')
        )

        # 7. Compute Evidence-Based Confidence Level (LOW, MEDIUM, HIGH)
        has_baseline = bool(features.get('traffic_volume_deviation') is not None)
        confidence = self.calculate_confidence(
            traffic_features=features,
            anomaly_score=anomaly_score,
            has_baseline=has_baseline,
            historical_alerts_count=historical_alerts_count
        )

        # 8. Dynamic Grounded Threat Explanation
        explanation = self.generate_threat_explanation(
            device_name=device_name,
            device_ip=device_ip,
            indicator=indicator,
            severity=severity,
            features=features,
            anomaly_score=anomaly_score,
            historical_count=historical_alerts_count
        )

        # 9. Recommended Security Actions
        recommended_actions = self.get_recommended_actions(indicator, severity)

        # 10. Assemble Evidence Collection (actual available data only, no fabricated evidence)
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
            'related_historical_alerts_count': historical_alerts_count,
            'related_historical_alert_codes': recent_alert_codes
        }

        report = {
            'device_id': device_id,
            'device_name': device_name,
            'device_ip': device_ip,
            'threat_indicator': indicator,
            'severity': severity,
            'threat_score': threat_score,
            'confidence': confidence,
            'explanation': explanation,
            'evidence': evidence,
            'recommended_actions': recommended_actions,
            'alert_code': alert_code,
            'timestamp': evidence['detection_timestamp']
        }

        # 11. Optionally Persist to SQLite
        if persist_report:
            try:
                self.save_report(report)
            except Exception as e:
                logger.warning(f"Failed to persist threat intelligence report to SQLite: {e}")

        return report

    # --------------------------------------------------------------------------
    # 8. DEVICE INTELLIGENCE PROFILE
    # --------------------------------------------------------------------------
    @classmethod
    def get_device_intelligence_profile(cls, device_id_input: Any) -> Dict[str, Any]:
        """
        Retrieve comprehensive intelligence profile for a specific monitored device.
        Raises NotFoundError if device does not exist.
        """
        parsed_id = DeviceService.parse_device_id(device_id_input)
        if parsed_id is None:
            raise ValidationError(f"Invalid device ID format: '{device_id_input}'")

        device = DeviceService.get_device_by_id(parsed_id)
        if not device:
            raise NotFoundError(f"Monitored device ID '{parsed_id}' not found.")

        # Query reports and alerts
        reports = cls.get_reports(device_id=parsed_id, limit=20)
        alerts = cls.get_device_historical_alerts(parsed_id, limit=20)

        # Average threat score
        avg_score = 0.0
        if reports:
            avg_score = round(sum(r['threat_score'] for r in reports) / len(reports), 1)

        # Most frequent indicator
        indicator_counts: Dict[str, int] = {}
        for r in reports:
            ind = r['threat_indicator']
            indicator_counts[ind] = indicator_counts.get(ind, 0) + 1

        top_indicator = max(indicator_counts.items(), key=lambda x: x[1])[0] if indicator_counts else "None"

        # Severity distribution
        severity_dist = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        for a in alerts:
            sev = a.get('severity', 'LOW')
            if sev in severity_dist:
                severity_dist[sev] += 1

        is_repeated_candidate = len(alerts) >= 2 or len(reports) >= 2

        return {
            'device': device,
            'device_id': parsed_id,
            'device_name': device['device_name'],
            'ip_address': device['ip_address'],
            'average_threat_score': avg_score,
            'top_threat_indicator': top_indicator,
            'is_repeated_anomalous_candidate': is_repeated_candidate,
            'total_alerts_count': len(alerts),
            'total_intelligence_reports_count': len(reports),
            'severity_distribution': severity_dist,
            'recent_alerts': alerts[:5],
            'recent_intelligence_reports': reports[:5]
        }

    # --------------------------------------------------------------------------
    # 9. HIGH-LEVEL INTELLIGENCE SUMMARY
    # --------------------------------------------------------------------------
    @classmethod
    def get_summary(cls) -> Dict[str, Any]:
        """Generate high-level summary of network threat intelligence across all devices."""
        with get_db() as conn:
            cursor = conn.cursor()

            # Reports summary
            cursor.execute("SELECT COUNT(*) AS total FROM threat_intelligence_reports;")
            total_reports = cursor.fetchone()['total']

            cursor.execute("""
                SELECT severity, COUNT(*) AS count
                FROM threat_intelligence_reports
                GROUP BY severity;
            """)
            sev_counts = {r['severity']: r['count'] for r in cursor.fetchall()}

            cursor.execute("""
                SELECT confidence, COUNT(*) AS count
                FROM threat_intelligence_reports
                GROUP BY confidence;
            """)
            conf_counts = {r['confidence']: r['count'] for r in cursor.fetchall()}

            cursor.execute("SELECT AVG(threat_score) AS avg_score FROM threat_intelligence_reports;")
            avg_row = cursor.fetchone()
            avg_threat_score = round(avg_row['avg_score'] or 0.0, 1)

            cursor.execute("""
                SELECT threat_indicator, COUNT(*) AS count
                FROM threat_intelligence_reports
                GROUP BY threat_indicator
                ORDER BY count DESC;
            """)
            top_indicators = [dict(r) for r in cursor.fetchall()]

            # High risk recurring devices
            cursor.execute("""
                SELECT d.id AS device_id, d.device_name, d.ip_address,
                       COUNT(r.id) AS report_count,
                       AVG(r.threat_score) AS mean_score
                FROM threat_intelligence_reports r
                JOIN devices d ON r.device_id = d.id
                GROUP BY r.device_id
                ORDER BY report_count DESC LIMIT 5;
            """)
            vulnerable_devices = [dict(r) for r in cursor.fetchall()]

        # Check sufficiency of historical data
        hist_analysis = cls.analyze_history()

        return {
            'total_reports': total_reports,
            'average_threat_score': avg_threat_score,
            'severity_distribution': {
                'CRITICAL': sev_counts.get('CRITICAL', 0),
                'HIGH': sev_counts.get('HIGH', 0),
                'MEDIUM': sev_counts.get('MEDIUM', 0),
                'LOW': sev_counts.get('LOW', 0)
            },
            'confidence_distribution': {
                'HIGH': conf_counts.get('HIGH', 0),
                'MEDIUM': conf_counts.get('MEDIUM', 0),
                'LOW': conf_counts.get('LOW', 0)
            },
            'top_threat_indicators': top_indicators,
            'most_frequently_flagged_devices': vulnerable_devices,
            'historical_data_status': hist_analysis.get('status', 'insufficient_data')
        }


# Convenience module-level wrapper functions:
def analyze_intelligence(traffic_data: Dict[str, Any], persist: bool = True) -> Dict[str, Any]:
    """Convenience function to analyze telemetry and generate an intelligence report."""
    service = ThreatIntelligenceService()
    return service.analyze_intelligence(traffic_data, persist_report=persist)
