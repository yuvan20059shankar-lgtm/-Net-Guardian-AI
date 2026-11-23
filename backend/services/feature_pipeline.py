"""
NetGuardian AI - Advanced Network Traffic Feature Engineering Pipeline
Converts raw simulated network telemetry into robust, leak-free numerical features
for training and real-time inference with the Isolation Forest model.

Features Extracted (18 Total):
Raw Input Features (8):
1. packet_count
2. average_packet_size
3. bytes_transferred
4. connection_frequency
5. packet_entropy
6. inbound_bytes
7. outbound_bytes
8. connection_duration

Advanced Derived Features (10):
1. bytes_per_packet             = bytes_transferred / packet_count
2. inbound_outbound_ratio        = inbound_bytes / max(outbound_bytes, 1.0)
3. packets_per_second            = packet_count / max(connection_duration, 0.001)
4. bytes_per_second              = bytes_transferred / max(connection_duration, 0.001)
5. average_connection_size       = bytes_transferred / max(connection_frequency * connection_duration, 1.0)
6. outbound_traffic_percentage   = (outbound_bytes / max(bytes_transferred, 1.0)) * 100.0
7. traffic_volume_deviation      = (bytes_transferred - baseline_mean_bytes) / baseline_std_bytes
8. connection_rate_deviation     = (connection_frequency - baseline_mean_freq) / baseline_std_freq
9. packet_size_variation         = |average_packet_size - bytes_per_packet|
10. traffic_entropy_deviation    = (packet_entropy - baseline_mean_entropy) / baseline_std_entropy
"""

from __future__ import annotations
import os
import math
import json
import logging
from typing import Dict, List, Any, Optional, Tuple, Union

import numpy as np
import pandas as pd

logger = logging.getLogger('netguardian.ai.pipeline')

# Base raw features expected in incoming telemetry
BASE_FEATURE_NAMES = [
    'packet_count',
    'average_packet_size',
    'bytes_transferred',
    'connection_frequency',
    'packet_entropy',
    'inbound_bytes',
    'outbound_bytes',
    'connection_duration'
]

# Advanced derived features calculated by the engineering pipeline
DERIVED_FEATURE_NAMES = [
    'bytes_per_packet',
    'inbound_outbound_ratio',
    'packets_per_second',
    'bytes_per_second',
    'average_connection_size',
    'outbound_traffic_percentage',
    'traffic_volume_deviation',
    'connection_rate_deviation',
    'packet_size_variation',
    'traffic_entropy_deviation'
]

# Complete unified feature schema for model training and prediction
ENGINEERED_FEATURE_NAMES = BASE_FEATURE_NAMES + DERIVED_FEATURE_NAMES

# Default baseline values used if training data baselines have not yet been fit
DEFAULT_BASELINE_STATS = {
    'mean_bytes_transferred': 540000.0,
    'std_bytes_transferred': 620000.0,
    'mean_connection_frequency': 24.5,
    'std_connection_frequency': 28.0,
    'mean_packet_entropy': 4.95,
    'std_packet_entropy': 0.65,
    'mean_average_packet_size': 850.0,
    'std_average_packet_size': 320.0
}

# Bounds for numerical sanity checking
FEATURE_VALUE_BOUNDS = {
    'packet_count': (0.0, 10_000_000.0),
    'average_packet_size': (0.0, 65535.0),
    'bytes_transferred': (0.0, 100_000_000_000.0),
    'connection_frequency': (0.0, 100_000.0),
    'packet_entropy': (0.0, 8.0),
    'inbound_bytes': (0.0, 100_000_000_000.0),
    'outbound_bytes': (0.0, 100_000_000_000.0),
    'connection_duration': (0.0, 86400.0),
    'bytes_per_packet': (0.0, 65535.0),
    'inbound_outbound_ratio': (0.0, 1_000_000.0),
    'packets_per_second': (0.0, 10_000_000.0),
    'bytes_per_second': (0.0, 100_000_000_000.0),
    'average_connection_size': (0.0, 100_000_000_000.0),
    'outbound_traffic_percentage': (0.0, 100.0),
    'traffic_volume_deviation': (-10.0, 50.0),
    'connection_rate_deviation': (-10.0, 50.0),
    'packet_size_variation': (0.0, 65535.0),
    'traffic_entropy_deviation': (-10.0, 50.0)
}


class PipelineValidationError(ValueError):
    """Raised when incoming data fails schema or validation constraints."""
    pass


def safe_divide(numerator: float, denominator: float, fallback: float = 0.0, min_denom: float = 1e-6) -> float:
    """Safely divide two numbers handling zero, near-zero, and extreme denominators."""
    if abs(denominator) < min_denom:
        return fallback
    result = numerator / denominator
    if math.isnan(result) or math.isinf(result):
        return fallback
    return result


def validate_feature_schema(data: Union[Dict[str, Any], List[Dict[str, Any]], pd.DataFrame]) -> bool:
    """
    Validate that incoming traffic data conforms to the required input schema.
    
    Args:
        data: Record dict, list of dicts, or DataFrame.
        
    Returns:
        bool: True if schema is valid.
        
    Raises:
        PipelineValidationError: If input is null, empty, or missing critical fields.
    """
    if data is None:
        raise PipelineValidationError("Validation failed: input data cannot be None")

    if isinstance(data, pd.DataFrame):
        if data.empty:
            raise PipelineValidationError("Validation failed: input DataFrame is empty")
        missing = [f for f in BASE_FEATURE_NAMES if f not in data.columns]
        if len(missing) == len(BASE_FEATURE_NAMES):
            raise PipelineValidationError("Validation failed: DataFrame contains none of the required traffic features")
        return True

    if isinstance(data, list):
        if not data:
            raise PipelineValidationError("Validation failed: input records list is empty")
        for idx, item in enumerate(data):
            if not isinstance(item, dict):
                raise PipelineValidationError(f"Record at index {idx} must be a dictionary, got {type(item).__name__}")
        return True

    if isinstance(data, dict):
        if not data:
            raise PipelineValidationError("Validation failed: empty dictionary record provided")
        # Check if list wrapper
        if 'traffic_data' in data and isinstance(data['traffic_data'], list):
            return validate_feature_schema(data['traffic_data'])
        if 'records' in data and isinstance(data['records'], list):
            return validate_feature_schema(data['records'])
        
        # Check that at least some valid base features are present
        present_count = sum(1 for f in BASE_FEATURE_NAMES if f in data)
        if present_count == 0:
            raise PipelineValidationError("Validation failed: record contains none of the required traffic features")
        return True

    raise PipelineValidationError(f"Unsupported data type for validation: {type(data).__name__}")


def calculate_traffic_baselines(training_data: Union[pd.DataFrame, List[Dict[str, Any]]]) -> Dict[str, float]:
    """
    Calculate baseline statistical distributions (mean, std, median) strictly from training data.
    IMPORTANT: Must be called with normal baseline samples only to prevent data leakage.
    
    Args:
        training_data: Clean normal baseline DataFrame or list of dicts.
        
    Returns:
        Dict[str, float]: Baseline statistics for deviation feature calculations.
    """
    if isinstance(training_data, list):
        df = pd.DataFrame(training_data)
    elif isinstance(training_data, pd.DataFrame):
        df = training_data.copy()
    else:
        raise PipelineValidationError("Training data must be a pandas DataFrame or list of dicts")

    if df.empty:
        logger.warning("Empty training data provided for baselines. Using default baseline statistics.")
        return dict(DEFAULT_BASELINE_STATS)

    # Filter to normal samples if 'label' column exists
    if 'label' in df.columns:
        df = df[df['label'] == 'NORMAL'].copy()

    baselines = {}
    
    # Bytes transferred stats
    bytes_s = pd.to_numeric(df.get('bytes_transferred', pd.Series([])), errors='coerce').dropna()
    baselines['mean_bytes_transferred'] = float(bytes_s.mean()) if len(bytes_s) > 0 else DEFAULT_BASELINE_STATS['mean_bytes_transferred']
    baselines['std_bytes_transferred'] = float(bytes_s.std(ddof=1)) if len(bytes_s) > 1 else DEFAULT_BASELINE_STATS['std_bytes_transferred']
    if baselines['std_bytes_transferred'] < 1.0:
        baselines['std_bytes_transferred'] = 1.0

    # Connection frequency stats
    freq_s = pd.to_numeric(df.get('connection_frequency', pd.Series([])), errors='coerce').dropna()
    baselines['mean_connection_frequency'] = float(freq_s.mean()) if len(freq_s) > 0 else DEFAULT_BASELINE_STATS['mean_connection_frequency']
    baselines['std_connection_frequency'] = float(freq_s.std(ddof=1)) if len(freq_s) > 1 else DEFAULT_BASELINE_STATS['std_connection_frequency']
    if baselines['std_connection_frequency'] < 0.01:
        baselines['std_connection_frequency'] = 0.01

    # Packet entropy stats
    ent_s = pd.to_numeric(df.get('packet_entropy', pd.Series([])), errors='coerce').dropna()
    baselines['mean_packet_entropy'] = float(ent_s.mean()) if len(ent_s) > 0 else DEFAULT_BASELINE_STATS['mean_packet_entropy']
    baselines['std_packet_entropy'] = float(ent_s.std(ddof=1)) if len(ent_s) > 1 else DEFAULT_BASELINE_STATS['std_packet_entropy']
    if baselines['std_packet_entropy'] < 0.01:
        baselines['std_packet_entropy'] = 0.01

    # Average packet size stats
    size_s = pd.to_numeric(df.get('average_packet_size', pd.Series([])), errors='coerce').dropna()
    baselines['mean_average_packet_size'] = float(size_s.mean()) if len(size_s) > 0 else DEFAULT_BASELINE_STATS['mean_average_packet_size']
    baselines['std_average_packet_size'] = float(size_s.std(ddof=1)) if len(size_s) > 1 else DEFAULT_BASELINE_STATS['std_average_packet_size']
    if baselines['std_average_packet_size'] < 1.0:
        baselines['std_average_packet_size'] = 1.0

    return baselines


def detect_duplicates(records: List[Dict[str, Any]], key_fields: Optional[List[str]] = None) -> List[int]:
    """
    Detect duplicate records in an incoming batch based on primary telemetry attributes.
    
    Args:
        records: List of record dictionaries.
        key_fields: Fields to consider for duplication identity (default: device_id, timestamp, packet_count, bytes_transferred).
        
    Returns:
        List[int]: Indices of duplicate records identified.
    """
    if key_fields is None:
        key_fields = ['device_id', 'timestamp', 'packet_count', 'bytes_transferred']

    seen = set()
    duplicate_indices = []

    for idx, rec in enumerate(records):
        key = tuple(str(rec.get(k, '')) for k in key_fields)
        if key in seen:
            duplicate_indices.append(idx)
        else:
            seen.add(key)

    return duplicate_indices


def extract_features(
    record: Dict[str, Any],
    baselines: Optional[Dict[str, float]] = None
) -> Dict[str, float]:
    """
    Extract all 18 numerical features (8 base + 10 advanced derived) from a single record.
    
    Args:
        record: Raw telemetry dictionary.
        baselines: Configurable baseline statistics dictionary (fitted from training data).
        
    Returns:
        Dict[str, float]: Fully populated feature dictionary with all 18 engineered features.
    """
    stats = baselines or DEFAULT_BASELINE_STATS

    # 1. Base Feature Extraction & Numerical Validation
    base = {}
    for feat in BASE_FEATURE_NAMES:
        val = record.get(feat)
        if val is None:
            raise PipelineValidationError(f"Missing required feature: '{feat}'")
        try:
            num = float(val)
        except (ValueError, TypeError):
            raise PipelineValidationError(f"Feature '{feat}' must be a numerical value, got: '{val}'")

        if math.isnan(num) or math.isinf(num):
            raise PipelineValidationError(f"Feature '{feat}' cannot be NaN or Infinite: {num}")

        min_b, max_b = FEATURE_VALUE_BOUNDS[feat]
        if num < min_b:
            logger.debug(f"Clamping negative value {num} for '{feat}' to {min_b}")
            num = min_b
        elif num > max_b:
            logger.debug(f"Clamping excessive value {num} for '{feat}' to {max_b}")
            num = max_b

        base[feat] = num

    # Extract base values into friendly variables
    pkt_count = base['packet_count']
    avg_pkt_size = base['average_packet_size']
    bytes_trans = base['bytes_transferred']
    conn_freq = base['connection_frequency']
    pkt_entropy = base['packet_entropy']
    in_bytes = base['inbound_bytes']
    out_bytes = base['outbound_bytes']
    conn_duration = base['connection_duration']

    # 2. Derive Advanced Features (10 Mathematical Formulations)

    # 1. bytes_per_packet: actual bytes per packet transferred
    bytes_per_pkt = safe_divide(bytes_trans, pkt_count, fallback=avg_pkt_size)

    # 2. inbound_outbound_ratio: ingress vs egress ratio (safe with zero outbound)
    in_out_ratio = safe_divide(in_bytes, max(out_bytes, 1.0), fallback=0.0)

    # 3. packets_per_second: packet throughput rate
    pkts_per_sec = safe_divide(pkt_count, max(conn_duration, 0.001), fallback=pkt_count)

    # 4. bytes_per_second: bandwidth volumetric rate
    bytes_per_sec = safe_divide(bytes_trans, max(conn_duration, 0.001), fallback=bytes_trans)

    # 5. average_connection_size: bytes transferred per estimated connection instance
    est_conns = max(conn_freq * conn_duration, 1.0)
    avg_conn_size = safe_divide(bytes_trans, est_conns, fallback=bytes_trans)

    # 6. outbound_traffic_percentage: proportion of total bytes that are outbound (0-100%)
    total_in_out = max(bytes_trans, in_bytes + out_bytes, 1.0)
    out_pct = (out_bytes / total_in_out) * 100.0
    out_pct = max(0.0, min(100.0, out_pct))

    # 7. traffic_volume_deviation: Z-score from training baseline bytes
    mean_bytes = stats.get('mean_bytes_transferred', DEFAULT_BASELINE_STATS['mean_bytes_transferred'])
    std_bytes = stats.get('std_bytes_transferred', DEFAULT_BASELINE_STATS['std_bytes_transferred'])
    vol_dev = (bytes_trans - mean_bytes) / max(std_bytes, 1.0)

    # 8. connection_rate_deviation: Z-score from training baseline frequency
    mean_freq = stats.get('mean_connection_frequency', DEFAULT_BASELINE_STATS['mean_connection_frequency'])
    std_freq = stats.get('std_connection_frequency', DEFAULT_BASELINE_STATS['std_connection_frequency'])
    conn_dev = (conn_freq - mean_freq) / max(std_freq, 0.001)

    # 9. packet_size_variation: discrepancy between configured mean packet size and actual ratio
    pkt_size_var = abs(avg_pkt_size - bytes_per_pkt)

    # 10. traffic_entropy_deviation: Z-score from training baseline entropy
    mean_ent = stats.get('mean_packet_entropy', DEFAULT_BASELINE_STATS['mean_packet_entropy'])
    std_ent = stats.get('std_packet_entropy', DEFAULT_BASELINE_STATS['std_packet_entropy'])
    ent_dev = (pkt_entropy - mean_ent) / max(std_ent, 0.001)

    derived = {
        'bytes_per_packet': round(bytes_per_pkt, 4),
        'inbound_outbound_ratio': round(in_out_ratio, 4),
        'packets_per_second': round(pkts_per_sec, 4),
        'bytes_per_second': round(bytes_per_sec, 4),
        'average_connection_size': round(avg_conn_size, 4),
        'outbound_traffic_percentage': round(out_pct, 4),
        'traffic_volume_deviation': round(vol_dev, 4),
        'connection_rate_deviation': round(conn_dev, 4),
        'packet_size_variation': round(pkt_size_var, 4),
        'traffic_entropy_deviation': round(ent_dev, 4)
    }

    # Combined 18 features dict
    combined = {**base, **derived}
    return combined


def preprocess_traffic_data(
    traffic_data: Union[Dict[str, Any], List[Dict[str, Any]], pd.DataFrame],
    baselines: Optional[Dict[str, float]] = None
) -> Tuple[np.ndarray, List[Dict[str, Any]]]:
    """
    Full preprocessing pipeline for incoming network traffic.
    - Validates feature schema
    - Detects and handles duplicates
    - Extracts all 18 base and derived features
    - Enforces consistent feature ordering
    - Returns ready-to-predict NumPy array and list of cleaned feature dicts.
    """
    validate_feature_schema(traffic_data)

    if isinstance(traffic_data, dict):
        if 'traffic_data' in traffic_data and isinstance(traffic_data['traffic_data'], list):
            records = traffic_data['traffic_data']
        elif 'records' in traffic_data and isinstance(traffic_data['records'], list):
            records = traffic_data['records']
        else:
            records = [traffic_data]
    elif isinstance(traffic_data, list):
        records = traffic_data
    elif isinstance(traffic_data, pd.DataFrame):
        records = traffic_data.to_dict(orient='records')
    else:
        raise PipelineValidationError(f"Unsupported input type: {type(traffic_data).__name__}")

    extracted_records = []
    feature_matrix = []

    for r in records:
        features_dict = extract_features(r, baselines=baselines)
        extracted_records.append(features_dict)
        # Vector in exact ENGINEERED_FEATURE_NAMES order
        vector = [features_dict[name] for name in ENGINEERED_FEATURE_NAMES]
        feature_matrix.append(vector)

    X = np.array(feature_matrix, dtype=np.float64)
    return X, extracted_records


def transform_network_traffic(
    traffic_data: Union[Dict[str, Any], List[Dict[str, Any]], pd.DataFrame],
    baselines: Optional[Dict[str, float]] = None
) -> np.ndarray:
    """
    Convert raw traffic input into numerical feature matrix X (N, 18).
    Convenience function matching Prompt 2 specification.
    """
    X, _ = preprocess_traffic_data(traffic_data, baselines=baselines)
    return X


def generate_feature_explanation(
    record: Dict[str, Any],
    features: Dict[str, float],
    baselines: Optional[Dict[str, float]] = None,
    is_anomaly: bool = False
) -> Dict[str, Any]:
    """
    Produce an understandable, mathematically grounded explanation for an anomaly prediction
    by comparing observed telemetry against fitted normal training baselines.
    
    IMPORTANT: Grounded directly in actual calculated Z-scores and deviations.
    """
    stats = baselines or DEFAULT_BASELINE_STATS
    explanations = []
    contributing_factors = []

    dev_id = record.get('device_id', 'Unknown')
    dev_name = record.get('device_name', f"Device {dev_id}")

    # Check 1: Outbound traffic percentage & Volume Deviation
    out_pct = features.get('outbound_traffic_percentage', 0.0)
    vol_dev = features.get('traffic_volume_deviation', 0.0)
    if out_pct > 80.0:
        msg = f"Outbound traffic is unusually dominant ({out_pct:.1f}% egress), indicating potential data exfiltration"
        explanations.append(msg)
        contributing_factors.append({
            'feature': 'outbound_traffic_percentage',
            'observed': f"{out_pct:.1f}%",
            'baseline': "50.0% nominal",
            'severity': 'HIGH'
        })
    elif vol_dev > 3.0:
        msg = f"Traffic volume ({features.get('bytes_transferred', 0):,.0f} bytes) deviates by {vol_dev:.1f}σ above baseline"
        explanations.append(msg)
        contributing_factors.append({
            'feature': 'traffic_volume_deviation',
            'observed': f"{vol_dev:.1f}σ",
            'baseline': "< 2.0σ",
            'severity': 'HIGH'
        })

    # Check 2: Packet Entropy Deviation
    ent_dev = features.get('traffic_entropy_deviation', 0.0)
    ent_val = features.get('packet_entropy', 0.0)
    mean_ent = stats.get('mean_packet_entropy', 4.95)
    if ent_dev > 3.0 or ent_val > 7.5:
        msg = f"Packet entropy ({ent_val:.2f}) is abnormally elevated ({ent_dev:.1f}σ above baseline mean {mean_ent:.2f}), matching encrypted or compressed payload tunneling"
        explanations.append(msg)
        contributing_factors.append({
            'feature': 'packet_entropy',
            'observed': f"{ent_val:.2f}",
            'baseline': f"{mean_ent:.2f} ± {stats.get('std_packet_entropy', 0.65):.2f}",
            'severity': 'HIGH'
        })
    elif ent_dev < -2.5 or ent_val < 2.5:
        msg = f"Packet entropy ({ent_val:.2f}) is unusually low ({ent_dev:.1f}σ below baseline), matching repetitive spoofed header templates"
        explanations.append(msg)
        contributing_factors.append({
            'feature': 'packet_entropy',
            'observed': f"{ent_val:.2f}",
            'baseline': f"{mean_ent:.2f}",
            'severity': 'MEDIUM'
        })

    # Check 3: Connection Rate Deviation
    conn_dev = features.get('connection_rate_deviation', 0.0)
    conn_freq = features.get('connection_frequency', 0.0)
    mean_freq = stats.get('mean_connection_frequency', 24.5)
    if conn_dev > 3.0 or conn_freq > 100.0:
        msg = f"Connection frequency ({conn_freq:.1f} conn/s) is abnormally high ({conn_dev:.1f}σ above baseline mean {mean_freq:.1f}), indicating port sweep or SYN flooding"
        explanations.append(msg)
        contributing_factors.append({
            'feature': 'connection_frequency',
            'observed': f"{conn_freq:.1f} conn/s",
            'baseline': f"{mean_freq:.1f} conn/s",
            'severity': 'HIGH'
        })

    # Check 4: Packet Size Variation / Jumbo packets
    size_var = features.get('packet_size_variation', 0.0)
    avg_size = features.get('average_packet_size', 0.0)
    if avg_size > 4000.0:
        msg = f"Average packet size ({avg_size:.0f} bytes) exceeds standard Ethernet MTU (1500 bytes), indicating jumbo packet abuse"
        explanations.append(msg)
        contributing_factors.append({
            'feature': 'average_packet_size',
            'observed': f"{avg_size:.0f} B",
            'baseline': "MTU <= 1500 B",
            'severity': 'MEDIUM'
        })

    # Check 5: Packets Per Second
    pps = features.get('packets_per_second', 0.0)
    if pps > 5000.0:
        msg = f"Packet rate ({pps:,.0f} pkts/sec) indicates extreme packet burst/flood"
        explanations.append(msg)
        contributing_factors.append({
            'feature': 'packets_per_second',
            'observed': f"{pps:,.0f} pkt/s",
            'baseline': "< 1,000 pkt/s",
            'severity': 'HIGH'
        })

    # Fallback explanation if no single extreme spike but multidimensional anomaly flagged
    if not explanations:
        if is_anomaly:
            summary = "Multidimensional deviation: telemetry features collectively reside in a low-density region of the Isolation Forest feature space."
        else:
            summary = "All observed traffic telemetry metrics conform to the configured normal baseline distributions."
    else:
        summary = "; ".join(explanations)

    return {
        'device_id': dev_id,
        'device_name': dev_name,
        'summary': summary,
        'is_anomaly': is_anomaly,
        'contributing_factors': contributing_factors,
        'top_deviations': {
            'traffic_volume_deviation': round(vol_dev, 2),
            'connection_rate_deviation': round(conn_dev, 2),
            'traffic_entropy_deviation': round(ent_dev, 2)
        }
    }
