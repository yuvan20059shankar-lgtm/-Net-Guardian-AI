"""
NetGuardian AI - AI/ML System Evaluation & Benchmark Script
PROMPT 6: Empirical evaluation of dataset, model performance, latency benchmarks,
and edge-case validation.
"""

import os
import sys
import time
import json
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score
from sklearn.model_selection import train_test_split

# Ensure backend root is on sys.path
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from services.traffic_generator import load_dataset
from services.feature_pipeline import (
    extract_features,
    preprocess_traffic_data,
    calculate_traffic_baselines,
    ENGINEERED_FEATURE_NAMES,
    BASE_FEATURE_NAMES,
    DEFAULT_BASELINE_STATS
)
from models.anomaly_detector import IsolationForestDetector
from services.threat_classifier import ThreatClassifierService, classify_threat, THREAT_CATEGORIES
from services.threat_intelligence import ThreatIntelligenceService
from services.ai_pipeline import AIPipelineService
from database import get_db

def evaluate_dataset():
    csv_path = os.path.join(BACKEND_DIR, 'data', 'network_traffic.csv')
    df = load_dataset(csv_path)
    
    total_samples = len(df)
    columns = list(df.columns)
    missing_values = df.isnull().sum().to_dict()
    label_counts = df['label'].value_counts().to_dict()
    anomaly_type_counts = df['anomaly_type'].value_counts().to_dict()
    
    stats = {}
    for col in BASE_FEATURE_NAMES:
        if col in df.columns:
            stats[col] = {
                'min': float(df[col].min()),
                'max': float(df[col].max()),
                'mean': round(float(df[col].mean()), 2),
                'std': round(float(df[col].std()), 2)
            }
            
    return {
        'total_samples': total_samples,
        'columns': columns,
        'missing_values': missing_values,
        'label_distribution': label_counts,
        'anomaly_type_distribution': anomaly_type_counts,
        'numerical_stats': stats
    }

def evaluate_model_performance():
    csv_path = os.path.join(BACKEND_DIR, 'data', 'network_traffic.csv')
    df = load_dataset(csv_path)
    
    # 80/20 train/test split stratified by label
    train_df, test_df = train_test_split(
        df, test_size=0.20, random_state=42, stratify=df['label']
    )
    
    # Calculate baseline statistics strictly from training normal samples (no leakage)
    train_normals = train_df[train_df['label'] == 'NORMAL']
    baselines_train = calculate_traffic_baselines(train_normals)
    
    # Extract features strictly on training data
    X_train, _ = preprocess_traffic_data(train_df, baselines=baselines_train)
    
    # Contamination parameter based on training split
    contamination = len(train_df[train_df['label'] == 'ANOMALY']) / len(train_df)
    detector = IsolationForestDetector(contamination=contamination, random_state=42, n_estimators=150)
    detector.train(X_train, baselines=baselines_train)
    
    # Extract features for test set using training baselines
    X_test, _ = preprocess_traffic_data(test_df, baselines=baselines_train)
    y_test_true = np.array([1 if lbl == 'ANOMALY' else 0 for lbl in test_df['label']])
    
    # Predict on test set using fitted model
    raw_preds = detector.model.predict(X_test)
    scores = detector.compute_anomaly_score(X_test)
    y_pred = np.array([1 if p == -1 else 0 for p in raw_preds])
    
    # Confusion Matrix: TN, FP, FN, TP
    tn, fp, fn, tp = confusion_matrix(y_test_true, y_pred, labels=[0, 1]).ravel()
    
    acc = accuracy_score(y_test_true, y_pred)
    prec = precision_score(y_test_true, y_pred, zero_division=0)
    rec = recall_score(y_test_true, y_pred, zero_division=0)
    f1 = f1_score(y_test_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    return {
        'train_samples': len(train_df),
        'test_samples': len(test_df),
        'test_normal_count': int(tn + fp),
        'test_anomaly_count': int(tp + fn),
        'true_negatives': int(tn),
        'false_positives': int(fp),
        'false_negatives': int(fn),
        'true_positives': int(tp),
        'accuracy': round(float(acc), 4),
        'precision': round(float(prec), 4),
        'recall': round(float(rec), 4),
        'f1_score': round(float(f1), 4),
        'fpr': round(float(fpr), 4),
        'fnr': round(float(fnr), 4),
        'mean_anomaly_score_nominal': round(float(np.mean([scores[i] for i in range(len(scores)) if y_test_true[i] == 0])), 4),
        'mean_anomaly_score_anomaly': round(float(np.mean([scores[i] for i in range(len(scores)) if y_test_true[i] == 1])), 4)
    }

def benchmark_latencies(iterations=50):
    model_path = os.path.join(BACKEND_DIR, 'data', 'isolation_forest_model.joblib')
    
    # 1. Model Loading Benchmark
    load_times = []
    for _ in range(10):
        t0 = time.perf_counter()
        det = IsolationForestDetector().load(model_path)
        load_times.append((time.perf_counter() - t0) * 1000)
    
    # Load detector once for cached prediction benchmarks
    detector = IsolationForestDetector().load(model_path)
    ai_pipeline = AIPipelineService()
    
    sample_nominal = {
        'device_id': 5,
        'packet_count': 65,
        'average_packet_size': 494.5,
        'bytes_transferred': 32144,
        'connection_frequency': 4.22,
        'packet_entropy': 4.89,
        'inbound_bytes': 13851,
        'outbound_bytes': 18293,
        'connection_duration': 4.71
    }
    
    sample_anomaly = {
        'device_id': 1,
        'packet_count': 32000,
        'average_packet_size': 45.0,
        'bytes_transferred': 1440000,
        'connection_frequency': 1450.0,
        'packet_entropy': 1.70,
        'inbound_bytes': 1340000,
        'outbound_bytes': 100000,
        'connection_duration': 0.1
    }
    
    # 2. Feature Extraction Latency
    feat_times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        _ = extract_features(sample_nominal)
        feat_times.append((time.perf_counter() - t0) * 1000)
        
    # 3. Model Single Prediction Latency
    pred_times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        _ = detector.predict_record(sample_nominal)
        pred_times.append((time.perf_counter() - t0) * 1000)
        
    # 4. Threat Classification Latency
    classifier = ThreatClassifierService()
    class_times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        _ = classifier.analyze_threat(sample_anomaly, create_alert_if_anomalous=False)
        class_times.append((time.perf_counter() - t0) * 1000)
        
    # 5. Full 6-Stage Unified Pipeline Latency
    pipeline_times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        _ = ai_pipeline.run_pipeline(sample_nominal, persist_results=False)
        pipeline_times.append((time.perf_counter() - t0) * 1000)
        
    # 6. SQLite Write Latency
    db_write_times = []
    test_report = {
        'device_id': 5,
        'threat_score': 75,
        'threat_level': 'HIGH',
        'severity': 'HIGH',
        'threat_indicator': 'DoS-like Traffic Spike',
        'confidence': 'HIGH',
        'explanation': 'High deviation detected in benchmark',
        'evidence': {'packet_count': 65},
        'recommended_actions': ['Isolate device and inspect telemetry']
    }
    import uuid
    for i in range(iterations):
        rep = dict(test_report)
        rep['report_id'] = f"TIR-BENCH-{uuid.uuid4().hex[:8].upper()}"
        t0 = time.perf_counter()
        ThreatIntelligenceService.save_report(rep)
        db_write_times.append((time.perf_counter() - t0) * 1000)
        
    def get_stats(arr):
        return {
            'min': round(float(np.min(arr)), 3),
            'max': round(float(np.max(arr)), 3),
            'mean': round(float(np.mean(arr)), 3),
            'std': round(float(np.std(arr)), 3)
        }
        
    return {
        'model_loading_ms': get_stats(load_times),
        'feature_extraction_ms': get_stats(feat_times),
        'single_prediction_ms': get_stats(pred_times),
        'threat_classification_ms': get_stats(class_times),
        'full_ai_pipeline_ms': get_stats(pipeline_times),
        'sqlite_report_write_ms': get_stats(db_write_times)
    }

if __name__ == '__main__':
    print("=== 1. DATASET VALIDATION ===")
    ds_res = evaluate_dataset()
    print(f"Total samples: {ds_res['total_samples']}")
    print(f"Columns ({len(ds_res['columns'])}): {ds_res['columns']}")
    print(f"Missing values: {ds_res['missing_values']}")
    print(f"Labels: {ds_res['label_distribution']}")
    print(f"Anomaly types: {ds_res['anomaly_type_distribution']}")
    
    print("\n=== 2. MODEL VALIDATION ===")
    m_res = evaluate_model_performance()
    print(json.dumps(m_res, indent=2))
    
    print("\n=== 3. LATENCY BENCHMARKS ===")
    b_res = benchmark_latencies(iterations=50)
    print(json.dumps(b_res, indent=2))
    
    # Save results to json for report generation
    out_file = os.path.join(BACKEND_DIR, 'data', 'prompt6_benchmark_results.json')
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump({
            'dataset_evaluation': ds_res,
            'model_evaluation': m_res,
            'latency_benchmarks': b_res
        }, f, indent=2)
    print(f"\nSaved empirical results to: {out_file}")
