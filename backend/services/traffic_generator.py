"""
NetGuardian AI - Synthetic Network Traffic Dataset Generator
Generates reproducible, realistic simulated network traffic records containing:
- Normal baseline traffic
- Unusual packet activity
- Suspicious outbound traffic (data exfiltration)
- Abnormally high connection frequency (DoS / Port Scanning)
- Unusual packet sizes (jumbo packets / fragments)
- Unusual packet entropy (encrypted exfiltration)
- Potential data-exfiltration patterns (asymmetric outbound transfer)
- Traffic spikes (burst volume surges)

Labels and dataset are strictly SIMULATED for machine learning prototype testing.
"""

from __future__ import annotations
import os
import csv
import random
import datetime
from typing import Dict, List, Any, Optional
import pandas as pd
import numpy as np

from services.feature_extractor import FEATURE_NAMES

# Simulated devices inventory: (device_id, device_name, device_type, nominal_role)
DEVICE_PROFILES = [
    {'id': 1,  'name': 'Smart Meter Communication Gateway', 'type': 'Gateway',    'tier': 'gateway'},
    {'id': 2,  'name': 'Head-End System (HES)',              'type': 'Server',     'tier': 'core_server'},
    {'id': 3,  'name': 'Meter Data Management System (MDMS)','type': 'Server',     'tier': 'core_server'},
    {'id': 4,  'name': 'Backup HES/MDMS Server',             'type': 'Server',     'tier': 'backup_server'},
    {'id': 5,  'name': 'Smart Meter 01 (Yelahanka)',         'type': 'Smart Meter','tier': 'field_meter'},
    {'id': 6,  'name': 'Smart Meter 02 (Vijayanagar)',       'type': 'Smart Meter','tier': 'field_meter'},
    {'id': 7,  'name': 'Smart Meter 03 (Rajajinagar)',       'type': 'Smart Meter','tier': 'field_meter'},
    {'id': 8,  'name': 'Smart Meter 04 (Hebbal)',            'type': 'Smart Meter','tier': 'field_meter'},
    {'id': 9,  'name': 'Smart Meter 05 (Jayanagar)',         'type': 'Smart Meter','tier': 'field_meter'},
    {'id': 10, 'name': 'BESCOM Security Firewall',           'type': 'Firewall',   'tier': 'perimeter'}
]


class TrafficDatasetGenerator:
    """
    Generates reproducible synthetic network traffic datasets for training and evaluating
    Isolation Forest anomaly detection models.
    """

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.rng = random.Random(random_state)
        if np is not None:
            np.random.seed(random_state)

    def _generate_normal_record(self, dev: Dict[str, Any], timestamp: datetime.datetime) -> Dict[str, Any]:
        """Generate a single realistic normal network telemetry record based on device tier."""
        tier = dev['tier']

        if tier == 'field_meter':
            # Smart meter field telemetry: periodic DLMS/COSEM bursts
            packet_count = self.rng.randint(12, 120)
            avg_packet_size = round(self.rng.uniform(250.0, 750.0), 2)
            bytes_transferred = int(packet_count * avg_packet_size)
            conn_freq = round(self.rng.uniform(0.5, 8.0), 2)
            entropy = round(self.rng.uniform(3.8, 5.4), 3)
            # Uplink meter reading is roughly 60% outbound, 40% inbound handshake
            outbound_ratio = self.rng.uniform(0.55, 0.70)
            outbound_bytes = int(bytes_transferred * outbound_ratio)
            inbound_bytes = bytes_transferred - outbound_bytes
            duration = round(self.rng.uniform(0.8, 6.0), 2)

        elif tier == 'core_server':
            # High-throughput database, ingestion and API services
            packet_count = self.rng.randint(200, 1200)
            avg_packet_size = round(self.rng.uniform(800.0, 1420.0), 2)
            bytes_transferred = int(packet_count * avg_packet_size)
            conn_freq = round(self.rng.uniform(15.0, 65.0), 2)
            entropy = round(self.rng.uniform(4.5, 6.0), 3)
            outbound_ratio = self.rng.uniform(0.45, 0.55)
            outbound_bytes = int(bytes_transferred * outbound_ratio)
            inbound_bytes = bytes_transferred - outbound_bytes
            duration = round(self.rng.uniform(1.5, 25.0), 2)

        elif tier == 'gateway':
            # Substation data concentrator aggregating field traffic
            packet_count = self.rng.randint(400, 2200)
            avg_packet_size = round(self.rng.uniform(650.0, 1200.0), 2)
            bytes_transferred = int(packet_count * avg_packet_size)
            conn_freq = round(self.rng.uniform(30.0, 95.0), 2)
            entropy = round(self.rng.uniform(4.2, 5.8), 3)
            outbound_ratio = self.rng.uniform(0.48, 0.52)
            outbound_bytes = int(bytes_transferred * outbound_ratio)
            inbound_bytes = bytes_transferred - outbound_bytes
            duration = round(self.rng.uniform(0.5, 12.0), 2)

        elif tier == 'backup_server':
            # Standby replication traffic
            packet_count = self.rng.randint(50, 400)
            avg_packet_size = round(self.rng.uniform(600.0, 1300.0), 2)
            bytes_transferred = int(packet_count * avg_packet_size)
            conn_freq = round(self.rng.uniform(5.0, 25.0), 2)
            entropy = round(self.rng.uniform(4.1, 5.5), 3)
            outbound_ratio = self.rng.uniform(0.20, 0.40)  # mostly receives replicas
            outbound_bytes = int(bytes_transferred * outbound_ratio)
            inbound_bytes = bytes_transferred - outbound_bytes
            duration = round(self.rng.uniform(2.0, 30.0), 2)

        else:  # perimeter firewall
            packet_count = self.rng.randint(600, 3500)
            avg_packet_size = round(self.rng.uniform(700.0, 1350.0), 2)
            bytes_transferred = int(packet_count * avg_packet_size)
            conn_freq = round(self.rng.uniform(50.0, 140.0), 2)
            entropy = round(self.rng.uniform(4.6, 6.2), 3)
            outbound_ratio = self.rng.uniform(0.48, 0.52)
            outbound_bytes = int(bytes_transferred * outbound_ratio)
            inbound_bytes = bytes_transferred - outbound_bytes
            duration = round(self.rng.uniform(0.2, 8.0), 2)

        return {
            'device_id': dev['id'],
            'device_name': dev['name'],
            'timestamp': timestamp.isoformat(),
            'packet_count': packet_count,
            'average_packet_size': avg_packet_size,
            'bytes_transferred': bytes_transferred,
            'connection_frequency': conn_freq,
            'packet_entropy': entropy,
            'inbound_bytes': inbound_bytes,
            'outbound_bytes': outbound_bytes,
            'connection_duration': duration,
            'label': 'NORMAL',
            'anomaly_type': 'none'
        }

    def _generate_anomalous_record(self, dev: Dict[str, Any], timestamp: datetime.datetime, anomaly_type: Optional[str] = None) -> Dict[str, Any]:
        """Generate a simulated anomalous traffic record across one of 7 distinct attack/abnormality archetypes."""
        types = [
            'data_exfiltration',
            'traffic_spike_syn_flood',
            'port_scan_recon',
            'high_entropy_encrypted_tunnel',
            'unusual_packet_sizes_jumbo',
            'abnormal_duration_slowloris',
            'unusual_packet_activity_burst'
        ]
        chosen_type = anomaly_type if anomaly_type in types else self.rng.choice(types)

        if chosen_type == 'data_exfiltration':
            # Severe outbound asymmetry with high entropy (encrypted exfiltration)
            packet_count = self.rng.randint(1500, 9500)
            avg_packet_size = round(self.rng.uniform(1380.0, 1490.0), 2)
            bytes_transferred = int(packet_count * avg_packet_size)
            conn_freq = round(self.rng.uniform(45.0, 120.0), 2)
            entropy = round(self.rng.uniform(7.72, 7.98), 3)  # Near theoretical max 8.0
            outbound_ratio = self.rng.uniform(0.92, 0.99)    # 92-99% outbound egress
            outbound_bytes = int(bytes_transferred * outbound_ratio)
            inbound_bytes = bytes_transferred - outbound_bytes
            duration = round(self.rng.uniform(120.0, 600.0), 2)

        elif chosen_type == 'traffic_spike_syn_flood':
            # Massive packet count spike of small packets with extreme connection frequency
            packet_count = self.rng.randint(12000, 65000)
            avg_packet_size = round(self.rng.uniform(40.0, 64.0), 2)  # Bare TCP SYN
            bytes_transferred = int(packet_count * avg_packet_size)
            conn_freq = round(self.rng.uniform(400.0, 2800.0), 2)     # Abnormally high
            entropy = round(self.rng.uniform(1.6, 2.7), 3)            # Very low entropy repetitive
            inbound_ratio = self.rng.uniform(0.90, 0.98)
            inbound_bytes = int(bytes_transferred * inbound_ratio)
            outbound_bytes = bytes_transferred - inbound_bytes
            duration = round(self.rng.uniform(0.02, 0.25), 2)

        elif chosen_type == 'port_scan_recon':
            # Rapid short probes across subnet
            packet_count = self.rng.randint(350, 1800)
            avg_packet_size = round(self.rng.uniform(44.0, 72.0), 2)
            bytes_transferred = int(packet_count * avg_packet_size)
            conn_freq = round(self.rng.uniform(150.0, 650.0), 2)
            entropy = round(self.rng.uniform(3.1, 4.0), 3)
            outbound_ratio = self.rng.uniform(0.85, 0.95)
            outbound_bytes = int(bytes_transferred * outbound_ratio)
            inbound_bytes = bytes_transferred - outbound_bytes
            duration = round(self.rng.uniform(0.05, 0.5), 2)

        elif chosen_type == 'high_entropy_encrypted_tunnel':
            # Stealthy DNS/ICMP tunneling or custom encrypted C2 beaconing
            packet_count = self.rng.randint(250, 950)
            avg_packet_size = round(self.rng.uniform(500.0, 1100.0), 2)
            bytes_transferred = int(packet_count * avg_packet_size)
            conn_freq = round(self.rng.uniform(8.0, 30.0), 2)
            entropy = round(self.rng.uniform(7.85, 7.99), 3)  # Extreme Shannon entropy
            outbound_ratio = self.rng.uniform(0.75, 0.88)
            outbound_bytes = int(bytes_transferred * outbound_ratio)
            inbound_bytes = bytes_transferred - outbound_bytes
            duration = round(self.rng.uniform(15.0, 90.0), 2)

        elif chosen_type == 'unusual_packet_sizes_jumbo':
            # Buffer overflow or fragmentation abuse
            packet_count = self.rng.randint(80, 450)
            avg_packet_size = round(self.rng.uniform(4500.0, 9200.0), 2)  # Exceeds standard MTU (1500)
            bytes_transferred = int(packet_count * avg_packet_size)
            conn_freq = round(self.rng.uniform(5.0, 20.0), 2)
            entropy = round(self.rng.uniform(6.8, 7.8), 3)
            outbound_bytes = int(bytes_transferred * 0.5)
            inbound_bytes = bytes_transferred - outbound_bytes
            duration = round(self.rng.uniform(1.0, 15.0), 2)

        elif chosen_type == 'abnormal_duration_slowloris':
            # Persistent connection held open with trickle traffic
            packet_count = self.rng.randint(8, 35)
            avg_packet_size = round(self.rng.uniform(80.0, 180.0), 2)
            bytes_transferred = int(packet_count * avg_packet_size)
            conn_freq = round(self.rng.uniform(0.01, 0.1), 3)
            entropy = round(self.rng.uniform(2.5, 3.8), 3)
            outbound_bytes = int(bytes_transferred * 0.4)
            inbound_bytes = bytes_transferred - outbound_bytes
            duration = round(self.rng.uniform(1800.0, 7200.0), 2)  # 30m to 2 hours

        else:  # unusual_packet_activity_burst
            packet_count = self.rng.randint(3500, 11000)
            avg_packet_size = round(self.rng.uniform(1100.0, 1450.0), 2)
            bytes_transferred = int(packet_count * avg_packet_size)
            conn_freq = round(self.rng.uniform(120.0, 350.0), 2)
            entropy = round(self.rng.uniform(6.5, 7.5), 3)
            outbound_bytes = int(bytes_transferred * 0.8)
            inbound_bytes = bytes_transferred - outbound_bytes
            duration = round(self.rng.uniform(5.0, 45.0), 2)

        return {
            'device_id': dev['id'],
            'device_name': dev['name'],
            'timestamp': timestamp.isoformat(),
            'packet_count': packet_count,
            'average_packet_size': avg_packet_size,
            'bytes_transferred': bytes_transferred,
            'connection_frequency': conn_freq,
            'packet_entropy': entropy,
            'inbound_bytes': inbound_bytes,
            'outbound_bytes': outbound_bytes,
            'connection_duration': duration,
            'label': 'ANOMALY',
            'anomaly_type': chosen_type
        }

    def generate(self, n_samples: int = 1500, anomaly_ratio: float = 0.08) -> List[Dict[str, Any]]:
        """
        Generate synthetic network traffic records.
        
        Args:
            n_samples: Total number of records to generate.
            anomaly_ratio: Fraction of records that are anomalous (default 8%).
            
        Returns:
            List[Dict[str, Any]]: List of simulated traffic records.
        """
        records = []
        n_anomalies = max(1, int(n_samples * anomaly_ratio))
        n_normals = n_samples - n_anomalies

        # Start simulated time window 24 hours ago
        base_time = datetime.datetime.now() - datetime.timedelta(hours=24)
        time_step = datetime.timedelta(seconds=int(86400 / n_samples))

        # Generate normal baseline records
        for i in range(n_normals):
            dev = self.rng.choice(DEVICE_PROFILES)
            t = base_time + (time_step * i) + datetime.timedelta(seconds=self.rng.randint(0, 30))
            records.append(self._generate_normal_record(dev, t))

        # Generate anomaly records
        for j in range(n_anomalies):
            # Prefer assigning anomalies to dev 7 (Rajajinagar suspicious), dev 10 (Firewall), dev 1 (Gateway), dev 5 (Yelahanka)
            dev_candidate = self.rng.choice([
                DEVICE_PROFILES[6],  # dev 7
                DEVICE_PROFILES[9],  # dev 10
                DEVICE_PROFILES[0],  # dev 1
                DEVICE_PROFILES[4],  # dev 5
                self.rng.choice(DEVICE_PROFILES)
            ])
            t = base_time + (time_step * (j * (n_samples // n_anomalies))) + datetime.timedelta(seconds=self.rng.randint(10, 50))
            records.append(self._generate_anomalous_record(dev_candidate, t))

        # Shuffle records to produce realistic interleaved timeline
        self.rng.shuffle(records)
        return records

    def generate_and_save(self, output_path: str, n_samples: int = 1500, anomaly_ratio: float = 0.08) -> str:
        """
        Generate dataset and save to a CSV file.
        
        Args:
            output_path: Target CSV file path.
            n_samples: Number of records.
            anomaly_ratio: Proportion of anomalies.
            
        Returns:
            str: Absolute path of written CSV.
        """
        records = self.generate(n_samples=n_samples, anomaly_ratio=anomaly_ratio)
        abs_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)

        fieldnames = [
            'device_id',
            'device_name',
            'timestamp',
            'packet_count',
            'average_packet_size',
            'bytes_transferred',
            'connection_frequency',
            'packet_entropy',
            'inbound_bytes',
            'outbound_bytes',
            'connection_duration',
            'label',
            'anomaly_type'
        ]

        with open(abs_path, 'w', newline='', encoding='utf-8') as f:
            # Explicit simulation header
            f.write("# NETGUARDIAN AI - SYNTHETIC NETWORK TRAFFIC DATASET\n")
            f.write("# SIMULATED DEMONSTRATION DATA FOR LOCAL MACHINE LEARNING TESTING ONLY\n")
            f.write("# NOT COLLECTED FROM ACTUAL PHYSICAL INFRASTRUCTURE OR PRODUCTION NETWORKS\n")
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in records:
                writer.writerow(r)

        return abs_path


def load_dataset(csv_path: str, normal_only: bool = False):
    """
    Load the synthetic traffic dataset as pandas DataFrame.
    
    Args:
        csv_path: Path to the CSV dataset.
        normal_only: If True, filters out anomalous samples for baseline training.
    """
    if pd is None:
        raise ImportError("pandas is required to load traffic dataset as DataFrame.")

    # Read CSV skipping initial comment lines
    df = pd.read_csv(csv_path, comment='#')
    if normal_only:
        df = df[df['label'] == 'NORMAL'].copy()
    return df


if __name__ == '__main__':
    default_csv = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'network_traffic.csv')
    gen = TrafficDatasetGenerator(random_state=42)
    saved_path = gen.generate_and_save(default_csv, n_samples=1600, anomaly_ratio=0.08)
    print(f"Successfully generated synthetic traffic dataset at: {saved_path}")
