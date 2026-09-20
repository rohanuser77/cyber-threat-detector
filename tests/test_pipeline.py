"""
Comprehensive Test Suite for Unidirectional IP Cyber Threat Detection Platform.
Problem Statement: NTRO PS #26145.

Covers:
- Feature engineering mathematical correctness & division-by-zero resilience.
- Dataset preparation schema validation.
- ML model inference and probability calibration validity.
- Streaming simulator alert schema & severity mapping.
- Run summary throughput calculation.
"""

import sys
import os
import json
import math
import pytest
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from features.feature_engineering import (
    source_ip_entropy,
    port_fanout_count,
    inter_arrival_stats,
    dns_entropy_and_length,
    byte_ratio,
    packet_timing_regularity
)
from data.prepare_dataset import (
    UNIFIED_SCHEMA,
    SUPPORTED_LABELS,
    generate_synthetic_flow_dataset
)
from pipeline.stream_simulator import (
    get_severity,
    extract_evidence,
    run_stream_simulator
)
from model.train_model import preprocess_data


# -----------------------------------------------------------------------------
# 1. Feature Engineering Tests
# -----------------------------------------------------------------------------

class TestFeatureEngineering:

    def test_source_ip_entropy_normal(self):
        # 4 distinct IPs with equal frequency => Shannon entropy = log2(4) = 2.0
        ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
        ent = source_ip_entropy(ips)
        assert math.isclose(ent, 2.0, rel_tol=1e-3)

    def test_source_ip_entropy_identical(self):
        # All identical => 0 entropy
        ips = ["10.0.0.1"] * 20
        assert source_ip_entropy(ips) == 0.0

    def test_source_ip_entropy_empty_and_edge_cases(self):
        assert source_ip_entropy([]) == 0.0
        assert source_ip_entropy(None) == 0.0
        assert source_ip_entropy(["10.0.0.1"]) == 0.0

    def test_port_fanout_count_dataframe(self):
        df = pd.DataFrame({
            "src_ip": ["192.168.1.5", "192.168.1.5", "192.168.1.5", "192.168.1.9"],
            "dst_port": [80, 443, 80, 22]
        })
        # 192.168.1.5 contacted 80 and 443 -> 2 unique ports
        assert port_fanout_count("192.168.1.5", df) == 2
        # 192.168.1.9 contacted port 22 -> 1 unique port
        assert port_fanout_count("192.168.1.9", df) == 1
        # Unseen IP -> 0
        assert port_fanout_count("10.0.0.1", df) == 0

    def test_port_fanout_count_empty(self):
        assert port_fanout_count("", None) == 0
        assert port_fanout_count("1.1.1.1", pd.DataFrame()) == 0

    def test_inter_arrival_stats(self):
        # Monotonic timestamps spaced by exactly 2.0 seconds
        timestamps = [0.0, 2.0, 4.0, 6.0, 8.0]
        mean_delta, var_delta = inter_arrival_stats(timestamps)
        assert math.isclose(mean_delta, 2.0, rel_tol=1e-3)
        assert math.isclose(var_delta, 0.0, abs_tol=1e-5)

    def test_inter_arrival_stats_edge_cases(self):
        assert inter_arrival_stats([]) == (0.0, 0.0)
        assert inter_arrival_stats([10.5]) == (0.0, 0.0)
        assert inter_arrival_stats(None) == (0.0, 0.0)

    def test_dns_entropy_and_length(self):
        # Low entropy English word
        ent1, len1 = dns_entropy_and_length("google.com")
        assert len1 > 0
        assert ent1 > 0.0

        # High entropy random DGA string
        ent2, len2 = dns_entropy_and_length("x9k2p8z4m1q7w3v6.ru")
        assert ent2 > ent1  # Random label must exhibit higher entropy than 'google'

    def test_dns_entropy_empty(self):
        assert dns_entropy_and_length("") == (0.0, 0)
        assert dns_entropy_and_length(None) == (0.0, 0)

    def test_byte_ratio_division_by_zero_prevention(self):
        # bytes_in = 0 must not raise ZeroDivisionError
        ratio = byte_ratio(bytes_out=1500, bytes_in=0)
        assert ratio > 0.0
        assert not math.isinf(ratio)
        assert not math.isnan(ratio)

    def test_byte_ratio_edge_cases(self):
        assert byte_ratio(-50, 100) == 0.0
        assert byte_ratio(None, None) == 0.0

    def test_packet_timing_regularity(self):
        # Perfect periodic sequence (0 variance) => regularity ~ 1.0
        periodic_deltas = [1.0, 1.0, 1.0, 1.0, 1.0]
        reg_periodic = packet_timing_regularity(periodic_deltas)
        assert math.isclose(reg_periodic, 1.0, rel_tol=1e-2)

        # High jitter sequence => lower regularity
        jittery_deltas = [0.01, 10.5, 0.1, 8.0, 0.05]
        reg_jitter = packet_timing_regularity(jittery_deltas)
        assert reg_jitter < reg_periodic


# -----------------------------------------------------------------------------
# 2. Dataset Generation & Schema Conformance Tests
# -----------------------------------------------------------------------------

class TestDatasetGeneration:

    def test_dataset_schema(self):
        df = generate_synthetic_flow_dataset(n_samples=100, seed=123)
        assert list(df.columns) == UNIFIED_SCHEMA
        assert len(df) == 100

    def test_all_supported_labels_present(self):
        df = generate_synthetic_flow_dataset(n_samples=500, seed=42)
        unique_labels = set(df["label"].unique())
        for expected in SUPPORTED_LABELS:
            assert expected in unique_labels, f"Expected label {expected} missing from dataset."

    def test_no_null_values_in_crucial_features(self):
        df = generate_synthetic_flow_dataset(n_samples=150, seed=99)
        assert not df["flow_bytes_per_sec"].isna().any()
        assert not df["flow_packets_per_sec"].isna().any()
        assert not df["outbound_inbound_byte_ratio"].isna().any()


# -----------------------------------------------------------------------------
# 3. Model Inference & Preprocessing Tests
# -----------------------------------------------------------------------------

@pytest.fixture(scope="session")
def model_artifacts():
    model_dir = PROJECT_ROOT / "model"
    rf_path = model_dir / "trained_model.pkl"
    le_path = model_dir / "label_encoder.pkl"
    if not rf_path.exists() or not le_path.exists():
        pytest.skip("Model artifacts not yet trained.")
    rf = joblib.load(rf_path)
    le = joblib.load(le_path)
    return rf, le


class TestModelInference:

    def test_model_predict_proba_range(self, model_artifacts):
        rf, le = model_artifacts
        sample_df = generate_synthetic_flow_dataset(n_samples=30, seed=777)
        X, _, _, _ = preprocess_data(sample_df, label_encoder=le, fit_encoder=False)
        probas = rf.predict_proba(X)

        # Probabilities must sum to 1.0 and each between 0.0 and 1.0
        assert np.all(probas >= 0.0) and np.all(probas <= 1.0)
        assert np.allclose(np.sum(probas, axis=1), 1.0)

    def test_label_encoder_classes(self, model_artifacts):
        _, le = model_artifacts
        for label in SUPPORTED_LABELS:
            assert label in le.classes_


# -----------------------------------------------------------------------------
# 4. Pipeline & Alert Schema Tests
# -----------------------------------------------------------------------------

class TestPipelineAlerts:

    def test_severity_thresholds(self):
        assert get_severity(0.45) == "Low"
        assert get_severity(0.599) == "Low"
        assert get_severity(0.60) == "Medium"
        assert get_severity(0.75) == "Medium"
        assert get_severity(0.85) == "Medium"
        assert get_severity(0.8501) == "High"
        assert get_severity(0.99) == "High"

    def test_extract_evidence_fields(self):
        row = pd.Series({
            "protocol": "TCP",
            "duration": 1.25,
            "flow_packets_per_sec": 15.0,
            "flow_bytes_per_sec": 3000.0,
            "outbound_inbound_byte_ratio": 4.5,
            "unique_dst_ports_per_src": 85,
            "inter_arrival_variance": 0.002,
            "dns_entropy": 3.8,
            "dns_query_length": 25,
            "packet_count": 20,
            "byte_count": 4000
        })

        ev_scan = extract_evidence(row, "port_scan")
        assert "unique_dst_ports_per_src" in ev_scan
        assert ev_scan["unique_dst_ports_per_src"] == 85

        ev_beacon = extract_evidence(row, "botnet_beacon")
        assert "inter_arrival_variance" in ev_beacon

        ev_dga = extract_evidence(row, "dga_dns")
        assert "dns_entropy" in ev_dga

    def test_existing_alerts_jsonl_schema(self):
        alerts_file = PROJECT_ROOT / "pipeline" / "alerts.jsonl"
        if not alerts_file.exists():
            pytest.skip("alerts.jsonl does not exist yet.")

        with open(alerts_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        if not lines:
            pytest.skip("alerts.jsonl is empty.")

        # Test first 20 alerts
        for line in lines[:20]:
            alert = json.loads(line.strip())
            assert "timestamp" in alert
            assert "flow_id" in alert
            assert "threat_class" in alert
            assert "confidence_score" in alert
            assert "severity" in alert
            assert "evidence" in alert
            assert 0.0 <= alert["confidence_score"] <= 1.0
            assert alert["severity"] in ("Low", "Medium", "High")

    def test_existing_run_summary_schema(self):
        summary_file = PROJECT_ROOT / "pipeline" / "run_summary.json"
        if not summary_file.exists():
            pytest.skip("run_summary.json does not exist yet.")

        with open(summary_file, "r", encoding="utf-8") as f:
            summary = json.load(f)

        assert "total_flows_processed" in summary
        assert "total_alerts" in summary
        assert "measured_throughput_flows_per_sec" in summary
        assert "avg_confidence_score" in summary
        assert "run_started_at" in summary
        assert "dataset_source" in summary
        assert "replay_status" in summary
        assert summary["measured_throughput_flows_per_sec"] >= 0.0
