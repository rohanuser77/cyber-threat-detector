"""
Central Configuration and Constant Definitions.
Problem Statement: NTRO PS #26145 - AI-Based Detection of Cyber Threats in Unidirectional IP Traffic.

This module acts as the single source of truth for:
1. Filesystem paths across data, model, pipeline, and dashboard modules.
2. Threat classes, display names, and theme colors.
3. Strict severity calibration thresholds and visual styles.
4. Preprocessing feature specifications.
"""

from pathlib import Path
from typing import Dict, List, Tuple

# -----------------------------------------------------------------------------
# 1. Filesystem & Directory Paths
# -----------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent

DATA_DIR = PROJECT_ROOT / "data"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
FLOWS_CSV = PROCESSED_DATA_DIR / "flows.csv"
DATASET_METADATA = PROCESSED_DATA_DIR / "dataset_metadata.json"

MODEL_DIR = PROJECT_ROOT / "model"
TRAINED_MODEL_PATH = MODEL_DIR / "trained_model.pkl"
ISOLATION_FOREST_PATH = MODEL_DIR / "isolation_forest.pkl"
LABEL_ENCODER_PATH = MODEL_DIR / "label_encoder.pkl"
METRICS_REPORT_PATH = MODEL_DIR / "metrics_report.txt"

PIPELINE_DIR = PROJECT_ROOT / "pipeline"
ALERTS_FILE = PIPELINE_DIR / "alerts.jsonl"
SUMMARY_FILE = PIPELINE_DIR / "run_summary.json"

# -----------------------------------------------------------------------------
# 2. Threat Classes & Categories
# -----------------------------------------------------------------------------
SUPPORTED_LABELS: List[str] = [
    "normal",
    "ddos",
    "port_scan",
    "botnet_beacon",
    "dga_dns",
    "encrypted_malware",
    "exfiltration"
]

ATTACK_CLASSES: List[str] = [
    "ddos",
    "port_scan",
    "botnet_beacon",
    "dga_dns",
    "encrypted_malware",
    "exfiltration"
]

THREAT_DISPLAY_NAMES: Dict[str, str] = {
    "ddos": "DDoS Flood",
    "port_scan": "Port Scan",
    "botnet_beacon": "Botnet Beacon",
    "dga_dns": "DGA DNS Query",
    "encrypted_malware": "Encrypted Malware",
    "exfiltration": "Data Exfiltration",
    "normal": "Benign Traffic"
}

# -----------------------------------------------------------------------------
# 3. Theme Colors & Visual Palettes
# -----------------------------------------------------------------------------
COLOR_PALETTE: Dict[str, str] = {
    "bg_dark": "#0A0E17",
    "topbar_bg": "#0B1E33",
    "sidebar_bg": "#0A1826",
    "card_bg": "#111C2E",
    "card_border": "rgba(255, 255, 255, 0.08)",
    "accent_cyan": "#00C2CB",
    "text_primary": "#E8EDF2",
    "text_muted": "#8A96A8",
    "high_red": "#FF4B4B",
    "med_orange": "#FFA940",
    "low_yellow": "#FFD666",
    "benign_green": "#00E676"
}

THREAT_COLORS: Dict[str, str] = {
    "ddos": "#FF4D4F",
    "port_scan": "#FA8C16",
    "botnet_beacon": "#9254DE",
    "dga_dns": "#13C2C2",
    "encrypted_malware": "#F759AB",
    "exfiltration": "#FFC53D",
    "normal": "#52C41A"
}

SEVERITY_COLORS: Dict[str, str] = {
    "Low": COLOR_PALETTE["low_yellow"],
    "Medium": COLOR_PALETTE["med_orange"],
    "High": COLOR_PALETTE["high_red"]
}

# Strict severity mapping thresholds per NTRO PS #26145
SEVERITY_LOW_MAX = 0.60
SEVERITY_MED_MAX = 0.85

# -----------------------------------------------------------------------------
# 4. Feature Specifications
# -----------------------------------------------------------------------------
NUMERIC_FEATURES: List[str] = [
    "packet_count",
    "byte_count",
    "duration",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "unique_dst_ports_per_src",
    "inter_arrival_variance",
    "dns_query_length",
    "dns_entropy",
    "outbound_inbound_byte_ratio"
]

CATEGORICAL_FEATURES: List[str] = ["protocol"]
