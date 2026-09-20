"""
Model Training and Evaluation Pipeline.
Problem Statement: NTRO PS #26145 - AI-Based Detection of Cyber Threats in Unidirectional IP Traffic.

This module trains:
1. Primary Supervised Classifier: RandomForestClassifier (with calibrated probability estimates).
2. Unsupervised Anomaly Baseline: IsolationForest (for detecting zero-day / anomalous traffic).
3. Evaluates per-class precision, recall, F1, accuracy, and confusion matrix.
4. Saves model artifacts (joblib), metrics report, and confusion matrix visualization.
"""

import sys
import os
import json
from pathlib import Path
from typing import Tuple, Dict, Any, List

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Headless backend
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix
)
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Features utilized for inference (excluding identifiers like IP, timestamp, or target label)
NUMERIC_FEATURES = [
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

CATEGORICAL_FEATURES = ["protocol"]


def preprocess_data(
    df: pd.DataFrame,
    label_encoder: LabelEncoder = None,
    fit_encoder: bool = True
) -> Tuple[pd.DataFrame, np.ndarray, LabelEncoder, List[str]]:
    """
    Extracts numerical features and one-hot encodes categorical metadata.
    """
    X = df[NUMERIC_FEATURES].copy()
    
    # Fill any NaNs safely with 0.0
    X = X.fillna(0.0)

    # Encode protocol
    protocol_encoded = pd.get_dummies(df["protocol"], prefix="proto", drop_first=False)
    # Ensure standard protocol columns exist
    for proto_col in ["proto_TCP", "proto_UDP"]:
        if proto_col not in protocol_encoded.columns:
            protocol_encoded[proto_col] = 0
    
    X = pd.concat([X, protocol_encoded[["proto_TCP", "proto_UDP"]]], axis=1)
    feature_names = list(X.columns)

    if "label" in df.columns:
        if fit_encoder or label_encoder is None:
            label_encoder = LabelEncoder()
            y = label_encoder.fit_transform(df["label"])
        else:
            y = label_encoder.transform(df["label"])
    else:
        y = np.array([])

    return X, y, label_encoder, feature_names


def train_models(
    data_path: Path,
    model_dir: Path,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Loads dataset, splits into stratified train/test sets, trains RF and Isolation Forest,
    saves artifacts and reports evaluation metrics.
    """
    model_dir.mkdir(parents=True, exist_ok=True)
    
    if not data_path.exists():
        raise FileNotFoundError(f"Processed dataset not found at {data_path}. Run data/prepare_dataset.py first.")

    print(f"[*] Loading dataset from {data_path}...")
    df = pd.read_csv(data_path)
    print(f"[+] Loaded {len(df)} flow records.")

    # Preprocess
    X, y, label_encoder, feature_names = preprocess_data(df, fit_encoder=True)
    class_names = list(label_encoder.classes_)

    # Stratified 80/20 train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.20,
        random_state=random_state,
        stratify=y
    )
    print(f"[*] Training split: {len(X_train)} samples, Test split: {len(X_test)} samples.")

    # 1. Train Primary Random Forest Classifier
    print("[*] Training Primary RandomForestClassifier...")
    rf_model = RandomForestClassifier(
        n_estimators=120,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=random_state,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    # Predictions & Probabilities
    y_pred = rf_model.predict(X_test)
    y_proba = rf_model.predict_proba(X_test)

    # 2. Train Secondary Unsupervised Isolation Forest
    print("[*] Training Baseline IsolationForest (Unsupervised Anomaly Detection)...")
    # Fit primarily on normal class in training set to establish baseline
    normal_idx = np.where(label_encoder.classes_ == "normal")[0]
    if len(normal_idx) > 0:
        normal_class_id = normal_idx[0]
        normal_train = X_train[y_train == normal_class_id]
        iso_forest = IsolationForest(
            n_estimators=100,
            contamination=0.08,
            random_state=random_state,
            n_jobs=-1
        )
        iso_forest.fit(normal_train)
    else:
        iso_forest = IsolationForest(contamination=0.1, random_state=random_state, n_jobs=-1)
        iso_forest.fit(X_train)

    # 3. Compute Metrics
    acc = accuracy_score(y_test, y_pred)
    prec_macro, rec_macro, f1_macro, _ = precision_recall_fscore_support(y_test, y_pred, average="macro")
    prec_weight, rec_weight, f1_weight, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted")
    report_str = classification_report(y_test, y_pred, target_names=class_names, digits=4)
    cm = confusion_matrix(y_test, y_pred)

    # Confidence distribution
    max_probas = np.max(y_proba, axis=1)
    conf_mean = float(np.mean(max_probas))
    conf_median = float(np.median(max_probas))
    conf_min = float(np.min(max_probas))
    conf_max = float(np.max(max_probas))

    # Low / Medium / High severity breakdown on test set predictions
    severities = []
    for conf in max_probas:
        if conf < 0.60:
            severities.append("Low")
        elif conf <= 0.85:
            severities.append("Medium")
        else:
            severities.append("High")
    sev_counts = pd.Series(severities).value_counts().to_dict()

    # 4. Save Metrics Report
    report_file = model_dir / "metrics_report.txt"
    with open(report_file, "w") as f:
        f.write("================================================================================\n")
        f.write("NTRO PS #26145 - AI-BASED CYBER THREAT DETECTION IN UNIDIRECTIONAL IP TRAFFIC\n")
        f.write("MODEL EVALUATION & BENCHMARK REPORT\n")
        f.write("================================================================================\n\n")
        f.write(f"Evaluated Test Samples: {len(y_test)}\n")
        f.write(f"Overall Test Accuracy:  {acc * 100:.2f}%\n")
        f.write(f"Macro F1-Score:         {f1_macro:.4f}\n")
        f.write(f"Weighted F1-Score:      {f1_weight:.4f}\n\n")
        f.write("--------------------------------------------------------------------------------\n")
        f.write("Classification Report by Threat Class:\n")
        f.write("--------------------------------------------------------------------------------\n")
        f.write(report_str)
        f.write("\n--------------------------------------------------------------------------------\n")
        f.write("Confidence Score Distribution (predict_proba):\n")
        f.write("--------------------------------------------------------------------------------\n")
        f.write(f"  Mean Confidence:   {conf_mean:.4f}\n")
        f.write(f"  Median Confidence: {conf_median:.4f}\n")
        f.write(f"  Min Confidence:    {conf_min:.4f}\n")
        f.write(f"  Max Confidence:    {conf_max:.4f}\n")
        f.write(f"  Severity Breakdown: Low (<0.60): {sev_counts.get('Low', 0)}, "
                f"Medium (0.60-0.85): {sev_counts.get('Medium', 0)}, "
                f"High (>0.85): {sev_counts.get('High', 0)}\n\n")
        f.write("--------------------------------------------------------------------------------\n")
        f.write("Feature Importances:\n")
        f.write("--------------------------------------------------------------------------------\n")
        for f_name, imp in sorted(zip(feature_names, rf_model.feature_importances_), key=lambda x: x[1], reverse=True):
            f.write(f"  - {f_name:28s}: {imp:.4f}\n")

    print(f"[+] Saved metrics report to {report_file}")

    # 5. Generate & Save Confusion Matrix Plot
    cm_plot_file = model_dir / "confusion_matrix.png"
    plt.figure(figsize=(9, 7))
    sns.set_theme(style="dark")
    cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    sns.heatmap(
        cm_norm,
        annot=True,
        fmt=".2f",
        cmap="Blues",
        xticklabels=class_names,
        yticklabels=class_names,
        cbar=True
    )
    plt.title("Normalized Confusion Matrix — NTRO PS #26145", fontsize=13, pad=15)
    plt.xlabel("Predicted Class", fontsize=11)
    plt.ylabel("True Class", fontsize=11)
    plt.xticks(rotation=35, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.savefig(cm_plot_file, dpi=180)
    plt.close()
    print(f"[+] Saved confusion matrix to {cm_plot_file}")

    # 6. Save Model Artifacts
    joblib.dump(rf_model, model_dir / "trained_model.pkl")
    joblib.dump(iso_forest, model_dir / "isolation_forest.pkl")
    joblib.dump(label_encoder, model_dir / "label_encoder.pkl")
    with open(model_dir / "feature_names.json", "w") as f:
        json.dump(feature_names, f, indent=2)

    summary_metrics = {
        "accuracy": round(float(acc), 4),
        "macro_f1": round(float(f1_macro), 4),
        "weighted_f1": round(float(f1_weight), 4),
        "test_samples": len(y_test),
        "classes": class_names,
        "avg_confidence": round(conf_mean, 4),
        "severity_counts": sev_counts
    }

    with open(model_dir / "model_summary.json", "w") as f:
        json.dump(summary_metrics, f, indent=2)

    print(f"[+] All artifacts saved in {model_dir}")
    print(f"[+] Final Test Accuracy: {acc * 100:.2f}%, Macro F1: {f1_macro:.4f}")
    return summary_metrics


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    data_csv = project_root / "data" / "processed" / "flows.csv"
    models_path = project_root / "model"
    train_models(data_csv, models_path)
